import asyncio
import logging
from dataclasses import dataclass
from typing import AsyncIterator, Dict, List, Optional, Set
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, Browser, BrowserContext, Page, TimeoutError as PlaywrightTimeoutError
from playwright._impl._errors import TargetClosedError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CrawlResult:
    url: str
    normalized_url: str
    depth: int
    status: int
    params: List[str]
    links: List[str]
    forms: List[Dict]
    headers: Dict[str, str]


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

class DFSCrawler:
    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        concurrency: int = 5,
        page_timeout_ms: int = 30000,
        idle_wait_ms: int = 500,
        retries: int = 2,
        include_subdomains: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.page_timeout_ms = page_timeout_ms
        self.idle_wait_ms = idle_wait_ms
        self.retries = retries
        self.include_subdomains = include_subdomains

        parsed = urlparse(base_url)
        self.base_domain = parsed.netloc

        self.concurrency = concurrency
        self._visited: Set[str] = set()
        self._queued: Set[str] = set()
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # URL helpers
    # ------------------------------------------------------------------

    def _normalize(self, url: str) -> str:
        p = urlparse(url)
        qs = parse_qs(p.query)
        normalized_qs = "&".join(f"{k}=" for k in sorted(qs.keys()))
        return urlunparse((p.scheme, p.netloc, p.path.rstrip("/"), "", normalized_qs, ""))

    def _is_same_domain(self, url: str) -> bool:
        host = urlparse(url).netloc
        if self.include_subdomains:
            return host == self.base_domain or host.endswith(f".{self.base_domain}")
        return host == self.base_domain

    @staticmethod
    def _extract_params(url: str) -> List[str]:
        return list(parse_qs(urlparse(url).query).keys())

    # ------------------------------------------------------------------
    # URL filtering
    # ------------------------------------------------------------------

    def _is_interesting(self, url: str) -> bool:
        path = urlparse(url).path.lower()

        skip_patterns = [
            "/commit", "/blob", "/tree", "/releases", "/tags",
            "/graphs", "/network", "/stargazers", "/watchers",
            "/topics", "/sponsors", "/issues", "/pulls",
        ]

        if any(p in path for p in skip_patterns):
            return False

        if "?" in url:
            return True

        important_keywords = [
            "search", "login", "register", "account",
            "api", "cart", "product", "user", "checkout",
            "redirect", "auth"
        ]

        return any(k in path for k in important_keywords)

    # ------------------------------------------------------------------
    # HTML parsing
    # ------------------------------------------------------------------

    def _extract_links(self, html: str, base_url: str) -> Set[str]:
        soup = BeautifulSoup(html, "lxml")
        links = set()

        for tag in soup.find_all("a", href=True):
            href = tag["href"]

            if href.startswith(("mailto:", "javascript:", "tel:", "#")):
                continue

            full = urljoin(base_url, href).split("#")[0]

            if self._is_same_domain(full) and self._is_interesting(full):
                links.add(full)

        return links

    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        soup = BeautifulSoup(html, "lxml")
        forms = []

        for form in soup.find_all("form"):
            action = urljoin(base_url, form.get("action") or base_url)
            method = form.get("method", "get").lower()

            inputs = [
                inp.get("name")
                for inp in form.find_all(["input", "textarea", "select"])
                if inp.get("name")
            ]

            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs
            })

        return forms

    # ------------------------------------------------------------------
    # Fetch with retry (page reused)
    # ------------------------------------------------------------------

    async def _fetch(self, page: Page, url: str):
        for attempt in range(self.retries + 1):
            try:
                response = await page.goto(
                    url,
                    timeout=self.page_timeout_ms,
                    wait_until="domcontentloaded"
                )

                if not response:
                    return None

                try:
                    await page.wait_for_load_state("networkidle", timeout=self.page_timeout_ms)
                except PlaywrightTimeoutError:
                    pass

                await page.wait_for_timeout(self.idle_wait_ms)

                html = await page.content()
                headers = {k.lower(): v for k, v in response.headers.items()}

                return html, response.status, headers

            except Exception as e:
                wait = 2 ** attempt
                logger.warning(f"{url} failed (attempt {attempt+1}): {e}")
                if attempt < self.retries:
                    await asyncio.sleep(wait)
                else:
                    return None

    # ------------------------------------------------------------------
    # Crawl single URL
    # ------------------------------------------------------------------

    async def _crawl_one(self, page: Page, url, depth, queue):
        norm = self._normalize(url)

        async with self._lock:
            if norm in self._visited or depth > self.max_depth:
                return None

        result = await self._fetch(page, url)
        if not result:
            return None

        html, status, headers = result

        # ✅ status filtering
        if status < 200 or status >= 400:
            return None

        async with self._lock:
            self._visited.add(norm)

        links = await asyncio.to_thread(self._extract_links, html, url)
        forms = await asyncio.to_thread(self._extract_forms, html, url)
        params = self._extract_params(url)

        for link in links:
            norm_link = self._normalize(link)

            async with self._lock:
                if norm_link not in self._visited and norm_link not in self._queued:
                    self._queued.add(norm_link)
                    await queue.put((link, depth + 1))

        return CrawlResult(
            url=url,
            normalized_url=norm,
            depth=depth,
            status=status,
            params=params,
            links=list(links),
            forms=forms,
            headers=headers,
        )

    # ------------------------------------------------------------------
    # Main crawl
    # ------------------------------------------------------------------

    async def crawl(self) -> AsyncIterator[CrawlResult]:
        queue: asyncio.LifoQueue = asyncio.LifoQueue()
        await queue.put((self.base_url, 0))
        results_queue: asyncio.Queue = asyncio.Queue()

        async with async_playwright() as pw:
            browser: Browser = await pw.chromium.launch(headless=True)
            context: BrowserContext = await browser.new_context()

            async def worker():
                page = await context.new_page()
                page.set_default_timeout(self.page_timeout_ms)

                while True:
                    url, depth = await queue.get()

                    if url is None:
                        break

                    norm = self._normalize(url)
                    async with self._lock:
                        self._queued.discard(norm)

                    try:
                        result = await self._crawl_one(page, url, depth, queue)
                        if result:
                            await results_queue.put(result)
                    finally:
                        queue.task_done()

                await page.close()

            workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]

            async def terminator():
                await queue.join()
                for _ in workers:
                    await queue.put((None, None))
                await results_queue.put(None)

            asyncio.create_task(terminator())

            while True:
                result = await results_queue.get()
                if result is None:
                    break
                yield result

            for w in workers:
                w.cancel()
            await browser.close()


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

async def run():
    crawler = DFSCrawler(
        base_url="http://localhost:3000",
        max_depth=3,
        concurrency=5,
    )

    async for page in crawler.crawl():
        print(f"[{page.status}] {page.url}")
        print(f"Params: {page.params}")
        print(f"Forms: {page.forms}")
        print("-" * 50)


if __name__ == "__main__":
    asyncio.run(run())