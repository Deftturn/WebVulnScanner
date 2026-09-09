import asyncio
import logging
import sys
import traceback
from dataclasses import dataclass
from typing import AsyncIterator, Dict, List, Optional, Set
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, Browser, BrowserContext, Page, TimeoutError as PlaywrightTimeoutError
from playwright._impl._errors import TargetClosedError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


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
    html: str = ""


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
        idle_timeout_ms: int = 2500,
        idle_wait_ms: int = 500,
        retries: int = 2,
        include_subdomains: bool = False,
        crawl_all_same_domain_links: bool = True,
        ignore_https_errors: bool = True,
        user_agent: str = DEFAULT_USER_AGENT,
    ):
        # Fail fast instead of silently crawling nothing if the caller forgot
        # the scheme (a very easy mistake when switching between target sites).
        parsed = urlparse(base_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(
                f"base_url must include a scheme, e.g. 'https://{base_url}' "
                f"(got {base_url!r})"
            )

        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.page_timeout_ms = page_timeout_ms
        # "networkidle" needs zero connections for 500ms straight; SPA-heavy
        # pages (Swagger UI, dashboards with polling) often never truly go
        # quiet, so this wait was silently costing the FULL page_timeout_ms
        # (30s) on every such page during crawling, not just injection
        # testing. 2.5s is enough for genuinely static pages to settle.
        self.idle_timeout_ms = idle_timeout_ms
        self.idle_wait_ms = idle_wait_ms
        self.retries = retries
        self.include_subdomains = include_subdomains
        self.ignore_https_errors = ignore_https_errors
        self.user_agent = user_agent

        # If True (default), every same-domain link is crawled and
        # _is_interesting() is only used to annotate/prioritize, not to drop
        # links. Set False to restore the old aggressive-filtering behavior.
        self.crawl_all_same_domain_links = crawl_all_same_domain_links

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
        """Heuristic signal for 'likely worth prioritizing', NOT a hard
        include/exclude filter. See crawl_all_same_domain_links."""
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

    def _should_queue(self, url: str) -> bool:
        """Actual decision of whether a discovered link gets crawled."""
        path = urlparse(url).path.lower()
        skip_patterns = [
            "/commit", "/blob", "/tree", "/releases", "/tags",
            "/graphs", "/network", "/stargazers", "/watchers",
            "/topics", "/sponsors", "/issues", "/pulls",
        ]
        if any(p in path for p in skip_patterns):
            return False

        if self.crawl_all_same_domain_links:
            return True
        return self._is_interesting(url)

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

            if self._is_same_domain(full) and self._should_queue(full):
                links.add(full)

        return links

    # Input types that can meaningfully receive an injected text payload via
    # a UI fill. Anything else (submit/button/reset -- can't be filled at
    # all; hidden -- not visible, so fill() just retry-waits until it times
    # out; checkbox/radio/file -- need a different interaction than fill())
    # was previously included anyway, so every payload against a login
    # form's submit button or a hidden CSRF-style field was guaranteed to
    # fail, but only after paying for a full page navigation first. That was
    # a large fraction of total scan time on form-heavy pages -- confirmed
    # directly in a run's logs: "Error: Input of type 'submit' cannot be
    # filled" and repeated "element is not visible" waits on a hidden field,
    # on nearly every form-bearing page.
    _FILLABLE_INPUT_TYPES = {
        "text", "search", "email", "tel", "url", "password", "number", "",
    }

    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        soup = BeautifulSoup(html, "lxml")
        forms = []

        for form in soup.find_all("form"):
            action = urljoin(base_url, form.get("action") or base_url)
            method = form.get("method", "get").lower()

            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                if inp.name == "input":
                    input_type = (inp.get("type") or "text").lower()
                    if input_type not in self._FILLABLE_INPUT_TYPES:
                        continue
                # textarea and select have no meaningful "type" attribute
                # for this purpose -- both are always fillable/selectable.
                inputs.append(name)

            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs
            })

        return forms

    def _safe_parse(self, html: str, url: str):
        """Parsing must never be allowed to kill the worker task. Raise the
        recursion limit for this call (deeply-nested real-world pages, e.g.
        Wikipedia, can exceed BeautifulSoup's default limit) and fall back to
        empty results rather than propagating."""
        old_limit = sys.getrecursionlimit()
        try:
            sys.setrecursionlimit(10000)
            links = self._extract_links(html, url)
            forms = self._extract_forms(html, url)
            return links, forms
        except RecursionError:
            logger.error(f"{url}: recursion limit hit parsing HTML, skipping link/form extraction")
            return set(), []
        except Exception:
            logger.error(f"{url}: parse error:\n{traceback.format_exc()}")
            return set(), []
        finally:
            sys.setrecursionlimit(old_limit)

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
                    await page.wait_for_load_state("networkidle", timeout=self.idle_timeout_ms)
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

        if status < 200 or status >= 400:
            logger.warning(f"{url}: status {status}, skipping")
            return None

        async with self._lock:
            self._visited.add(norm)

        links, forms = await asyncio.to_thread(self._safe_parse, html, url)
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
            html=html,
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
            context: BrowserContext = await browser.new_context(
                ignore_https_errors=self.ignore_https_errors,
                user_agent=self.user_agent,
            )

            async def worker(worker_id: int):
                page = await context.new_page()
                page.set_default_timeout(self.page_timeout_ms)

                while True:
                    url, depth = await queue.get()

                    if url is None:
                        queue.task_done()
                        break

                    norm = self._normalize(url)
                    async with self._lock:
                        self._queued.discard(norm)

                    try:
                        result = await self._crawl_one(page, url, depth, queue)
                        if result:
                            await results_queue.put(result)
                    except Exception:
                        logger.error(
                            f"worker {worker_id}: unhandled error on {url}:\n"
                            f"{traceback.format_exc()}"
                        )
                    finally:
                        queue.task_done()

                await page.close()

            workers = [asyncio.create_task(worker(i)) for i in range(self.concurrency)]

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

    count = 0
    async for page in crawler.crawl():
        count += 1
        print(f"[{page.status}] {page.url}")
        print(f"Params: {page.params}")
        print(f"Forms: {page.forms}")
        print("-" * 50)

    if count == 0:
        print("0 pages crawled — check the WARNING/ERROR log lines above for the cause.")


if __name__ == "__main__":
    asyncio.run(run())