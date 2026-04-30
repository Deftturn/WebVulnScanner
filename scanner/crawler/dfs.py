import asyncio
import logging
from dataclasses import dataclass
from typing import AsyncIterator, Dict, List, Optional, Set
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, Browser, BrowserContext, Page
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

        self._sem = asyncio.Semaphore(concurrency)
        self._visited: Set[str] = set()
        self._queued: Set[str] = set()
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # URL helpers
    # ------------------------------------------------------------------

    def _normalize(self, url: str) -> str:
        """Normalize URL but KEEP parameter structure (important for scanning)."""
        p = urlparse(url)
        keys = sorted(parse_qs(p.query).keys())
        query_signature = "&".join(keys)
        return urlunparse((p.scheme, p.netloc, p.path.rstrip("/"), "", query_signature, ""))

    def _is_same_domain(self, url: str) -> bool:
        host = urlparse(url).netloc
        if self.include_subdomains:
            return host == self.base_domain or host.endswith(f".{self.base_domain}")
        return host == self.base_domain

    @staticmethod
    def _extract_params(url: str) -> List[str]:
        return list(parse_qs(urlparse(url).query).keys())

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

            if self._is_same_domain(full):
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
    # Fetch with retry
    # ------------------------------------------------------------------

    async def _fetch(self, context: BrowserContext, url: str):
        async with self._sem:
            for attempt in range(self.retries + 1):
                page: Optional[Page] = None
                try:
                    page = await context.new_page()
                    
                    # Set timeout for all operations on this page
                    page.set_default_timeout(self.page_timeout_ms)
                    page.set_default_navigation_timeout(self.page_timeout_ms)

                    response = await page.goto(
                        url,
                        timeout=self.page_timeout_ms,
                        wait_until="domcontentloaded"
                    )

                    if not response:
                        return None

                    if response.status >= 400:
                        return None

                    # Wait for network to be idle to ensure page is fully loaded
                    try:
                        await page.wait_for_load_state("networkidle", timeout=self.page_timeout_ms)
                    except asyncio.TimeoutError:
                        logger.debug(f"Network idle timeout for {url}, continuing anyway")

                    await page.wait_for_timeout(self.idle_wait_ms)

                    html = await page.content()
                    headers = dict(response.headers)

                    return html, response.status, headers

                except (TargetClosedError, ConnectionError) as e:
                    # Page/browser was closed, retry with backoff
                    wait = 2 ** attempt
                    logger.warning(f"{url} - target closed (attempt {attempt+1}), retrying in {wait}s")
                    if attempt < self.retries:
                        await asyncio.sleep(wait)
                    else:
                        return None
                except asyncio.TimeoutError as e:
                    wait = 2 ** attempt
                    logger.warning(f"{url} - timeout (attempt {attempt+1}), retrying in {wait}s")
                    if attempt < self.retries:
                        await asyncio.sleep(wait)
                    else:
                        return None
                except Exception as e:
                    wait = 2 ** attempt
                    logger.warning(f"{url} failed (attempt {attempt+1}): {type(e).__name__}: {e}")
                    if attempt < self.retries:
                        await asyncio.sleep(wait)
                    else:
                        return None
                finally:
                    if page:
                        try:
                            await page.close()
                        except (TargetClosedError, Exception):
                            # Page already closed, ignore
                            pass

    # ------------------------------------------------------------------
    # Crawl single URL
    # ------------------------------------------------------------------

    async def _crawl_one(self, context, url, depth, queue):
        norm = self._normalize(url)

        async with self._lock:
            if norm in self._visited or depth > self.max_depth:
                return None
            self._visited.add(norm)

        result = await self._fetch(context, url)
        if not result:
            return None

        html, status, headers = result

        links = self._extract_links(html, url)
        forms = self._extract_forms(html, url)
        params = self._extract_params(url)

        for link in links:
            norm_link = self._normalize(link)

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
        queue: asyncio.LifoQueue = asyncio.LifoQueue()  # DFS behavior
        await queue.put((self.base_url, 0))

        async with async_playwright() as pw:
            browser: Browser = await pw.chromium.launch(headless=True)

            context: BrowserContext = await browser.new_context()

            # Block heavy resources globally
            await context.route(
                "**/*",
                lambda route: route.abort()
                if route.request.resource_type in {"image", "media", "font"}
                else route.continue_(),
            )

            try:
                while not queue.empty():
                    try:
                        url, depth = await asyncio.wait_for(queue.get(), timeout=5.0)
                    except asyncio.TimeoutError:
                        break

                    try:
                        result = await self._crawl_one(context, url, depth, queue)
                        if result:
                            yield result
                    except (TargetClosedError, ConnectionError) as e:
                        logger.warning(f"Target closed while crawling {url}: {e}")
                    except Exception as e:
                        logger.warning(f"Error crawling {url}: {type(e).__name__}: {e}")
                    finally:
                        queue.task_done()

                await queue.join()
            except Exception as e:
                logger.error(f"Error in crawl loop: {e}")
            finally:
                await browser.close()


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

async def run():
    crawler = DFSCrawler(
        base_url="https://earndot.online",
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