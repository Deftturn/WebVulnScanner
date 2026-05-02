import asyncio
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
from typing import List, Dict, Optional, Any, Set


class DFSCrawler: 
    def __init__(self, base_url:str, max_depth:int = 3, concurrency:int =5):
        self.base_url = base_url
        self.visited:Set = set()
        self.base_domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.concurrency = asyncio.Semaphore(concurrency)


    def normalize_url(self, url:str):
        parsed = urlparse(url)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", "" # Remove params,query,fragment
        ))

    def check_same_domain(self, url:str):
        return urlparse(url).netloc == self.base_domain

    def parameter_extractor(self, current_url:str):
        return list(parse_qs(urlparse(current_url).query).keys())

    def link_extractor(self, html:str, url:str):
        soup = BeautifulSoup(html, "lxml")
        links = set()

        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            full_url = urljoin(url, href)

            if self.check_same_domain(full_url):
                links.add(full_url)
        return links

    def form_extractor(self, html:str, current_url:str):
        soup = BeautifulSoup(html, "lxml")
        forms:List = []

        for form in soup.find_all("form"):
            action = form.get("action") or current_url
            method = form.get("method", "get").lower()

            action_url = urljoin(current_url, action)
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inp_name = inp.get("name")
                if inp_name:
                    inputs.append(inp_name)
            forms.append({
                "action": action_url,
                "method": method,
                "inputs": inputs
            })
        return forms

    async def fetch(self, context, url:str):
        async with self.concurrency:
            page = await context.new_page()
            try:
                response = await page.goto(url, timeout=1000000, wait_until="networkidle")
                await page.wait_for_timeout(5000)  # Wait for any dynamic content to load
                content = await page.content()
                headers = response.headers if response else {}
                return content, headers
            except:
                response = await page.goto(url, timeout=1000000, wait_until="domcontentloaded")
                content = await page.content()
                headers = response.headers if response else {}
                return content, headers
            finally:
                await page.close()

    async def main(self):
        stack = [(self.base_url, 0)]

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()

            while stack:
                url, depth = stack.pop()
                norm_url= self.normalize_url(url)

                if norm_url in self.visited or depth > self.max_depth:
                    continue
                self.visited.add(norm_url)

                html, headers = await self.fetch(context, norm_url) #type:ignore
                if not html:
                    continue

                links = self.link_extractor(html, url)
                forms = self.form_extractor(html, url)
                params = self.parameter_extractor(url)

                yield {
                    "url": url,
                    "normalized_url": norm_url,
                    "depth": depth,
                    "params": params,
                    "links": list(links), #type:ignore
                    "forms": forms,
                    "headers": headers
                }

                for link in links: #type:ignore
                    stack.append((link, depth+1))
            await browser.close()

async def run():
    crawler = DFSCrawler(
        base_url="https://earndot.online",
        max_depth=3,
        concurrency=5
    )

    async for page in crawler.main():
        print(f"URL: {page['url']}")
        print(f"Params: {page['params']}")
        print(f"Forms: {page['forms']}")
        print("-"*40)

if __name__ == "__main__":
    asyncio.run(run())