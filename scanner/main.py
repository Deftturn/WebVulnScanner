import asyncio
from crawler.dfs import DFSCrawler

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
