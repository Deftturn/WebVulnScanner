import asyncio
from crawler.dfs import DFSCrawler
from extractor.write_to_file import JSONLogger

async def run():
    logger = JSONLogger()
    crawler = DFSCrawler(
        base_url="https://github.com",
        max_depth=3,
        concurrency=5
    )

    async for page in crawler.crawl():
        # print(f"URL: {page['url']}")
        # print(f"Params: {page['params']}")
        # print(f"Forms: {page['forms']}")
        # print("-"*40)
        logger.log({
            "url": page.url,
            "normalized_url": page.normalized_url,
            "params": page.params,
            "forms": page.forms,
            "depth": page.depth,
            "links": page.links,
            "headers": page.headers
        })
        logger.save_final()

if __name__ == "__main__":
    asyncio.run(run())
