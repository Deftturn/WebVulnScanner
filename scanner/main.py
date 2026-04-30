import asyncio
import json
import os
import logging
import sys
from datetime import datetime
from tqdm import tqdm
from crawler.dfs import DFSCrawler
from extractor.write_to_file import JSONLogger
from injector.sql_injector import SQLInjectionTester

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class SQLiReportLogger:
    """Logger for SQL injection test results."""
    def __init__(self, filename="sqli_report.json"):
        self.filename = filename
        self.results = []
    
    def log_result(self, result):
        """Log a SQL injection test result."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            **result.to_dict()
        }
        self.results.append(entry)
        self.save()
    
    def save(self):
        """Save results to JSON file."""
        report = {
            "scan_summary": {
                "total_tests": len(self.results),
                "vulnerabilities_found": sum(1 for r in self.results if r.get("vulnerable")),
                "timestamp": datetime.now().isoformat(),
            },
            "results": self.results
        }
        
        temp_file = self.filename + ".tmp"
        with open(temp_file, "w") as f:
            json.dump(report, f, indent=2)
        
        if os.path.exists(self.filename):
            os.remove(self.filename)
        os.rename(temp_file, self.filename)


async def run():
    # Initialize loggers
    crawl_logger = JSONLogger()
    sqli_logger = SQLiReportLogger()
    
    # Initialize crawler and tester
    crawler = DFSCrawler(
        base_url="http://localhost:3000/#/",
        max_depth=3,
        concurrency=5
    )
    
    tester = SQLInjectionTester(
        page_timeout_ms=30000,
        time_threshold_ms=4000,
        check_errors=True,
        check_union=True,
        check_time_based=True,
    )

    print("\n[*] PHASE 1: Crawling target site...\n")
    
    # PHASE 1: Crawl and collect all pages
    crawl_results = []
    with tqdm(desc="Crawling pages", unit=" pages", colour="cyan") as crawl_pbar:
        try:
            async for page in crawler.crawl():
                crawl_results.append(page)
                crawl_logger.log({
                    "url": page.url,
                    "normalized_url": page.normalized_url,
                    "params": page.params,
                    "forms": page.forms,
                    "depth": page.depth,
                    "links": page.links,
                    "headers": page.headers
                })
                crawl_pbar.update(1)
        except Exception as e:
            logger.error(f"Crawler failed: {type(e).__name__}: {e}", exc_info=True)
            print(f"\n[!] Crawler error: {e}")
    
    crawl_logger.save_final()
    print(f"\n[+] Crawling complete. Found {len(crawl_results)} pages.\n")
    
    if not crawl_results:
        print("[!] No pages crawled. Exiting.")
        return
    
    # PHASE 2: Test crawled pages for SQL injection
    print("[*] PHASE 2: Testing for SQL injection vulnerabilities...\n")
    
    from playwright.async_api import async_playwright
    
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context()
            
            # Block heavy resources
            await context.route(
                "**/*",
                lambda route: route.abort()
                if route.request.resource_type in {"image", "media", "font"}
                else route.continue_(),
            )
            
            with tqdm(total=len(crawl_results), desc="Testing pages", unit=" pages", colour="green") as test_pbar:
                for page_result in crawl_results:
                    try:
                        # Test URL parameters
                        if page_result.params:
                            for param in page_result.params:
                                try:
                                    results = await asyncio.wait_for(
                                        tester.test_url_parameter(
                                            context,
                                            page_result.url,
                                            param,
                                        ),
                                        timeout=15.0
                                    )
                                    for result in results:
                                        sqli_logger.log_result(result)
                                except asyncio.TimeoutError:
                                    logger.warning(f"Timeout testing parameter {param} in {page_result.url}")
                                except Exception as e:
                                    logger.debug(f"Error testing parameter {param}: {type(e).__name__}: {e}")
                        
                        # Test forms
                        if page_result.forms:
                            for form in page_result.forms:
                                try:
                                    results = await asyncio.wait_for(
                                        tester.test_form(
                                            context,
                                            form,
                                            page_result.url,
                                        ),
                                        timeout=15.0
                                    )
                                    for result in results:
                                        sqli_logger.log_result(result)
                                except asyncio.TimeoutError:
                                    logger.warning(f"Timeout testing form in {page_result.url}")
                                except Exception as e:
                                    logger.debug(f"Error testing form: {type(e).__name__}: {e}")
                        
                        test_pbar.update(1)
                    except Exception as e:
                        logger.error(f"Error processing page {page_result.url}: {type(e).__name__}: {e}", exc_info=True)
                        test_pbar.update(1)
            
            await browser.close()
    except Exception as e:
        logger.error(f"Testing phase failed: {type(e).__name__}: {e}", exc_info=True)
        print(f"\n[!] Testing error: {e}")
    
    print("\n" + "=" * 80)
    print("SCAN COMPLETE")
    print("=" * 80)
    print(f"\n[+] Crawling Results: scan_results.json")
    print(f"[+] SQL Injection Results: sqli_report.json")
    
    # Print summary
    tester.print_summary()
    
    # Log vulnerable results
    vulnerabilities = tester.get_vulnerable_results()
    if vulnerabilities:
        print("\n[!] VULNERABILITIES FOUND:")
        for vuln in vulnerabilities:
            print(f"\n  [{vuln.test_type.upper()}] {vuln.url}")
            print(f"    Parameter: {vuln.parameter}")
            print(f"    Payload: {vuln.payload}")
            print(f"    Confidence: {vuln.confidence:.2%}")
            if vuln.error_message:
                print(f"    Error: {vuln.error_message}")


if __name__ == "__main__":
    asyncio.run(run())
