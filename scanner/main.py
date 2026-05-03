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
from injector.xss_injector import XSSScanner, XSSResult

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
        entry = {
            "timestamp": datetime.now().isoformat(),
            **result.to_dict()
        }
        self.results.append(entry)
        self.save()

    def save(self):
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


class XSSReportLogger:
    """Logger for XSS scan results."""
    def __init__(self, filename="xss_report.json"):
        self.filename = filename
        self.results = []

    def log_result(self, result: XSSResult):
        entry = {
            "timestamp": datetime.now().isoformat(),
            **result.to_dict()
        }
        self.results.append(entry)
        self.save()

    def save(self):
        report = {
            "scan_summary": {
                "total_findings": len(self.results),
                "by_vector": {
                    "reflected": sum(1 for r in self.results if r.get("vector_type") == "reflected"),
                    "dom":       sum(1 for r in self.results if r.get("vector_type") == "dom"),
                    "stored":    sum(1 for r in self.results if r.get("vector_type") == "stored"),
                },
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

    def print_summary(self):
        total = len(self.results)
        if total == 0:
            print("[+] XSS: No vulnerabilities found.")
            return
        print(f"\n[!] XSS: {total} finding(s) — "
              f"reflected={sum(1 for r in self.results if r.get('vector_type') == 'reflected')}, "
              f"dom={sum(1 for r in self.results if r.get('vector_type') == 'dom')}, "
              f"stored={sum(1 for r in self.results if r.get('vector_type') == 'stored')}")
        for r in self.results:
            print(f"\n  [{r['vector_type'].upper()}] {r['url']}")
            if r.get("param"):
                print(f"    Parameter : {r['param']}")
            if r.get("form_action"):
                print(f"    Form action: {r['form_action']}")
            print(f"    Payload   : {r['payload']}")
            print(f"    Evidence  : {r['evidence']}")


async def run():
    crawl_logger = JSONLogger()
    sqli_logger  = SQLiReportLogger()
    xss_logger   = XSSReportLogger()

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

    # ------------------------------------------------------------------
    # PHASE 1: Crawl
    # ------------------------------------------------------------------
    print("[*] PHASE 1: Crawling...\n")
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

    # ------------------------------------------------------------------
    # PHASE 2: SQLi + XSS testing
    # ------------------------------------------------------------------
    print("[*] PHASE 2: Testing for SQLi and XSS vulnerabilities...\n")

    from playwright.async_api import async_playwright

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context()

            # Block heavy resources to speed up testing
            await context.route(
                "**/*",
                lambda route: route.abort()
                if route.request.resource_type in {"image", "media", "font"}
                else route.continue_(),
            )

            xss_scanner = XSSScanner(context=context, page_timeout_ms=30000)

            with tqdm(total=len(crawl_results), desc="Testing pages", unit=" pages", colour="green") as test_pbar:
                for page_result in crawl_results:
                    url    = page_result.url
                    params = page_result.params or []
                    forms  = page_result.forms  or []

                    # ── SQLi ──────────────────────────────────────────
                    for param in params:
                        try:
                            results = await asyncio.wait_for(
                                tester.test_url_parameter(context, url, param),
                                timeout=15.0
                            )
                            for result in results:
                                sqli_logger.log_result(result)
                        except asyncio.TimeoutError:
                            logger.warning(f"SQLi timeout: param={param} url={url}")
                        except Exception as e:
                            logger.debug(f"SQLi error param={param}: {type(e).__name__}: {e}")

                    for form in forms:
                        try:
                            results = await asyncio.wait_for(
                                tester.test_form(context, form, url),
                                timeout=15.0
                            )
                            for result in results:
                                sqli_logger.log_result(result)
                        except asyncio.TimeoutError:
                            logger.warning(f"SQLi timeout: form in {url}")
                        except Exception as e:
                            logger.debug(f"SQLi error form: {type(e).__name__}: {e}")

                    # ── XSS ───────────────────────────────────────────
                    try:
                        xss_results = await asyncio.wait_for(
                            xss_scanner.scan_page(
                                url=url,
                                params=params if params else None,
                                forms=forms  if forms  else None,
                            ),
                            timeout=60.0   # XSS tests many payloads; give it more room
                        )
                        for xss_result in xss_results:
                            xss_logger.log_result(xss_result)
                    except asyncio.TimeoutError:
                        logger.warning(f"XSS timeout: {url}")
                    except Exception as e:
                        logger.error(f"XSS error {url}: {type(e).__name__}: {e}", exc_info=True)

                    test_pbar.update(1)

            await browser.close()

    except Exception as e:
        logger.error(f"Testing phase failed: {type(e).__name__}: {e}", exc_info=True)
        print(f"\n[!] Testing error: {e}")
    finally:
        # Always write report files so they exist even when no findings are recorded
        sqli_logger.save()
        xss_logger.save()

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("SCAN COMPLETE")
    print("=" * 80)
    print(f"\n[+] Crawl results  : scan_results.json")
    print(f"[+] SQLi results   : sqli_report.json")
    print(f"[+] XSS results    : xss_report.json")

    tester.print_summary()
    xss_logger.print_summary()

    sqli_vulns = tester.get_vulnerable_results()
    if sqli_vulns:
        print("\n[!] SQLi VULNERABILITIES FOUND:")
        for vuln in sqli_vulns:
            print(f"\n  [{vuln.test_type.upper()}] {vuln.url}")
            print(f"    Parameter : {vuln.parameter}")
            print(f"    Payload   : {vuln.payload}")
            print(f"    Confidence: {vuln.confidence:.2%}")
            if vuln.error_message:
                print(f"    Error     : {vuln.error_message}")

    if xss_logger.results:
        print("\n[!] XSS VULNERABILITIES FOUND:")
        for finding in xss_logger.results:
            print(f"\n  [{finding['vector_type'].upper()}] {finding['url']}")
            if finding.get("param"):
                print(f"    Parameter  : {finding['param']}")
            if finding.get("form_action"):
                print(f"    Form action: {finding['form_action']}")
            print(f"    Payload    : {finding['payload']}")
            print(f"    Evidence   : {finding['evidence']}")


if __name__ == "__main__":
    asyncio.run(run())
