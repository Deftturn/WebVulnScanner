import asyncio
import json
import os
import logging
import sys
import time
from datetime import datetime
from tqdm import tqdm
from crawler.dfs import DFSCrawler
from extractor.write_to_file import JSONLogger
from injector.sql_injector import SQLInjectionTester
from injector.xss_injector import XSSScanner, XSSResult
from injector.misconfig_injector import MisconfigScanner
from injector.sensitive_info_injector import SensitiveInfoScanner

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('scanner.log'), logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

PROGRESS_FILE = "scan_progress.json"


def _write_progress(**kwargs):
    """Overwrites a small status file the frontend can poll for real
    progress, instead of App.tsx's old fixed 10s-per-step fake timer that
    had no relationship to what the scan was actually doing. Best-effort --
    a failure here should never interrupt the actual scan."""
    try:
        payload = {"updated_at": datetime.now().isoformat(), **kwargs}
        with open(PROGRESS_FILE, "w") as f:
            json.dump(payload, f)
    except Exception as e:
        logger.debug(f"Progress write failed: {type(e).__name__}: {e}")


class _BaseReportLogger:
    """Shared save() logic for all four report loggers below.

    save() upserts by (scan_url, scan_time) instead of always appending.
    scan_time is set once in __init__ for the whole run, so calling save()
    repeatedly during a long scan just refreshes the same entry in place --
    it does NOT pile up one entry per call. This is what lets main.py call
    save() after every page: results are continuously persisted to disk, so
    if the process gets killed (a subprocess timeout, Ctrl+C, a crash)
    partway through, whatever was found up to that point is still on disk
    instead of being lost entirely.
    """
    def __init__(self, filename):
        self.filename, self.results, self.scan_url = filename, [], ""
        self.scan_time = time.strftime("%Y-%m-%d %H:%M:%S")

    def set_scan_info(self, url):
        self.scan_url = url

    def save(self):
        data = {"scans": []}
        if os.path.exists(self.filename):
            with open(self.filename, "r") as f:
                try: data = json.load(f)
                except: data = {"scans": []}
        entry = {"scan_url": self.scan_url, "scan_time": self.scan_time,
            "total_findings": len(self.results), "results": self.results}
        for i, existing in enumerate(data["scans"]):
            if existing.get("scan_url") == self.scan_url and existing.get("scan_time") == self.scan_time:
                data["scans"][i] = entry
                break
        else:
            data["scans"].append(entry)
        with open(self.filename, "w") as f: json.dump(data, f, indent=2)


class SQLiReportLogger(_BaseReportLogger):
    def __init__(self, filename="sqli_report.json"):
        super().__init__(filename)
    def log_result(self, result):
        try: self.results.append({"timestamp": datetime.now().isoformat(), **result.to_dict()})
        except Exception as e: logger.error(f"SQLi logger error: {type(e).__name__}: {e}", exc_info=True)


class XSSReportLogger(_BaseReportLogger):
    def __init__(self, filename="xss_report.json"):
        super().__init__(filename)
    def log_result(self, result: XSSResult):
        try: self.results.append({"timestamp": datetime.now().isoformat(), **result.to_dict()})
        except Exception as e: logger.error(f"XSS logger error: {type(e).__name__}: {e}", exc_info=True)


class MisconfigReportLogger(_BaseReportLogger):
    def __init__(self, filename="misconfig_report.json"):
        super().__init__(filename)
    def log_result(self, result: dict):
        try: self.results.append({"timestamp": datetime.now().isoformat(), **result})
        except Exception as e: logger.error(f"Misconfig logger error: {type(e).__name__}: {e}")


class SensitiveReportLogger(_BaseReportLogger):
    def __init__(self, filename="sensitive_report.json"):
        super().__init__(filename)
    def log_result(self, result: dict):
        try: self.results.append({"timestamp": datetime.now().isoformat(), **result})
        except Exception as e: logger.error(f"Sensitive logger error: {type(e).__name__}: {e}")


def _form_key(form: dict, page_url: str) -> tuple:
    """Identity of a form independent of which page it was scraped from. A
    site-wide search box or nav form gets extracted fresh from every page's
    HTML by the crawler (correctly -- it has no way to know ahead of time
    it's the same form), but that means it was being FULLY payload-tested
    once per page it appears on. On a 15-page site where one form is in the
    header of every page, that's up to 15x redundant SQLi + XSS testing of
    a single form -- almost certainly the dominant cost of a slow run, more
    than AI latency or navigation timeouts."""
    action = form.get("action", page_url)
    method = form.get("method", "get").lower()
    inputs = tuple(sorted(form.get("inputs", [])))
    return (action, method, inputs)


def _sync_new_results(source_list, seen_count, log_fn):
    total = len(source_list)
    if total > seen_count:
        for item in source_list[seen_count:total]: log_fn(item)
    return total


async def run():
    _write_progress(phase="starting")
    crawl_logger = JSONLogger()
    sqli_logger = SQLiReportLogger()
    xss_logger = XSSReportLogger()
    misconfig_logger = MisconfigReportLogger()
    sensitive_logger = SensitiveReportLogger()
    all_loggers = [sqli_logger, xss_logger, misconfig_logger, sensitive_logger]

    crawler = DFSCrawler(
        base_url=sys.argv[1] if len(sys.argv) > 1 else "http://zero.webappsecurity.com/",
        max_depth=3, concurrency=5)
    scan_url = crawler.base_url
    for log in all_loggers: log.set_scan_info(scan_url)

    tester = SQLInjectionTester(page_timeout_ms=30000, time_threshold_ms=4000,
        check_errors=True, check_union=True, check_time_based=True)
    misconfig_scanner = MisconfigScanner(timeout_ms=10000)
    sensitive_scanner = SensitiveInfoScanner(timeout_ms=10000)

    print("[*] PHASE 1: Crawling...\n")
    crawl_results = []
    _write_progress(phase="crawling", pages_found=0, scan_url=scan_url)
    with tqdm(desc="Crawling pages", unit=" pages", colour="cyan") as crawl_pbar:
        try:
            async for page in crawler.crawl():
                crawl_results.append(page)
                crawl_logger.log({"url": page.url, "normalized_url": page.normalized_url,
                    "params": page.params, "forms": page.forms, "depth": page.depth,
                    "links": page.links, "headers": page.headers})
                crawl_pbar.update(1)
                _write_progress(phase="crawling", pages_found=len(crawl_results), scan_url=scan_url)
        except Exception as e: logger.error(f"Crawler failed: {type(e).__name__}: {e}", exc_info=True)
    crawl_logger.save_final()
    print(f"\n[+] Crawling complete. Found {len(crawl_results)} pages.\n")
    if not crawl_results:
        _write_progress(phase="complete", pages_found=0, scan_url=scan_url, error="No pages crawled")
        return

    print("[*] PHASE 2: Testing...\n")
    from playwright.async_api import async_playwright
    sqli_seen, xss_seen, xss_has_results_attr = 0, 0, None
    xss_scanner = None
    total_pages = len(crawl_results)
    _write_progress(phase="testing", current_page=0, total_pages=total_pages,
        current_url="", findings_so_far=0, scan_url=scan_url)

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context()
            await context.route("**/*", lambda route: route.abort()
                if route.request.resource_type in {"image", "media", "font"} else route.continue_())
            xss_scanner = XSSScanner(context=context, page_timeout_ms=10000)
            xss_has_results_attr = hasattr(xss_scanner, "results")
            tested_form_keys = set()

            with tqdm(total=total_pages, desc="Testing pages", unit=" pages", colour="green") as test_pbar:
                for page_index, page_result in enumerate(crawl_results):
                    url, params, forms = page_result.url, page_result.params or [], page_result.forms or []

                    # Deduplicate forms across the WHOLE crawl, not per page.
                    new_forms = []
                    for form in forms:
                        key = _form_key(form, url)
                        if key not in tested_form_keys:
                            tested_form_keys.add(key)
                            new_forms.append(form)
                    forms = new_forms

                    for param in params:
                        try:
                            await tester.test_url_parameter(context, url, param)
                        except Exception as e:
                            logger.warning(f"SQLi param error: {type(e).__name__}: {e}")
                        finally:
                            sqli_seen = _sync_new_results(tester.results, sqli_seen, sqli_logger.log_result)
                    for form in forms:
                        try:
                            await tester.test_form(context, form, url)
                        except Exception as e:
                            logger.warning(f"SQLi form error: {type(e).__name__}: {e}")
                        finally:
                            sqli_seen = _sync_new_results(tester.results, sqli_seen, sqli_logger.log_result)
                    try:
                        xss_return = await xss_scanner.scan_page(url=url, params=params, forms=forms)
                        if not xss_has_results_attr:
                            for xr in xss_return: xss_logger.log_result(xr)
                    except Exception as e:
                        logger.warning(f"XSS error: {type(e).__name__}: {e}")
                    finally:
                        if xss_has_results_attr:
                            xss_seen = _sync_new_results(xss_scanner.results, xss_seen, xss_logger.log_result)
                    try:
                        for result in misconfig_scanner.scan_url(url, headers=page_result.headers, html=page_result.html):
                            misconfig_logger.log_result(result.to_dict())
                    except Exception as e:
                        logger.debug(f"Misconfig error: {type(e).__name__}: {e}")
                    try:
                        for result in sensitive_scanner.scan_url(url, html=page_result.html, headers=page_result.headers):
                            sensitive_logger.log_result(result.to_dict())
                    except Exception as e:
                        logger.debug(f"Sensitive error: {type(e).__name__}: {e}")

                    for log in all_loggers:
                        try:
                            log.save()
                        except Exception as e:
                            logger.debug(f"Incremental save failed for {log.filename}: {type(e).__name__}: {e}")

                    total_findings = sum(len(log.results) for log in all_loggers)
                    _write_progress(phase="testing", current_page=page_index + 1, total_pages=total_pages,
                        current_url=url, findings_so_far=total_findings, scan_url=scan_url)

                    test_pbar.update(1)
            await browser.close()
    except Exception as e:
        logger.error(f"Testing failed: {type(e).__name__}: {e}", exc_info=True)
    finally:
        sqli_seen = _sync_new_results(tester.results, sqli_seen, sqli_logger.log_result)
        if xss_scanner is not None and xss_has_results_attr:
            xss_seen = _sync_new_results(xss_scanner.results, xss_seen, xss_logger.log_result)
        for log in all_loggers:
            try:
                log.save()
            except Exception as e:
                logger.error(f"Final save failed for {log.filename}: {type(e).__name__}: {e}")

    total_findings = sum(len(log.results) for log in all_loggers)
    _write_progress(phase="complete", current_page=total_pages, total_pages=total_pages,
        findings_so_far=total_findings, scan_url=scan_url)

    print("\n" + "=" * 80 + "\nSCAN COMPLETE\n" + "=" * 80)
    tester.print_summary()


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except Exception as e:
        # An uncaught crash (e.g. the WinError 32 PermissionError from two
        # concurrent scans writing the same file) would otherwise die
        # before ever reaching the phase="complete" write at the bottom of
        # run(). Without this, the frontend's poller would just see the
        # last progress state before the crash and wait forever for an
        # update that will never come, since the process is dead.
        _write_progress(phase="complete", error=f"Scan crashed: {type(e).__name__}: {e}")
        raise