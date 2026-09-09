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
ACTIVITY_FILE = "scan_activity.log"

# Danger ranking for SQLi techniques (higher = more dangerous)
_SQLI_DANGER_ORDER = {
    "destructive": 5,
    "time_based": 4,
    "error_based": 3,
    "union_based": 2,
    "boolean_based": 1,
}


def _write_progress(**kwargs):
    """Writes progress JSON and also appends a line to activity log."""
    try:
        payload = {"updated_at": datetime.now().isoformat(), **kwargs}
        with open(PROGRESS_FILE, "w") as f:
            json.dump(payload, f)
        
        phase = kwargs.get("phase", "")
        current_test = kwargs.get("current_test", "")
        findings = kwargs.get("findings_so_far", 0)
        current_page = kwargs.get("current_page", 0)
        total_pages = kwargs.get("total_pages", 0)
        
        parts = []
        if phase == "crawling":
            parts.append(f"[CRAWL] Found {kwargs.get('pages_found', 0)} pages")
        elif phase == "testing":
            if current_test == "sqli":
                parts.append(f"[TEST] Page {current_page}/{total_pages} — Running SQL Injection")
            elif current_test == "xss":
                parts.append(f"[TEST] Page {current_page}/{total_pages} — Running XSS checks")
            elif current_test == "misconfig":
                parts.append(f"[TEST] Page {current_page}/{total_pages} — Checking security config")
            elif current_test == "sensitive":
                parts.append(f"[TEST] Page {current_page}/{total_pages} — Scanning exposed data")
            if findings > 0:
                parts.append(f"{findings} findings so far")
        elif phase == "complete":
            parts.append(f"[DONE] Scan complete — {findings} vulnerabilities found")
        
        if parts:
            log_line = " | ".join(parts)
            with open(ACTIVITY_FILE, "a", encoding="utf-8") as f:
                f.write(log_line + "\n")
    except Exception as e:
        logger.debug(f"Progress write failed: {type(e).__name__}: {e}")


class _BaseReportLogger:
    def __init__(self, filename):
        self.filename, self.results, self.scan_url = filename, [], ""
        self.scan_time = time.strftime("%Y-%m-%d %H:%M:%S")
        self._seen_keys = set()

    def set_scan_info(self, url):
        self.scan_url = url

    def _is_duplicate(self, key):
        if key in self._seen_keys:
            return True
        self._seen_keys.add(key)
        return False

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
        try:
            d = result.to_dict()
            # Skip LOW severity / low confidence findings
            if d.get('ai_severity') == 'LOW' or d.get('confidence', 0) < 0.5:
                return
            
            key = f"{d.get('url')}::{d.get('parameter')}"
            
            for i, existing in enumerate(self.results):
                existing_key = f"{existing.get('url')}::{existing.get('parameter')}"
                if existing_key == key:
                    # Group: keep most dangerous as primary, collect others as supporting
                    existing_danger = _SQLI_DANGER_ORDER.get(existing.get('technique', ''), 0)
                    new_danger = _SQLI_DANGER_ORDER.get(d.get('technique', ''), 0)
                    
                    if new_danger > existing_danger:
                        # New payload is more dangerous — swap primary
                        supporting = existing.get('supporting_payloads', [])
                        supporting.append({
                            "payload": existing.get('payload'),
                            "technique": existing.get('technique'),
                            "confidence": existing.get('ai_confidence', 0)
                        })
                        d['supporting_payloads'] = supporting
                        self.results[i] = {"timestamp": datetime.now().isoformat(), **d}
                    else:
                        # Add to supporting payloads
                        if 'supporting_payloads' not in existing:
                            existing['supporting_payloads'] = []
                        existing['supporting_payloads'].append({
                            "payload": d.get('payload'),
                            "technique": d.get('technique'),
                            "confidence": d.get('ai_confidence', 0)
                        })
                        self.results[i] = existing
                    return
            
            # New finding
            d['supporting_payloads'] = []
            self.results.append({"timestamp": datetime.now().isoformat(), **d})
        except Exception as e:
            logger.error(f"SQLi logger error: {type(e).__name__}: {e}", exc_info=True)


class XSSReportLogger(_BaseReportLogger):
    def __init__(self, filename="xss_report.json"):
        super().__init__(filename)
    
    def log_result(self, result: XSSResult):
        try:
            d = result.to_dict()
            # Skip LOW severity
            if d.get('ai_severity') == 'LOW':
                return
            key = f"{d.get('url')}::{d.get('param')}"
            if self._is_duplicate(key):
                return
            self.results.append({"timestamp": datetime.now().isoformat(), **d})
        except Exception as e:
            logger.error(f"XSS logger error: {type(e).__name__}: {e}", exc_info=True)


class MisconfigReportLogger(_BaseReportLogger):
    def __init__(self, filename="misconfig_report.json"):
        super().__init__(filename)
    
    def log_result(self, result: dict):
        try:
            key = f"{result.get('url')}::{result.get('check_type')}"
            if self._is_duplicate(key):
                return
            self.results.append({"timestamp": datetime.now().isoformat(), **result})
        except Exception as e:
            logger.error(f"Misconfig logger error: {type(e).__name__}: {e}")


class SensitiveReportLogger(_BaseReportLogger):
    def __init__(self, filename="sensitive_report.json"):
        super().__init__(filename)
    
    def log_result(self, result: dict):
        try:
            key = f"{result.get('url')}::{result.get('check_type')}"
            if self._is_duplicate(key):
                return
            self.results.append({"timestamp": datetime.now().isoformat(), **result})
        except Exception as e:
            logger.error(f"Sensitive logger error: {type(e).__name__}: {e}")


def _form_key(form: dict, page_url: str) -> tuple:
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
    if os.path.exists(ACTIVITY_FILE):
        os.remove(ACTIVITY_FILE)
    
    _write_progress(phase="starting")
    crawl_logger = JSONLogger()
    sqli_logger = SQLiReportLogger()
    xss_logger = XSSReportLogger()
    misconfig_logger = MisconfigReportLogger()
    sensitive_logger = SensitiveReportLogger()
    all_loggers = [sqli_logger, xss_logger, misconfig_logger, sensitive_logger]

    # SMART TIMEOUT: Read from command line (passed by API server)
    # python main.py URL [timeout_ms]
    payload_timeout = 5.0  # Default: 5s for fast local scans
    if len(sys.argv) > 2:
        try:
            payload_timeout = float(sys.argv[2])
            logger.info(f"Using payload timeout: {payload_timeout}s")
        except ValueError:
            logger.warning(f"Invalid timeout '{sys.argv[2]}', using default 5s")

    crawler = DFSCrawler(
        base_url=sys.argv[1] if len(sys.argv) > 1 else "http://zero.webappsecurity.com/",
        max_depth=3, concurrency=5)
    scan_url = crawler.base_url
    for log in all_loggers: log.set_scan_info(scan_url)

    tester = SQLInjectionTester(page_timeout_ms=30000, time_threshold_ms=4000,
        check_errors=True, check_union=True, check_time_based=True,
        payload_hard_timeout_s=payload_timeout)  # Configurable timeout
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
        current_url="", findings_so_far=0, current_test="sqli", scan_url=scan_url)

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

                    new_forms = []
                    for form in forms:
                        key = _form_key(form, url)
                        if key not in tested_form_keys:
                            tested_form_keys.add(key)
                            new_forms.append(form)
                    forms = new_forms

                    # --- SQL Injection ---
                    _write_progress(phase="testing", current_page=page_index + 1, total_pages=total_pages,
                        current_url=url, findings_so_far=sum(len(log.results) for log in all_loggers),
                        current_test="sqli", scan_url=scan_url)
                    
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

                    # --- XSS ---
                    _write_progress(phase="testing", current_page=page_index + 1, total_pages=total_pages,
                        current_url=url, findings_so_far=sum(len(log.results) for log in all_loggers),
                        current_test="xss", scan_url=scan_url)
                    
                    try:
                        xss_return = await xss_scanner.scan_page(url=url, params=params, forms=forms)
                        if not xss_has_results_attr:
                            for xr in xss_return: xss_logger.log_result(xr)
                    except Exception as e:
                        logger.warning(f"XSS error: {type(e).__name__}: {e}")
                    finally:
                        if xss_has_results_attr:
                            xss_seen = _sync_new_results(xss_scanner.results, xss_seen, xss_logger.log_result)

                    # --- Misconfig ---
                    _write_progress(phase="testing", current_page=page_index + 1, total_pages=total_pages,
                        current_url=url, findings_so_far=sum(len(log.results) for log in all_loggers),
                        current_test="misconfig", scan_url=scan_url)
                    
                    try:
                        for result in misconfig_scanner.scan_url(url, headers=page_result.headers, html=page_result.html):
                            misconfig_logger.log_result(result.to_dict())
                    except Exception as e:
                        logger.debug(f"Misconfig error: {type(e).__name__}: {e}")

                    # --- Sensitive ---
                    _write_progress(phase="testing", current_page=page_index + 1, total_pages=total_pages,
                        current_url=url, findings_so_far=sum(len(log.results) for log in all_loggers),
                        current_test="sensitive", scan_url=scan_url)
                    
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
        _write_progress(phase="complete", error=f"Scan crashed: {type(e).__name__}: {e}")
        raise