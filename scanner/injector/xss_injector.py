import asyncio
import requests
import logging
from typing import Dict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from playwright.async_api import Page, BrowserContext

AI_API_URL = "http://127.0.0.1:8000/analyze"
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class XSSResult:
    def __init__(self, url, param=None, form_action=None, payload=None, vector_type=None,
                 evidence=None, ai_severity="UNKNOWN", ai_confidence=0.0, fix=""):
        self.url = url
        self.param = param
        self.form_action = form_action
        self.payload = payload
        self.vector_type = vector_type
        self.evidence = evidence
        self.ai_severity = ai_severity
        self.ai_confidence = ai_confidence
        self.fix = fix

    def to_dict(self):
        return self.__dict__


class XSSScanner:
    XSS_PAYLOADS = [
        "<script>window.__xss=1</script>",
        "<img src=x onerror=window.__xss=1>",
        "<svg onload=window.__xss=1>",
        "\"><script>window.__xss=1</script>",
        "'><script>window.__xss=1</script>",
        "<body onload=window.__xss=1>",
        "<iframe src='javascript:window.__xss=1'></iframe>",
        "<input onfocus=window.__xss=1 autofocus>",
        "<a href='javascript:window.__xss=1'>X</a>",
    ]

    def __init__(self, context: BrowserContext, page_timeout_ms: int = 30000,
                 ai_confirmation_threshold: float = 0.5,
                 payload_hard_timeout_s: float = 15.0):
        self.context = context
        self.page_timeout_ms = page_timeout_ms
        self.ai_confirmation_threshold = ai_confirmation_threshold
        self.results: list = []
        self.payload_hard_timeout_s = payload_hard_timeout_s

        self._ai_cache: Dict[str, Dict] = {}
        self._http_session = requests.Session()

    async def _call_ai_api(self, payload: str, response_text: str = "") -> dict:
        cache_key = f"{payload}::{response_text[:500]}"
        if cache_key in self._ai_cache:
            return self._ai_cache[cache_key]

        def _do_request():
            try:
                result = self._http_session.post(AI_API_URL, json={
                    "payload": payload, "parameter": "", "url": "",
                    "vulnerable_code": response_text[:2000] if response_text else "",
                    "language": "javascript", "attack_type": "xss"
                }, timeout=15)
                if result.status_code == 200:
                    data = result.json()
                    return {"severity": data.get("severity", "UNKNOWN"),
                        "confidence": data.get("confidence", 0.0), "fix": data.get("fix", "")}
                return {"severity": "UNKNOWN", "confidence": 0.0, "fix": ""}
            except Exception:
                return {"severity": "UNKNOWN", "confidence": 0.0, "fix": ""}

        result = await asyncio.to_thread(_do_request)
        self._ai_cache[cache_key] = result
        return result

    def inject_url(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    async def test_reflected(self, page: Page, url: str, param: str):
        results = []
        for payload in self.XSS_PAYLOADS:
            try:
                await asyncio.wait_for(
                    self._do_test_reflected(page, url, param, payload, results),
                    timeout=self.payload_hard_timeout_s
                )
            except asyncio.TimeoutError:
                logger.warning(f"[XSS TIMEOUT] {param}={payload!r} exceeded {self.payload_hard_timeout_s}s, skipping")
        return results

    async def _do_test_reflected(self, page: Page, url: str, param: str, payload: str, results: list):
        test_url = self.inject_url(url, param, payload)
        try: await page.evaluate("() => { window.__xss = 0; }")
        except Exception: pass
        await page.goto(test_url, timeout=self.page_timeout_ms)
        await page.wait_for_timeout(800)
        content = await page.content()
        reflected = payload in content
        executed = False
        try: executed = await page.evaluate("() => window.__xss === 1")
        except Exception: pass
        if reflected or executed:
            evidence = []
            if reflected: evidence.append("payload reflected in HTML")
            if executed: evidence.append("window.__xss flag set (executed)")
            ai_result = await self._call_ai_api(payload, content)
            ai_severity, ai_confidence, ai_fix = ai_result["severity"], ai_result["confidence"], ai_result["fix"]
            if ai_confidence >= self.ai_confirmation_threshold:
                result = XSSResult(url=test_url, param=param, payload=payload,
                    vector_type="reflected", evidence=", ".join(evidence),
                    ai_severity=ai_severity, ai_confidence=ai_confidence, fix=ai_fix)
                results.append(result)
                self.results.append(result)
                logger.info(f"[XSS] {param} in {url} - {payload} - {ai_severity}")

    async def test_reflected_form(self, page: Page, form_action: str, input_name: str, method: str = "get"):
        results = []
        for payload in self.XSS_PAYLOADS:
            try:
                await asyncio.wait_for(
                    self._do_test_reflected_form(page, form_action, input_name, method, payload, results),
                    timeout=self.payload_hard_timeout_s
                )
            except asyncio.TimeoutError:
                logger.warning(f"[XSS-FORM TIMEOUT] {input_name}={payload!r} exceeded {self.payload_hard_timeout_s}s, skipping")
        return results

    async def _do_test_reflected_form(self, page: Page, form_action: str, input_name: str, method: str, payload: str, results: list):
        try: await page.evaluate("() => { window.__xss = 0; }")
        except Exception: pass
        if method.lower() == "get":
            test_url = self.inject_url(form_action, input_name, payload)
            await page.goto(test_url, timeout=self.page_timeout_ms)
        else:
            await page.goto(form_action, timeout=self.page_timeout_ms)
            await page.wait_for_timeout(500)
            try:
                await page.fill(f"[name='{input_name}']", payload)
                await page.click("input[type=submit], button[type=submit]", timeout=3000)
            except Exception:
                try:
                    await page.press(f"[name='{input_name}']", "Enter", timeout=3000)
                except Exception:
                    pass
            await page.wait_for_timeout(1000)
        content = await page.content()
        reflected = payload in content
        executed = False
        try: executed = await page.evaluate("() => window.__xss === 1")
        except Exception: pass
        if reflected or executed:
            evidence = []
            if reflected: evidence.append("payload reflected in HTML")
            if executed: evidence.append("window.__xss flag set (executed)")
            ai_result = await self._call_ai_api(payload, content)
            ai_severity, ai_confidence, ai_fix = ai_result["severity"], ai_result["confidence"], ai_result["fix"]
            if ai_confidence >= self.ai_confirmation_threshold:
                result = XSSResult(url=form_action, param=input_name, payload=payload,
                    vector_type="reflected_form", evidence=", ".join(evidence),
                    ai_severity=ai_severity, ai_confidence=ai_confidence, fix=ai_fix)
                results.append(result)
                self.results.append(result)
                logger.info(f"[XSS-FORM] {input_name} in {form_action} - {payload} - {ai_severity}")

    async def test_dom(self, page: Page, url: str):
        results = []
        for payload in self.XSS_PAYLOADS:
            try:
                await asyncio.wait_for(
                    self._do_test_dom(page, url, payload, results),
                    timeout=self.payload_hard_timeout_s
                )
            except asyncio.TimeoutError:
                logger.warning(f"[XSS-DOM TIMEOUT] {payload!r} exceeded {self.payload_hard_timeout_s}s, skipping")
        return results

    async def _do_test_dom(self, page: Page, url: str, payload: str, results: list):
        triggered = False
        def handler(dialog):
            nonlocal triggered
            triggered = True
            async def _dismiss():
                try: await dialog.dismiss()
                except Exception: pass
            asyncio.create_task(_dismiss())
        page.on("dialog", handler)
        try:
            await page.goto(url, timeout=self.page_timeout_ms)
            await page.evaluate(f"""() => {{ window.__xss = 0; location.hash = `{payload}`; document.body.innerHTML = location.hash; }}""")
            await page.wait_for_timeout(1000)
            flag = await page.evaluate("() => window.__xss === 1")
            content = await page.content()
            if triggered or flag:
                ai_result = await self._call_ai_api(payload, content)
                ai_severity, ai_confidence, ai_fix = ai_result["severity"], ai_result["confidence"], ai_result["fix"]
                if ai_confidence >= self.ai_confirmation_threshold:
                    result = XSSResult(url=url, payload=payload, vector_type="dom",
                        evidence="DOM execution detected", ai_severity=ai_severity,
                        ai_confidence=ai_confidence, fix=ai_fix)
                    results.append(result)
                    self.results.append(result)
                    logger.info(f"[XSS-DOM] {url} - {payload} - {ai_severity}")
        finally:
            page.remove_listener("dialog", handler)

    async def test_stored(self, page: Page, url: str, form: dict):
        results = []
        for payload in self.XSS_PAYLOADS:
            try:
                await asyncio.wait_for(
                    self._do_test_stored(page, url, form, payload, results),
                    timeout=self.payload_hard_timeout_s
                )
            except asyncio.TimeoutError:
                logger.warning(f"[XSS-STORED TIMEOUT] {payload!r} exceeded {self.payload_hard_timeout_s}s, skipping")
        return results

    async def _do_test_stored(self, page: Page, url: str, form: dict, payload: str, results: list):
        await page.goto(url, timeout=self.page_timeout_ms)
        # FIX: form.get("inputs", []) is a list of field-name STRINGS
        # (CrawlResult stores them that way -- see dfs.py's _extract_forms),
        # not a list of dicts. The old code did `name = inp.get("name")`,
        # calling .get() on a plain string -- guaranteed AttributeError on
        # the very first input of every single stored-XSS payload attempt,
        # which is exactly the "'str' object has no attribute 'get'" crash
        # seen in main.py's "XSS error:" log line. This means stored XSS
        # testing has never actually run even once before this fix -- every
        # attempt failed before it filled a single field.
        for name in form.get("inputs", []):
            if name:
                try: await page.fill(f"[name='{name}']", payload)
                except Exception: pass
        try:
            async with page.expect_navigation(timeout=5000):
                await page.click("input[type=submit], button[type=submit]", timeout=3000)
        except Exception: pass
        await page.wait_for_timeout(1500)
        await page.goto(url, timeout=self.page_timeout_ms)
        content = await page.content()
        executed = False
        try: executed = await page.evaluate("() => window.__xss === 1")
        except Exception: pass
        if payload in content or executed:
            evidence = []
            if payload in content: evidence.append("payload persisted in response")
            if executed: evidence.append("window.__xss flag set (executed)")
            ai_result = await self._call_ai_api(payload, content)
            ai_severity, ai_confidence, ai_fix = ai_result["severity"], ai_result["confidence"], ai_result["fix"]
            if ai_confidence >= self.ai_confirmation_threshold:
                result = XSSResult(url=url, form_action=form.get("action"), payload=payload,
                    vector_type="stored", evidence=", ".join(evidence),
                    ai_severity=ai_severity, ai_confidence=ai_confidence, fix=ai_fix)
                results.append(result)
                self.results.append(result)
                logger.info(f"[XSS-STORED] {url} - {payload} - {ai_severity}")

    async def scan_page(self, url: str, params=None, forms=None):
        results = []
        page = await self.context.new_page()
        try:
            if params:
                for p in params:
                    results += await self.test_reflected(page, url, p)
            if forms:
                for form in forms:
                    form_action = form.get("action", url)
                    form_method = form.get("method", "get")
                    for input_name in form.get("inputs", []):
                        if input_name:
                            results += await self.test_reflected_form(page, form_action, input_name, form_method)
            results += await self.test_dom(page, url)
        finally:
            await page.close()
        if forms:
            stored_page = await self.context.new_page()
            try:
                for form in forms:
                    results += await self.test_stored(stored_page, url, form)
            finally:
                await stored_page.close()
        return results