import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from playwright.async_api import Page, BrowserContext


class XSSResult:
    def __init__(self, url, param=None, form_action=None, payload=None, vector_type=None, evidence=None):
        self.url = url
        self.param = param
        self.form_action = form_action
        self.payload = payload
        self.vector_type = vector_type
        self.evidence = evidence

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

    def __init__(self, context: BrowserContext, page_timeout_ms: int = 30000):
        self.context = context
        self.page_timeout_ms = page_timeout_ms

    # -------------------------
    # URL injection
    # -------------------------
    def inject_url(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    # -------------------------
    # Reflected XSS
    # -------------------------
    async def test_reflected(self, page: Page, url: str, param: str):
        results = []

        for payload in self.XSS_PAYLOADS:
            test_url = self.inject_url(url, param, payload)

            try:
                # Reset flag before navigation so a stale value can't cause a false positive
                await page.evaluate("() => { window.__xss = 0; }")
            except Exception:
                pass

            try:
                await page.goto(test_url, timeout=self.page_timeout_ms)
                await page.wait_for_timeout(800)

                content = await page.content()
                reflected = payload in content

                # Check whether the injected payload actually executed
                executed = False
                try:
                    executed = await page.evaluate("() => window.__xss === 1")
                except Exception:
                    pass

                if reflected or executed:
                    evidence = []
                    if reflected:
                        evidence.append("payload reflected in HTML")
                    if executed:
                        evidence.append("window.__xss flag set (executed)")

                    results.append(XSSResult(
                        url=test_url,
                        param=param,
                        payload=payload,
                        vector_type="reflected",
                        evidence=", ".join(evidence)
                    ))

            except Exception:
                continue

        return results

    # -------------------------
    # DOM XSS
    # -------------------------
    async def test_dom(self, page: Page, url: str):
        results = []

        for payload in self.XSS_PAYLOADS:
            triggered = False

            def handler(dialog):
                nonlocal triggered
                triggered = True
                asyncio.create_task(dialog.dismiss())

            try:
                page.on("dialog", handler)

                await page.goto(url, timeout=self.page_timeout_ms)

                await page.evaluate(f"""
                    () => {{
                        window.__xss = 0;
                        location.hash = `{payload}`;
                        document.body.innerHTML = location.hash;
                    }}
                """)

                await page.wait_for_timeout(1000)

                flag = await page.evaluate("() => window.__xss === 1")

                if triggered or flag:
                    results.append(XSSResult(
                        url=url,
                        payload=payload,
                        vector_type="dom",
                        evidence="DOM execution detected"
                    ))

            except Exception:
                continue
            finally:
                page.remove_listener("dialog", handler)

        return results

    # -------------------------
    # Stored XSS
    # -------------------------
    async def test_stored(self, page: Page, url: str, form: dict):
        results = []

        for payload in self.XSS_PAYLOADS:
            try:
                await page.goto(url, timeout=self.page_timeout_ms)

                for inp in form.get("inputs", []):
                    name = inp.get("name")
                    if not name:
                        continue
                    try:
                        await page.fill(f"[name='{name}']", payload)
                    except Exception:
                        continue

                # Submit and wait for navigation; tolerate missing submit buttons
                try:
                    async with page.expect_navigation(timeout=5000):
                        await page.click("input[type=submit], button[type=submit]")
                except Exception:
                    pass  # no nav or no button — continue anyway

                await page.wait_for_timeout(1500)

                # Re-visit to check persistence
                await page.goto(url, timeout=self.page_timeout_ms)
                content = await page.content()

                executed = False
                try:
                    executed = await page.evaluate("() => window.__xss === 1")
                except Exception:
                    pass

                if payload in content or executed:
                    evidence = []
                    if payload in content:
                        evidence.append("payload persisted in response")
                    if executed:
                        evidence.append("window.__xss flag set (executed)")

                    results.append(XSSResult(
                        url=url,
                        form_action=form.get("action"),
                        payload=payload,
                        vector_type="stored",
                        evidence=", ".join(evidence)
                    ))

            except Exception:
                continue

        return results

    # -------------------------
    # Public API
    # -------------------------
    async def scan_page(self, url: str, params=None, forms=None):
        results = []

        # Reflected + DOM share one page
        page = await self.context.new_page()
        try:
            if params:
                for p in params:
                    results += await self.test_reflected(page, url, p)

            results += await self.test_dom(page, url)
        finally:
            await page.close()

        # Stored gets its own fresh page so a closed-page bug can never silently kill it
        if forms:
            stored_page = await self.context.new_page()
            try:
                for form in forms:
                    results += await self.test_stored(stored_page, url, form)
            finally:
                await stored_page.close()

        return results