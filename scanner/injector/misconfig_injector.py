import requests
import logging
from typing import Dict, Set
from urllib.parse import urlparse
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

AI_API_URL = "http://127.0.0.1:8000/analyze"

class MisconfigResult:
    def __init__(self, url, check_type, evidence, ai_severity="UNKNOWN", ai_confidence=0.0, fix=""):
        self.url = url
        self.check_type = check_type
        self.evidence = evidence
        self.ai_severity = ai_severity
        self.ai_confidence = ai_confidence
        self.fix = fix

    def to_dict(self):
        return self.__dict__


class MisconfigScanner:

    SECURITY_HEADERS = [
        "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
        "Strict-Transport-Security", "X-XSS-Protection", "Referrer-Policy", "Permissions-Policy",
    ]

    SENSITIVE_PATHS = [
        "/.git/config", "/.env", "/admin/", "/wp-admin/", "/phpinfo.php",
        "/debug/", "/.DS_Store", "/backup/", "/logs/",
    ]

    def __init__(self, timeout_ms: int = 10000):
        self.timeout_ms = timeout_ms / 1000
        self.results = []
        # Reuses TCP/TLS connections across the ~9 sensitive-path probes and
        # the header/debug checks against the same host, instead of a fresh
        # handshake per request.
        self._http_session = requests.Session()
        # Same evidence -> same AI verdict; avoids re-paying AI latency for
        # duplicate findings (e.g. the same missing-headers evidence
        # recurring across many pages of the same site).
        self._ai_cache: Dict[str, Dict] = {}
        # Sensitive-path exposure (.git/config, .env, /admin/, etc.) is a
        # property of the HOST, not of any individual crawled page -- it
        # doesn't need to be re-probed once per URL. Tracking checked
        # origins avoids re-running the same 9 requests (and 9 potential AI
        # calls) for every single page the crawler found.
        self._checked_origins: Set[str] = set()
        # NEW: Track header checks per origin to avoid duplicate findings
        # for the same host (e.g. http://site.com and http://site.com/index.html
        # both missing the same headers is ONE finding, not two).
        self._checked_header_origins: Set[str] = set()

    def _call_ai_api(self, evidence: str, url: str = "", status_code: int = 0, headers: dict = None) -> dict:
        """Call AI API with headers for language detection."""
        cache_key = f"{evidence[:500]}::{url}::{status_code}"
        if cache_key in self._ai_cache:
            return self._ai_cache[cache_key]
        try:
            result = self._http_session.post(AI_API_URL, json={
                "payload": "",
                "url": url,
                "parameter": "",
                "vulnerable_code": evidence[:2000],
                "language": "unknown",
                "attack_type": "misconfig",
                "response_text": evidence[:2000],
                "status_code": status_code,
                "detected_at": datetime.now().isoformat(),
                "headers": headers or {}
            }, timeout=15)
            if result.status_code == 200:
                data = result.json()
                out = {"severity": data.get("severity", "UNKNOWN"),
                    "confidence": data.get("confidence", 0.0), "fix": data.get("fix", "")}
            else:
                out = {"severity": "UNKNOWN", "confidence": 0.0, "fix": ""}
        except Exception:
            out = {"severity": "UNKNOWN", "confidence": 0.0, "fix": ""}
        self._ai_cache[cache_key] = out
        return out

    def check_security_headers(self, url: str, headers: dict = None):
        """If `headers` is supplied (e.g. from the crawler's already-fetched
        CrawlResult.headers), this makes zero network requests. Falls back to
        a fresh GET only when called standalone without crawl data.
        
        FIXED: Now tracks header checks per origin to avoid duplicate findings
        for the same host (e.g. http://site.com and http://site.com/index.html
        both missing the same headers should be ONE finding, not two)."""
        results = []
        try:
            # FIXED: Skip if we already checked this origin for headers
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if origin in self._checked_header_origins:
                logger.debug(f"[MISCONFIG] Header check already done for {origin}, skipping")
                return results
            self._checked_header_origins.add(origin)

            status_code = 200
            if headers is None:
                response = self._http_session.get(url, timeout=self.timeout_ms, allow_redirects=True)
                headers = response.headers
                status_code = response.status_code

            # Crawler headers are lowercased; a plain requests.Response
            # object's .headers is case-insensitive already, so this
            # comparison works either way.
            headers_lower = {k.lower() for k in headers.keys()}
            missing = [h for h in self.SECURITY_HEADERS if h.lower() not in headers_lower]
            if missing:
                evidence = f"Missing security headers: {', '.join(missing)}"
                # FIXED: Pass headers to AI API for language detection
                ai = self._call_ai_api(evidence, url, status_code=status_code, headers=headers)
                result = MisconfigResult(url=url, check_type="missing_headers", evidence=evidence,
                    ai_severity=ai["severity"], ai_confidence=ai["confidence"], fix=ai["fix"])
                results.append(result)
                logger.info(f"[MISCONFIG] {url}: Missing {len(missing)} security headers")
        except Exception as e:
            logger.debug(f"Header check failed for {url}: {e}")
        return results

    def check_sensitive_paths(self, url: str):
        results = []
        # Use scheme+host only -- never the page's own path or query string.
        # The old code did base = url.rstrip('/'); f"{base}{path}", which for
        # a URL like ".../survey_questions.jsp?step=a" produced
        # ".../survey_questions.jsp?step=a/.git/config" -- that's not a real
        # path at all, it's junk appended after the query string, and the
        # server's normal/soft-404 response to it was getting misread as
        # every single sensitive path being "exposed".
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        if origin in self._checked_origins:
            return results
        self._checked_origins.add(origin)

        for path in self.SENSITIVE_PATHS:
            try:
                test_url = f"{origin}{path}"
                response = self._http_session.get(test_url, timeout=self.timeout_ms, allow_redirects=False)
                
                # FIXED: Only flag 200 as truly "exposed". 403 means the path
                # exists but is properly blocked - not a vulnerability.
                if response.status_code == 200:
                    evidence = f"Accessible path found: {test_url} (Status: {response.status_code})"
                    # FIXED: Pass headers to AI API
                    response_headers = {k.lower(): v for k, v in response.headers.items()}
                    ai = self._call_ai_api(evidence, test_url, status_code=response.status_code, 
                                          headers=response_headers)
                    result = MisconfigResult(url=test_url, check_type="exposed_path", evidence=evidence,
                        ai_severity=ai["severity"], ai_confidence=ai["confidence"], fix=ai["fix"])
                    results.append(result)
                    logger.warning(f"[MISCONFIG] Exposed: {test_url}")
                elif response.status_code == 403:
                    # Path exists but is blocked - log as info, not a finding
                    logger.info(f"[MISCONFIG] Blocked path (not a vulnerability): {test_url} (403 Forbidden)")
                elif response.status_code == 404:
                    # Path doesn't exist - not a finding
                    logger.debug(f"[MISCONFIG] Path not found: {test_url} (404)")
                else:
                    # Other status codes (301, 302, 500, etc.) - log for manual review
                    logger.debug(f"[MISCONFIG] Path returned {response.status_code}: {test_url}")
            except Exception as e:
                logger.debug(f"Path check failed for {test_url}: {e}")
        return results

    def check_debug_mode(self, url: str, html: str = None):
        """If `html` is supplied (e.g. from CrawlResult.html), this makes
        zero network requests. Falls back to a fresh GET when called
        standalone without crawl data."""
        results = []
        debug_indicators = ["DEBUG=True", "DEBUG = True", "django-debug", "stack trace",
            "Traceback (most recent call last)", "PHP Debug", "laravel-debugbar"]
        try:
            status_code = 200
            headers = {}
            if html is None:
                response = self._http_session.get(url, timeout=self.timeout_ms)
                html = response.text
                status_code = response.status_code
                headers = {k.lower(): v for k, v in response.headers.items()}
            content = html.lower()
            found = [ind for ind in debug_indicators if ind.lower() in content]
            if found:
                evidence = f"Debug indicators found: {', '.join(found)}"
                # FIXED: Pass headers to AI API
                ai = self._call_ai_api(evidence, url, status_code=status_code, headers=headers)
                result = MisconfigResult(url=url, check_type="debug_mode", evidence=evidence,
                    ai_severity=ai["severity"], ai_confidence=ai["confidence"], fix=ai["fix"])
                results.append(result)
                logger.warning(f"[MISCONFIG] Debug mode detected on {url}")
        except Exception as e:
            logger.debug(f"Debug check failed for {url}: {e}")
        return results

    def scan_url(self, url: str, headers: dict = None, html: str = None):
        """Pass headers/html from the crawler's CrawlResult to avoid
        re-fetching pages the crawler already retrieved. Sensitive-path
        probing always makes its own requests since those paths were never
        part of the crawl."""
        all_results = []
        all_results.extend(self.check_security_headers(url, headers=headers))
        all_results.extend(self.check_sensitive_paths(url))
        all_results.extend(self.check_debug_mode(url, html=html))
        self.results.extend(all_results)
        return all_results

    def get_summary(self) -> dict:
        return {"total_checks": len(self.results),
            "high_severity": sum(1 for r in self.results if r.ai_severity in ["CRITICAL", "HIGH"]),
            "findings": [r.to_dict() for r in self.results]}