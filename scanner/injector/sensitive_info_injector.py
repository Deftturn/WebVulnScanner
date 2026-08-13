import requests
import re
import logging
from typing import Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

AI_API_URL = "http://127.0.0.1:8000/analyze"

class SensitiveInfoResult:
    def __init__(self, url, check_type, evidence, ai_severity="UNKNOWN", ai_confidence=0.0, fix=""):
        self.url = url
        self.check_type = check_type
        self.evidence = evidence
        self.ai_severity = ai_severity
        self.ai_confidence = ai_confidence
        self.fix = fix

    def to_dict(self):
        return self.__dict__


class SensitiveInfoScanner:

    PATTERNS = {
        "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
        "credit_card": r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
        "api_key": r'(?:api[_-]?key|api[_-]?secret|access[_-]?key)\s*[:=]\s*["\']?[a-zA-Z0-9_-]{20,}["\']?',
        "password": r'(?:password|passwd|pwd)\s*[:=]\s*["\']?[^"\'&\s]{3,}["\']?',
        "token": r'(?:token|jwt|bearer)\s*[:=]\s*["\']?[a-zA-Z0-9._-]{10,}["\']?',
        "database_url": r'(?:database_url|db_url|mongo_uri)\s*=\s*["\']?[^"\'&\s]{10,}["\']?',
        "aws_key": r'AKIA[0-9A-Z]{16}',
        "private_key": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
    }

    def __init__(self, timeout_ms: int = 10000, ai_confirmation_threshold: float = 0.5):
        self.timeout_ms = timeout_ms / 1000
        self.ai_confirmation_threshold = ai_confirmation_threshold
        self.results = []
        # Reuses the connection across the single GET this scanner makes per
        # URL, and across repeat calls for other URLs on the same host.
        self._http_session = requests.Session()
        # A page with, say, 5 emails on it would otherwise trigger 5 near-
        # identical AI calls; cache by evidence so repeats are free.
        self._ai_cache: Dict[str, Dict] = {}

    def _call_ai_api(self, evidence: str, url: str = "") -> dict:
        cache_key = evidence[:500]
        if cache_key in self._ai_cache:
            return self._ai_cache[cache_key]
        try:
            result = self._http_session.post(AI_API_URL, json={
                "payload": "", "url": url, "vulnerable_code": evidence[:2000],
                "language": "unknown", "attack_type": "sensitive_info",
                "response_text": evidence[:2000]
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

    def scan_response(self, url: str, html: str = None, headers: dict = None):
        """Pass `html`/`headers` from the crawler's CrawlResult to avoid a
        redundant fetch of a page the crawler already retrieved. Falls back
        to a fresh GET when called standalone without crawl data."""
        results = []
        try:
            if html is None or headers is None:
                response = self._http_session.get(url, timeout=self.timeout_ms)
                if html is None:
                    html = response.text
                if headers is None:
                    headers = response.headers
            content = html
            headers_str = str(headers)
            for pattern_name, pattern in self.PATTERNS.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    unique_matches = list(set(matches))[:5]
                    evidence = f"Found {pattern_name}: {unique_matches}"
                    ai = self._call_ai_api(evidence, url)
                    if ai["confidence"] >= self.ai_confirmation_threshold:
                        result = SensitiveInfoResult(url=url, check_type=f"exposed_{pattern_name}",
                            evidence=evidence, ai_severity=ai["severity"],
                            ai_confidence=ai["confidence"], fix=ai["fix"])
                        results.append(result)
                        logger.warning(f"[SENSITIVE] {url}: Exposed {pattern_name}")
            for pattern_name, pattern in self.PATTERNS.items():
                matches = re.findall(pattern, headers_str, re.IGNORECASE)
                if matches:
                    unique_matches = list(set(matches))[:3]
                    evidence = f"Found {pattern_name} in headers: {unique_matches}"
                    ai = self._call_ai_api(evidence, url)
                    if ai["confidence"] >= self.ai_confirmation_threshold:
                        result = SensitiveInfoResult(url=url, check_type=f"exposed_{pattern_name}_header",
                            evidence=evidence, ai_severity=ai["severity"],
                            ai_confidence=ai["confidence"], fix=ai["fix"])
                        results.append(result)
        except Exception as e:
            logger.warning(f"Scan failed for {url}: {e}", exc_info=True)
        self.results.extend(results)
        return results

    def scan_url(self, url: str, html: str = None, headers: dict = None):
        return self.scan_response(url, html=html, headers=headers)

    def get_summary(self) -> dict:
        return {"total_checks": len(self.results),
            "high_severity": sum(1 for r in self.results if r.ai_severity in ["CRITICAL", "HIGH"]),
            "findings": [r.to_dict() for r in self.results]}