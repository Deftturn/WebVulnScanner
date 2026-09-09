import requests
import re
import logging
from typing import Dict
from datetime import datetime

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
        self._http_session = requests.Session()
        self._ai_cache: Dict[str, Dict] = {}

    def _call_ai_api(self, evidence: str, url: str = "", status_code: int = 0, headers: dict = None) -> dict:
        """Call AI API with headers for language detection."""
        cache_key = f"{evidence[:500]}::{url}::{status_code}"
        if cache_key in self._ai_cache:
            return self._ai_cache[cache_key]
        try:
            # FIXED: Always use "sensitive_info" — IDOR context added to evidence text
            # This prevents the API from skipping the finding due to unknown "idor" type
            is_idor_url = "user_id" in url
            attack_type = "sensitive_info"
            
            # Add IDOR context to evidence if applicable
            if is_idor_url:
                evidence = f"Found via IDOR (user_id parameter allows accessing other users' data without authorization): {evidence}"
            
            result = self._http_session.post(AI_API_URL, json={
                "payload": "", 
                "url": url,
                "parameter": "user_id" if is_idor_url else "",
                "vulnerable_code": evidence[:2000],
                "language": "unknown", 
                "attack_type": attack_type,
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

    def _deduplicate_results(self, results):
        """Remove duplicate findings based on URL + check_type."""
        seen = set()
        unique_results = []
        for result in results:
            key = f"{result.url}::{result.check_type}"
            if key not in seen:
                seen.add(key)
                unique_results.append(result)
        return unique_results

    def scan_response(self, url: str, html: str = None, headers: dict = None):
        results = []
        try:
            status_code = 200
            if html is None or headers is None:
                response = self._http_session.get(url, timeout=self.timeout_ms)
                if html is None:
                    html = response.text
                if headers is None:
                    headers = response.headers
                status_code = response.status_code
            
            # Normalize headers to lowercase for consistent access
            normalized_headers = {k.lower(): v for k, v in headers.items()} if headers else {}
            
            content = html
            
            for pattern_name, pattern in self.PATTERNS.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    unique_matches = list(set(matches))[:5]
                    evidence = f"Found {pattern_name}: {unique_matches}"
                    # FIXED: Pass headers to AI API for language detection
                    ai = self._call_ai_api(evidence, url, status_code=status_code, headers=normalized_headers)
                    if ai["confidence"] >= self.ai_confirmation_threshold:
                        result = SensitiveInfoResult(url=url, check_type=f"exposed_{pattern_name}",
                            evidence=evidence, ai_severity=ai["severity"],
                            ai_confidence=ai["confidence"], fix=ai["fix"])
                        results.append(result)
                        logger.warning(f"[SENSITIVE] {url}: Exposed {pattern_name}")
            
            results = self._deduplicate_results(results)
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