from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import requests
import os
import re
import joblib
import numpy as np
import subprocess
import sys
import json
import glob
import pandas as pd
import threading
from datetime import datetime

# Import fix templates from separate file
from API.fix_templates import (
    SQLI_CODE, XSS_ENCODE,
    SQLI_TECHNIQUE_LABELS, SQLI_TECHNIQUE_IMPACT, SQLI_TECHNIQUE_EXTRA_DEFENSES,
    detect_language_from_url, detect_language_from_headers
)

env_file = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(env_file):
    with open(env_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ[key.strip()] = value.strip()

DATAROBOT_KEY = os.getenv("DATAROBOT_API_KEY")
DEPLOYMENT_ID = os.getenv("DATAROBOT_DEPLOYMENT_ID", "6aa03f0cc561056ceacf7dfe")
DATAROBOT_URL = f"https://app.datarobot.com/api/v2/deployments/{DEPLOYMENT_ID}/predictions"
_WORKING_AUTH_TYPE = None

LOCAL_MODEL = None
LOCAL_VECTORIZER = None
try:
    LOCAL_MODEL = joblib.load(os.path.join(os.path.dirname(__file__), "severity_model_local.pkl"))
    LOCAL_VECTORIZER = joblib.load(os.path.join(os.path.dirname(__file__), "vectorizer_local.pkl"))
    print("Local backup model loaded")
except Exception as e:
    print(f"Local model not loaded: {e}")

if not DATAROBOT_KEY and not LOCAL_MODEL:
    raise RuntimeError("Neither DataRobot API key nor local model available.")

app = FastAPI(title="Vuln Severity API", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

FIX_DATASET = None
try:
    dataset_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "final_balanced_dataset_v2.csv")
    df = pd.read_csv(dataset_path)
    FIX_DATASET = df[['vulnerability_type', 'category', 'technique', 'secure_code', 'conversation_text', 'real_incident', 'cve_id', 'language']].copy()
    print(f"Fix dataset loaded: {len(FIX_DATASET)} rows")
except Exception as e:
    print(f"Fix dataset not loaded: {e}")

def clean_text(text):
    text = re.sub(r'```[^`]*```', '[code example]', text)
    text = re.sub(r'`([^`]*)`', r'\1', text)
    text = text.replace('**', '')
    return text.strip()

def _classify_sqli_technique(payload: str) -> str:
    if re.search(r'SLEEP|WAITFOR|pg_sleep', payload, re.IGNORECASE): return "time_based"
    if re.search(r'UNION\s+SELECT', payload, re.IGNORECASE): return "union_based"
    if re.search(r'extractvalue|updatexml', payload, re.IGNORECASE): return "error_based"
    if re.search(r'DROP\s+TABLE', payload, re.IGNORECASE): return "destructive"
    return "boolean_based"

def _classify_xss_technique(payload: str) -> str:
    if re.search(r'onerror|onload|onfocus|onclick', payload, re.IGNORECASE): return "event_handler"
    return "script_tag"

def _format_evidence_block(url, parameter, status_code, response_time_ms, detected_at, response_excerpt, payload):
    lines = ["DETECTION EVIDENCE (as captured by the scanner -- not reconstructed or invented)"]
    if detected_at: lines.append(f"Detected at: {detected_at}")
    if url: lines.append(f"URL tested: {url}")
    if parameter: lines.append(f"Parameter/field tested: {parameter}")
    lines.append(f"Payload sent: {payload}")
    if status_code: lines.append(f"HTTP status code returned: {status_code}")
    if response_time_ms and response_time_ms > 0:
        lines.append(f"Response time: {response_time_ms:.0f}ms" + (" (elevated -- consistent with a time-based payload)" if response_time_ms > 4000 else ""))
    if response_excerpt:
        lines.append(f"Excerpt from the actual captured response (truncated):\n{response_excerpt[:300]}")
    return "\n".join(lines)

def get_smart_fix(vulnerability_type, payload="", check_type="", language="",
                   url="", parameter="", status_code=0, response_time_ms=0.0,
                   detected_at="", response_text="", headers=None):
    result = []

    result.append(f"WHERE FOUND\nURL: {url if url else 'Unknown'}\nParameter: {parameter if parameter else 'N/A'}")
    result.append(f"What Was Found\nA {vulnerability_type.lower()} vulnerability was detected in the application.")
    result.append(_format_evidence_block(url, parameter, status_code, response_time_ms, detected_at, response_text, payload))

    detected_lang, lang_confidence = detect_language_from_url(url)
    if not detected_lang and headers:
        detected_lang, lang_confidence = detect_language_from_headers(headers)

    if vulnerability_type == "SQL Injection":
        technique = _classify_sqli_technique(payload)
        technique_label = SQLI_TECHNIQUE_LABELS[technique]
        result.append(f"Technique: {technique_label} (classified from the actual payload sent, above)")

        result.append(
            "Root Cause (inferred, not observed)\n"
            f"The behavior above is consistent with a common pattern for {technique_label.lower()}: "
            "user input concatenated directly into a SQL query string without parameterization. "
            "The scanner tests only over HTTP and has no access to this site's server-side source "
            "code, so this is a general inferred pattern -- not a transcription of the actual code."
        )
        result.append(f"Impact If Exploited\n{SQLI_TECHNIQUE_IMPACT[technique]}")

        if FIX_DATASET is not None:
            matches = FIX_DATASET[FIX_DATASET['vulnerability_type'] == 'SQL Injection']
            if len(matches) > 0:
                sqli_matches = matches[matches['technique'].str.contains('sql', case=False, na=False)]
                row = sqli_matches.iloc[0] if len(sqli_matches) > 0 else matches.iloc[0]
                incident = row.get('real_incident', '')
                if incident and isinstance(incident, str) and len(str(incident)) > 5:
                    result.append(f"Real-World Precedent (industry context, not specific to this site)\nSQL injection of this type has caused real incidents elsewhere, e.g.: {incident}")
                cve = row.get('cve_id', '')
                if cve and isinstance(cve, str) and len(str(cve)) > 3:
                    result.append(f"Security Reference: {cve}")

        if detected_lang and detected_lang in SQLI_CODE:
            langs_to_show = [detected_lang]
            lang_note = f"Language: {detected_lang} ({lang_confidence})"
        else:
            langs_to_show = ["PHP", "Java"]
            lang_note = "Language: not reliably detected -- showing two widely-applicable reference patterns rather than guessing"
        result.append(lang_note)

        for lang in langs_to_show:
            code = SQLI_CODE[lang]
            before = code["before"].format(param=parameter or "param")
            after = code["after"].format(param=parameter or "param")
            result.append(
                f"General Secure-Coding Pattern ({lang}) -- illustrative, not this site's actual source\n"
                f"BEFORE (vulnerable pattern):\n{before}\n\nAFTER (parameterized):\n{after}"
            )

        result.append("Verification Steps\nRe-send the same payload after applying the fix. Expect the database to treat it as a literal string with no special meaning -- e.g. no extra rows returned, no added delay, no database error.")
        result.append("Additional Defenses\n" + "\n".join(f"- {d}" for d in SQLI_TECHNIQUE_EXTRA_DEFENSES[technique]))

    elif vulnerability_type == "XSS":
        technique = _classify_xss_technique(payload)
        result.append(f"Technique: {'Event-Handler Injection' if technique == 'event_handler' else 'Script-Tag Injection'} (classified from the actual payload sent, above)")
        if technique == "event_handler":
            result.append("Root Cause (inferred, not observed)\nConsistent with user input being rendered into an HTML attribute without encoding, allowing an event-handler attribute (onerror, onload, onfocus, etc.) to execute on page load or interaction.")
        else:
            result.append("Root Cause (inferred, not observed)\nConsistent with user input being reflected directly into the HTML response without encoding, allowing an injected <script> tag or attribute breakout to execute.")
        result.append("Impact If Exploited\nAn attacker could execute arbitrary JavaScript in a victim's browser session -- stealing session cookies, performing actions as the victim, or redirecting to a malicious site.")

        if FIX_DATASET is not None:
            matches = FIX_DATASET[FIX_DATASET['vulnerability_type'] == 'XSS']
            if len(matches) > 0:
                row = matches.iloc[0]
                incident = row.get('real_incident', '')
                if incident and isinstance(incident, str) and len(str(incident)) > 5:
                    result.append(f"Real-World Precedent (industry context, not specific to this site)\nXSS of this type has caused real incidents elsewhere, e.g.: {incident}")

        if detected_lang and detected_lang in XSS_ENCODE:
            result.append(f"Language: {detected_lang} ({lang_confidence})")
            result.append(f"General Secure-Coding Pattern ({detected_lang}) -- illustrative, not this site's actual source\nHTML-encode all user-supplied output before rendering:\n{XSS_ENCODE[detected_lang]}")
        else:
            result.append("Language: not reliably detected -- output encoding is required in any backend language; PHP and Python examples shown as reference")
            result.append(f"General Secure-Coding Pattern (PHP) -- illustrative\n{XSS_ENCODE['PHP']}")
            result.append(f"General Secure-Coding Pattern (Python) -- illustrative\n{XSS_ENCODE['Python']}")

        result.append("Verification Steps\nRe-send the same payload after applying the fix. Expect the payload to appear as literal encoded text in the page source (e.g. &lt;script&gt;) rather than executing.")
        result.append("Additional Defenses\n- Add a Content-Security-Policy that disallows inline scripts/event handlers.\n- Prefer `textContent`/auto-escaping template output over `innerHTML` or raw string concatenation on the frontend.")

    elif vulnerability_type == "Security Misconfiguration":
        result.append("Root Cause\nThe web server / application is not configured to send the expected security headers, or an unintended path is publicly reachable -- this is a configuration issue, not an application code issue.")
        if check_type == "missing_headers":
            result.append("General Fix Pattern -- add security headers at the web server or application middleware level (example, Apache):\n<IfModule mod_headers.c>\n  Header set Content-Security-Policy \"default-src 'self'\"\n  Header set X-Frame-Options \"DENY\"\n  Header set X-Content-Type-Options \"nosniff\"\n</IfModule>")
        elif check_type == "exposed_path":
            result.append("General Fix Pattern -- block the path at the web server config or move sensitive files outside the web root (example, Apache):\n<Files \".env\">\n  Require all denied\n</Files>")
        result.append("Verification Steps\nRe-request the same URL/headers after the fix and confirm the header is now present, or the path now returns 403/404.")

    elif vulnerability_type == "Sensitive Information Disclosure":
        result.append("Root Cause\nSensitive data (e.g. email, token, or credential-like content) was found directly in a response the scanner could access -- either hardcoded, logged, or served from an unprotected file/endpoint.")
        if "user_id" in url:
            result.append("IDOR Context: This data was accessible via the user_id parameter without authentication, indicating a Broken Access Control vulnerability (CWE-639).")
        result.append("General Fix Pattern\n- Remove hardcoded secrets/PII from source and served files; use environment variables or a secrets manager.\n- Ensure the exposing endpoint requires authentication.\n- Verify the authenticated user matches the requested resource.")
        result.append("Verification Steps\nRe-request the same URL after the fix and confirm the sensitive value no longer appears in the response.")

    else:
        result.append("No fix template available for this vulnerability type.")

    return "\n\n".join(result)


class ScannerInput(BaseModel):
    payload: str = ""
    parameter: str = ""
    url: str = ""
    vulnerable_code: str = ""
    language: str = ""
    response_text: str = ""
    status_code: int = 200
    attack_type: str = "unknown"
    response_time_ms: float = 0.0
    detected_at: str = ""
    headers: dict = {}
    timeout_ms: float = 5000.0

def predict_local(payload, code, language, technique):
    combined = f"{code} {payload} {language} {technique}"
    X = LOCAL_VECTORIZER.transform([combined])
    severity = LOCAL_MODEL.predict(X)[0]
    proba = LOCAL_MODEL.predict_proba(X)[0]
    return severity, float(max(proba))

@app.post("/analyze")
def analyze_vulnerability(data: ScannerInput):
    payload = data.payload or ""
    code = data.vulnerable_code or ""
    language = data.language or ""
    attack_type = data.attack_type or "unknown"
    response_text = data.response_text or ""
    headers = data.headers or {}
    
    sql_patterns = [
        r"' OR \d=\d", r"' OR '[^']*'='[^']*", r"UNION\s+SELECT", r"DROP\s+TABLE",
        r"SLEEP\s*\(\s*\d", r"WAITFOR\s+DELAY", r"--\s*$", r"/\*.*\*/", r"';",
        r"admin'\s*--", r"' OR '1'='1"
    ]
    xss_patterns = [
        r"<script.*?>", r"javascript\s*:", r"onerror\s*=", r"onclick\s*=",
        r"<img[^>]+onerror", r"<svg[^>]+onload", r"window\.__xss",
        r"<body[^>]+onload", r"<iframe[^>]+src\s*=\s*['\"]javascript",
        r"<input[^>]+onfocus", r"<a[^>]+href\s*=\s*['\"]javascript"
    ]
    
    has_attack = any(re.search(p, payload, re.IGNORECASE) for p in sql_patterns + xss_patterns)
    has_code = len(code) > 20 and ("SELECT" in code.upper() or "eval" in code.lower() or "exec" in code.lower())
    
    is_sql = any(re.search(p, payload, re.IGNORECASE) for p in sql_patterns)
    is_xss = any(re.search(p, payload, re.IGNORECASE) for p in xss_patterns)
    
    skip_prefilter = attack_type in ["misconfig", "sensitive_info", "sensitive_information_disclosure"]
    if not skip_prefilter and not has_attack and not has_code:
        return {"severity": "LOW", "confidence": 0.99, "note": "No action needed.", "fix": "No action needed."}
    
    if attack_type == "sqli" or is_sql:
        vt, technique = "SQL Injection", "sql_injection"
    elif attack_type == "xss" or is_xss:
        vt, technique = "XSS", "xss"
    elif attack_type == "misconfig":
        vt, technique = "Security Misconfiguration", "security_misconfiguration"
    elif attack_type in ["sensitive_info", "sensitive_information_disclosure"]:
        vt, technique = "Sensitive Information Disclosure", "sensitive_information_disclosure"
    else:
        vt, technique = "Unknown", "unknown"
    
    check_type = ""
    if vt == "Security Misconfiguration":
        if "debug" in code.lower():
            check_type = "debug_mode"
        elif "directory listing" in response_text.lower():
            check_type = "exposed_path"
        else:
            check_type = "missing_headers"
    
    if vt == "Sensitive Information Disclosure":
        for kw in ["email", "credit_card", "ssn", "password", "token", "api_key"]:
            if kw in (code + response_text).lower():
                check_type = f"exposed_{kw}"
                break
    
    fix_params = {
        "vulnerability_type": vt,
        "payload": payload,
        "check_type": check_type,
        "language": language,
        "url": data.url,
        "parameter": data.parameter,
        "status_code": data.status_code,
        "response_time_ms": data.response_time_ms,
        "detected_at": data.detected_at or datetime.now().isoformat(),
        "response_text": response_text,
        "headers": headers
    }
    
    if DATAROBOT_KEY:
        pd_data = [{"id": "scanner-test-001", "category": technique, "owasp_2021": "", "severity": None, "cwe": "", "language": language or "unknown", "epss_score": 0.85, "cve_id": "", "real_incident": "Scanner detected vulnerability", "incident_year": 2024, "vulnerable_code": code[:2000] if code else payload[:2000], "secure_code": "", "attack_payload": payload[:2000], "conversation_text": f"Payload: {payload}"[:2000], "complexity": "moderate", "technique": technique, "subcategory": technique, "full_json": "{}", "vulnerability_type": vt}]
        global _WORKING_AUTH_TYPE
        auth_types_to_try = [_WORKING_AUTH_TYPE] if _WORKING_AUTH_TYPE else ["Bearer", "Token"]
        for auth_type in auth_types_to_try:
            headers_req = {"Authorization": f"{auth_type} {DATAROBOT_KEY}", "Content-Type": "application/json"}
            try:
                response = requests.post(DATAROBOT_URL, headers=headers_req, json=pd_data, timeout=8)
            except requests.exceptions.RequestException:
                break
            if response.status_code == 200:
                _WORKING_AUTH_TYPE = auth_type
                result = response.json()
                prediction = result['data'][0]
                severity = prediction.get('prediction', 'UNKNOWN')
                confidence = max(p.get('value', 0) for p in prediction.get('predictionValues', []))
                return {
                    "severity": severity,
                    "confidence": confidence,
                    "attack_type": vt,
                    "model": "DataRobot",
                    "fix": get_smart_fix(**fix_params)
                }
            elif response.status_code not in (401, 403):
                break
    
    if LOCAL_MODEL:
        try:
            severity, confidence = predict_local(payload, code, language, technique)
            return {
                "severity": severity,
                "confidence": confidence,
                "attack_type": vt,
                "model": "Local (Backup)",
                "fix": get_smart_fix(**fix_params)
            }
        except:
            return {"error": "Local model error"}
    
    return {"error": "No prediction model available"}

def _read_latest_reports(scanner_dir: str) -> dict:
    reports = {}
    for name in ["sqli", "xss", "misconfig", "sensitive"]:
        path = os.path.join(scanner_dir, f"{name}_report.json")
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    d = json.load(f)
                    scans = d.get("scans", [])
                if scans:
                    reports[name] = scans[-1]
            except Exception:
                pass
    return reports

_scan_in_progress = False

@app.post("/check-url")
def check_url(data: ScannerInput):
    target_url = data.url or ""
    if not target_url:
        return {"status": "invalid", "error": "URL is empty"}
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    try:
        response = requests.get(target_url, timeout=10, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        if response.status_code < 400:
            return {"status": "reachable", "status_code": response.status_code}
        else:
            return {"status": "unreachable", "status_code": response.status_code, "error": f"Server returned {response.status_code}"}
    except requests.exceptions.ConnectionError:
        return {"status": "unreachable", "error": "Connection failed — domain may not exist or is offline"}
    except requests.exceptions.Timeout:
        return {"status": "unreachable", "error": "Connection timed out — site may be slow or blocking requests"}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)}

@app.post("/start-scan")
def start_scan(data: ScannerInput):
    global _scan_in_progress
    target_url = data.url or ""
    if not target_url:
        return {"error": "URL is required"}
    scanner_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scanner")

    if _scan_in_progress:
        return {"status": "already_running", "error": "A scan is already in progress."}

    # SMART TIMEOUT: 5s for local, 15s for remote (configurable via frontend)
    is_local = "localhost" in target_url or "127.0.0.1" in target_url or "0.0.0.0" in target_url
    timeout_ms = getattr(data, 'timeout_ms', 5000.0)
    if not is_local and timeout_ms == 5000.0:
        timeout_ms = 15000.0  # Auto-upgrade to 15s for remote sites

    progress_path = os.path.join(scanner_dir, "scan_progress.json")
    try:
        with open(progress_path, "w") as f:
            json.dump({"phase": "starting"}, f)
    except Exception:
        pass

    try:
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        process = subprocess.Popen(
            [sys.executable, "main.py", target_url, str(timeout_ms)],
            cwd=scanner_dir,
            creationflags=creationflags
        )
    except Exception as e:
        return {"status": "error", "error": str(e)}

    _scan_in_progress = True

    def _watch(proc):
        global _scan_in_progress
        proc.wait()
        _scan_in_progress = False

    threading.Thread(target=_watch, args=(process,), daemon=True).start()

    return {"status": "started"}

@app.get("/scan-results")
def scan_results():
    scanner_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scanner")
    return {"reports": _read_latest_reports(scanner_dir)}

@app.get("/scan-history")
def scan_history():
    d = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scanner")
    all_scans = []
    for f in glob.glob(os.path.join(d, "*_report.json")):
        try:
            with open(f, "r") as fh:
                data = json.load(fh)
            for scan in data.get("scans", []):
                all_scans.append({
                    "filename": os.path.basename(f),
                    "scan_type": os.path.basename(f).replace("_report.json", ""),
                    "scan_url": scan.get("scan_url", ""),
                    "scan_time": scan.get("scan_time", ""),
                    "findings": scan.get("total_findings", 0)
                })
        except:
            pass
    return {"scans": sorted(all_scans, key=lambda x: x["scan_time"], reverse=True)}

@app.get("/scan-report/{filename}")
def scan_report(filename: str):
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scanner", filename)
    if not os.path.exists(path):
        return {"error": "Not found"}
    with open(path, "r") as f:
        return json.load(f)

@app.get("/scan-stats")
def scan_stats():
    d = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scanner")
    ts, tf, tc, cc = 0, 0, 0.0, 0
    for f in glob.glob(os.path.join(d, "*_report.json")):
        try:
            with open(f, "r") as fh:
                data = json.load(fh)
            for scan in data.get("scans", []):
                ts += 1
                for r in scan.get("results", []):
                    tf += 1
                    conf = r.get("ai_confidence") or r.get("confidence", 0)
                    if conf and conf > 0:
                        tc += conf
                        cc += 1
        except:
            pass
    return {"total_scans": ts, "total_findings": tf, "avg_confidence": round((tc / cc) * 100, 1) if cc > 0 else 0}

@app.get("/health")
def health():
    return {"status": "ok", "datarobot": bool(DATAROBOT_KEY), "local_model": LOCAL_MODEL is not None}

@app.get("/scan-progress")
def scan_progress():
    scanner_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scanner")
    path = os.path.join(scanner_dir, "scan_progress.json")
    if not os.path.exists(path):
        return {"phase": "idle"}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {"phase": "idle"}

@app.get("/scan-log")
def scan_log():
    scanner_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scanner")
    log_path = os.path.join(scanner_dir, "scan_activity.log")
    if not os.path.exists(log_path):
        return {"log": ""}
    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.strip().split("\n")
            return {"log": "\n".join(lines[-25:])}
    except Exception:
        return {"log": ""}

@app.get("/datarobot-latency-check")
def datarobot_latency_check():
    if not DATAROBOT_KEY:
        return {"error": "DATAROBOT_API_KEY not set"}
    import time as _time
    pd_data = [{"id": "latency-check", "category": "sql_injection", "owasp_2021": "", "severity": None,
        "cwe": "", "language": "unknown", "epss_score": 0.85, "cve_id": "",
        "real_incident": "", "incident_year": 2024, "vulnerable_code": "SELECT * FROM users",
        "secure_code": "", "attack_payload": "' OR 1=1 --", "conversation_text": "",
        "complexity": "moderate", "technique": "sql_injection", "subcategory": "sql_injection",
        "full_json": "{}", "vulnerability_type": "SQL Injection"}]
    results = []
    for auth_type in ["Bearer", "Token"]:
        headers = {"Authorization": f"{auth_type} {DATAROBOT_KEY}", "Content-Type": "application/json"}
        start = _time.time()
        try:
            response = requests.post(DATAROBOT_URL, headers=headers, json=pd_data, timeout=15)
            elapsed = round(_time.time() - start, 2)
            results.append({"auth_type": auth_type, "status_code": response.status_code, "seconds": elapsed})
        except requests.exceptions.RequestException as e:
            elapsed = round(_time.time() - start, 2)
            results.append({"auth_type": auth_type, "error": f"{type(e).__name__}: {e}", "seconds": elapsed})
    return {"deployment_url": DATAROBOT_URL, "results": results, "learned_working_auth_type": _WORKING_AUTH_TYPE}