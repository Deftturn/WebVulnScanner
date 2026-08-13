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

env_file = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(env_file):
    with open(env_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ[key.strip()] = value.strip()

DATAROBOT_KEY = os.getenv("DATAROBOT_API_KEY")
DEPLOYMENT_ID = os.getenv("DATAROBOT_DEPLOYMENT_ID", "6a582fee4fddbe367c204d21")
DATAROBOT_URL = f"https://app.datarobot.com/api/v2/deployments/{DEPLOYMENT_ID}/predictions"
# Learned on first successful call in analyze_vulnerability() and reused for
# every call after that -- see the comment there for why this matters.
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

def get_smart_fix(vulnerability_type, payload="", check_type="", language=""):
    if FIX_DATASET is None: return "Unable to load fix database."
    type_map = {"SQL Injection": "SQL Injection", "XSS": "XSS", "Security Misconfiguration": "Security Misconfiguration", "Sensitive Information Disclosure": "Sensitive Information Disclosure"}
    lookup = type_map.get(vulnerability_type, vulnerability_type)
    matches = FIX_DATASET[FIX_DATASET['vulnerability_type'] == lookup]
    if len(matches) == 0: return f"No fix available for {vulnerability_type}."
    
    if vulnerability_type == "SQL Injection":
        base_sql_matches = matches[matches['technique'].str.contains('sql', case=False, na=False)]
        if len(base_sql_matches) > 0: matches = base_sql_matches
        if re.search(r'SLEEP|WAITFOR|pg_sleep', payload, re.IGNORECASE): tm = matches[matches['technique'].str.contains('time|blind|sleep', case=False, na=False)]; matches = tm if len(tm) > 0 else matches
        elif re.search(r'UNION\s+SELECT', payload, re.IGNORECASE): um = matches[matches['technique'].str.contains('union', case=False, na=False)]; matches = um if len(um) > 0 else matches
        elif re.search(r'extractvalue|updatexml', payload, re.IGNORECASE): em = matches[matches['technique'].str.contains('error', case=False, na=False)]; matches = em if len(em) > 0 else matches
        elif re.search(r'DROP\s+TABLE', payload, re.IGNORECASE): dm = matches[matches['technique'].str.contains('destructive|drop', case=False, na=False)]; matches = dm if len(dm) > 0 else matches
        mt = str(matches.iloc[0].get('technique', '')).lower()
        if 'command' in mt or 'xss' in mt: matches = base_sql_matches
    
    if vulnerability_type == "XSS":
        if re.search(r'onerror|onload|onfocus|onclick', payload, re.IGNORECASE): em = matches[matches['technique'].str.contains('event|handler|dom|stored', case=False, na=False)]; matches = em if len(em) > 0 else matches
        elif re.search(r'<script', payload, re.IGNORECASE): sm = matches[matches['technique'].str.contains('script|reflected', case=False, na=False)]; matches = sm if len(sm) > 0 else matches
    
    if vulnerability_type == "Security Misconfiguration" and check_type:
        if 'header' in check_type: hm = matches[matches['technique'].str.contains('header|cors|csp|hsts', case=False, na=False)]; matches = hm if len(hm) > 0 else matches
        elif 'path' in check_type or 'exposed' in check_type: pm = matches[matches['technique'].str.contains('path|directory|exposed', case=False, na=False)]; matches = pm if len(pm) > 0 else matches
    
    if vulnerability_type == "Sensitive Information Disclosure" and check_type:
        cc = check_type.replace('exposed_', '').replace('_header', '')
        sm = matches[matches['technique'].str.contains(cc, case=False, na=False)]; matches = sm if len(sm) > 0 else matches
    
    if language and language != "unknown": lm = matches[matches['language'].str.lower() == language.lower()]; matches = lm if len(lm) > 0 else matches
    
    row = matches.iloc[0]; result = []; conversation = str(row.get('conversation_text', ''))
    hm = re.search(r'"content":"(.*?)"', conversation)
    result.append(f"What Was Found\nA {vulnerability_type.lower()} vulnerability was detected. {hm.group(1).strip()[:200]}" if hm else f"What Was Found\nA {vulnerability_type.lower()} vulnerability was detected in the application.")
    incident = row.get('real_incident', '')
    if incident and isinstance(incident, str) and len(str(incident)) > 5: result.append(f"Has This Happened Before?\nYes: {incident}")
    cve = row.get('cve_id', '')
    if cve and isinstance(cve, str) and len(str(cve)) > 3: result.append(f"Security Reference: {cve}")
    danger_text = None
    for p in [r'\*\*Why This Is Dangerous\*\*[:\s]*(.*?)(?:\*\*|\n\n\*\*|\Z)', r'Why This Is Dangerous[:\s]*(.*?)(?:\n\n|\Z)']:
        dm = re.search(p, conversation, re.DOTALL | re.IGNORECASE)
        if dm: danger_text = clean_text(dm.group(1))[:800]; break
    if danger_text and len(danger_text.strip()) > 3: result.append(f"Why This Matters\n{danger_text}")
    controls_text = None
    for p in [r'\*\*Key Security Controls\*\*[:\s]*(.*?)(?:\*\*|\n\n\*\*|\Z)', r'Key Security Controls[:\s]*(.*?)(?:\n\n|\Z)', r'\*\*Secure Implementation\*\*[:\s]*(.*?)(?:\*\*|\n\n\*\*|\Z)', r'\*\*Security Pattern\*\*[:\s]*(.*?)(?:\*\*|\n\n\*\*|\Z)', r'###\s*Tier.*?\n(.*?)(?=###|\Z)']:
        cm = re.search(p, conversation, re.DOTALL | re.IGNORECASE)
        if cm: controls_text = clean_text(cm.group(1))[:800]; break
    if not controls_text:
        lm = re.search(r'((?:\d+\.\s+\*\*[^*]+\*\*[^\n]*\n?){2,})', conversation)
        if lm: controls_text = clean_text(lm.group(1))[:800]
    if not controls_text:
        am = re.search(r'"role":"assistant".*?"content":"(.*?)"', conversation, re.DOTALL)
        if am: controls_text = clean_text(am.group(1))[:600]
    if controls_text and len(controls_text.strip()) > 3: result.append(f"How to Fix This\n{controls_text}")
    secure_code = row.get('secure_code', '')
    if secure_code and isinstance(secure_code, str) and len(str(secure_code)) > 20: result.append(f"Code Example ({row.get('language', '')})\n{str(secure_code)[:1000]}")
    return "\n\n".join(result) if result else "Review and patch."

class ScannerInput(BaseModel):
    payload: str = ""; parameter: str = ""; url: str = ""; vulnerable_code: str = ""
    language: str = ""; response_text: str = ""; status_code: int = 200; attack_type: str = "unknown"

def predict_local(payload, code, language, technique):
    combined = f"{code} {payload} {language} {technique}"
    X = LOCAL_VECTORIZER.transform([combined])
    severity = LOCAL_MODEL.predict(X)[0]
    proba = LOCAL_MODEL.predict_proba(X)[0]
    return severity, float(max(proba))

@app.post("/analyze")
def analyze_vulnerability(data: ScannerInput):
    payload, code, language, attack_type, response_text = data.payload or "", data.vulnerable_code or "", data.language or "", data.attack_type or "unknown", data.response_text or ""
    sql_patterns = [r"' OR \d=\d", r"' OR '[^']*'='[^']*", r"UNION\s+SELECT", r"DROP\s+TABLE", r"SLEEP\s*\(\s*\d", r"WAITFOR\s+DELAY", r"--\s*$", r"/\*.*\*/", r"';", r"admin'\s*--", r"' OR '1'='1"]
    xss_patterns = [r"<script.*?>", r"javascript\s*:", r"onerror\s*=", r"onclick\s*=", r"<img[^>]+onerror", r"<svg[^>]+onload", r"window\.__xss", r"<body[^>]+onload", r"<iframe[^>]+src\s*=\s*['\"]javascript", r"<input[^>]+onfocus", r"<a[^>]+href\s*=\s*['\"]javascript"]
    all_patterns = sql_patterns + xss_patterns
    has_attack = any(re.search(p, payload, re.IGNORECASE) for p in all_patterns)
    has_code = len(code) > 20 and ("SELECT" in code.upper() or "eval" in code.lower() or "exec" in code.lower())
    is_sql = any(re.search(p, payload, re.IGNORECASE) for p in sql_patterns)
    is_xss = any(re.search(p, payload, re.IGNORECASE) for p in xss_patterns) or attack_type == "xss"
    is_misconfig = attack_type == "misconfig" or "debug" in code.lower() or "secret_key" in code.lower() or "directory listing" in response_text.lower() or "hardcoded" in code.lower()
    is_sensitive = attack_type in ["sensitive_info", "sensitive_information_disclosure"] or "ssn" in code.lower() or "email" in code.lower() or "password" in code.lower() or "token" in code.lower()
    skip_prefilter = attack_type in ["misconfig", "sensitive_info", "sensitive_information_disclosure"]
    if not skip_prefilter and not has_attack and not has_code: return {"severity": "LOW", "confidence": 0.99, "note": "No action needed.", "fix": "No action needed."}
    if is_sensitive: vt, technique = "Sensitive Information Disclosure", "sensitive_information_disclosure"
    elif is_misconfig: vt, technique = "Security Misconfiguration", "security_misconfiguration"
    elif is_xss: vt, technique = "XSS", "xss"
    elif is_sql: vt, technique = "SQL Injection", "sql_injection"
    else: vt, technique = "Unknown", "unknown"
    check_type = ""
    if is_misconfig:
        if "debug" in code.lower(): check_type = "debug_mode"
        elif "directory listing" in response_text.lower(): check_type = "exposed_path"
        else: check_type = "missing_headers"
    if is_sensitive:
        for kw in ["email", "ssn", "password", "token", "api_key"]:
            if kw in (code + response_text).lower(): check_type = f"exposed_{kw}"; break
    if DATAROBOT_KEY:
        pd_data = [{"id": "scanner-test-001", "category": technique, "owasp_2021": "", "severity": None, "cwe": "", "language": language or "unknown", "epss_score": 0.85, "cve_id": "", "real_incident": "Scanner detected vulnerability", "incident_year": 2024, "vulnerable_code": code[:2000] if code else payload[:2000], "secure_code": "", "attack_payload": payload[:2000], "conversation_text": f"Payload: {payload}"[:2000], "complexity": "moderate", "technique": technique, "subcategory": technique, "full_json": "{}", "vulnerability_type": vt}]
        global _WORKING_AUTH_TYPE
        # Once we've learned which scheme this deployment accepts, use it
        # directly instead of guessing "Token" first on every single call.
        # This was silently doubling the cost of nearly every AI-confirmed
        # finding: if the deployment only accepts "Bearer" (the DataRobot
        # default), every call was paying for a wasted "Token" attempt --
        # up to its full 10s timeout if that attempt didn't fail fast --
        # before ever reaching the auth type that actually works.
        auth_types_to_try = [_WORKING_AUTH_TYPE] if _WORKING_AUTH_TYPE else ["Bearer", "Token"]
        for auth_type in auth_types_to_try:
            headers = {"Authorization": f"{auth_type} {DATAROBOT_KEY}", "Content-Type": "application/json"}
            try:
                response = requests.post(DATAROBOT_URL, headers=headers, json=pd_data, timeout=8)
            except requests.exceptions.RequestException:
                # Network-level failure (timeout, connection refused, DNS,
                # etc.) is never an auth problem -- retrying with a different
                # header here just pays the same timeout twice for nothing.
                # Go straight to the local model instead.
                break
            if response.status_code == 200:
                _WORKING_AUTH_TYPE = auth_type
                result = response.json(); prediction = result['data'][0]
                severity = prediction.get('prediction', 'UNKNOWN')
                confidence = max(p.get('value', 0) for p in prediction.get('predictionValues', []))
                if is_sensitive:
                    inds = ["ssn", "email", "password", "token", "api key"]
                    mc = sum(1 for kw in inds if kw in (code + response_text).lower())
                    if mc >= 3: confidence = max(confidence, 0.92)
                    elif mc >= 2: confidence = max(confidence, 0.85)
                    elif mc >= 1: confidence = max(confidence, 0.78)
                return {"severity": severity, "confidence": confidence, "attack_type": vt, "model": "DataRobot", "fix": get_smart_fix(vt, payload, check_type, language)}
            elif response.status_code not in (401, 403):
                # Any non-auth error (500, 429, malformed request, etc.) --
                # retrying with the other auth header won't fix it either.
                break
            # else: 401/403 -- genuinely worth trying the other scheme once.
    if LOCAL_MODEL:
        try:
            severity, confidence = predict_local(payload, code, language, technique)
            return {"severity": severity, "confidence": confidence, "attack_type": vt, "model": "Local (Backup)", "fix": get_smart_fix(vt, payload, check_type, language)}
        except: return {"error": "Local model error"}
    return {"error": "No prediction model available"}

def _read_latest_reports(scanner_dir: str) -> dict:
    reports = {}
    for name in ["sqli", "xss", "misconfig", "sensitive"]:
        path = os.path.join(scanner_dir, f"{name}_report.json")
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    d = json.load(f); scans = d.get("scans", [])
                if scans: reports[name] = scans[-1]
            except Exception:
                pass
    return reports


_scan_in_progress = False


@app.post("/start-scan")
def start_scan(data: ScannerInput):
    global _scan_in_progress
    target_url = data.url or ""
    if not target_url: return {"error": "URL is required"}
    scanner_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scanner")

    # Guards against launching a second scan while one is still running --
    # this is what let two /start-scan clicks (or a double-click before
    # React state caught up) run two main.py processes concurrently, both
    # writing the same output files and crashing with a WinError 32
    # PermissionError when one tried to replace a file the other still had
    # open.
    if _scan_in_progress:
        return {"status": "already_running", "error": "A scan is already in progress."}

    # Overwrite any stale progress file immediately and synchronously,
    # before returning. Without this there's a race: this endpoint returns
    # almost instantly, but the actual Python subprocess takes a moment to
    # boot (interpreter + imports + Playwright launch) before IT writes its
    # own first "starting" progress. In that gap the frontend's very first
    # poll could still see a LEFTOVER "complete" file from the previous
    # scan and think the brand-new scan already finished -- exactly the
    # "click scan, instantly see SCAN COMPLETE" symptom.
    progress_path = os.path.join(scanner_dir, "scan_progress.json")
    try:
        with open(progress_path, "w") as f:
            json.dump({"phase": "starting"}, f)
    except Exception:
        pass

    try:
        # CREATE_NEW_PROCESS_GROUP detaches the child from the parent
        # console's Ctrl+C group on Windows. Without this, restarting or
        # interrupting uvicorn (including its own --reload cycling) took
        # the in-flight scan down with it, mid-run, with no trace beyond a
        # raw KeyboardInterrupt/CancelledError in the child's traceback.
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        process = subprocess.Popen([sys.executable, "main.py", target_url], cwd=scanner_dir,
            creationflags=creationflags)
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
    """Call once /scan-progress reports phase == 'complete'. Separated from
    /start-scan so results retrieval never depends on the connection that
    kicked the scan off still being alive."""
    scanner_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scanner")
    return {"reports": _read_latest_reports(scanner_dir)}



@app.get("/scan-history")
def scan_history():
    d = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scanner"); all_scans = []
    for f in glob.glob(os.path.join(d, "*_report.json")):
        try:
            with open(f, "r") as fh: data = json.load(fh)
            for scan in data.get("scans", []): all_scans.append({"filename": os.path.basename(f), "scan_type": os.path.basename(f).replace("_report.json", ""), "scan_url": scan.get("scan_url", ""), "scan_time": scan.get("scan_time", ""), "findings": scan.get("total_findings", 0)})
        except: pass
    return {"scans": sorted(all_scans, key=lambda x: x["scan_time"], reverse=True)}

@app.get("/scan-report/{filename}")
def scan_report(filename: str):
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scanner", filename)
    if not os.path.exists(path): return {"error": "Not found"}
    with open(path, "r") as f: return json.load(f)

@app.get("/scan-stats")
def scan_stats():
    d = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scanner"); ts, tf, tc, cc = 0, 0, 0.0, 0
    for f in glob.glob(os.path.join(d, "*_report.json")):
        try:
            with open(f, "r") as fh: data = json.load(fh)
            for scan in data.get("scans", []):
                ts += 1
                for r in scan.get("results", []): tf += 1; conf = r.get("ai_confidence") or r.get("confidence", 0)
                if conf and conf > 0: tc += conf; cc += 1
        except: pass
    return {"total_scans": ts, "total_findings": tf, "avg_confidence": round((tc / cc) * 100, 1) if cc > 0 else 0}

@app.get("/health")
def health(): return {"status": "ok", "datarobot": bool(DATAROBOT_KEY), "local_model": LOCAL_MODEL is not None}

@app.get("/scan-progress")
def scan_progress():
    """Real progress written incrementally by main.py, for the frontend to
    poll while a scan runs -- replaces App.tsx's old fixed-interval fake
    timer, which advanced on a 10s clock regardless of what the scan was
    actually doing."""
    scanner_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scanner")
    path = os.path.join(scanner_dir, "scan_progress.json")
    if not os.path.exists(path):
        return {"phase": "idle"}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {"phase": "idle"}

@app.get("/datarobot-latency-check")
def datarobot_latency_check():
    """Hit DataRobot directly and report how long it actually takes, so you
    can see the real number instead of inferring it from scan timing."""
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