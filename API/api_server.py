from fastapi import FastAPI
from pydantic import BaseModel
import requests
import os
import re
from dotenv import load_dotenv

# Load from .env file ONLY (never commit .env to GitHub)
load_dotenv()

DATAROBOT_KEY = os.getenv("DATAROBOT_API_KEY")
DEPLOYMENT_ID = os.getenv("DATAROBOT_DEPLOYMENT_ID", "69f5f4d083d091ceb74a02a4")
DATAROBOT_URL = f"https://app.datarobot.com/api/v2/deployments/{DEPLOYMENT_ID}/predictions"

if not DATAROBOT_KEY:
    raise RuntimeError("DATAROBOT_API_KEY not set. Create .env file in the API folder.")

app = FastAPI(title="Vuln Severity API", version="1.0")

class ScannerInput(BaseModel):
    payload: str
    parameter: str = ""
    url: str = ""
    vulnerable_code: str = ""
    language: str = ""
    response_text: str = ""
    status_code: int = 200 

@app.post("/analyze")
def analyze_vulnerability(data: ScannerInput):
    payload = data.payload or ""
    code = data.vulnerable_code or ""
    language = data.language or ""
    
    sql_patterns = [
        r"' OR \d=\d",
        r"' OR '[^']*'='[^']*",
        r"UNION\s+SELECT",
        r"DROP\s+TABLE",
        r"SLEEP\s*\(\s*\d",
        r"WAITFOR\s+DELAY",
        r"--\s*$",
        r"/\*.*\*/",
        r"';",
        r"admin'\s*--",
        r"' OR '1'='1",
    ]
    
    xss_patterns = [
        r"<script.*?>",
        r"javascript\s*:",
        r"onerror\s*=",
        r"onclick\s*=",
        r"<img[^>]+onerror",
        r"<svg[^>]+onload",
    ]
    
    all_patterns = sql_patterns + xss_patterns
    has_attack = any(re.search(pattern, payload, re.IGNORECASE) for pattern in all_patterns)
    has_code = len(code) > 20 and ("SELECT" in code.upper() or "eval" in code.lower() or "exec" in code.lower())
    
    if not has_attack and not has_code:
        return {
            "severity": "LOW",
            "confidence": 0.99,
            "note": "No attack indicators detected"
        }
    
    prediction_data = [{
        "id": "scanner-test-001",
        "category": "injection" if has_attack else "unknown",
        "owasp_2021": "A03:2021-Injection" if has_attack else "",
        "severity": None,
        "cwe": "CWE-89" if has_attack else "",
        "language": language or "unknown",
        "complexity": "moderate" if has_attack else "low",
        "technique": "sql_injection" if has_attack else "unknown",
        "real_incident": "",
        "cve_id": "",
        "vulnerable_code": code[:2000] if code else payload[:2000],
        "attack_payload": payload[:2000],
        "conversation_text": f"Payload: {payload}\nCode: {code}"[:2000]
    }]
    
    for auth_type in ["Token", "Bearer"]:
        headers = {
            "Authorization": f"{auth_type} {DATAROBOT_KEY}",
            "Content-Type": "application/json"
        }
        
        response = requests.post(DATAROBOT_URL, headers=headers, json=prediction_data)
        
        if response.status_code == 200:
            result = response.json()
            prediction = result['data'][0]
            return {
                "severity": prediction.get('prediction', 'UNKNOWN'),
                "confidence": max(p.get('value', 0) for p in prediction.get('predictionValues', []))
            }
    
    return {"error": f"API error: {response.status_code}", "detail": response.text[:200]}

@app.get("/health")
def health():
    return {"status": "ok"}