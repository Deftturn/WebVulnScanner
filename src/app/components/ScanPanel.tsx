// @ts-nocheck

import { useRef } from "react";
import { Search, Globe, AlertTriangle, Shield, Loader2, X, Bug, Info, CheckCircle2, Activity, Terminal, ShieldCheck, FileSearch } from "lucide-react";

const API_BASE = "http://127.0.0.1:8000";

interface ScanResult { severity: string; confidence: number; attack_type: string; model?: string; fix?: string; }
interface ScanPanelProps {
  scanResults: ScanResult[]; scanning: boolean; scanError: string;
  scanProgress: any;
  scanLog: string;
  scanUrl: string; setScanUrl: (v: string) => void;
  onScanStart: (v: boolean) => void; onScanComplete: (r: ScanResult[]) => void; onScanError: (e: string) => void;
  onCancelScan: () => void;
}

const SCAN_STEPS = [
  { icon: Globe, label: "Crawling website..." },
  { icon: Bug, label: "Testing SQL Injection..." },
  { icon: Terminal, label: "Testing XSS..." },
  { icon: ShieldCheck, label: "Checking Security Config..." },
  { icon: FileSearch, label: "Scanning for Data Exposure..." },
  { icon: Activity, label: "Analyzing Results..." },
];

function ProgressDisplay({ scanProgress, scanLog }: { scanProgress: any; scanLog: string }) {
  const phase = scanProgress?.phase ?? "idle";
  const totalPages = scanProgress.total_pages ?? 0;
  const done = scanProgress.current_page ?? 0;
  const findings = scanProgress.findings_so_far ?? 0;
  const pageCount = totalPages > 0 ? totalPages : (scanProgress.pages_found ?? 0);
  const currentTest = scanProgress.current_test ?? "";

  let pct = 0;
  let ratio: number | null = null;
  
  if (phase === "crawling" && totalPages > 0) {
    pct = Math.round((pageCount / Math.max(1, pageCount + 2)) * 10);
    ratio = pct / 100;
  } else if (phase === "testing" && totalPages > 0) {
    const testMap: Record<string, number> = { sqli: 1, xss: 2, misconfig: 3, sensitive: 4 };
    const testIndex = testMap[currentTest] ?? 1;
    const stepBase = testIndex * 18;
    const pageProgress = (done / totalPages) * 18;
    pct = Math.min(90, Math.round(stepBase + pageProgress));
    ratio = pct / 100;
  } else if (phase === "complete") {
    pct = 100;
    ratio = 1;
  }

  let activeIndex = -1;
  if (phase === "crawling") activeIndex = 0;
  else if (phase === "testing") {
    const testMap: Record<string, number> = { sqli: 1, xss: 2, misconfig: 3, sensitive: 4 };
    activeIndex = testMap[currentTest] ?? 1;
  } else if (phase === "complete") activeIndex = 5;

  return (
    <div className="space-y-3">
      {/* Steps */}
      <div className="space-y-1">
        {SCAN_STEPS.map((step, i) => {
          const Icon = step.icon;
          const isDone = i < activeIndex;
          const isActive = i === activeIndex;
          return (
            <div key={i} className="flex items-center gap-2" style={{ opacity: isActive || isDone ? 1 : 0.3 }}>
              {isDone ? (
                <CheckCircle2 size={13} style={{ color: "#22c55e", flexShrink: 0 }} />
              ) : isActive ? (
                <Loader2 size={13} className="animate-spin" style={{ color: "#00d4ff", flexShrink: 0 }} />
              ) : (
                <Icon size={13} style={{ color: "#3a5a72", flexShrink: 0 }} />
              )}
              <div style={{ 
                color: isDone ? "#22c55e" : isActive ? "#00d4ff" : "#5a8aaa", 
                fontSize: "10px", 
                fontWeight: isActive ? 600 : 400 
              }}>
                {step.label}
              </div>
            </div>
          );
        })}
      </div>

      {/* Live log */}
      {scanLog && (
        <div style={{ 
          maxHeight: "120px", 
          overflowY: "auto",
          background: "rgba(0,0,0,0.4)",
          borderRadius: "4px",
          padding: "8px",
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: "9px",
          color: "#5a8aaa",
          border: "1px solid rgba(0,212,255,0.08)",
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
          lineHeight: "1.6"
        }}>
          {scanLog}
        </div>
      )}

      {/* Progress bar */}
      {ratio !== null && (
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
            <span style={{ color: "#5a8aaa", fontSize: "9px" }}>Overall Progress</span>
            <span style={{ color: "#00d4ff", fontSize: "9px", fontWeight: 600 }}>{pct}%</span>
          </div>
          <div style={{ height: "4px", borderRadius: "2px", background: "rgba(0,212,255,0.1)", overflow: "hidden" }}>
            <div style={{
              width: `${pct}%`, height: "100%",
              background: "linear-gradient(90deg, #00d4ff, #0088cc)",
              transition: "width 0.5s ease",
              borderRadius: "2px",
            }} />
          </div>
        </div>
      )}

      {/* Findings alert */}
      {findings > 0 && (
        <div style={{ 
          display: "flex", alignItems: "center", gap: "6px",
          color: "#ff8800", fontSize: "10px",
          background: "rgba(255,136,0,0.06)", padding: "6px 8px",
          borderRadius: "4px", border: "1px solid rgba(255,136,0,0.2)"
        }}>
          <AlertTriangle size={10} style={{ flexShrink: 0 }} />
          <span>{findings} vulnerabilities found so far</span>
        </div>
      )}
    </div>
  );
}

export function ScanPanel({ scanResults, scanning, scanError, scanProgress, scanLog, scanUrl, setScanUrl, onScanStart, onScanComplete, onScanError, onCancelScan }: ScanPanelProps) {
  const submittingRef = useRef(false);

  const startScan = async () => {
    if (scanning || !scanUrl || submittingRef.current) return;
    
    let urlToScan = scanUrl.trim();
    
    if (!urlToScan) {
      onScanError("Please enter a URL to scan.");
      return;
    }
    
    if (!urlToScan.startsWith("http://") && !urlToScan.startsWith("https://")) {
      urlToScan = "http://" + urlToScan;
      setScanUrl(urlToScan);
    }
    
    try {
      const parsed = new URL(urlToScan);
      if (!parsed.hostname.includes(".")) {
        onScanError("Invalid URL. Please enter a valid domain (e.g., example.com).");
        return;
      }
    } catch {
      onScanError("Invalid URL format. Please enter a valid URL.");
      return;
    }
    
    submittingRef.current = true;
    onScanStart(true);

    try {
      const checkRes = await fetch(`${API_BASE}/check-url`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: urlToScan }),
      });
      
      const checkData = await checkRes.json();
      
      if (checkData.status === "unreachable") {
        onScanError(checkData.error || `Cannot reach ${urlToScan}. Please check the URL and try again.`);
        onScanStart(false);
        submittingRef.current = false;
        return;
      }
      
      const scanRes = await fetch(`${API_BASE}/start-scan`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: urlToScan, payload: "", language: "python" }),
      });
      
      if (!scanRes.ok) onScanError("Failed to start scan.");
    } catch {
      onScanError("Failed to connect.");
      onScanStart(false);
    } finally {
      submittingRef.current = false;
    }
  };

  const severityColor = (s: string) => {
    switch (s) { case "CRITICAL": return "#ff2244"; case "HIGH": return "#ff8800"; case "MEDIUM": return "#ffcc00"; case "LOW": return "#22c55e"; default: return "#5a8aaa"; }
  };

  const formatAttackType = (key: string, checkType: string, attackType: string): string => {
    if (attackType && attackType !== "unknown") return attackType;
    if (checkType === "missing_headers") return "Missing Security Headers";
    if (checkType === "exposed_path") return "Exposed Sensitive Path";
    if (checkType === "debug_mode") return "Debug Mode Enabled";
    if (checkType?.startsWith("exposed_")) return checkType.replace("exposed_", "Exposed ").replace(/_/g, " ");
    return key.replace("_report", "").replace(/_/g, " ");
  };

  return (
    <div className="rounded-lg p-5" style={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.15)", fontFamily: "'Rajdhani', sans-serif" }}>
      <div className="flex items-center gap-2 mb-4">
        <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" style={{ boxShadow: "0 0 8px #00d4ff" }} />
        <span style={{ color: "#00d4ff", fontSize: "13px", fontWeight: 600, letterSpacing: "0.12em" }}>LIVE SCAN PANEL</span>
      </div>

      <div className="flex gap-3 mb-4">
        <div className="flex-1 flex items-center gap-2 px-3 py-2.5 rounded" style={{ background: "#050b12", border: "1px solid rgba(0,212,255,0.2)" }}>
          <Globe size={14} style={{ color: "#5a8aaa" }} />
          <input value={scanUrl} onChange={(e) => setScanUrl(e.target.value)} placeholder="Enter target URL..." className="flex-1 bg-transparent outline-none"
            style={{ color: "#e2f0ff", fontSize: "13px", fontFamily: "'JetBrains Mono', monospace" }}
            disabled={scanning} />
        </div>
        {!scanning ? (
          <button onClick={startScan} className="flex items-center gap-2 px-5 py-2.5 rounded font-semibold"
            style={{ background: "linear-gradient(135deg, #00d4ff 0%, #0088cc 100%)", color: "#050b12", border: "1px solid rgba(0,212,255,0.4)", fontSize: "13px", cursor: "pointer" }}>
            <Search size={14} /> SCAN
          </button>
        ) : (
          <button onClick={onCancelScan} className="flex items-center gap-2 px-5 py-2.5 rounded font-semibold"
            style={{ background: "rgba(255,34,68,0.15)", color: "#ff2244", border: "1px solid rgba(255,34,68,0.4)", fontSize: "13px", cursor: "pointer" }}>
            <X size={14} /> CANCEL
          </button>
        )}
      </div>

      <div className="rounded p-4 min-h-[200px] max-h-[500px] overflow-y-auto" style={{ background: "#030810", border: "1px solid rgba(0,212,255,0.1)", fontFamily: "'JetBrains Mono', monospace" }}>

        {scanning && <ProgressDisplay scanProgress={scanProgress} scanLog={scanLog} />}

        {/* SCAN COMPLETE banner */}
        {!scanning && scanResults.length > 0 && (
          <div className="flex items-center gap-2 mb-3" style={{ 
            background: "rgba(34,197,94,0.06)", 
            border: "1px solid rgba(34,197,94,0.2)",
            borderRadius: "4px",
            padding: "8px 12px"
          }}>
            <CheckCircle2 size={16} style={{ color: "#22c55e", flexShrink: 0 }} />
            <div>
              <span style={{ color: "#22c55e", fontSize: "12px", fontWeight: 600 }}>SCAN COMPLETE</span>
              <span style={{ color: "#5a8aaa", fontSize: "10px", marginLeft: "8px" }}>
                {scanResults.length} vulnerabilities found
              </span>
            </div>
          </div>
        )}

        {!scanning && scanResults.length === 0 && !scanError && (
          <div className="py-4" style={{ color: "#5a8aaa", fontSize: "12px" }}>
            <span style={{ color: "#00d4ff" }}>$</span> Ready. Enter a URL and click SCAN.
          </div>
        )}

        {scanError && (
          <div className="flex items-center gap-2 p-3 rounded" style={{ background: "rgba(255,34,68,0.06)", border: "1px solid rgba(255,34,68,0.2)" }}>
            <AlertTriangle size={14} style={{ color: "#ff2244" }} />
            <span style={{ color: "#ff2244", fontSize: "12px" }}>{scanError}</span>
          </div>
        )}

        {!scanning && scanResults.map((r, i) => (
          <div key={i} className="mt-3 p-3 rounded" style={{ background: r.severity === "CRITICAL" ? "rgba(255,34,68,0.06)" : "rgba(0,212,255,0.04)", border: `1px solid ${severityColor(r.severity)}33` }}>
            <div className="flex items-center gap-2 mb-2">
              {r.severity === "CRITICAL" || r.severity === "HIGH" ? <AlertTriangle size={13} style={{ color: severityColor(r.severity) }} /> : <Shield size={13} style={{ color: severityColor(r.severity) }} />}
              <span style={{ color: severityColor(r.severity), fontSize: "11px", fontWeight: 700 }}>{r.severity} — {r.attack_type}</span>
            </div>
            <div className="grid grid-cols-2 gap-y-1">
              <span style={{ color: "#5a8aaa", fontSize: "11px" }}>Confidence:</span>
              <span style={{ color: "#22c55e", fontSize: "11px" }}>{(r.confidence * 100).toFixed(1)}%</span>
              <span style={{ color: "#5a8aaa", fontSize: "11px" }}>Model:</span>
              <span style={{ color: "#8aadcc", fontSize: "11px" }}>{r.model || "DataRobot"}</span>
            </div>
            {r.fix && (
              <div style={{ marginTop: "8px", paddingTop: "8px", borderTop: "1px solid rgba(255,255,255,0.08)", whiteSpace: "pre-line", color: "#22c55e", fontSize: "10px", lineHeight: "1.6" }}>{r.fix}</div>
            )}
          </div>
        ))}

        {/* AI Disclaimer */}
        <div style={{ 
          display: "flex", alignItems: "center", gap: "6px",
          color: "#3a5a72", fontSize: "9px", textAlign: "center",
          marginTop: "12px", paddingTop: "8px",
          borderTop: "1px solid rgba(0,212,255,0.06)",
          fontFamily: "'Rajdhani', sans-serif", fontStyle: "italic"
        }}>
          <Info size={10} style={{ flexShrink: 0 }} />
          <span>AI-powered detection — results may contain false positives or miss vulnerabilities. Always verify findings manually.</span>
        </div>
      </div>
    </div>
  );
}