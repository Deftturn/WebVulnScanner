// @ts-nocheck

import { useRef } from "react";
import { Search, Globe, AlertTriangle, Shield, Loader2, X, Bug } from "lucide-react";

const API_BASE = "http://127.0.0.1:8000";

interface ScanResult { severity: string; confidence: number; attack_type: string; model?: string; fix?: string; }
interface ScanPanelProps {
  scanResults: ScanResult[]; scanning: boolean; scanError: string;
  scanProgress: any;
  scanUrl: string; setScanUrl: (v: string) => void;
  onScanStart: (v: boolean) => void; onScanComplete: (r: ScanResult[]) => void; onScanError: (e: string) => void;
  onCancelScan: () => void;
}

function ProgressDisplay({ scanProgress }: { scanProgress: any }) {
  const phase = scanProgress?.phase ?? "idle";
  const totalPages = scanProgress.total_pages ?? 0;
  const done = scanProgress.current_page ?? 0;
  const findings = scanProgress.findings_so_far ?? 0;
  const pageCount = totalPages > 0 ? totalPages : (scanProgress.pages_found ?? 0);
  const ratio = totalPages > 0 && done > 0 ? Math.min(1, done / totalPages) : null;
  const pct = ratio !== null ? Math.round(ratio * 100) : 0;

  return (
    <div className="space-y-2">
      {/* Header */}
      <div className="flex items-center gap-2 pb-2" style={{ borderBottom: "1px solid rgba(0,212,255,0.1)" }}>
        <Loader2 size={14} className="animate-spin" style={{ color: "#00d4ff" }} />
        <span style={{ color: "#00d4ff", fontSize: "12px", fontWeight: 600 }}>
          {phase === "starting" && "Initializing..."}
          {phase === "crawling" && `Crawling — ${pageCount} pages found`}
          {phase === "testing" && `Testing page ${done}/${totalPages}`}
          {phase === "complete" && "Complete"}
        </span>
        {ratio !== null && (
          <span style={{ color: "#5a8aaa", fontSize: "10px", marginLeft: "auto" }}>{pct}%</span>
        )}
      </div>

      {/* Progress bar */}
      {ratio !== null && (
        <div style={{ height: "4px", borderRadius: "2px", background: "rgba(0,212,255,0.1)", overflow: "hidden" }}>
          <div style={{
            width: `${pct}%`, height: "100%",
            background: "linear-gradient(90deg, #00d4ff, #0088cc)",
            transition: "width 0.5s ease",
            borderRadius: "2px",
          }} />
        </div>
      )}

      {/* Details */}
      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "10px" }}>
        {phase === "starting" && (
          <div style={{ color: "#5a8aaa" }}>
            <div>• Launching browser engine</div>
            <div>• Initializing test modules</div>
          </div>
        )}
        
        {(phase === "crawling" || phase === "testing" || phase === "complete") && pageCount > 0 && (
          <div style={{ color: "#5a8aaa" }}>
            <div>• {pageCount} pages discovered</div>
            <div>• Forms and parameters extracted</div>
          </div>
        )}

        {(phase === "testing" || phase === "complete") && (
          <div style={{ color: "#5a8aaa" }}>
            {scanProgress.current_url && (
              <div style={{ color: "#3a5a72", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                • Current: {scanProgress.current_url}
              </div>
            )}
            <div>• Testing: SQL Injection (20 variants)</div>
            <div>• Testing: Cross-Site Scripting (9 variants)</div>
            <div>• Testing: Security Misconfiguration</div>
            <div>• Testing: Sensitive Data Exposure</div>
          </div>
        )}

        {findings > 0 && (
          <div style={{ color: "#ff8800", marginTop: "2px" }}>
            ▶ {findings} vulnerabilit{findings === 1 ? 'y' : 'ies'} found so far
          </div>
        )}
      </div>
    </div>
  );
}

export function ScanPanel({ scanResults, scanning, scanError, scanProgress, scanUrl, setScanUrl, onScanStart, onScanComplete, onScanError, onCancelScan }: ScanPanelProps) {
  const submittingRef = useRef(false);

  const startScan = async () => {
    if (scanning || !scanUrl || submittingRef.current) return;
    submittingRef.current = true;
    onScanStart(true);

    try {
      const scanRes = await fetch(`${API_BASE}/start-scan`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: scanUrl, payload: "", language: "python" }),
      });
      if (!scanRes.ok) onScanError("Failed to start scan.");
    } catch {
      onScanError("Failed to connect.");
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

        {scanning && <ProgressDisplay scanProgress={scanProgress} />}

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
      </div>
    </div>
  );
}