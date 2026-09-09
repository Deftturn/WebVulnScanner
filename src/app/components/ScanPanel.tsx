// @ts-nocheck

import { useRef, useState } from "react";
import { Search, Globe, AlertTriangle, Shield, Loader2, X, Bug, Info, CheckCircle2, Activity, Terminal, ShieldCheck, FileSearch, ChevronDown, ChevronUp } from "lucide-react";

const API_BASE = "http://127.0.0.1:8000";

interface ScanResult { 
  severity: string; 
  confidence: number; 
  attack_type: string; 
  model?: string; 
  fix?: string;
  supporting_payloads?: Array<{ payload: string; technique: string; confidence: number }>;
}
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

const COLORS = {
  background: "#0d1f2d",
  surface: "#132a3a",
  surfaceDark: "#0a1824",
  border: "#1e3d52",
  textPrimary: "#e8f4f8",
  textSecondary: "#9bb8cc",
  textMuted: "#6b8fa5",
  cyan: "#00b8e6",
  cyanDim: "#0088aa",
  green: "#4ade80",
  greenBright: "#86efac",
  red: "#f87171",
  orange: "#fb923c",
  yellow: "#fbbf24",
  blue: "#60a5fa",
};

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
      <div className="space-y-1">
        {SCAN_STEPS.map((step, i) => {
          const Icon = step.icon;
          const isDone = i < activeIndex;
          const isActive = i === activeIndex;
          return (
            <div key={i} className="flex items-center gap-2" style={{ opacity: isActive || isDone ? 1 : 0.5 }}>
              {isDone ? (
                <CheckCircle2 size={13} style={{ color: COLORS.green, flexShrink: 0 }} />
              ) : isActive ? (
                <Loader2 size={13} className="animate-spin" style={{ color: COLORS.cyan, flexShrink: 0 }} />
              ) : (
                <Icon size={13} style={{ color: COLORS.textMuted, flexShrink: 0 }} />
              )}
              <div style={{ 
                color: isDone ? COLORS.green : isActive ? COLORS.cyan : COLORS.textSecondary, 
                fontSize: "11px", 
                fontWeight: isActive ? 600 : 400 
              }}>
                {step.label}
              </div>
            </div>
          );
        })}
      </div>

      {scanLog && (
        <div style={{ 
          maxHeight: "120px", 
          overflowY: "auto",
          background: COLORS.surfaceDark,
          borderRadius: "6px",
          padding: "10px",
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: "10px",
          color: COLORS.textSecondary,
          border: `1px solid ${COLORS.border}`,
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
          lineHeight: "1.6"
        }}>
          {scanLog}
        </div>
      )}

      {ratio !== null && (
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
            <span style={{ color: COLORS.textSecondary, fontSize: "10px" }}>Overall Progress</span>
            <span style={{ color: COLORS.cyan, fontSize: "10px", fontWeight: 600 }}>{pct}%</span>
          </div>
          <div style={{ height: "5px", borderRadius: "3px", background: "rgba(0,184,230,0.15)", overflow: "hidden" }}>
            <div style={{
              width: `${pct}%`, height: "100%",
              background: `linear-gradient(90deg, ${COLORS.cyan}, #0066cc)`,
              transition: "width 0.5s ease",
              borderRadius: "3px",
            }} />
          </div>
        </div>
      )}

      {findings > 0 && (
        <div style={{ 
          display: "flex", alignItems: "center", gap: "8px",
          color: COLORS.orange, fontSize: "11px",
          background: "rgba(251,146,60,0.08)", 
          padding: "8px 10px",
          borderRadius: "6px", 
          border: "1px solid rgba(251,146,60,0.25)"
        }}>
          <AlertTriangle size={12} style={{ flexShrink: 0 }} />
          <span>{findings} vulnerabilities found so far</span>
        </div>
      )}
    </div>
  );
}

// Component for displaying supporting payloads
function SupportingPayloads({ payloads }: { payloads?: Array<{ payload: string; technique: string; confidence: number }> }) {
  const [expanded, setExpanded] = useState(false);
  
  // Show "no additional payloads" message when empty
  if (!payloads || payloads.length === 0) {
    return (
      <div style={{ 
        marginTop: "8px", 
        borderTop: `1px solid ${COLORS.border}`, 
        paddingTop: "8px",
        display: "flex", alignItems: "center", gap: "6px",
        color: COLORS.textMuted, fontSize: "9px",
        fontFamily: "'JetBrains Mono', monospace"
      }}>
        <CheckCircle2 size={10} style={{ color: COLORS.green, flexShrink: 0 }} />
        <span>Confirmed by primary payload only — no additional payloads tested positive</span>
      </div>
    );
  }
  
  return (
    <div style={{ marginTop: "8px", borderTop: `1px solid ${COLORS.border}`, paddingTop: "8px" }}>
      <button 
        onClick={() => setExpanded(!expanded)}
        style={{
          display: "flex", alignItems: "center", gap: "6px",
          background: "none", border: "none", cursor: "pointer",
          color: COLORS.cyan, fontSize: "10px", padding: "0",
          fontFamily: "'JetBrains Mono', monospace"
        }}
      >
        {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        {expanded ? "Hide" : "Show"} {payloads.length} additional confirming payload(s)
      </button>
      
      {expanded && (
        <div style={{ marginTop: "6px", paddingLeft: "8px" }}>
          {payloads.map((p, i) => (
            <div key={i} style={{ 
              display: "flex", alignItems: "center", gap: "8px",
              fontSize: "9px", color: COLORS.textSecondary,
              padding: "3px 0",
              fontFamily: "'JetBrains Mono', monospace"
            }}>
              <CheckCircle2 size={10} style={{ color: COLORS.green, flexShrink: 0 }} />
              <span style={{ color: COLORS.textPrimary }}>{p.payload}</span>
              <span style={{ color: COLORS.textMuted }}>({p.technique})</span>
              <span style={{ color: COLORS.greenBright }}>{(p.confidence * 100).toFixed(1)}%</span>
            </div>
          ))}
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
    switch (s) { 
      case "CRITICAL": return COLORS.red; 
      case "HIGH": return COLORS.orange; 
      case "MEDIUM": return COLORS.yellow; 
      case "LOW": return COLORS.green; 
      default: return COLORS.textSecondary; 
    }
  };

  return (
    <div className="rounded-lg p-5" style={{ 
      background: COLORS.background, 
      border: `1px solid ${COLORS.border}`, 
      fontFamily: "'Rajdhani', sans-serif" 
    }}>
      <div className="flex items-center gap-2 mb-4">
        <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" style={{ boxShadow: `0 0 8px ${COLORS.cyan}` }} />
        <span style={{ color: COLORS.cyan, fontSize: "13px", fontWeight: 600, letterSpacing: "0.12em" }}>LIVE SCAN PANEL</span>
      </div>

      <div className="flex gap-3 mb-4">
        <div className="flex-1 flex items-center gap-2 px-3 py-2.5 rounded" style={{ 
          background: COLORS.surfaceDark, 
          border: `1px solid ${COLORS.border}` 
        }}>
          <Globe size={14} style={{ color: COLORS.textSecondary }} />
          <input 
            value={scanUrl} 
            onChange={(e) => setScanUrl(e.target.value)} 
            placeholder="Enter target URL..." 
            className="flex-1 bg-transparent outline-none"
            style={{ color: COLORS.textPrimary, fontSize: "13px", fontFamily: "'JetBrains Mono', monospace" }}
            disabled={scanning} 
          />
        </div>
        {!scanning ? (
          <button onClick={startScan} className="flex items-center gap-2 px-5 py-2.5 rounded font-semibold"
            style={{ 
              background: `linear-gradient(135deg, ${COLORS.cyan} 0%, #0066cc 100%)`, 
              color: "#ffffff", 
              border: `1px solid rgba(0,184,230,0.5)`, 
              fontSize: "13px", 
              cursor: "pointer",
              fontWeight: 700
            }}>
            <Search size={14} /> SCAN
          </button>
        ) : (
          <button onClick={onCancelScan} className="flex items-center gap-2 px-5 py-2.5 rounded font-semibold"
            style={{ 
              background: "rgba(248,113,113,0.15)", 
              color: COLORS.red, 
              border: "1px solid rgba(248,113,113,0.4)", 
              fontSize: "13px", 
              cursor: "pointer" 
            }}>
            <X size={14} /> CANCEL
          </button>
        )}
      </div>

      <div className="rounded p-4 min-h-[200px] max-h-[600px] overflow-y-auto" style={{ 
        background: COLORS.surfaceDark, 
        border: `1px solid ${COLORS.border}`, 
        fontFamily: "'JetBrains Mono', monospace" 
      }}>

        {scanning && <ProgressDisplay scanProgress={scanProgress} scanLog={scanLog} />}

        {!scanning && scanResults.length > 0 && (
          <div className="flex items-center gap-2 mb-3" style={{ 
            background: "rgba(74,222,128,0.08)", 
            border: "1px solid rgba(74,222,128,0.25)",
            borderRadius: "6px",
            padding: "10px 14px"
          }}>
            <CheckCircle2 size={16} style={{ color: COLORS.green, flexShrink: 0 }} />
            <div>
              <span style={{ color: COLORS.greenBright, fontSize: "12px", fontWeight: 600 }}>SCAN COMPLETE</span>
              <span style={{ color: COLORS.textSecondary, fontSize: "11px", marginLeft: "8px" }}>
                {scanResults.length} unique vulnerabilities found
              </span>
            </div>
          </div>
        )}

        {!scanning && scanResults.length === 0 && !scanError && (
          <div className="py-4" style={{ color: COLORS.textSecondary, fontSize: "12px" }}>
            <span style={{ color: COLORS.cyan }}>$</span> Ready. Enter a URL and click SCAN.
          </div>
        )}

        {scanError && (
          <div className="flex items-center gap-2 p-3 rounded" style={{ 
            background: "rgba(248,113,113,0.08)", 
            border: "1px solid rgba(248,113,113,0.25)" 
          }}>
            <AlertTriangle size={14} style={{ color: COLORS.red }} />
            <span style={{ color: COLORS.red, fontSize: "12px" }}>{scanError}</span>
          </div>
        )}

        {!scanning && scanResults.map((r: any, i) => (
          <div key={i} className="mt-3 p-3 rounded" style={{ 
            background: r.severity === "CRITICAL" ? "rgba(248,113,113,0.08)" : "rgba(0,184,230,0.06)", 
            border: `1px solid ${severityColor(r.severity)}40` 
          }}>
            <div className="flex items-center gap-2 mb-2">
              {r.severity === "CRITICAL" || r.severity === "HIGH" ? 
                <AlertTriangle size={13} style={{ color: severityColor(r.severity) }} /> : 
                <Shield size={13} style={{ color: severityColor(r.severity) }} />}
              <span style={{ color: severityColor(r.severity), fontSize: "12px", fontWeight: 700 }}>
                {r.severity} — {r.attack_type}
              </span>
            </div>
            <div className="grid grid-cols-2 gap-y-1">
              <span style={{ color: COLORS.textSecondary, fontSize: "11px" }}>Confidence:</span>
              <span style={{ color: COLORS.greenBright, fontSize: "11px" }}>{(r.confidence * 100).toFixed(1)}%</span>
              <span style={{ color: COLORS.textSecondary, fontSize: "11px" }}>Model:</span>
              <span style={{ color: COLORS.textPrimary, fontSize: "11px" }}>{r.model || "DataRobot"}</span>
            </div>
            
            {/* ALWAYS show supporting payloads (or "no additional" message) */}
            <SupportingPayloads payloads={r.supporting_payloads} />
            
            {r.fix && (
              <div style={{ 
                marginTop: "10px", 
                paddingTop: "10px", 
                borderTop: `1px solid ${COLORS.border}`, 
                whiteSpace: "pre-line", 
                color: COLORS.textPrimary,
                fontSize: "10px", 
                lineHeight: "1.7",
                fontFamily: "'JetBrains Mono', monospace"
              }}>
                {r.fix}
              </div>
            )}
          </div>
        ))}

        <div style={{ 
          display: "flex", 
          alignItems: "center", 
          gap: "6px",
          color: COLORS.textMuted, 
          fontSize: "10px", 
          textAlign: "center",
          marginTop: "14px", 
          paddingTop: "10px",
          borderTop: `1px solid ${COLORS.border}`,
          fontFamily: "'Rajdhani', sans-serif", 
          fontStyle: "italic"
        }}>
          <Info size={10} style={{ flexShrink: 0 }} />
          <span>AI-powered detection — results may contain false positives or miss vulnerabilities. Always verify findings manually.</span>
        </div>
      </div>
    </div>
  );
}