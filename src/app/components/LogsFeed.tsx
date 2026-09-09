// @ts-nocheck

import { useState, useEffect } from "react";
import { Clock, Download, Eye, X, ChevronDown, ChevronUp, CheckCircle2, AlertTriangle } from "lucide-react";

const API_BASE = "http://127.0.0.1:8000";

interface ScanRecord {
  filename: string;
  scan_type: string;
  scan_url: string;
  scan_time: string;
  findings: number;
}

const COLORS = {
  background: "#0d1f2d",
  surface: "#132a3a",
  surfaceDark: "#0a1824",
  border: "#1e3d52",
  textPrimary: "#e8f4f8",
  textSecondary: "#9bb8cc",
  textMuted: "#6b8fa5",
  cyan: "#00b8e6",
  green: "#4ade80",
  greenBright: "#86efac",
  red: "#f87171",
  orange: "#fb923c",
  yellow: "#fbbf24",
  blue: "#60a5fa",
};

// Supporting payloads collapsible component
function SupportingPayloads({ payloads }: { payloads?: Array<{ payload: string; technique: string; confidence: number }> }) {
  const [expanded, setExpanded] = useState(false);

  if (!payloads || payloads.length === 0) {
    return (
      <div style={{
        marginTop: "6px", paddingTop: "6px",
        borderTop: `1px solid ${COLORS.border}`,
        display: "flex", alignItems: "center", gap: "6px",
        color: COLORS.textMuted, fontSize: "9px",
        fontFamily: "'JetBrains Mono', monospace"
      }}>
        <CheckCircle2 size={10} style={{ color: COLORS.green, flexShrink: 0 }} />
        <span>Confirmed by primary payload only</span>
      </div>
    );
  }

  return (
    <div style={{ marginTop: "6px", paddingTop: "6px", borderTop: `1px solid ${COLORS.border}` }}>
      <button
        onClick={() => setExpanded(!expanded)}
        style={{
          display: "flex", alignItems: "center", gap: "6px",
          background: "none", border: "none", cursor: "pointer",
          color: COLORS.cyan, fontSize: "9px", padding: "0",
          fontFamily: "'JetBrains Mono', monospace"
        }}
      >
        {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        {expanded ? "Hide" : "Show"} {payloads.length} additional confirming payload(s)
      </button>

      {expanded && (
        <div style={{ marginTop: "4px", paddingLeft: "8px" }}>
          {payloads.map((p, i) => (
            <div key={i} style={{
              display: "flex", alignItems: "center", gap: "8px",
              fontSize: "8px", color: COLORS.textSecondary,
              padding: "2px 0",
              fontFamily: "'JetBrains Mono', monospace"
            }}>
              <CheckCircle2 size={9} style={{ color: COLORS.green, flexShrink: 0 }} />
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

export function ScanHistory() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [selectedReport, setSelectedReport] = useState<any>(null);
  const [selectedScanIndex, setSelectedScanIndex] = useState<number>(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const res = await fetch(`${API_BASE}/scan-history`);
      if (res.ok) {
        const data = await res.json();
        setScans(data.scans || []);
      }
    } catch {}
    setLoading(false);
  };

  const viewReport = async (filename: string, scanUrl: string, scanTime: string) => {
    try {
      const res = await fetch(`${API_BASE}/scan-report/${filename}`);
      if (res.ok) {
        const data = await res.json();
        const scans = data.scans || [];
        const idx = scans.findIndex((s: any) => s.scan_url === scanUrl && s.scan_time === scanTime);
        setSelectedReport(data);
        setSelectedScanIndex(idx >= 0 ? idx : 0);
      }
    } catch {}
  };

  const downloadReport = async (filename: string) => {
    try {
      const res = await fetch(`${API_BASE}/scan-report/${filename}`);
      if (res.ok) {
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch {}
  };

  const formatScanType = (type: string) => {
    const labels: Record<string, string> = {
      sqli: "SQL Injection",
      xss: "XSS",
      misconfig: "Security Misconfig",
      sensitive: "Sensitive Info"
    };
    return labels[type] || type;
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
    <div>
      <div className="flex items-center gap-2 mb-4" style={{ fontFamily: "'Rajdhani', sans-serif" }}>
        <div className="w-1 h-4 rounded" style={{ background: COLORS.cyan }} />
        <span style={{ color: COLORS.textSecondary, fontSize: "12px", fontWeight: 600, letterSpacing: "0.12em" }}>
          SCAN HISTORY
        </span>
        <button onClick={fetchHistory} className="ml-auto text-xs" style={{ color: COLORS.textSecondary }}>
          REFRESH
        </button>
      </div>

      {loading ? (
        <div style={{ color: COLORS.textSecondary, fontSize: "12px" }}>Loading...</div>
      ) : scans.length === 0 ? (
        <div style={{ color: COLORS.textSecondary, fontSize: "12px" }}>No scans yet. Run a scan to see history.</div>
      ) : (
        <div className="space-y-2 max-h-[500px] overflow-y-auto">
          {scans.map((scan, i) => (
            <div key={i} className="flex items-center gap-3 p-3 rounded"
              style={{ background: COLORS.surface, border: `1px solid ${COLORS.border}` }}>
              <Clock size={14} style={{ color: COLORS.textSecondary, flexShrink: 0 }} />
              <div className="flex-1 min-w-0">
                <div style={{ color: COLORS.textPrimary, fontSize: "12px", fontWeight: 600 }}>
                  {formatScanType(scan.scan_type)}
                </div>
                <div style={{ color: COLORS.textSecondary, fontSize: "10px" }}>
                  {scan.scan_url}
                </div>
                <div style={{ color: COLORS.textMuted, fontSize: "10px" }}>
                  {scan.scan_time} — {scan.findings} finding(s)
                </div>
              </div>
              <button onClick={() => viewReport(scan.filename, scan.scan_url, scan.scan_time)}
                className="p-1.5 rounded transition-colors hover:bg-cyan-400/10"
                style={{ color: COLORS.cyan }} title="View">
                <Eye size={14} />
              </button>
              <button onClick={() => downloadReport(scan.filename)}
                className="p-1.5 rounded transition-colors hover:bg-cyan-400/10"
                style={{ color: COLORS.green }} title="Download">
                <Download size={14} />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Report Popup */}
      {selectedReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: "rgba(0,0,0,0.75)" }}>
          <div className="rounded-lg p-6 w-full max-w-3xl max-h-[85vh] overflow-y-auto"
            style={{ background: COLORS.background, border: `1px solid ${COLORS.border}` }}>
            <div className="flex items-center justify-between mb-4">
              <div>
                <span style={{ color: COLORS.cyan, fontSize: "14px", fontWeight: 600 }}>📋 Scan Report</span>
                <div style={{ color: COLORS.textSecondary, fontSize: "10px", marginTop: "2px" }}>
                  {(selectedReport.scans || [])[selectedScanIndex]?.scan_url} — {(selectedReport.scans || [])[selectedScanIndex]?.scan_time}
                </div>
              </div>
              <button onClick={() => setSelectedReport(null)} style={{ color: COLORS.textSecondary }}>
                <X size={18} />
              </button>
            </div>

            <div style={{ color: COLORS.textSecondary, fontSize: "11px", marginBottom: "12px" }}>
              Total: {(selectedReport.scans || [])[selectedScanIndex]?.total_findings || 0} unique findings
            </div>

            {((selectedReport.scans || [])[selectedScanIndex]?.results || []).map((r: any, i: number) => (
              <div key={i} className="mb-3 p-4 rounded"
                style={{
                  background: COLORS.surfaceDark,
                  border: `1px solid ${severityColor(r.ai_severity || r.severity)}40`
                }}>
                {/* Header */}
                <div className="flex items-center gap-2 mb-2">
                  {r.ai_severity === "CRITICAL" || r.ai_severity === "HIGH" ? (
                    <AlertTriangle size={14} style={{ color: severityColor(r.ai_severity) }} />
                  ) : (
                    <CheckCircle2 size={14} style={{ color: severityColor(r.ai_severity) }} />
                  )}
                  <span style={{
                    color: severityColor(r.ai_severity || r.severity),
                    fontSize: "12px",
                    fontWeight: 700
                  }}>
                    {r.ai_severity || r.severity || "UNKNOWN"} — {r.check_type || r.attack_type || "Finding"}
                  </span>
                </div>

                {/* Location */}
                {r.url && (
                  <div style={{ color: COLORS.textSecondary, fontSize: "10px", marginBottom: "4px" }}>
                    📍 URL: <span style={{ color: COLORS.textPrimary }}>{r.url}</span>
                    {r.parameter && <span> | Parameter: <span style={{ color: COLORS.textPrimary }}>{r.parameter}</span></span>}
                  </div>
                )}

                {/* Evidence */}
                {r.evidence && (
                  <div style={{ color: COLORS.textMuted, fontSize: "9px", marginBottom: "4px" }}>
                    🔍 {r.evidence}
                  </div>
                )}

                {/* Confidence */}
                {(r.ai_confidence || r.confidence) > 0 && (
                  <div style={{ color: COLORS.greenBright, fontSize: "10px", marginBottom: "4px" }}>
                    Confidence: {((r.ai_confidence || r.confidence) * 100).toFixed(1)}%
                  </div>
                )}

                {/* Supporting payloads */}
                <SupportingPayloads payloads={r.supporting_payloads} />

                {/* Fix */}
                {r.fix && (
                  <div style={{
                    marginTop: "8px",
                    paddingTop: "8px",
                    borderTop: `1px solid ${COLORS.border}`,
                    whiteSpace: "pre-line",
                    color: COLORS.textPrimary,
                    fontSize: "9px",
                    lineHeight: "1.7",
                    fontFamily: "'JetBrains Mono', monospace"
                  }}>
                    {r.fix}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}