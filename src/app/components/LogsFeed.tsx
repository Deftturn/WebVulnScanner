// @ts-nocheck

import { useState, useEffect } from "react";
import { Clock, Download, Eye, X } from "lucide-react";

const API_BASE = "http://127.0.0.1:8000";

interface ScanRecord {
  filename: string;
  scan_type: string;
  scan_url: string;
  scan_time: string;
  findings: number;
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
      case "CRITICAL": return "#ff2244";
      case "HIGH": return "#ff8800";
      case "MEDIUM": return "#ffcc00";
      case "LOW": return "#22c55e";
      default: return "#5a8aaa";
    }
  };

  return (
    <div>
      <div className="flex items-center gap-2 mb-4" style={{ fontFamily: "'Rajdhani', sans-serif" }}>
        <div className="w-1 h-4 rounded" style={{ background: "#00d4ff" }} />
        <span style={{ color: "#8aadcc", fontSize: "12px", fontWeight: 600, letterSpacing: "0.12em" }}>
          SCAN HISTORY
        </span>
        <button onClick={fetchHistory} className="ml-auto text-xs" style={{ color: "#5a8aaa" }}>
          REFRESH
        </button>
      </div>

      {loading ? (
        <div style={{ color: "#5a8aaa", fontSize: "12px" }}>Loading...</div>
      ) : scans.length === 0 ? (
        <div style={{ color: "#5a8aaa", fontSize: "12px" }}>No scans yet. Run a scan to see history.</div>
      ) : (
        <div className="space-y-2 max-h-[500px] overflow-y-auto">
          {scans.map((scan, i) => (
            <div key={i} className="flex items-center gap-3 p-3 rounded"
              style={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.1)" }}>
              <Clock size={14} style={{ color: "#5a8aaa", flexShrink: 0 }} />
              <div className="flex-1 min-w-0">
                <div style={{ color: "#e2f0ff", fontSize: "12px", fontWeight: 600 }}>
                  {formatScanType(scan.scan_type)}
                </div>
                <div style={{ color: "#5a8aaa", fontSize: "10px" }}>
                  {scan.scan_url}
                </div>
                <div style={{ color: "#5a8aaa", fontSize: "10px" }}>
                  {scan.scan_time} — {scan.findings} finding(s)
                </div>
              </div>
              <button onClick={() => viewReport(scan.filename, scan.scan_url, scan.scan_time)}
                className="p-1.5 rounded transition-colors hover:bg-cyan-400/10"
                style={{ color: "#00d4ff" }} title="View">
                <Eye size={14} />
              </button>
              <button onClick={() => downloadReport(scan.filename)}
                className="p-1.5 rounded transition-colors hover:bg-cyan-400/10"
                style={{ color: "#22c55e" }} title="Download">
                <Download size={14} />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Report Popup */}
      {selectedReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: "rgba(0,0,0,0.7)" }}>
          <div className="rounded-lg p-6 w-full max-w-2xl max-h-[80vh] overflow-y-auto"
            style={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.2)" }}>
            <div className="flex items-center justify-between mb-4">
              <div>
                <span style={{ color: "#00d4ff", fontSize: "14px", fontWeight: 600 }}>Scan Report</span>
                <div style={{ color: "#5a8aaa", fontSize: "10px", marginTop: "2px" }}>
                  {(selectedReport.scans || [])[selectedScanIndex]?.scan_url} — {(selectedReport.scans || [])[selectedScanIndex]?.scan_time}
                </div>
              </div>
              <button onClick={() => setSelectedReport(null)} style={{ color: "#5a8aaa" }}><X size={18} /></button>
            </div>

            <div style={{ color: "#5a8aaa", fontSize: "11px", marginBottom: "12px" }}>
              Total: {(selectedReport.scans || [])[selectedScanIndex]?.total_findings || 0} findings
            </div>

            {((selectedReport.scans || [])[selectedScanIndex]?.results || []).map((r: any, i: number) => (
              <div key={i} className="mb-3 p-3 rounded"
                style={{ background: "#050b12", border: "1px solid rgba(0,212,255,0.08)" }}>
                <div style={{ color: severityColor(r.ai_severity || r.severity), fontSize: "11px", fontWeight: 700, marginBottom: "4px" }}>
                  {r.ai_severity || r.severity || "UNKNOWN"} — {r.check_type || r.attack_type || r.payload || r.test_type || "Finding"}
                </div>
                <div style={{ color: "#8aadcc", fontSize: "10px" }}>
                  {r.parameter ? `Parameter: ${r.parameter}` : ""}
                  {r.parameter && (r.url || r.evidence) ? " — " : ""}
                  {r.evidence || r.url || ""}
                </div>
                {(r.ai_confidence || r.confidence) && (
                  <div style={{ color: "#22c55e", fontSize: "10px", marginTop: "2px" }}>
                    Confidence: {((r.ai_confidence || r.confidence) * 100).toFixed(1)}%
                  </div>
                )}
                {r.fix && (
  <div style={{ marginTop: "8px", paddingTop: "8px", borderTop: "1px solid rgba(255,255,255,0.08)", whiteSpace: "pre-line", color: "#22c55e", fontSize: "10px", lineHeight: "1.6" }}>
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