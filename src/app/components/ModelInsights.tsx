// @ts-nocheck

import { useState, useEffect } from "react";
import { Cpu, GitBranch, Layers } from "lucide-react";

const severityColor: Record<string, string> = {
  CRITICAL: "#ff2244", HIGH: "#ff8800", MEDIUM: "#ffcc00", LOW: "#22c55e",
};

export function ModelInsights() {
  const [stats, setStats] = useState<any>({ scans: [], totalFindings: 0, bySeverity: {}, byType: [] });

  useEffect(() => {
    fetch("http://127.0.0.1:8000/scan-stats")
      .then(r => r.json())
      .then(data => {
        // Also fetch all reports for breakdown
        fetch("http://127.0.0.1:8000/scan-history")
          .then(r => r.json())
          .then(history => {
            const allResults: any[] = [];
            const bySeverity: any = {};
            const byType: any = {};

            // Load each report to get detailed results
            const files = [...new Set((history.scans || []).map((s: any) => s.filename))];
            Promise.all(files.map((f: string) =>
              fetch(`http://127.0.0.1:8000/scan-report/${f}`).then(r => r.json())
            )).then(reports => {
              reports.forEach(report => {
                (report.scans || []).forEach((scan: any) => {
                  (scan.results || []).forEach((r: any) => {
                    allResults.push(r);
                    const sev = r.ai_severity || r.severity || "UNKNOWN";
                    bySeverity[sev] = (bySeverity[sev] || 0) + 1;
                    const type = r.check_type || r.attack_type || r.test_type || "other";
                    byType[type] = (byType[type] || 0) + 1;
                  });
                });
              });
              setStats({
                totalFindings: allResults.length,
                bySeverity,
                byType: Object.entries(byType).map(([name, count]) => ({ name, count: count as number })),
                results: allResults.slice(0, 20),
              });
            });
          });
      })
      .catch(() => {});
  }, []);

  const pipelineSteps = [
    { id: 1, label: "Crawler Engine", detail: "Playwright + BeautifulSoup DFS crawler", status: "active" },
    { id: 2, label: "Vulnerability Injectors", detail: "SQLi, XSS, Misconfig, Sensitive Info", status: "active" },
    { id: 3, label: "AI Analysis Layer", detail: "DataRobot XGBoost + Local scikit-learn", status: "active" },
    { id: 4, label: "OWASP Classifier", detail: "A01-A10 category mapping + CWE assignment", status: "active" },
    { id: 5, label: "Report Generation", detail: "Structured JSON + remediation suggestions", status: "active" },
  ];

  return (
    <div className="space-y-5" style={{ fontFamily: "'Rajdhani', sans-serif" }}>
      {/* Detection Pipeline */}
      <div className="rounded-lg p-5" style={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.15)" }}>
        <div className="flex items-center gap-2 mb-4">
          <GitBranch size={14} style={{ color: "#00d4ff" }} />
          <span style={{ color: "#00d4ff", fontSize: "13px", fontWeight: 600, letterSpacing: "0.12em" }}>
            DETECTION PIPELINE
          </span>
        </div>
        <div className="relative">
          <div className="absolute left-5 top-5 bottom-5 w-px" style={{ background: "linear-gradient(to bottom, #00d4ff44, #aa44ff44)" }} />
          <div className="space-y-3">
            {pipelineSteps.map((step) => (
              <div key={step.id} className="flex items-start gap-4 ml-1">
                <div className="relative z-10 w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0"
                  style={{ background: "rgba(0,212,255,0.1)", border: "1px solid #00d4ff" }}>
                  <Layers size={13} style={{ color: "#00d4ff" }} />
                </div>
                <div className="flex-1 pt-1">
                  <div className="flex items-center gap-2">
                    <span style={{ color: "#e2f0ff", fontSize: "13px", fontWeight: 600 }}>{step.label}</span>
                    <span className="px-1.5 py-0.5 rounded-full"
                      style={{ background: "rgba(34,197,94,0.1)", border: "1px solid #22c55e44", color: "#22c55e", fontSize: "9px" }}>
                      DONE
                    </span>
                  </div>
                  <div style={{ color: "#5a8aaa", fontSize: "11px", marginTop: "2px", fontFamily: "'JetBrains Mono', monospace" }}>
                    {step.detail}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "Total Findings", value: stats.totalFindings, color: "#ff2244" },
          { label: "CRITICAL", value: stats.bySeverity?.CRITICAL || 0, color: "#ff2244" },
          { label: "HIGH", value: stats.bySeverity?.HIGH || 0, color: "#ff8800" },
          { label: "MEDIUM/LOW", value: (stats.bySeverity?.MEDIUM || 0) + (stats.bySeverity?.LOW || 0), color: "#22c55e" },
        ].map(s => (
          <div key={s.label} className="rounded-lg p-4" style={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.15)" }}>
            <div style={{ color: "#5a8aaa", fontSize: "10px", letterSpacing: "0.1em" }}>{s.label}</div>
            <div style={{ color: s.color, fontSize: "28px", fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Findings Table */}
      <div className="rounded-lg overflow-hidden" style={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.15)" }}>
        <div className="px-5 py-3" style={{ borderBottom: "1px solid rgba(0,212,255,0.1)" }}>
          <span style={{ color: "#00d4ff", fontSize: "13px", fontWeight: 600, letterSpacing: "0.12em" }}>
            RECENT FINDINGS
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "12px" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid rgba(0,212,255,0.08)" }}>
                {["TYPE", "SEVERITY", "CONFIDENCE", "DETAIL"].map(h => (
                  <th key={h} className="text-left px-4 py-2.5"
                    style={{ color: "#5a8aaa", fontSize: "10px", letterSpacing: "0.12em", fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(stats.results || []).map((row: any, i: number) => (
                <tr key={i} className="transition-colors hover:bg-cyan-400/5"
                  style={{ borderBottom: "1px solid rgba(0,212,255,0.05)" }}>
                  <td className="px-4 py-2.5" style={{ color: "#e2f0ff" }}>
                    {row.check_type || row.attack_type || row.test_type || row.payload || "Finding"}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="px-2 py-0.5 rounded"
                      style={{ background: `${severityColor[row.ai_severity || row.severity] || "#5a8aaa"}18`,
                        border: `1px solid ${severityColor[row.ai_severity || row.severity] || "#5a8aaa"}44`,
                        color: severityColor[row.ai_severity || row.severity] || "#5a8aaa", fontSize: "10px" }}>
                      {row.ai_severity || row.severity || "?"}
                    </span>
                  </td>
                  <td className="px-4 py-2.5" style={{ color: "#22c55e" }}>
                    {row.ai_confidence ? `${(row.ai_confidence * 100).toFixed(1)}%` : row.confidence ? `${(row.confidence * 100).toFixed(1)}%` : "—"}
                  </td>
                  <td className="px-4 py-2.5" style={{ color: "#8aadcc", fontSize: "10px" }}>
                    {row.evidence || row.url || row.parameter || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}