import { RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from "recharts";
import { Cpu, GitBranch, Layers } from "lucide-react";

const pipelineSteps = [
  { id: 1, label: "Input Normalization", detail: "Sanitize & tokenize raw request", status: "active" },
  { id: 2, label: "Feature Extraction", detail: "NLP + pattern vectorization", status: "active" },
  { id: 3, label: "Ensemble Model", detail: "BERT-sec + XGBoost + RF", status: "active" },
  { id: 4, label: "OWASP Classifier", detail: "Top-10 category mapping", status: "active" },
  { id: 5, label: "Risk Scoring", detail: "CVSS v3.1 severity calc", status: "processing" },
  { id: 6, label: "Report Output", detail: "Structured JSON + remediation", status: "pending" },
];

const radarData = [
  { subject: "SQLi", A: 97 },
  { subject: "XSS", A: 95 },
  { subject: "CSRF", A: 78 },
  { subject: "SSRF", A: 82 },
  { subject: "RCE", A: 91 },
  { subject: "LFI", A: 73 },
  { subject: "Auth", A: 88 },
];

const vulnTable = [
  { type: "SQL Injection", severity: "CRITICAL", confidence: 0.979, count: 24, cvss: 9.8, color: "#ff2244" },
  { type: "XSS (Stored)", severity: "CRITICAL", confidence: 0.953, count: 18, cvss: 9.4, color: "#ff8800" },
  { type: "SSRF", severity: "HIGH", confidence: 0.891, count: 7, cvss: 8.2, color: "#ff8800" },
  { type: "Broken Auth", severity: "HIGH", confidence: 0.864, count: 12, cvss: 7.9, color: "#ffcc00" },
  { type: "Sensitive Exposure", severity: "CRITICAL", confidence: 0.962, count: 9, cvss: 9.6, color: "#aa44ff" },
  { type: "Misconfiguration", severity: "CRITICAL", confidence: 0.941, count: 31, cvss: 9.1, color: "#ffcc00" },
  { type: "Path Traversal", severity: "HIGH", confidence: 0.812, count: 5, cvss: 7.5, color: "#ff8800" },
  { type: "CSRF", severity: "MEDIUM", confidence: 0.773, count: 3, cvss: 6.1, color: "#22c55e" },
];

const barData = [
  { name: "SQLi", value: 24, color: "#ff2244" },
  { name: "XSS", value: 18, color: "#ff8800" },
  { name: "Misconf", value: 31, color: "#ffcc00" },
  { name: "Auth", value: 12, color: "#aa44ff" },
  { name: "SSRF", value: 7, color: "#00d4ff" },
  { name: "LFI", value: 5, color: "#22c55e" },
];

const severityColor: Record<string, string> = {
  CRITICAL: "#ff2244",
  HIGH: "#ff8800",
  MEDIUM: "#ffcc00",
  LOW: "#22c55e",
};

export function ModelInsights() {
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
          {/* Connector line */}
          <div
            className="absolute left-5 top-5 bottom-5 w-px"
            style={{ background: "linear-gradient(to bottom, #00d4ff44, #aa44ff44)" }}
          />

          <div className="space-y-3">
            {pipelineSteps.map((step) => (
              <div key={step.id} className="flex items-start gap-4 ml-1">
                <div
                  className="relative z-10 w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0"
                  style={{
                    background: step.status === "pending" ? "#0d1e35" : step.status === "processing" ? "rgba(255,204,0,0.1)" : "rgba(0,212,255,0.1)",
                    border: `1px solid ${step.status === "pending" ? "rgba(90,138,170,0.3)" : step.status === "processing" ? "#ffcc00" : "#00d4ff"}`,
                  }}
                >
                  <Layers
                    size={13}
                    style={{ color: step.status === "pending" ? "#5a8aaa" : step.status === "processing" ? "#ffcc00" : "#00d4ff" }}
                  />
                </div>
                <div className="flex-1 pt-1">
                  <div className="flex items-center gap-2">
                    <span style={{ color: step.status === "pending" ? "#5a8aaa" : "#e2f0ff", fontSize: "13px", fontWeight: 600 }}>
                      {step.label}
                    </span>
                    {step.status === "processing" && (
                      <span
                        className="px-1.5 py-0.5 rounded-full"
                        style={{ background: "rgba(255,204,0,0.1)", border: "1px solid #ffcc0044", color: "#ffcc00", fontSize: "9px", letterSpacing: "0.1em" }}
                      >
                        RUNNING
                      </span>
                    )}
                    {step.status === "active" && (
                      <span
                        className="px-1.5 py-0.5 rounded-full"
                        style={{ background: "rgba(34,197,94,0.1)", border: "1px solid #22c55e44", color: "#22c55e", fontSize: "9px", letterSpacing: "0.1em" }}
                      >
                        DONE
                      </span>
                    )}
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

      {/* Charts row */}
      <div className="grid grid-cols-2 gap-4">
        {/* Radar */}
        <div className="rounded-lg p-4" style={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.15)" }}>
          <div className="flex items-center gap-2 mb-3">
            <Cpu size={13} style={{ color: "#00d4ff" }} />
            <span style={{ color: "#00d4ff", fontSize: "12px", fontWeight: 600, letterSpacing: "0.12em" }}>
              THREAT COVERAGE
            </span>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="rgba(0,212,255,0.12)" />
              <PolarAngleAxis dataKey="subject" tick={{ fill: "#5a8aaa", fontSize: 10, fontFamily: "JetBrains Mono" }} />
              <Radar name="Score" dataKey="A" stroke="#00d4ff" fill="#00d4ff" fillOpacity={0.08} strokeWidth={1.5} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        {/* Bar */}
        <div className="rounded-lg p-4" style={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.15)" }}>
          <div className="flex items-center gap-2 mb-3">
            <Cpu size={13} style={{ color: "#aa44ff" }} />
            <span style={{ color: "#aa44ff", fontSize: "12px", fontWeight: 600, letterSpacing: "0.12em" }}>
              VECTOR DISTRIBUTION
            </span>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={barData} barSize={18}>
              <XAxis dataKey="name" tick={{ fill: "#5a8aaa", fontSize: 10, fontFamily: "JetBrains Mono" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: "#5a8aaa", fontSize: 10, fontFamily: "JetBrains Mono" }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.2)", borderRadius: "6px", color: "#e2f0ff", fontFamily: "JetBrains Mono", fontSize: "11px" }}
                cursor={{ fill: "rgba(0,212,255,0.04)" }}
              />
              <Bar dataKey="value" radius={[3, 3, 0, 0]}>
                {barData.map((entry, index) => (
                  <Cell key={index} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Vulnerability Table */}
      <div className="rounded-lg overflow-hidden" style={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.15)" }}>
        <div className="px-5 py-3" style={{ borderBottom: "1px solid rgba(0,212,255,0.1)" }}>
          <span style={{ color: "#00d4ff", fontSize: "13px", fontWeight: 600, letterSpacing: "0.12em" }}>
            VULNERABILITY BREAKDOWN
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "12px" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid rgba(0,212,255,0.08)" }}>
                {["TYPE", "SEVERITY", "CONFIDENCE", "COUNT", "CVSS"].map((h) => (
                  <th
                    key={h}
                    className="text-left px-4 py-2.5"
                    style={{ color: "#5a8aaa", fontSize: "10px", letterSpacing: "0.12em", fontWeight: 600 }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {vulnTable.map((row, i) => (
                <tr
                  key={i}
                  className="transition-colors hover:bg-cyan-400/5"
                  style={{ borderBottom: "1px solid rgba(0,212,255,0.05)" }}
                >
                  <td className="px-4 py-2.5" style={{ color: "#e2f0ff" }}>{row.type}</td>
                  <td className="px-4 py-2.5">
                    <span
                      className="px-2 py-0.5 rounded"
                      style={{ background: `${severityColor[row.severity]}18`, border: `1px solid ${severityColor[row.severity]}44`, color: severityColor[row.severity], fontSize: "10px", letterSpacing: "0.08em" }}
                    >
                      {row.severity}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-1 rounded-full overflow-hidden" style={{ background: "#0d1e35", maxWidth: "60px" }}>
                        <div className="h-full rounded-full" style={{ width: `${row.confidence * 100}%`, background: `linear-gradient(90deg, ${row.color}, ${row.color}88)` }} />
                      </div>
                      <span style={{ color: row.color }}>{(row.confidence * 100).toFixed(1)}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-2.5" style={{ color: "#8aadcc" }}>{row.count}</td>
                  <td className="px-4 py-2.5" style={{ color: row.cvss >= 9 ? "#ff2244" : row.cvss >= 7 ? "#ff8800" : "#ffcc00" }}>
                    {row.cvss.toFixed(1)}
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
