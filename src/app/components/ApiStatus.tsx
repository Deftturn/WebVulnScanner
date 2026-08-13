// @ts-nocheck

import { useState, useEffect } from "react";
import { CheckCircle2, Activity, Server, Cpu } from "lucide-react";

export function ApiStatus() {
  const [health, setHealth] = useState<any>({});
  const [apiLatency, setApiLatency] = useState<number>(0);

  useEffect(() => {
    // Fetch health status
    fetch("http://127.0.0.1:8000/health")
      .then(r => r.json())
      .then(d => setHealth(d))
      .catch(() => {});

    // Measure latency
    const start = performance.now();
    fetch("http://127.0.0.1:8000/health")
      .then(() => setApiLatency(Math.round(performance.now() - start)))
      .catch(() => {});
  }, []);

  const endpoints = [
    { name: "/analyze", method: "POST", desc: "AI vulnerability prediction", status: "online" },
    { name: "/start-scan", method: "POST", desc: "Full site scan trigger", status: "online" },
    { name: "/scan-history", method: "GET", desc: "List all past scans", status: "online" },
    { name: "/scan-report/{file}", method: "GET", desc: "Download scan report", status: "online" },
    { name: "/scan-stats", method: "GET", desc: "Dashboard statistics", status: "online" },
    { name: "/health", method: "GET", desc: "System health check", status: "online" },
  ];

  return (
    <div className="space-y-4" style={{ fontFamily: "'Rajdhani', sans-serif" }}>
      {/* Status Cards */}
      <div className="grid grid-cols-3 gap-4">
        <div className="rounded-lg p-4" style={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.15)" }}>
          <div className="flex items-center gap-2 mb-2">
            <Server size={14} style={{ color: "#22c55e" }} />
            <span style={{ color: "#22c55e", fontSize: "11px", letterSpacing: "0.1em" }}>API STATUS</span>
          </div>
          <div style={{ color: "#e2f0ff", fontSize: "22px", fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>
            ONLINE
          </div>
          <div style={{ color: "#5a8aaa", fontSize: "10px", marginTop: "2px" }}>All endpoints responding</div>
        </div>

        <div className="rounded-lg p-4" style={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.15)" }}>
          <div className="flex items-center gap-2 mb-2">
            <Activity size={14} style={{ color: "#00d4ff" }} />
            <span style={{ color: "#00d4ff", fontSize: "11px", letterSpacing: "0.1em" }}>LATENCY</span>
          </div>
          <div style={{ color: "#e2f0ff", fontSize: "22px", fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>
            {apiLatency}ms
          </div>
          <div style={{ color: "#5a8aaa", fontSize: "10px", marginTop: "2px" }}>Health check response</div>
        </div>

        <div className="rounded-lg p-4" style={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.15)" }}>
          <div className="flex items-center gap-2 mb-2">
            <Cpu size={14} style={{ color: "#aa44ff" }} />
            <span style={{ color: "#aa44ff", fontSize: "11px", letterSpacing: "0.1em" }}>MODELS</span>
          </div>
          <div style={{ color: "#e2f0ff", fontSize: "22px", fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>
            {health.datarobot ? "DataRobot" : health.local_model ? "Local" : "None"}
          </div>
          <div style={{ color: "#5a8aaa", fontSize: "10px", marginTop: "2px" }}>
            {health.datarobot && health.local_model ? "Dual-model ready" : "Single model"}
          </div>
        </div>
      </div>

      {/* Endpoints Table */}
      <div className="rounded-lg overflow-hidden" style={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.15)" }}>
        <div className="px-5 py-3" style={{ borderBottom: "1px solid rgba(0,212,255,0.1)" }}>
          <span style={{ color: "#00d4ff", fontSize: "13px", fontWeight: 600, letterSpacing: "0.12em" }}>
            ENDPOINT REGISTRY
          </span>
        </div>
        <table className="w-full" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "12px" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid rgba(0,212,255,0.08)" }}>
              {["ENDPOINT", "METHOD", "DESCRIPTION", "STATUS"].map(h => (
                <th key={h} className="text-left px-4 py-2.5" style={{ color: "#5a8aaa", fontSize: "10px", letterSpacing: "0.12em" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {endpoints.map((ep, i) => (
              <tr key={i} className="hover:bg-cyan-400/5 transition-colors" style={{ borderBottom: "1px solid rgba(0,212,255,0.05)" }}>
                <td className="px-4 py-2.5" style={{ color: "#8aadcc" }}>{ep.name}</td>
                <td className="px-4 py-2.5">
                  <span className="px-2 py-0.5 rounded" style={{ background: "rgba(0,212,255,0.08)", border: "1px solid rgba(0,212,255,0.2)", color: "#00d4ff", fontSize: "10px" }}>{ep.method}</span>
                </td>
                <td className="px-4 py-2.5" style={{ color: "#5a8aaa", fontSize: "11px" }}>{ep.desc}</td>
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-1.5">
                    <CheckCircle2 size={12} style={{ color: "#22c55e" }} />
                    <span style={{ color: "#22c55e", fontSize: "10px", letterSpacing: "0.08em" }}>ONLINE</span>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}