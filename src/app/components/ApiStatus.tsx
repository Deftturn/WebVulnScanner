import { useState, useEffect } from "react";
import { CheckCircle2, XCircle, Clock, Zap, Activity } from "lucide-react";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

const endpoints = [
  { name: "/api/scan/submit", method: "POST", status: "online", latency: 142, uptime: 99.97, requests: "1.2M" },
  { name: "/api/vulnerabilities", method: "GET", status: "online", latency: 87, uptime: 99.99, requests: "4.8M" },
  { name: "/api/model/predict", method: "POST", status: "online", latency: 318, uptime: 99.94, requests: "890K" },
  { name: "/api/reports/export", method: "GET", status: "degraded", latency: 1240, uptime: 98.21, requests: "230K" },
  { name: "/api/targets/register", method: "POST", status: "online", latency: 95, uptime: 99.98, requests: "560K" },
  { name: "/api/auth/token", method: "POST", status: "online", latency: 61, uptime: 100.0, requests: "3.1M" },
];

const generateLatencyData = () =>
  Array.from({ length: 20 }, (_, i) => ({
    t: i,
    v: 80 + Math.random() * 120 + (Math.random() > 0.9 ? 400 : 0),
  }));

const statusColor = { online: "#22c55e", degraded: "#ffcc00", offline: "#ff2244" };
const statusLabel = { online: "ONLINE", degraded: "DEGRADED", offline: "OFFLINE" };

export function ApiStatus() {
  const [latencyData, setLatencyData] = useState(generateLatencyData());

  useEffect(() => {
    const iv = setInterval(() => {
      setLatencyData((prev) => {
        const next = [...prev.slice(1), { t: prev[prev.length - 1].t + 1, v: 80 + Math.random() * 120 + (Math.random() > 0.92 ? 400 : 0) }];
        return next;
      });
    }, 1500);
    return () => clearInterval(iv);
  }, []);

  return (
    <div className="space-y-4" style={{ fontFamily: "'Rajdhani', sans-serif" }}>
      {/* Live latency chart */}
      <div className="rounded-lg p-5" style={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.15)" }}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Activity size={14} style={{ color: "#00d4ff" }} />
            <span style={{ color: "#00d4ff", fontSize: "13px", fontWeight: 600, letterSpacing: "0.12em" }}>
              LIVE API LATENCY
            </span>
            <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" style={{ boxShadow: "0 0 6px #00d4ff" }} />
          </div>
          <div className="flex gap-4">
            {[
              { label: "p50", value: "98ms", color: "#22c55e" },
              { label: "p95", value: "287ms", color: "#ffcc00" },
              { label: "p99", value: "1.2s", color: "#ff2244" },
            ].map((m) => (
              <div key={m.label} className="text-right">
                <div style={{ color: m.color, fontSize: "13px", fontWeight: 600, fontFamily: "'JetBrains Mono', monospace" }}>{m.value}</div>
                <div style={{ color: "#5a8aaa", fontSize: "10px", letterSpacing: "0.08em" }}>{m.label}</div>
              </div>
            ))}
          </div>
        </div>
        <ResponsiveContainer width="100%" height={100}>
          <LineChart data={latencyData}>
            <XAxis hide />
            <YAxis hide />
            <Tooltip
              contentStyle={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.2)", borderRadius: "6px", fontSize: "11px", fontFamily: "JetBrains Mono", color: "#e2f0ff" }}
              formatter={(v: number) => [`${v.toFixed(0)}ms`, "Latency"]}
              labelFormatter={() => ""}
            />
            <Line type="monotone" dataKey="v" stroke="#00d4ff" strokeWidth={1.5} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Endpoints table */}
      <div className="rounded-lg overflow-hidden" style={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.15)" }}>
        <div className="px-5 py-3" style={{ borderBottom: "1px solid rgba(0,212,255,0.1)" }}>
          <span style={{ color: "#00d4ff", fontSize: "13px", fontWeight: 600, letterSpacing: "0.12em" }}>
            ENDPOINT REGISTRY
          </span>
        </div>
        <table className="w-full" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "12px" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid rgba(0,212,255,0.08)" }}>
              {["ENDPOINT", "METHOD", "STATUS", "LATENCY", "UPTIME", "REQUESTS"].map((h) => (
                <th key={h} className="text-left px-4 py-2.5" style={{ color: "#5a8aaa", fontSize: "10px", letterSpacing: "0.12em" }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {endpoints.map((ep, i) => {
              const sc = statusColor[ep.status as keyof typeof statusColor];
              return (
                <tr key={i} className="hover:bg-cyan-400/5 transition-colors" style={{ borderBottom: "1px solid rgba(0,212,255,0.05)" }}>
                  <td className="px-4 py-2.5" style={{ color: "#8aadcc" }}>{ep.name}</td>
                  <td className="px-4 py-2.5">
                    <span className="px-2 py-0.5 rounded" style={{ background: "rgba(0,212,255,0.08)", border: "1px solid rgba(0,212,255,0.2)", color: "#00d4ff", fontSize: "10px" }}>
                      {ep.method}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-1.5">
                      {ep.status === "online" ? <CheckCircle2 size={12} style={{ color: sc }} /> : ep.status === "degraded" ? <Clock size={12} style={{ color: sc }} /> : <XCircle size={12} style={{ color: sc }} />}
                      <span style={{ color: sc, fontSize: "10px", letterSpacing: "0.08em" }}>{statusLabel[ep.status as keyof typeof statusLabel]}</span>
                    </div>
                  </td>
                  <td className="px-4 py-2.5" style={{ color: ep.latency > 500 ? "#ff2244" : ep.latency > 200 ? "#ffcc00" : "#22c55e" }}>
                    {ep.latency}ms
                  </td>
                  <td className="px-4 py-2.5" style={{ color: ep.uptime > 99.9 ? "#22c55e" : "#ffcc00" }}>
                    {ep.uptime}%
                  </td>
                  <td className="px-4 py-2.5" style={{ color: "#8aadcc" }}>
                    <div className="flex items-center gap-1">
                      <Zap size={10} style={{ color: "#00d4ff" }} />
                      {ep.requests}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
