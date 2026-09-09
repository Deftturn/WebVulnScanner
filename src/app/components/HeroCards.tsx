// @ts-nocheck

import { useState, useEffect } from "react";
import { Database, Code2, Settings, FileWarning } from "lucide-react";

export function HeroCards() {
  const [scores, setScores] = useState<any>({});

  useEffect(() => {
    const fetchScores = async () => {
      const payloads = [
        { id: "sqli", payload: "' OR 1=1 --", attack_type: "sql", language: "Python" },
        { id: "xss", payload: "<img src=x onerror=alert('XSS')>", attack_type: "xss", language: "JavaScript" },
        { id: "misconfig", payload: "", attack_type: "misconfig", language: "Python", vulnerable_code: "DEBUG=True" },
        { id: "sensitive", payload: "", attack_type: "sensitive_info", language: "Python", vulnerable_code: "email=admin@test.com" },
      ];

      const results: any = {};
      for (const p of payloads) {
        try {
          const res = await fetch("http://127.0.0.1:8000/analyze", {
            method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(p),
          });
          if (res.ok) {
            const data = await res.json();
            results[p.id] = { score: Math.round(data.confidence * 100), severity: data.severity };
          }
        } catch {}
      }
      setScores(results);
    };
    fetchScores();
  }, []);

  const threats = [
    { id: "sqli", label: "SQL Injection", icon: Database, color: "#ff2244", glow: "rgba(255,34,68,0.25)" },
    { id: "xss", label: "XSS Detection", icon: Code2, color: "#ff8800", glow: "rgba(255,136,0,0.25)" },
    { id: "misconfig", label: "Misconfiguration", icon: Settings, color: "#ffcc00", glow: "rgba(255,204,0,0.2)" },
    { id: "sensitive", label: "Sensitive Data Leak", icon: FileWarning, color: "#aa44ff", glow: "rgba(170,68,255,0.25)" },
  ];

  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      {threats.map((t) => {
        const Icon = t.icon;
        const data = scores[t.id];
        return (
          <div key={t.id} className="relative rounded-lg p-4 overflow-hidden transition-all duration-300 hover:scale-[1.02] cursor-default"
            style={{
              background: `linear-gradient(135deg, #0a1628 0%, #050b12 100%)`,
              border: `1px solid ${t.color}33`,
              boxShadow: `0 0 20px ${t.glow}, inset 0 0 20px rgba(0,0,0,0.3)`,
            }}>
            <div className="absolute top-0 right-0 w-12 h-12 opacity-20"
              style={{ background: `radial-gradient(circle at top right, ${t.color}, transparent 70%)` }} />

            <div className="flex items-start justify-between mb-3">
              <div className="w-9 h-9 rounded flex items-center justify-center"
                style={{ background: `${t.color}18`, border: `1px solid ${t.color}44` }}>
                <Icon size={18} style={{ color: t.color }} />
              </div>
              {data && (
                <div className="flex items-center gap-1 px-2 py-0.5 rounded-full"
                  style={{
                    background: data.severity === "CRITICAL" ? "#ff224418" : data.severity === "HIGH" ? "#ff880018" : "#22c55e18",
                    border: `1px solid ${data.severity === "CRITICAL" ? "#ff2244" : data.severity === "HIGH" ? "#ff8800" : "#22c55e"}33`
                  }}>
                  <span style={{
                    color: data.severity === "CRITICAL" ? "#ff2244" : data.severity === "HIGH" ? "#ff8800" : "#22c55e",
                    fontSize: "9px", fontWeight: 700, letterSpacing: "0.1em", fontFamily: "'JetBrains Mono', monospace"
                  }}>{data.severity}</span>
                </div>
              )}
            </div>

            <div style={{ fontFamily: "'Rajdhani', sans-serif" }}>
              <div style={{ color: "#8aadcc", fontSize: "11px", letterSpacing: "0.08em", marginBottom: "4px" }}>{t.label.toUpperCase()}</div>
              <div style={{ fontSize: "36px", fontWeight: 700, color: t.color, lineHeight: 1, textShadow: `0 0 20px ${t.color}66`, fontFamily: "'JetBrains Mono', monospace" }}>
                {data?.score || "—"}
              </div>
              <div style={{ color: "#5a8aaa", fontSize: "10px", marginTop: "2px" }}>confidence score</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}