import { Database, Code2, Settings, FileWarning, TrendingUp, AlertTriangle } from "lucide-react";

const threats = [
  {
    id: "sqli",
    label: "SQL Injection",
    icon: Database,
    critical: 97,
    count: 24,
    trend: "+3",
    color: "#ff2244",
    glow: "rgba(255,34,68,0.25)",
  },
  {
    id: "xss",
    label: "XSS Detection",
    icon: Code2,
    critical: 95,
    count: 18,
    trend: "+2",
    color: "#ff8800",
    glow: "rgba(255,136,0,0.25)",
  },
  {
    id: "misconfig",
    label: "Misconfiguration",
    icon: Settings,
    critical: 94,
    count: 31,
    trend: "+7",
    color: "#ffcc00",
    glow: "rgba(255,204,0,0.2)",
  },
  {
    id: "dataleak",
    label: "Sensitive Data Leak",
    icon: FileWarning,
    critical: 96,
    count: 9,
    trend: "+1",
    color: "#aa44ff",
    glow: "rgba(170,68,255,0.25)",
  },
];

export function HeroCards() {
  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      {threats.map((t) => {
        const Icon = t.icon;
        return (
          <div
            key={t.id}
            className="relative rounded-lg p-4 overflow-hidden transition-all duration-300 hover:scale-[1.02] cursor-default"
            style={{
              background: `linear-gradient(135deg, #0a1628 0%, #050b12 100%)`,
              border: `1px solid ${t.color}33`,
              boxShadow: `0 0 20px ${t.glow}, inset 0 0 20px rgba(0,0,0,0.3)`,
            }}
          >
            {/* Corner accent */}
            <div
              className="absolute top-0 right-0 w-12 h-12 opacity-20"
              style={{ background: `radial-gradient(circle at top right, ${t.color}, transparent 70%)` }}
            />

            <div className="flex items-start justify-between mb-3">
              <div
                className="w-9 h-9 rounded flex items-center justify-center"
                style={{ background: `${t.color}18`, border: `1px solid ${t.color}44` }}
              >
                <Icon size={18} style={{ color: t.color }} />
              </div>
              <div
                className="flex items-center gap-1 px-2 py-0.5 rounded-full"
                style={{ background: "#ff224418", border: "1px solid #ff224433" }}
              >
                <AlertTriangle size={9} style={{ color: "#ff2244" }} />
                <span style={{ color: "#ff2244", fontSize: "9px", fontWeight: 700, letterSpacing: "0.1em", fontFamily: "'JetBrains Mono', monospace" }}>CRITICAL</span>
              </div>
            </div>

            <div style={{ fontFamily: "'Rajdhani', sans-serif" }}>
              <div style={{ color: "#8aadcc", fontSize: "11px", letterSpacing: "0.08em", marginBottom: "4px" }}>
                {t.label.toUpperCase()}
              </div>
              <div
                style={{
                  fontSize: "36px",
                  fontWeight: 700,
                  color: t.color,
                  lineHeight: 1,
                  textShadow: `0 0 20px ${t.color}66`,
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              >
                {t.critical}
              </div>
              <div style={{ color: "#5a8aaa", fontSize: "10px", marginTop: "2px" }}>confidence score</div>
            </div>

            <div className="flex items-center justify-between mt-3 pt-3" style={{ borderTop: `1px solid ${t.color}1a` }}>
              <span style={{ color: "#5a8aaa", fontSize: "11px", fontFamily: "'JetBrains Mono', monospace" }}>
                {t.count} vectors
              </span>
              <div className="flex items-center gap-1">
                <TrendingUp size={11} style={{ color: "#22c55e" }} />
                <span style={{ color: "#22c55e", fontSize: "11px", fontFamily: "'JetBrains Mono', monospace" }}>{t.trend}</span>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
