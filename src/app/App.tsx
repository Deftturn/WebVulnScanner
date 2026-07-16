import { useState } from "react";
import { Sidebar } from "./components/Sidebar";
import { HeroCards } from "./components/HeroCards";
import { ScanPanel } from "./components/ScanPanel";
import { ModelInsights } from "./components/ModelInsights";
import { ApiStatus } from "./components/ApiStatus";
import { LogsFeed } from "./components/LogsFeed";
import { Shield, Clock, Bell, RefreshCw } from "lucide-react";

function TopBar({ section }: { section: string }) {
  const labels: Record<string, string> = {
    dashboard: "Dashboard",
    scan: "Scan Target",
    insights: "Model Insights",
    api: "API Status",
    logs: "Logs",
  };

  const now = new Date();
  const timeStr = now.toLocaleTimeString("en-US", { hour12: false });

  return (
    <div
      className="flex items-center gap-4 px-6 py-3.5"
      style={{
        background: "#070f1e",
        borderBottom: "1px solid rgba(0,212,255,0.12)",
        fontFamily: "'Rajdhani', sans-serif",
      }}
    >
      <div className="flex items-center gap-2">
        <Shield size={14} style={{ color: "#00d4ff" }} />
        <span style={{ color: "#5a8aaa", fontSize: "12px", letterSpacing: "0.06em" }}>SENTINEL</span>
        <span style={{ color: "#3a5a72", fontSize: "12px" }}>/</span>
        <span style={{ color: "#e2f0ff", fontSize: "13px", fontWeight: 600, letterSpacing: "0.08em" }}>
          {labels[section] ?? section}
        </span>
      </div>
      <div className="ml-auto flex items-center gap-4">
        <div className="flex items-center gap-1.5" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
          <Clock size={12} style={{ color: "#5a8aaa" }} />
          <span style={{ color: "#5a8aaa", fontSize: "11px" }}>{timeStr} UTC</span>
        </div>
        <button className="p-1.5 rounded transition-colors hover:bg-cyan-400/10" style={{ color: "#5a8aaa" }}>
          <Bell size={14} />
        </button>
        <button className="p-1.5 rounded transition-colors hover:bg-cyan-400/10" style={{ color: "#5a8aaa" }}>
          <RefreshCw size={14} />
        </button>
      </div>
    </div>
  );
}

function DashboardHome() {
  return (
    <div className="space-y-6">
      {/* Hero stat cards */}
      <div>
        <div
          className="flex items-center gap-2 mb-4"
          style={{ fontFamily: "'Rajdhani', sans-serif" }}
        >
          <div className="w-1 h-4 rounded" style={{ background: "#00d4ff" }} />
          <span style={{ color: "#8aadcc", fontSize: "12px", fontWeight: 600, letterSpacing: "0.12em" }}>
            THREAT OVERVIEW · REAL-TIME
          </span>
        </div>
        <HeroCards />
      </div>

      {/* Quick scan */}
      <div>
        <div className="flex items-center gap-2 mb-4" style={{ fontFamily: "'Rajdhani', sans-serif" }}>
          <div className="w-1 h-4 rounded" style={{ background: "#aa44ff" }} />
          <span style={{ color: "#8aadcc", fontSize: "12px", fontWeight: 600, letterSpacing: "0.12em" }}>
            QUICK SCAN
          </span>
        </div>
        <ScanPanel />
      </div>

      {/* Summary grid */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: "Total Scans Today", value: "247", sub: "+18 this hour", color: "#00d4ff" },
          { label: "Vulnerabilities Found", value: "104", sub: "82 critical severity", color: "#ff2244" },
          { label: "Avg. Confidence", value: "94.1%", sub: "BERT-sec + XGBoost", color: "#22c55e" },
        ].map((stat) => (
          <div
            key={stat.label}
            className="rounded-lg px-5 py-4"
            style={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.12)", fontFamily: "'Rajdhani', sans-serif" }}
          >
            <div style={{ color: "#5a8aaa", fontSize: "11px", letterSpacing: "0.1em", marginBottom: "6px" }}>{stat.label.toUpperCase()}</div>
            <div style={{ color: stat.color, fontSize: "28px", fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", lineHeight: 1, textShadow: `0 0 16px ${stat.color}44` }}>
              {stat.value}
            </div>
            <div style={{ color: "#5a8aaa", fontSize: "11px", marginTop: "4px" }}>{stat.sub}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function App() {
  const [activeSection, setActiveSection] = useState("dashboard");

  const renderContent = () => {
    switch (activeSection) {
      case "dashboard": return <DashboardHome />;
      case "scan": return <ScanPanel />;
      case "insights": return <ModelInsights />;
      case "api": return <ApiStatus />;
      case "logs": return <LogsFeed />;
      default: return <DashboardHome />;
    }
  };

  return (
    <div
      className="size-full flex"
      style={{ background: "#050b12", fontFamily: "'Rajdhani', sans-serif" }}
    >
      {/* Sidebar */}
      <Sidebar activeSection={activeSection} onNavigate={setActiveSection} />

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0" style={{ marginLeft: "224px" }}>
        <TopBar section={activeSection} />

        <main
          className="flex-1 overflow-y-auto px-6 py-6"
          style={{
            background: "radial-gradient(ellipse at 20% 0%, rgba(0,212,255,0.03) 0%, transparent 50%), #050b12",
          }}
        >
          {renderContent()}
        </main>
      </div>

      {/* Scanline overlay */}
      <div
        className="pointer-events-none fixed inset-0 z-50"
        style={{
          background: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.015) 2px, rgba(0,0,0,0.015) 4px)",
        }}
      />
    </div>
  );
}
