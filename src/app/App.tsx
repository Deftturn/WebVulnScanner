// @ts-nocheck

import { useState, useEffect, useRef } from "react";
import { Sidebar } from "./components/Sidebar";
import { HeroCards } from "./components/HeroCards";
import { ScanPanel } from "./components/ScanPanel";
import { ModelInsights } from "./components/ModelInsights";
import { ApiStatus } from "./components/ApiStatus";
import { ScanHistory } from "./components/LogsFeed";
import { Shield, Clock, Bell, RefreshCw } from "lucide-react";

const API_BASE = "http://127.0.0.1:8000";

function TopBar({ section }: { section: string }) {
  const labels: Record<string, string> = {
    dashboard: "Dashboard", scan: "Scan Target", insights: "Model Insights", api: "API Status", logs: "Logs",
  };
  const now = new Date();
  const timeStr = now.toLocaleTimeString("en-US", { hour12: false });

  return (
    <div className="flex items-center gap-4 px-6 py-3.5"
      style={{ background: "#070f1e", borderBottom: "1px solid rgba(0,212,255,0.12)", fontFamily: "'Rajdhani', sans-serif" }}>
      <div className="flex items-center gap-2">
        <Shield size={14} style={{ color: "#00d4ff" }} />
        <span style={{ color: "#5a8aaa", fontSize: "12px", letterSpacing: "0.06em" }}>WEBSEC</span>
        <span style={{ color: "#3a5a72", fontSize: "12px" }}>/</span>
        <span style={{ color: "#e2f0ff", fontSize: "13px", fontWeight: 600, letterSpacing: "0.08em" }}>{labels[section] ?? section}</span>
      </div>
      <div className="ml-auto flex items-center gap-4">
        <div className="flex items-center gap-1.5" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
          <Clock size={12} style={{ color: "#5a8aaa" }} />
          <span style={{ color: "#5a8aaa", fontSize: "11px" }}>{timeStr} UTC</span>
        </div>
        <button className="p-1.5 rounded transition-colors hover:bg-cyan-400/10" style={{ color: "#5a8aaa" }}><Bell size={14} /></button>
        <button className="p-1.5 rounded transition-colors hover:bg-cyan-400/10" style={{ color: "#5a8aaa" }}><RefreshCw size={14} /></button>
      </div>
    </div>
  );
}

function DashboardHome({ scanResults, scanning, scanError, scanProgress, scanLog, scanUrl, setScanUrl, onScanStart, onScanComplete, onScanError, onCancelScan }: any) {
  const [stats, setStats] = useState({ total_scans: 0, total_findings: 0, avg_confidence: 0 });

  useEffect(() => {
    fetch(`${API_BASE}/scan-stats`)
      .then(r => r.json()).then(d => setStats(d)).catch(() => {});
  }, [scanResults]);

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-4" style={{ fontFamily: "'Rajdhani', sans-serif" }}>
          <div className="w-1 h-4 rounded" style={{ background: "#00d4ff" }} />
          <span style={{ color: "#8aadcc", fontSize: "12px", fontWeight: 600, letterSpacing: "0.12em" }}>THREAT OVERVIEW · REAL-TIME</span>
        </div>
        <HeroCards />
      </div>
      <div>
        <div className="flex items-center gap-2 mb-4" style={{ fontFamily: "'Rajdhani', sans-serif" }}>
          <div className="w-1 h-4 rounded" style={{ background: "#aa44ff" }} />
          <span style={{ color: "#8aadcc", fontSize: "12px", fontWeight: 600, letterSpacing: "0.12em" }}>QUICK SCAN</span>
        </div>
        <ScanPanel
          scanResults={scanResults} scanning={scanning} scanError={scanError}
          scanProgress={scanProgress} scanLog={scanLog}
          scanUrl={scanUrl} setScanUrl={setScanUrl}
          onScanStart={onScanStart} onScanComplete={onScanComplete} onScanError={onScanError}
          onCancelScan={onCancelScan}
        />
      </div>
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: "Total Scans", value: stats.total_scans, sub: "All time", color: "#00d4ff" },
          { label: "Vulnerabilities Found", value: stats.total_findings, sub: "Across all scans", color: "#ff2244" },
          { label: "Avg. Confidence", value: `${stats.avg_confidence}%`, sub: "DataRobot XGBoost", color: "#22c55e" },
        ].map((stat) => (
          <div key={stat.label} className="rounded-lg px-5 py-4"
            style={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.12)", fontFamily: "'Rajdhani', sans-serif" }}>
            <div style={{ color: "#5a8aaa", fontSize: "11px", letterSpacing: "0.1em", marginBottom: "6px" }}>{stat.label.toUpperCase()}</div>
            <div style={{ color: stat.color, fontSize: "28px", fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", lineHeight: 1, textShadow: `0 0 16px ${stat.color}44` }}>{stat.value}</div>
            <div style={{ color: "#5a8aaa", fontSize: "11px", marginTop: "4px" }}>{stat.sub}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

const IDLE_PROGRESS = { phase: "idle" };

const formatAttackType = (key: string, checkType: string, attackType: string): string => {
  if (attackType && attackType !== "unknown") return attackType;
  if (checkType === "missing_headers") return "Missing Security Headers";
  if (checkType === "exposed_path") return "Exposed Sensitive Path";
  if (checkType === "debug_mode") return "Debug Mode Enabled";
  if (checkType?.startsWith("exposed_")) return checkType.replace("exposed_", "Exposed ").replace(/_/g, " ");
  return key.replace("_report", "").replace(/_/g, " ");
};

export default function App() {
  const [activeSection, setActiveSection] = useState("dashboard");
  const [scanResults, setScanResults] = useState<any[]>([]);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState("");
  const [scanProgress, setScanProgress] = useState<any>(IDLE_PROGRESS);
  const [scanLog, setScanLog] = useState("");
  const [scanUrl, setScanUrl] = useState("");
  const pollRef = useRef<any>(null);
  const seenActivePhaseRef = useRef(false);

  const stopPolling = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  const handleScanComplete = (r: any[]) => {
    setScanning(false);
    setScanResults(r);
  };

  const handleScanError = (e: string) => {
    setScanning(false);
    setScanError(e);
    stopPolling();
  };

  const fetchAndCompleteScan = async () => {
    try {
      const res = await fetch(`${API_BASE}/scan-results`);
      const data = await res.json();
      const findings: any[] = [];
      if (data.reports) {
        for (const [key, report] of Object.entries<any>(data.reports)) {
          for (const r of report.results || []) {
            findings.push({
              severity: r.ai_severity || r.severity || "UNKNOWN",
              confidence: r.ai_confidence || r.confidence || 0,
              attack_type: formatAttackType(key, r.check_type || "", r.attack_type || ""),
              model: r.model || "DataRobot", fix: r.fix || "Review and patch."
            });
          }
        }
      }
      handleScanComplete(findings);
    } catch {
      handleScanError("Scan finished but results couldn't be loaded.");
    }
  };

  const startPolling = () => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/scan-progress`);
        if (!res.ok) return;
        const data = await res.json();

        // Also fetch the log
        try {
          const logRes = await fetch(`${API_BASE}/scan-log`);
          const logData = await logRes.json();
          if (logData.log) setScanLog(logData.log);
        } catch {}

        if (data.phase === "starting" || data.phase === "crawling" || data.phase === "testing") {
          seenActivePhaseRef.current = true;
          setScanProgress(data);
          return;
        }

        if (data.phase === "complete") {
          if (!seenActivePhaseRef.current) return;
          setScanProgress(data);
          stopPolling();
          if (data.error) {
            handleScanError(data.error);
          } else {
            fetchAndCompleteScan();
          }
          return;
        }

        setScanProgress(data);
      } catch {}
    }, 1500);
  };

  const handleScanStart = (v: boolean) => {
    setScanning(v);
    if (v) {
      setScanResults([]);
      setScanError("");
      setScanProgress({ phase: "starting" });
      setScanLog("");
      seenActivePhaseRef.current = false;
      startPolling();
    } else {
      stopPolling();
    }
  };

  const handleCancelScan = () => {
    stopPolling();
    setScanning(false);
    setScanError("Scan cancelled.");
    setScanProgress(IDLE_PROGRESS);
    setScanLog("");
  };

  const scanProps = {
    scanResults, scanning, scanError, scanProgress, scanLog, scanUrl, setScanUrl,
    onScanStart: handleScanStart, onScanComplete: handleScanComplete, onScanError: handleScanError,
    onCancelScan: handleCancelScan,
  };

  useEffect(() => {
    return () => stopPolling();
  }, []);

  const renderContent = () => {
    switch (activeSection) {
      case "dashboard": return <DashboardHome {...scanProps} />;
      case "scan": return <ScanPanel {...scanProps} />;
      case "insights": return <ModelInsights />;
      case "api": return <ApiStatus />;
      case "logs": return <ScanHistory />;
      default: return <DashboardHome {...scanProps} />;
    }
  };

  return (
    <div className="size-full flex" style={{ background: "#050b12", fontFamily: "'Rajdhani', sans-serif" }}>
      <Sidebar activeSection={activeSection} onNavigate={setActiveSection} />
      <div className="flex-1 flex flex-col min-w-0" style={{ marginLeft: "224px" }}>
        <TopBar section={activeSection} />
        <main className="flex-1 overflow-y-auto px-6 py-6"
          style={{ background: "radial-gradient(ellipse at 20% 0%, rgba(0,212,255,0.03) 0%, transparent 50%), #050b12" }}>
          {renderContent()}
        </main>
      </div>
      <div className="pointer-events-none fixed inset-0 z-50"
        style={{ background: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.015) 2px, rgba(0,0,0,0.015) 4px)" }} />
    </div>
  );
}