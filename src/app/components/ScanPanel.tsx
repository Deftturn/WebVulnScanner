import { useState, useEffect, useRef } from "react";
import { Search, Globe, ChevronDown, AlertTriangle, CheckCircle2, Loader2, X } from "lucide-react";

const LANGUAGES = ["Python", "JavaScript", "PHP", "Java", "Go", "Ruby", "C#", "Rust"];

const SCAN_STEPS = [
  { label: "Crawling pages...", delay: 600 },
  { label: "Injectors running...", delay: 1400 },
  { label: "AI Model analyzing...", delay: 2400 },
  { label: "OWASP mapping complete", delay: 3600 },
];

const SCAN_RESULT = {
  severity: "CRITICAL",
  attackType: "SQL Injection",
  confidence: 0.9793,
  endpoint: "/api/users?id=1",
  payload: "' OR '1'='1' --",
  cve: "CVE-2024-38812",
  remediation: "Use parameterized queries / prepared statements",
};

export function ScanPanel() {
  const [url, setUrl] = useState("https://target.example.com");
  const [lang, setLang] = useState("Python");
  const [langOpen, setLangOpen] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [steps, setSteps] = useState<number[]>([]);
  const [result, setResult] = useState(false);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  const startScan = () => {
    if (scanning) return;
    setSteps([]);
    setResult(false);
    setScanning(true);

    SCAN_STEPS.forEach((step, i) => {
      const t = setTimeout(() => {
        setSteps((prev) => [...prev, i]);
        if (i === SCAN_STEPS.length - 1) {
          const rt = setTimeout(() => {
            setResult(true);
            setScanning(false);
          }, 600);
          timers.current.push(rt);
        }
      }, step.delay);
      timers.current.push(t);
    });
  };

  const reset = () => {
    timers.current.forEach(clearTimeout);
    timers.current = [];
    setSteps([]);
    setResult(false);
    setScanning(false);
  };

  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  return (
    <div
      className="rounded-lg p-5"
      style={{
        background: "#0a1628",
        border: "1px solid rgba(0,212,255,0.15)",
        fontFamily: "'Rajdhani', sans-serif",
      }}
    >
      <div className="flex items-center gap-2 mb-4">
        <div className="w-2 h-2 rounded-full bg-cyan-400" style={{ boxShadow: "0 0 8px #00d4ff" }} />
        <span style={{ color: "#00d4ff", fontSize: "13px", fontWeight: 600, letterSpacing: "0.12em" }}>
          LIVE SCAN PANEL
        </span>
      </div>

      {/* Input row */}
      <div className="flex gap-3 mb-4">
        {/* URL input */}
        <div className="flex-1 flex items-center gap-2 px-3 py-2.5 rounded" style={{ background: "#050b12", border: "1px solid rgba(0,212,255,0.2)" }}>
          <Globe size={14} style={{ color: "#5a8aaa" }} />
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter target URL..."
            className="flex-1 bg-transparent outline-none"
            style={{ color: "#e2f0ff", fontSize: "13px", fontFamily: "'JetBrains Mono', monospace" }}
          />
        </div>

        {/* Language dropdown */}
        <div className="relative">
          <button
            onClick={() => setLangOpen((v) => !v)}
            className="flex items-center gap-2 px-3 py-2.5 rounded"
            style={{ background: "#050b12", border: "1px solid rgba(0,212,255,0.2)", color: "#8aadcc", fontSize: "13px", minWidth: "120px" }}
          >
            {lang}
            <ChevronDown size={12} className="ml-auto" />
          </button>
          {langOpen && (
            <div
              className="absolute top-full mt-1 left-0 w-full rounded z-50"
              style={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.2)" }}
            >
              {LANGUAGES.map((l) => (
                <button
                  key={l}
                  onClick={() => { setLang(l); setLangOpen(false); }}
                  className="w-full text-left px-3 py-1.5 transition-colors hover:bg-cyan-400/10"
                  style={{ color: l === lang ? "#00d4ff" : "#8aadcc", fontSize: "13px" }}
                >
                  {l}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Scan button */}
        <button
          onClick={startScan}
          disabled={scanning}
          className="flex items-center gap-2 px-5 py-2.5 rounded font-semibold transition-all duration-200"
          style={{
            background: scanning ? "rgba(0,212,255,0.1)" : "linear-gradient(135deg, #00d4ff 0%, #0088cc 100%)",
            color: scanning ? "#5a8aaa" : "#050b12",
            border: "1px solid rgba(0,212,255,0.4)",
            fontSize: "13px",
            letterSpacing: "0.08em",
            cursor: scanning ? "not-allowed" : "pointer",
          }}
        >
          {scanning ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
          {scanning ? "SCANNING..." : "SCAN"}
        </button>
      </div>

      {/* Terminal output */}
      <div
        className="rounded p-4 min-h-[180px]"
        style={{ background: "#030810", border: "1px solid rgba(0,212,255,0.1)", fontFamily: "'JetBrains Mono', monospace" }}
      >
        {/* Header */}
        <div className="flex items-center gap-2 mb-3 pb-2" style={{ borderBottom: "1px solid rgba(0,212,255,0.08)" }}>
          <div className="flex gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full" style={{ background: "#ff2244" }} />
            <div className="w-2.5 h-2.5 rounded-full" style={{ background: "#ffcc00" }} />
            <div className="w-2.5 h-2.5 rounded-full" style={{ background: "#22c55e" }} />
          </div>
          <span style={{ color: "#5a8aaa", fontSize: "10px", letterSpacing: "0.1em" }}>sentinel@scan:~$</span>
          {(scanning || result) && (
            <button onClick={reset} className="ml-auto" style={{ color: "#5a8aaa" }}>
              <X size={12} />
            </button>
          )}
        </div>

        {steps.length === 0 && !scanning && !result && (
          <div style={{ color: "#5a8aaa", fontSize: "12px" }}>
            <span style={{ color: "#00d4ff" }}>$</span> Ready. Enter target URL and click SCAN.
          </div>
        )}

        {/* Steps */}
        <div className="space-y-2">
          {SCAN_STEPS.map((step, i) => {
            const done = steps.includes(i);
            const active = scanning && !done && steps.length === i;
            return (
              <div key={i} className="flex items-center gap-2" style={{ opacity: done || active ? 1 : 0.3 }}>
                {done ? (
                  <CheckCircle2 size={13} style={{ color: "#22c55e", flexShrink: 0 }} />
                ) : active ? (
                  <Loader2 size={13} className="animate-spin" style={{ color: "#00d4ff", flexShrink: 0 }} />
                ) : (
                  <div className="w-3 h-3 rounded-full" style={{ border: "1px solid #5a8aaa", flexShrink: 0 }} />
                )}
                <span style={{ color: done ? "#22c55e" : active ? "#00d4ff" : "#5a8aaa", fontSize: "12px" }}>
                  {step.label}
                </span>
              </div>
            );
          })}
        </div>

        {/* Result */}
        {result && (
          <div
            className="mt-4 p-3 rounded"
            style={{ background: "rgba(255,34,68,0.06)", border: "1px solid rgba(255,34,68,0.25)" }}
          >
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle size={13} style={{ color: "#ff2244" }} />
              <span style={{ color: "#ff2244", fontSize: "11px", fontWeight: 700, letterSpacing: "0.1em" }}>
                VULNERABILITY DETECTED
              </span>
            </div>
            <div className="grid grid-cols-2 gap-y-1.5 gap-x-6">
              {[
                ["Severity", SCAN_RESULT.severity, "#ff2244"],
                ["Attack Type", SCAN_RESULT.attackType, "#ff8800"],
                ["Confidence", SCAN_RESULT.confidence.toString(), "#22c55e"],
                ["Endpoint", SCAN_RESULT.endpoint, "#8aadcc"],
                ["Payload", SCAN_RESULT.payload, "#aa44ff"],
                ["CVE", SCAN_RESULT.cve, "#00d4ff"],
              ].map(([k, v, c]) => (
                <div key={k} className="flex gap-2">
                  <span style={{ color: "#5a8aaa", fontSize: "11px", minWidth: "80px" }}>{k}:</span>
                  <span style={{ color: c, fontSize: "11px" }}>{v}</span>
                </div>
              ))}
            </div>
            <div className="mt-2 pt-2" style={{ borderTop: "1px solid rgba(255,34,68,0.1)" }}>
              <span style={{ color: "#5a8aaa", fontSize: "11px" }}>Fix: </span>
              <span style={{ color: "#22c55e", fontSize: "11px" }}>{SCAN_RESULT.remediation}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
