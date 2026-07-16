import { useState, useEffect, useRef } from "react";
import { ScrollText, AlertTriangle, Info, CheckCircle2, XCircle, Filter } from "lucide-react";

type LogLevel = "CRIT" | "WARN" | "INFO" | "OK" | "ERR";

interface LogEntry {
  id: number;
  ts: string;
  level: LogLevel;
  source: string;
  message: string;
}

const levelColor: Record<LogLevel, string> = {
  CRIT: "#ff2244",
  WARN: "#ffcc00",
  INFO: "#00d4ff",
  OK: "#22c55e",
  ERR: "#ff8800",
};

const levelIcon: Record<LogLevel, React.ReactNode> = {
  CRIT: <AlertTriangle size={11} />,
  WARN: <AlertTriangle size={11} />,
  INFO: <Info size={11} />,
  OK: <CheckCircle2 size={11} />,
  ERR: <XCircle size={11} />,
};

const LOG_POOL: Omit<LogEntry, "id" | "ts">[] = [
  { level: "CRIT", source: "scanner.core", message: "SQL Injection detected at /api/users?id=' OR 1=1--" },
  { level: "CRIT", source: "xss.detector", message: "Stored XSS payload found in <script>alert('xss')</script>" },
  { level: "WARN", source: "auth.module", message: "Brute force attempt detected from 203.0.113.42 (14 attempts)" },
  { level: "OK", source: "scanner.core", message: "Scan completed: target.example.com (82 vectors tested)" },
  { level: "INFO", source: "model.predict", message: "BERT-sec inference completed in 318ms (confidence: 0.9793)" },
  { level: "ERR", source: "api.export", message: "Report export timeout after 30s — retrying (attempt 2/3)" },
  { level: "INFO", source: "crawler.web", message: "Crawled 47 pages, discovered 12 new endpoints" },
  { level: "CRIT", source: "data.leak", message: "Sensitive data exposure: PII fields in /api/profile response" },
  { level: "OK", source: "owasp.mapper", message: "OWASP Top-10 classification complete — 6/10 categories flagged" },
  { level: "WARN", source: "misconfig", message: "CORS policy misconfiguration: wildcard origin permitted on /api/*" },
  { level: "INFO", source: "scheduler", message: "Next scheduled scan queued: api.prod.corp (T+00:04:17)" },
  { level: "ERR", source: "model.predict", message: "GPU memory pressure — falling back to CPU inference" },
  { level: "OK", source: "auth.module", message: "Token rotation complete for service account sentinel-svc@corp" },
  { level: "CRIT", source: "ssrf.detector", message: "SSRF attempt blocked: internal metadata endpoint probed" },
  { level: "INFO", source: "scanner.core", message: "Rate limiting applied: 120 req/s cap enforced on target" },
];

function makeTimestamp() {
  const now = new Date();
  return `${now.toTimeString().slice(0, 8)}.${String(now.getMilliseconds()).padStart(3, "0")}`;
}

let idCounter = 100;

function generateLog(): LogEntry {
  const template = LOG_POOL[Math.floor(Math.random() * LOG_POOL.length)];
  return { ...template, id: idCounter++, ts: makeTimestamp() };
}

const INITIAL_LOGS: LogEntry[] = Array.from({ length: 12 }, (_, i) => ({
  ...LOG_POOL[i % LOG_POOL.length],
  id: i,
  ts: makeTimestamp(),
}));

const ALL_LEVELS: LogLevel[] = ["CRIT", "ERR", "WARN", "OK", "INFO"];

export function LogsFeed() {
  const [logs, setLogs] = useState<LogEntry[]>(INITIAL_LOGS);
  const [filter, setFilter] = useState<LogLevel | "ALL">("ALL");
  const [paused, setPaused] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (paused) return;
    const iv = setInterval(() => {
      setLogs((prev) => {
        const next = [generateLog(), ...prev].slice(0, 200);
        return next;
      });
    }, 2200);
    return () => clearInterval(iv);
  }, [paused]);

  useEffect(() => {
    if (!paused) bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs, paused]);

  const displayed = filter === "ALL" ? logs : logs.filter((l) => l.level === filter);

  return (
    <div className="space-y-4" style={{ fontFamily: "'Rajdhani', sans-serif" }}>
      <div className="rounded-lg overflow-hidden" style={{ background: "#0a1628", border: "1px solid rgba(0,212,255,0.15)" }}>
        {/* Header */}
        <div className="flex items-center gap-3 px-5 py-3" style={{ borderBottom: "1px solid rgba(0,212,255,0.1)" }}>
          <ScrollText size={14} style={{ color: "#00d4ff" }} />
          <span style={{ color: "#00d4ff", fontSize: "13px", fontWeight: 600, letterSpacing: "0.12em" }}>
            ACTIVITY FEED
          </span>
          <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse ml-1" style={{ boxShadow: "0 0 6px #22c55e" }} />
          <div className="ml-auto flex items-center gap-2">
            <Filter size={12} style={{ color: "#5a8aaa" }} />
            <div className="flex gap-1">
              {(["ALL", ...ALL_LEVELS] as const).map((l) => (
                <button
                  key={l}
                  onClick={() => setFilter(l)}
                  className="px-2 py-0.5 rounded transition-all"
                  style={{
                    background: filter === l ? (l === "ALL" ? "rgba(0,212,255,0.15)" : `${levelColor[l as LogLevel]}18`) : "transparent",
                    border: `1px solid ${filter === l ? (l === "ALL" ? "rgba(0,212,255,0.3)" : `${levelColor[l as LogLevel]}44`) : "rgba(0,212,255,0.1)"}`,
                    color: filter === l ? (l === "ALL" ? "#00d4ff" : levelColor[l as LogLevel]) : "#5a8aaa",
                    fontSize: "10px",
                    letterSpacing: "0.08em",
                  }}
                >
                  {l}
                </button>
              ))}
            </div>
            <button
              onClick={() => setPaused((v) => !v)}
              className="px-2 py-0.5 rounded ml-1"
              style={{
                background: paused ? "rgba(255,204,0,0.1)" : "rgba(34,197,94,0.08)",
                border: `1px solid ${paused ? "rgba(255,204,0,0.3)" : "rgba(34,197,94,0.3)"}`,
                color: paused ? "#ffcc00" : "#22c55e",
                fontSize: "10px",
                letterSpacing: "0.08em",
              }}
            >
              {paused ? "PAUSED" : "LIVE"}
            </button>
          </div>
        </div>

        {/* Log entries */}
        <div
          className="overflow-y-auto"
          style={{ maxHeight: "440px", fontFamily: "'JetBrains Mono', monospace", fontSize: "11px" }}
        >
          {displayed.map((log) => {
            const c = levelColor[log.level];
            return (
              <div
                key={log.id}
                className="flex items-start gap-3 px-4 py-2 transition-colors hover:bg-cyan-400/5"
                style={{ borderBottom: "1px solid rgba(0,212,255,0.04)" }}
              >
                <span style={{ color: "#3a5a72", flexShrink: 0 }}>{log.ts}</span>
                <span
                  className="flex items-center gap-1 px-1.5 py-0.5 rounded flex-shrink-0"
                  style={{ background: `${c}12`, color: c, border: `1px solid ${c}30`, minWidth: "48px", justifyContent: "center" }}
                >
                  {levelIcon[log.level]}
                  {log.level}
                </span>
                <span style={{ color: "#00d4ff88", flexShrink: 0 }}>[{log.source}]</span>
                <span style={{ color: log.level === "CRIT" ? "#ffc0c8" : log.level === "ERR" ? "#ffd0b0" : "#8aadcc" }}>
                  {log.message}
                </span>
              </div>
            );
          })}
          <div ref={bottomRef} />
        </div>

        {/* Footer stats */}
        <div className="px-5 py-2.5 flex gap-5" style={{ borderTop: "1px solid rgba(0,212,255,0.08)" }}>
          {ALL_LEVELS.map((l) => {
            const cnt = logs.filter((log) => log.level === l).length;
            return (
              <div key={l} className="flex items-center gap-1.5">
                <div className="w-1.5 h-1.5 rounded-full" style={{ background: levelColor[l] }} />
                <span style={{ color: "#5a8aaa", fontSize: "10px" }}>{l}: </span>
                <span style={{ color: levelColor[l], fontSize: "10px", fontFamily: "'JetBrains Mono', monospace" }}>{cnt}</span>
              </div>
            );
          })}
          <span style={{ color: "#5a8aaa", fontSize: "10px", marginLeft: "auto" }}>
            {logs.length} entries · {paused ? "paused" : "streaming"}
          </span>
        </div>
      </div>
    </div>
  );
}
