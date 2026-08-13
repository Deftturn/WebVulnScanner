// @ts-nocheck

import { Shield, Target, Brain, Wifi, ScrollText, ChevronRight } from "lucide-react";

interface SidebarProps {
  activeSection: string;
  onNavigate: (section: string) => void;
}

const navItems = [
  { id: "dashboard", label: "Dashboard", icon: Shield },
  { id: "scan", label: "Scan Target", icon: Target },
  { id: "insights", label: "Model Insights", icon: Brain },
  { id: "api", label: "API Status", icon: Wifi },
  { id: "logs", label: "Logs", icon: ScrollText },
];

export function Sidebar({ activeSection, onNavigate }: SidebarProps) {
  return (
    <aside
      style={{ fontFamily: "'Rajdhani', sans-serif" }}
      className="fixed left-0 top-0 h-full w-56 flex flex-col z-20"
      css-border="right"
    >
      <div
        className="h-full flex flex-col"
        style={{
          background: "linear-gradient(180deg, #070f1e 0%, #050b12 100%)",
          borderRight: "1px solid rgba(0,212,255,0.15)",
        }}
      >
        {/* Logo */}
        <div className="px-5 py-6 border-b" style={{ borderColor: "rgba(0,212,255,0.12)" }}>
          <div className="flex items-center gap-2">
            <div
              className="w-8 h-8 rounded flex items-center justify-center"
              style={{ background: "linear-gradient(135deg, #00d4ff 0%, #0066cc 100%)" }}
            >
              <Shield size={16} className="text-white" />
            </div>
            <div>
              <div style={{ color: "#00d4ff", letterSpacing: "0.12em", fontSize: "13px", fontWeight: 700 }}>WEBSEC</div>
              <div style={{ color: "#5a8aaa", fontSize: "9px", letterSpacing: "0.2em" }}>SEC · AI · v4.2</div>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeSection === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onNavigate(item.id)}
                className="w-full flex items-center gap-3 px-3 py-2.5 rounded transition-all duration-200 group"
                style={{
                  background: isActive ? "rgba(0,212,255,0.08)" : "transparent",
                  borderLeft: isActive ? "2px solid #00d4ff" : "2px solid transparent",
                  color: isActive ? "#00d4ff" : "#5a8aaa",
                }}
              >
                <Icon size={16} />
                <span style={{ fontSize: "13px", fontWeight: isActive ? 600 : 500, letterSpacing: "0.06em" }}>
                  {item.label}
                </span>
                {isActive && <ChevronRight size={12} className="ml-auto" />}
              </button>
            );
          })}
        </nav>

        {/* System Status */}
        <div className="px-4 py-4 border-t" style={{ borderColor: "rgba(0,212,255,0.12)" }}>
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span style={{ color: "#5a8aaa", fontSize: "11px", letterSpacing: "0.1em" }}>SYSTEM STATUS</span>
              <div className="flex items-center gap-1.5">
                <div className="w-1.5 h-1.5 rounded-full bg-green-400" style={{ boxShadow: "0 0 6px #22c55e" }} />
                <span style={{ color: "#22c55e", fontSize: "10px", fontWeight: 600 }}>ONLINE</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span style={{ color: "#5a8aaa", fontSize: "11px", letterSpacing: "0.1em" }}>API</span>
              <div className="flex items-center gap-1.5">
                <div className="w-1.5 h-1.5 rounded-full bg-cyan-400" style={{ boxShadow: "0 0 6px #00d4ff" }} />
                <span style={{ color: "#00d4ff", fontSize: "10px", fontWeight: 600 }}>CONNECTED</span>
              </div>
            </div>
          </div>
        </div>

        {/* User Profile */}
        <div className="px-4 py-3 border-t" style={{ borderColor: "rgba(0,212,255,0.12)" }}>
          <div className="flex items-center gap-2.5">
            <div
              className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold"
              style={{ background: "linear-gradient(135deg, #00d4ff22, #0066cc44)", border: "1px solid rgba(0,212,255,0.3)", color: "#00d4ff" }}
            >
              AX
            </div>
            <div>
              <div style={{ color: "#e2f0ff", fontSize: "12px", fontWeight: 600 }}>Analyst</div>
              <div style={{ color: "#5a8aaa", fontSize: "10px" }}>Red Team · L3</div>
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
}
