import { useState, useCallback, useEffect, useRef } from "react";
import jsQR from "jsqr";
import Tesseract from 'tesseract.js';
import { GoogleOAuthProvider, GoogleLogin } from '@react-oauth/google';

const API_BASE_URL = "/api";

const KILL_CHAIN_STAGES = [
  { name: "Reconnaissance", icon: "🔍", color: "#60a5fa", desc: "Attacker gathers target info" },
  { name: "Weaponization", icon: "⚙️", color: "#a78bfa", desc: "Building the attack payload" },
  { name: "Delivery", icon: "📨", color: "#fbbf24", desc: "Transmitting weapon to victim" },
  { name: "Exploitation", icon: "💥", color: "#f97316", desc: "Exploiting a vulnerability" },
  { name: "Installation", icon: "📦", color: "#f87171", desc: "Installing backdoor or malware" },
  { name: "C2", icon: "📡", color: "#e879f9", desc: "Attacker command & control" },
  { name: "Actions on Objectives", icon: "🎯", color: "#ef4444", desc: "Final goal - data theft/damage" },
];

const THREAT_COLORS = {
  LOW: { bg: "#0d2b1a", border: "#1a5c35", text: "#4ade80", badge: "#166534", dot: "#22c55e" },
  MEDIUM: { bg: "#2b1f0a", border: "#854d0e", text: "#fbbf24", badge: "#713f12", dot: "#f59e0b" },
  HIGH: { bg: "#2b0f0a", border: "#991b1b", text: "#f87171", badge: "#7f1d1d", dot: "#ef4444" },
  CRITICAL: { bg: "#1a0a2b", border: "#6b21a8", text: "#c084fc", badge: "#4a044e", dot: "#a855f7" },
};

const MODULES = [
  { id: "message", icon: "✉", label: "Threat Message", desc: "Analyze suspicious text or message", inputType: "textarea", placeholder: "Paste suspicious message, scam text, or threat communication here..." },
  { id: "url", icon: "🔗", label: "Phishing Link", desc: "Analyze a suspicious URL", inputType: "text", placeholder: "https://paytm-secure-login.xyz/verify..." },
  { id: "qr", icon: "▦", label: "QR Code Image", desc: "Upload QR code image to analyze", inputType: "image", placeholder: "Upload a QR code to decode and analyze..." },
  { id: "screenshot", icon: "🖼", label: "Screenshot Text", desc: "Upload screenshot to extract and analyze text", inputType: "image", placeholder: "Upload a screenshot for AI OCR analysis..." },
  { id: "ransomware", icon: "🛡️", label: "Ransomware Shield", desc: "Analyze system logs for encryption signals", inputType: "textarea", placeholder: "Paste suspicious command logs or ransom note text here..." },
  { id: "vault", icon: "🔒", label: "Secure Vault", desc: "AI-Monitored Encrypted File Storage", inputType: "vault" },
];

const getAnalysisSteps = (moduleId) => [
  "Initializing neural inspection engine...",
  "Establishing sandboxed environment...",
  moduleId === "url" ? "Parsing URL structure and DNS metadata..." : "Analyzing semantic content and pressure tactics...",
  moduleId === "url" ? "Cross-referencing brand impersonation databases..." : "Extracting suspicious entities and links...",
  "Mapping Cyber Kill Chain stage...",
  "Finalizing Threat Intelligence Report...",
];

async function fetchAnalysis(moduleId, input, isDemoMode) {
  if (moduleId === "train") {
    const formData = new FormData();
    formData.append("file", input);
    const res = await fetch(`${API_BASE_URL}/train`, {
      method: "POST",
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "Training failed. Check server.");
    }
    return res.json();
  }

  const res = await fetch(`${API_BASE_URL}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ moduleId, input, isDemoMode }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Analysis failed. Check server.");
  }
  return res.json();
}

function ScoreRing({ score, size = 80 }) {
  const r = (size / 2) - 8;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const color = score >= 80 ? "#f87171" : score >= 60 ? "#fbbf24" : score >= 40 ? "#60a5fa" : "#4ade80";
  return (
    <svg width={size} height={size} style={{ transform: "rotate(-90deg)", flexShrink: 0 }}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#1e293b" strokeWidth="6" />
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth="6"
        strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
        style={{ transition: "stroke-dashoffset 1s ease" }} />
      <text x="50%" y="50%" textAnchor="middle" dominantBaseline="middle"
        style={{ fill: color, fontSize: size*0.22, fontWeight: 700, transform: "rotate(90deg)", transformOrigin: "center", fontFamily: "monospace" }}>
        {score}
      </text>
    </svg>
  );
}

function KillChainView({ currentStage }) {
  const [hovered, setHovered] = useState(null);
  const currentIdx = KILL_CHAIN_STAGES.findIndex(s => s.name === currentStage);

  return (
    <div style={{ marginTop: 20 }}>
      <div style={{ color: "#94a3b8", fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", marginBottom: 14 }}>
        🔗 Cyber Kill Chain Stage Analysis
      </div>
      <div style={{ display: "flex", gap: 0, overflowX: "auto" }}>
        {KILL_CHAIN_STAGES.map((stage, i) => {
          const isPast = i <= currentIdx;
          const isCurrent = i === currentIdx;
          const color = isCurrent ? stage.color : isPast ? "#334155" : "#1e293b";
          return (
            <div key={stage.name} style={{ flex: 1, minWidth: 68, position: "relative" }}
              onMouseEnter={() => setHovered(i)} onMouseLeave={() => setHovered(null)}>
              {/* Connector line */}
              {i > 0 && <div style={{ position: "absolute", top: 22, left: 0, width: "50%", height: 2, background: isPast ? "#334155" : "#1e293b" }} />}
              {i < KILL_CHAIN_STAGES.length - 1 && <div style={{ position: "absolute", top: 22, left: "50%", width: "50%", height: 2, background: isPast ? "#334155" : "#1e293b" }} />}
              
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", padding: "0 4px", textAlign: "center" }}>
                <div style={{
                  width: 44, height: 44, borderRadius: "50%", fontSize: 16,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  background: isCurrent ? `${stage.color}25` : isPast ? "#1e293b" : "#0f172a",
                  border: `2px solid ${isCurrent ? stage.color : isPast ? "#334155" : "#1e293b"}`,
                  boxShadow: isCurrent ? `0 0 18px ${stage.color}60` : "none",
                  transition: "all 0.3s", zIndex: 1, position: "relative",
                  cursor: "default"
                }}>
                  {stage.icon}
                </div>
                <div style={{ fontSize: 8, marginTop: 5, color: isCurrent ? stage.color : isPast ? "#64748b" : "#334155", fontWeight: isCurrent ? 700 : 400, lineHeight: 1.2 }}>
                  {stage.name}
                </div>
              </div>

              {/* Tooltip */}
              {hovered === i && (
                <div style={{
                  position: "absolute", bottom: "calc(100% + 8px)", left: "50%",
                  transform: "translateX(-50%)",
                  background: "#0f172a", border: `1px solid ${stage.color}`,
                  borderRadius: 8, padding: "8px 12px", width: 140, zIndex: 100,
                  fontSize: 10, color: "#e2e8f0", lineHeight: 1.5, textAlign: "center",
                  pointerEvents: "none",
                  boxShadow: `0 4px 20px ${stage.color}40`
                }}>
                  <div style={{ fontWeight: 700, color: stage.color, marginBottom: 4 }}>{stage.name}</div>
                  {stage.desc}
                </div>
              )}
            </div>
          );
        })}
      </div>
      {currentIdx >= 0 && (
        <div style={{ marginTop: 12, padding: "8px 12px", background: `${KILL_CHAIN_STAGES[currentIdx].color}15`, border: `1px solid ${KILL_CHAIN_STAGES[currentIdx].color}40`, borderRadius: 8 }}>
          <span style={{ color: KILL_CHAIN_STAGES[currentIdx].color, fontWeight: 700, fontSize: 12 }}>
            Active Stage: {KILL_CHAIN_STAGES[currentIdx].icon} {currentStage}
          </span>
          <span style={{ color: "#94a3b8", fontSize: 11, marginLeft: 8 }}>— {KILL_CHAIN_STAGES[currentIdx].desc}</span>
        </div>
      )}
    </div>
  );
}

function SOCStatsPanel({ stats, lastRefresh }) {
  const MODULE_ICONS = { message: "✉", url: "🔗", qr: "▦", screenshot: "🖼" };
  const MODULE_LABELS = { message: "Msg", url: "URL", qr: "QR", screenshot: "IMG" };

  if (!stats) return (
    <div style={{ background: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 12, padding: 20 }}>
      <div style={{ color: "#94a3b8", fontSize: 11, fontWeight: 700, letterSpacing: 2, textTransform: "uppercase", marginBottom: 12 }}>
        📊 SOC Analytics
      </div>
      <div style={{ color: "#475569", fontSize: 12, textAlign: "center", padding: 20 }}>Run first analysis to see stats</div>
    </div>
  );

  const total = stats.counts.reduce((a, b) => a + b.count, 0);
  const levelOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const sortedCounts = levelOrder.map(level => stats.counts.find(c => c.threatLevel === level) || { threatLevel: level, count: 0 });
  const avg = stats.avgStats || {};

  return (
    <div style={{ background: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 12, padding: 20, marginBottom: 16 }}>
      {/* Header with refresh */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <div style={{ color: "#94a3b8", fontSize: 11, fontWeight: 700, letterSpacing: 2, textTransform: "uppercase" }}>
          📊 SOC Analytics
        </div>
        <div style={{ color: "#334155", fontSize: 9, fontFamily: "monospace" }}>
          ↺ {lastRefresh}
        </div>
      </div>

      {/* Key Metrics Row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, marginBottom: 16 }}>
        {[
          { label: "Total Scans", value: total, color: "#0ea5e9" },
          { label: "Avg Confidence", value: `${Math.round(avg.avgConfidence || 0)}%`, color: "#4ade80" },
          { label: "Peak Risk", value: Math.round(avg.maxRisk || 0), color: "#f87171" },
        ].map(m => (
          <div key={m.label} style={{ background: "#0f172a", borderRadius: 8, padding: "10px 8px", textAlign: "center", border: "1px solid #1e293b" }}>
            <div style={{ color: m.color, fontSize: 18, fontWeight: 900, fontFamily: "monospace" }}>{m.value}</div>
            <div style={{ color: "#475569", fontSize: 9, marginTop: 2, letterSpacing: 0.5 }}>{m.label}</div>
          </div>
        ))}
      </div>

      {/* Threat Level Bars */}
      <div style={{ marginBottom: 16 }}>
        <div style={{ color: "#64748b", fontSize: 10, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", marginBottom: 8 }}>Threat Distribution</div>
        {sortedCounts.map(c => {
          const pct = total > 0 ? Math.round((c.count / total) * 100) : 0;
          const col = THREAT_COLORS[c.threatLevel]?.text || "#fff";
          return (
            <div key={c.threatLevel} style={{ marginBottom: 8 }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                <span style={{ color: col, fontSize: 10, fontWeight: 700 }}>{c.threatLevel}</span>
                <span style={{ color: "#64748b", fontSize: 10 }}>{c.count} ({pct}%)</span>
              </div>
              <div style={{ height: 5, background: "#1e293b", borderRadius: 3, overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${pct}%`, background: col, borderRadius: 3, transition: "width 1s ease", boxShadow: `0 0 8px ${col}60` }} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Module Type Breakdown */}
      {stats.moduleBreakdown?.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ color: "#64748b", fontSize: 10, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", marginBottom: 8 }}>Scanner Usage</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 4 }}>
            {(["message","url","qr","screenshot"]).map(modId => {
              const entry = stats.moduleBreakdown?.find(m => m.moduleId === modId);
              const count = entry?.count || 0;
              const pct = total > 0 ? Math.round((count / total) * 100) : 0;
              return (
                <div key={modId} style={{ background: "#0f172a", borderRadius: 6, padding: "6px 4px", textAlign: "center", border: `1px solid ${count > 0 ? "#1e3a5f" : "#0f172a"}` }}>
                  <div style={{ fontSize: 14 }}>{MODULE_ICONS[modId]}</div>
                  <div style={{ color: count > 0 ? "#0ea5e9" : "#334155", fontSize: 11, fontWeight: 700, fontFamily: "monospace" }}>{count}</div>
                  <div style={{ color: "#475569", fontSize: 8 }}>{MODULE_LABELS[modId]}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Kill Chain Distribution */}
      {stats.stages?.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ color: "#64748b", fontSize: 10, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", marginBottom: 8 }}>Kill Chain Distribution</div>
          {stats.stages.map((s) => {
            const stageInfo = KILL_CHAIN_STAGES.find(k => k.name === s.killChainStage);
            const pct = total > 0 ? Math.round((s.count / total) * 100) : 0;
            return (
              <div key={s.killChainStage} style={{ marginBottom: 6 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 2 }}>
                  <span style={{ fontSize: 10, color: stageInfo?.color || "#94a3b8" }}>{stageInfo?.icon} {s.killChainStage}</span>
                  <span style={{ fontSize: 10, color: "#64748b", fontFamily: "monospace" }}>{s.count}x</span>
                </div>
                <div style={{ height: 3, background: "#1e293b", borderRadius: 2, overflow: "hidden" }}>
                  <div style={{ height: "100%", width: `${pct}%`, background: stageInfo?.color || "#0ea5e9", borderRadius: 2, transition: "width 1s ease" }} />
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Top Threat Categories */}
      {stats.topCategories?.length > 0 && (
        <div>
          <div style={{ color: "#64748b", fontSize: 10, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", marginBottom: 8 }}>Top Threat Categories</div>
          {stats.topCategories.map((cat, i) => (
            <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", background: "#0f172a", borderRadius: 6, padding: "6px 8px", marginBottom: 4 }}>
              <span style={{ fontSize: 10, color: "#94a3b8", flex: 1, marginRight: 8 }}>{cat.category}</span>
              <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
                <span style={{ fontSize: 9, color: "#64748b", fontFamily: "monospace" }}>×{cat.count}</span>
                <span style={{ fontSize: 9, color: "#fbbf24", fontFamily: "monospace" }}>r:{Math.round(cat.avgRisk)}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function GlobalThreatMap() {
  const [events, setEvents] = useState([
    { id: 1, loc: "Mumbai", type: "MITM Detection", time: "Just Now", color: "#f87171" },
    { id: 2, loc: "Dubai", type: "WAF Trigger", time: "Just Now", color: "#fbbf24" }
  ]);
  const [activeMarkers, setActiveMarkers] = useState([]);
  const [utcTime, setUtcTime] = useState(new Date().toUTCString().slice(17, 25));

  useEffect(() => {
    const locations = ["Mumbai", "Dubai", "Tokyo", "Sydney"];
    const types = ["MITM Detection", "WAF Trigger", "DDoS Mitigation", "Payload Blocked"];
    const colors = ["#f87171", "#fbbf24", "#c084fc", "#60a5fa"];

    const interval = setInterval(() => {
      // Update UTC Clock
      setUtcTime(new Date().toUTCString().slice(17, 25));

      // Probability to add a new event
      if (Math.random() > 0.4) {
        const newEvent = {
          id: Date.now(),
          loc: locations[Math.floor(Math.random() * locations.length)],
          type: types[Math.floor(Math.random() * types.length)],
          time: "Just Now",
          color: colors[Math.floor(Math.random() * colors.length)]
        };
        setEvents(prev => [newEvent, ...prev.slice(0, 3)]);

        // Add matching map marker
        const newMarker = {
          id: Date.now(),
          top: `${30 + Math.random() * 40}%`,
          left: `${15 + Math.random() * 70}%`,
          color: newEvent.color
        };
        setActiveMarkers(prev => [...prev.slice(-3), newMarker]);
      }
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  const hotspots = [
    { top: "30%", left: "22%", label: "US", color: "#f87171", size: 10 },
    { top: "28%", left: "48%", label: "EU", color: "#fbbf24", size: 8 },
    { top: "32%", left: "72%", label: "IN", color: "#4ade80", size: 12 },
    { top: "52%", left: "84%", label: "SEA", color: "#c084fc", size: 7 },
    { top: "65%", left: "30%", label: "BR", color: "#fbbf24", size: 6 },
    { top: "32%", left: "62%", label: "RU", color: "#f87171", size: 9 },
  ];

  return (
    <div style={{ background: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 12, padding: 20, marginBottom: 16 }}>
      <div style={{ color: "#94a3b8", fontSize: 11, fontWeight: 700, letterSpacing: 2, textTransform: "uppercase", marginBottom: 12 }}>
        🌍 Global Threat Overlay
      </div>
      <div style={{ position: "relative", height: 160, background: "linear-gradient(180deg, #020c1a 0%, #041328 100%)", borderRadius: 8, overflow: "hidden", border: "1px solid #1e293b" }}>
        {/* Radar Sweep */}
        <div style={{
          position: "absolute", top: "50%", left: "50%", width: "200%", height: "200%",
          transform: "translate(-50%, -50%)",
          background: "conic-gradient(from 0deg, #0ea5e920 0deg, transparent 90deg)",
          animation: "radarRotate 4s linear infinite",
          zIndex: 1, pointerEvents: "none"
        }} />

        <div style={{ position: "absolute", inset: 0, backgroundImage: "linear-gradient(rgba(14,165,233,0.03) 1px, transparent 1px)", backgroundSize: "100% 4px", animation: "scanline 10s linear infinite", pointerEvents: "none", zIndex: 1 }} />
        <div style={{ position: "absolute", inset: 0, backgroundImage: "radial-gradient(rgba(14,165,233,0.08) 1px, transparent 1px)", backgroundSize: "20px 20px" }} />
        
        {/* Permanent Hotspots */}
        {hotspots.map((h, i) => (
          <div key={`static-${i}`} style={{ position: "absolute", top: h.top, left: h.left, transform: "translate(-50%,-50%)", zIndex: 2 }}>
            <div style={{
              width: h.size, height: h.size, borderRadius: "50%",
              background: h.color, boxShadow: `0 0 ${h.size*2}px ${h.color}`,
              animation: `pulse ${1.5 + i * 0.5}s ease-in-out infinite`
            }} />
            <div style={{ color: h.color, fontSize: 8, textAlign: "center", fontWeight: 700, marginTop: 2, textShadow: "0 0 5px #000" }}>{h.label}</div>
          </div>
        ))}

        {/* Dynamic Attack Markers */}
        {activeMarkers.map((m) => (
          <div key={m.id} style={{ position: "absolute", top: m.top, left: m.left, transform: "translate(-50%,-50%)", zIndex: 3 }}>
            <div style={{ 
              width: 12, height: 12, borderRadius: "50%", border: `2px solid ${m.color}`, 
              animation: "ping 1.5s cubic-bezier(0, 0, 0.2, 1) infinite" 
            }} />
            <div style={{ 
              position: "absolute", top: 0, left: 0, width: 12, height: 12, 
              borderRadius: "50%", background: m.color, opacity: 0.8 
            }} />
          </div>
        ))}
        
        <div style={{ position: "absolute", bottom: 6, right: 8, fontSize: 9, color: "#1e395a", fontWeight: 700, fontFamily: "monospace", zIndex: 4, letterSpacing: 1 }}>
          LIVE • {utcTime} UTC
        </div>
      </div>

      <style>{`
        @keyframes scanline {
          0% { transform: translateY(0); }
          100% { transform: translateY(160px); }
        }
      `}</style>

      {/* Live Incident Log */}
      <div style={{ marginTop: 12, borderTop: "1px solid #1e3a5f", paddingTop: 10 }}>
        <div style={{ fontSize: 9, color: "#475569", fontWeight: 700, textTransform: "uppercase", marginBottom: 6, display: "flex", justifyContent: "space-between" }}>
          <span>Live Global Incident Feed</span>
          <span style={{ color: "#0ea5e9", animation: "pulse 1s infinite" }}>● LIVE</span>
        </div>
        <div style={{ height: 100, overflow: "hidden", display: "flex", flexDirection: "column", gap: 4 }}>
          {events.map((e) => (
            <div key={e.id} style={{ 
              display: "flex", justifyContent: "space-between", alignItems: "center", 
              fontSize: 10, background: "#0f172a", padding: "4px 8px", borderRadius: 4,
              animation: "fadeSlideIn 0.3s ease" 
            }}>
              <span style={{ color: "#94a3b8" }}>{e.time}</span>
              <span style={{ color: "#cbd5e1", flex: 1, margin: "0 8px" }}>{e.loc}</span>
              <span style={{ color: e.color, fontWeight: 700, fontFamily: "monospace" }}>{e.type}</span>
            </div>
          ))}
        </div>
      </div>

      <style>
        {`
          @keyframes radarRotate {
            from { transform: translate(-50%, -50%) rotate(0deg); }
            to { transform: translate(-50%, -50%) rotate(360deg); }
          }
          @keyframes ping {
            75%, 100% { transform: scale(2.5); opacity: 0; }
          }
        `}
      </style>
    </div>
  );
}
  
function ExplainableAIView({ result, colors }) {
  if (!result.explanation && !result.featureAnalysis) return null;

  return (
    <div style={{ 
      marginTop: 20, 
      padding: 16, 
      background: "#0c1e35", 
      border: `1px solid ${colors.border}80`, 
      borderRadius: 12,
      position: "relative",
      overflow: "hidden"
    }}>
      <div style={{ 
        position: "absolute", 
        top: 0, 
        left: 0, 
        width: "100%", 
        height: 2, 
        background: `linear-gradient(90deg, transparent, ${colors.text}, transparent)`,
        animation: "scanLine 3s linear infinite"
      }} />
      
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
        <span style={{ fontSize: 16 }}>🧠</span>
        <div style={{ color: "#94a3b8", fontSize: 10, fontWeight: 700, letterSpacing: 1.5, textTransform: "uppercase" }}>
          Explainable AI (XAI) Reasoning
        </div>
      </div>

      <div style={{ color: "#e2e8f0", fontSize: 13, fontWeight: 500, lineHeight: 1.6, marginBottom: 14 }}>
        "{result.explanation || "No specific reasoning provided."}"
      </div>

      {result.featureAnalysis?.length > 0 && (
        <div>
          <div style={{ color: "#475569", fontSize: 9, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", marginBottom: 8 }}>
            Malicious Features Analysis
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {result.featureAnalysis.map((feature, i) => (
              <div key={i} style={{ 
                background: `${colors.dot}15`, 
                border: `1px solid ${colors.dot}40`, 
                color: colors.text, 
                fontSize: 10, 
                padding: "4px 10px", 
                borderRadius: 4,
                display: "flex",
                alignItems: "center",
                gap: 5
              }}>
                <span style={{ width: 4, height: 4, borderRadius: "50%", background: colors.dot }} />
                {feature}
              </div>
            ))}
          </div>
        </div>
      )}

      <style>
        {`
          @keyframes scanLine {
            0% { transform: translateY(-10px); opacity: 0; }
            50% { opacity: 0.5; }
            100% { transform: translateY(120px); opacity: 0; }
          }
        `}
      </style>
    </div>
  );
}

function ThreatTrendChart({ history }) {
  if (history.length < 2) return null;
  const scans = history.slice(0, 8).reverse();
  const maxScore = Math.max(...scans.map(h => h.result?.riskScore || 0), 1);

  return (
    <div style={{ background: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 12, padding: 20, marginBottom: 16 }}>
      <div style={{ color: "#94a3b8", fontSize: 11, fontWeight: 700, letterSpacing: 2, textTransform: "uppercase", marginBottom: 12 }}>
        📈 Session Threat Trend
      </div>
      <div style={{ display: "flex", alignItems: "flex-end", height: 80, gap: 6, borderBottom: "1px solid #1e293b" }}>
        {scans.map((h, i) => {
          const score = h.result?.riskScore || 0;
          const height = `${(score / maxScore) * 100}%`;
          const color = score >= 80 ? "#f87171" : score >= 60 ? "#fbbf24" : score >= 40 ? "#60a5fa" : "#4ade80";
          return (
            <div key={i} title={`Risk: ${score}`} style={{ flex: 1, display: "flex", alignItems: "flex-end" }}>
              <div style={{ width: "100%", height, background: `linear-gradient(to top, ${color}60, ${color})`, borderRadius: "3px 3px 0 0", minHeight: 2, transition: "height 0.8s ease" }} />
            </div>
          );
        })}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 6 }}>
        <span style={{ fontSize: 9, color: "#475569" }}>← Older</span>
        <span style={{ fontSize: 9, color: "#0ea5e9" }}>Latest →</span>
      </div>
    </div>
  );
}

function XAIReasoningPanel({ result }) {
  if (!result.reasoningPath && !result.phishingIndicators) return null;

  return (
    <div style={{ marginTop: 20, borderTop: "1px solid #1e3a5f", paddingTop: 16 }}>
      <div style={{ fontSize: 11, fontWeight: 700, color: "#0ea5e9", letterSpacing: 1, textTransform: "uppercase", marginBottom: 12, display: "flex", alignItems: "center", gap: 6 }}>
        <span>🧠</span> XAI REASONING ENGINE ACTIVE
      </div>

      {/* Audit Trail */}
      {result.reasoningPath && (
        <div style={{ background: "#061325", borderRadius: 8, padding: 12, marginBottom: 16, border: "1px solid #0f2a4a" }}>
          <div style={{ fontSize: 9, color: "#475569", fontWeight: 700, marginBottom: 8, textTransform: "uppercase" }}>Neural Decision Path</div>
          {result.reasoningPath.map((step, i) => (
            <div key={i} style={{ display: "flex", gap: 10, marginBottom: 6, opacity: 0.8 }}>
              <span style={{ color: "#0ea5e9", fontSize: 10 }}>{i + 1}</span>
              <span style={{ color: "#e2e8f0", fontSize: 10, fontFamily: "monospace" }}>{step}</span>
            </div>
          ))}
        </div>
      )}

      {/* Severity Justification */}
      {result.severityJustification && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 9, color: "#475569", fontWeight: 700, marginBottom: 4, textTransform: "uppercase" }}>Severity Justification</div>
          <div style={{ background: "rgba(14, 165, 233, 0.05)", borderLeft: "2px solid #0ea5e9", padding: "8px 12px", fontSize: 11, color: "#94a3b8", fontStyle: "italic" }}>
             "{result.severityJustification}"
          </div>
        </div>
      )}

      {/* Phishing Indicators */}
      {result.phishingIndicators && (
        <div>
          <div style={{ fontSize: 9, color: "#475569", fontWeight: 700, marginBottom: 8, textTransform: "uppercase" }}>Risk Vector Breakdown</div>
          <div style={{ display: "grid", gap: 8 }}>
            {result.phishingIndicators.map((ind, i) => {
              const color = ind.level === "HIGH" ? "#f87171" : ind.level === "MEDIUM" ? "#fbbf24" : "#4ade80";
              return (
                <div key={i} style={{ background: "#0c1e35", border: `1px solid ${color}30`, borderRadius: 6, padding: "8px 12px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <div style={{ fontSize: 11, color: "#e2e8f0", fontWeight: 600 }}>{ind.indicator}</div>
                    <div style={{ fontSize: 9, color: "#475569" }}>{ind.impact}</div>
                  </div>
                  <div style={{ fontSize: 8, fontWeight: 700, background: color, color: "#000", padding: "2px 6px", borderRadius: 4 }}>{ind.level}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

function ResultCard({ result, onExport, onDecrypt, decrypting, decryptError, decryptSuccess }) {
  const colors = THREAT_COLORS[result.threatLevel] || THREAT_COLORS.MEDIUM;
  return (
    <div style={{ background: colors.bg, border: `1px solid ${colors.border}`, borderRadius: 12, padding: 24, marginTop: 20, animation: "fadeSlideIn 0.4s ease" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 12 }}>
        <div style={{ flex: 1 }}>
          <span style={{ background: colors.badge, color: colors.text, fontSize: 11, fontWeight: 700, padding: "3px 10px", borderRadius: 20, fontFamily: "monospace", textTransform: "uppercase" }}>
            {result.threatLevel} THREAT
          </span>
          <div style={{ color: "#e2e8f0", fontSize: 17, fontWeight: 700, marginTop: 8 }}>{result.category}</div>
          <div style={{ color: "#94a3b8", fontSize: 12, marginTop: 3 }}>
            AI Confidence: <span style={{ color: colors.text, fontWeight: 700 }}>{result.confidenceScore}%</span>
          </div>
        </div>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
          <ScoreRing score={result.riskScore} />
          <button onClick={onExport} style={{ background: "none", border: `1px solid ${colors.border}`, color: colors.text, fontSize: 9, padding: "3px 8px", borderRadius: 4, cursor: "pointer", fontWeight: 700, fontFamily: "monospace", letterSpacing: 1 }}>
            ↓ EXPORT JSON
          </button>
        </div>
      </div>

      <p style={{ color: "#cbd5e1", fontSize: 13, lineHeight: 1.7, borderLeft: `3px solid ${colors.border}`, paddingLeft: 12, margin: "0 0 16px" }}>
        {result.explanation || result.summary}
      </p>

      {result.category === "Ransomware Deployment" && (
        <RansomwareOverview 
            result={result} 
            onDecrypt={onDecrypt}
            decrypting={decrypting}
            decryptError={decryptError}
            decryptSuccess={decryptSuccess}
        />
      )}
      
      <XAIReasoningPanel result={result} />
      {result.killChainStage && <KillChainView currentStage={result.killChainStage} />}

      {result.indicators?.length > 0 && (
        <div style={{ marginTop: 20, marginBottom: 16 }}>
          <div style={{ color: "#94a3b8", fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", marginBottom: 8 }}>⚡ Threat Indicators Detected</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {result.indicators.map((ind, i) => (
              <span key={i} style={{ background: "#0f172a", border: `1px solid ${colors.border}`, color: colors.text, fontSize: 11, padding: "3px 10px", borderRadius: 6 }}>{ind}</span>
            ))}
          </div>
        </div>
      )}

      {result.recommendedActions?.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ color: "#94a3b8", fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", marginBottom: 8 }}>🛡 Recommended Mitigation Steps</div>
          {result.recommendedActions.map((a, i) => (
            <div key={i} style={{ display: "flex", gap: 8, background: "#0f172a", borderRadius: 6, padding: "8px 12px", marginBottom: 4 }}>
              <span style={{ color: colors.text, fontWeight: 700, fontSize: 12, minWidth: 20 }}>{i + 1}.</span>
              <span style={{ color: "#cbd5e1", fontSize: 13 }}>{a}</span>
            </div>
          ))}
        </div>
      )}

      {result.technicalDetails && (
        <div style={{ background: "#0f172a", borderRadius: 8, padding: 12, border: "1px solid #1e293b" }}>
          <div style={{ color: "#64748b", fontSize: 10, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", marginBottom: 6 }}>🔬 Technical Forensics</div>
          <p style={{ color: "#64748b", fontSize: 11, fontFamily: "monospace", margin: 0, lineHeight: 1.6 }}>{result.technicalDetails}</p>
        </div>
      )}
    </div>
  );
}

function RansomwareOverview({ result, onDecrypt, decrypting, decryptError, decryptSuccess }) {
  const isCritical = result.threatLevel === "CRITICAL";
  const [keyInput, setKeyInput] = useState("");

  return (
    <div style={{ marginTop: 24, padding: 20, background: isCritical ? "rgba(239, 68, 68, 0.05)" : "rgba(14, 165, 233, 0.05)", border: `1px solid ${isCritical ? "#ef444450" : "#0ea5e950"}`, borderRadius: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: isCritical ? "#f87171" : "#0ea5e9", letterSpacing: 1, textTransform: "uppercase" }}>
          🛡️ Ransomware Signal Analysis
        </div>
        <div style={{ fontSize: 10, background: isCritical ? "#ef4444" : "#0ea5e9", color: "#000", padding: "2px 8px", borderRadius: 4, fontWeight: 900 }}>
          {isCritical ? "ACTIVE THREAT" : "PROACTIVE SCAN"}
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
        <div style={{ background: "#0f172a", padding: 12, borderRadius: 8, border: "1px solid #1e293b" }}>
          <div style={{ color: "#475569", fontSize: 9, textTransform: "uppercase", marginBottom: 4 }}>Canary Status</div>
          <div style={{ color: isCritical && !decryptSuccess ? "#f87171" : "#4ade80", fontSize: 14, fontWeight: 700 }}>
             {isCritical && !decryptSuccess ? "⚠️ COMPROMISED" : "🟢 SECURE"}
          </div>
        </div>
        <div style={{ background: "#0f172a", padding: 12, borderRadius: 8, border: "1px solid #1e293b" }}>
          <div style={{ color: "#475569", fontSize: 9, textTransform: "uppercase", marginBottom: 4 }}>Encryption Signal</div>
          <div style={{ color: isCritical && !decryptSuccess ? "#f87171" : "#60a5fa", fontSize: 14, fontWeight: 700 }}>
             {isCritical && !decryptSuccess ? "AES-256 DETECTED" : "NONE"}
          </div>
        </div>
      </div>

      {isCritical && !decryptSuccess && (
        <div style={{ background: "#7f1d1d40", border: "1px solid #f8717150", padding: 12, borderRadius: 8, color: "#fca5a5", fontSize: 11, lineHeight: 1.5, marginBottom: 16 }}>
           <strong>IMMEDIATE ACTION REQUIRED:</strong> System identified military-grade encryption payloads. Isolate host immediately to prevent lateral spread.
        </div>
      )}

      {/* Incident Response: Decryption Panel */}
      {isCritical && (
        <div style={{ background: "#020817", border: "1px solid #1e3a5f", padding: 16, borderRadius: 8 }}>
           <div style={{ fontSize: 11, color: "#0ea5e9", fontWeight: 700, textTransform: "uppercase", marginBottom: 8 }}>⬡ Incident Response: Decrypt Files</div>
           <p style={{ fontSize: 11, color: "#94a3b8", marginBottom: 12 }}>Enter the recovered AES-256 private key to reverse the encryption and restore compromised Canary folders.</p>
           
           <div style={{ display: "flex", gap: 8 }}>
               <input 
                  type="text" 
                  className="cyber-input" 
                  placeholder="Enter AES-256 Key..." 
                  value={keyInput} 
                  onChange={e => setKeyInput(e.target.value)}
                  style={{ flex: 1, padding: 8, fontSize: 12, fontFamily: "monospace" }}
                  disabled={decryptSuccess || decrypting}
               />
               <button 
                  onClick={() => onDecrypt(keyInput)} 
                  disabled={decryptSuccess || decrypting || !keyInput.trim()}
                  style={{ background: decryptSuccess ? "#166534" : (decrypting ? "#0f2a4a" : "#0ea5e9"), color: "#fff", border: "none", borderRadius: 4, padding: "0 16px", cursor: "pointer", fontWeight: 700, fontSize: 11 }}
               >
                  {decrypting ? "DECRYPTING..." : (decryptSuccess ? "DATA RESTORED" : "EXECUTE RECOVERY")}
               </button>
           </div>
           
           {decryptError && <div style={{ color: "#f87171", fontSize: 10, marginTop: 8 }}>⚠ {decryptError}</div>}
           {decryptSuccess && <div style={{ color: "#4ade80", fontSize: 10, marginTop: 8, fontWeight: 700 }}>✓ Decryption successful. Files restored to original state.</div>}
        </div>
      )}
    </div>
  );
}

function SmartFolderProtection({ isSirenActive, decryptSuccess }) {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(false);
  const fileInputRef = useRef(null);

  const fetchFiles = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/canary/files`);
      const data = await res.json();
      if (data.success) {
        setFiles(data.files);
      }
    } catch (e) {
      console.error("Failed to fetch canary files", e);
    }
  }, []);

  useEffect(() => {
    fetchFiles();
    const interval = setInterval(fetchFiles, 5000);
    return () => clearInterval(interval);
  }, [fetchFiles]);

  useEffect(() => {
    fetchFiles();
  }, [isSirenActive, decryptSuccess, fetchFiles]);

  const handleUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setLoading(true);
    const formData = new FormData();
    formData.append("file", file);
    try {
      const res = await fetch(`${API_BASE_URL}/canary/upload`, {
        method: "POST",
        body: formData
      });
      const data = await res.json();
      if (data.success) {
        fetchFiles();
      }
    } catch (err) {
      console.error("Upload failed", err);
    } finally {
      setLoading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const handleDelete = async (name) => {
    try {
      const res = await fetch(`${API_BASE_URL}/canary/delete/${name}`, { method: "DELETE" });
      const data = await res.json();
      if (data.success) fetchFiles();
    } catch (e) {
      console.error("Delete failed", e);
    }
  };

  const getIcon = (name) => {
    if (!name.includes('.')) return "📄";
    const ext = name.split('.').pop().toLowerCase();
    if (ext === 'pdf') return "📄";
    if (ext === 'xlsx' || ext === 'csv') return "📈";
    if (ext === 'png' || ext === 'jpg' || ext === 'jpeg') return "🖼️";
    if (ext === 'txt') return "📝";
    return "💾";
  };

  const defaultFolders = [
    { name: "./demo_target/", icon: "📂" },
    { name: "C:\\Finance_Records\\", icon: "📈" },
    { name: "E:\\Client_Backups\\", icon: "💾" },
  ];

  const locked = isSirenActive && !decryptSuccess;
  
  const displayItems = files.length > 0 
    ? files.map(f => ({ name: f.name, icon: getIcon(f.name), isEncrypted: f.is_encrypted }))
    : defaultFolders.map(f => ({ ...f, isEncrypted: locked }));

  return (
    <div style={{ background: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 12, padding: 20, marginBottom: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ color: "#94a3b8", fontSize: 11, fontWeight: 700, letterSpacing: 2, textTransform: "uppercase" }}>
            📁 Smart Canary Folders
          </div>
          <span style={{ fontSize: 9, background: "#450a0a", color: "#f87171", padding: "2px 8px", borderRadius: 4, fontWeight: 900, border: "1px solid #7f1d1d" }}>🔴 ATTACK ZONE (PC)</span>
        </div>
        <input type="file" ref={fileInputRef} onChange={handleUpload} style={{ display: "none" }} />
        <button 
          onClick={() => fileInputRef.current?.click()} 
          disabled={loading || locked}
          style={{ background: "#0ea5e9", color: "#fff", border: "none", borderRadius: 4, padding: "4px 8px", fontSize: 10, fontWeight: 700, cursor: (loading || locked) ? "not-allowed" : "pointer", opacity: (loading || locked) ? 0.5 : 1 }}>
          {loading ? "..." : "+ UPLOAD"}
        </button>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {displayItems.length === 0 && <div style={{ color: "#475569", fontSize: 11, textAlign: "center", padding: "10px 0" }}>No files in vault</div>}
        {displayItems.map(f => {
          const isItemLocked = f.isEncrypted !== undefined ? f.isEncrypted : locked;
          return (
          <div key={f.name} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", background: "#0f172a", padding: "8px 12px", borderRadius: 6, border: `1px solid ${isItemLocked ? "#7f1d1d" : "#1e293b"}` }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, overflow: "hidden" }}>
              <span style={{ fontSize: 16, flexShrink: 0 }}>{f.icon}</span>
              <span style={{ color: isItemLocked ? "#fca5a5" : "#cbd5e1", fontSize: 11, fontFamily: "monospace", textOverflow: "ellipsis", overflow: "hidden", whiteSpace: "nowrap" }}>{f.name}</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              {isItemLocked ? (
                  <span style={{ color: "#f87171", fontSize: 10, fontWeight: 900, animation: "pulse 0.5s infinite", flexShrink: 0 }}>LOCKED (AES)</span>
              ) : (
                  <>
                    <a 
                      href={`${API_BASE_URL}/canary/download/${f.name}`} 
                      download 
                      style={{ textDecoration: "none", color: "#0ea5e9", fontSize: 10, fontWeight: 900, border: "1px solid #0ea5e940", padding: "2px 6px", borderRadius: 4, background: "#0ea5e910" }}
                    >
                      DOWNLOAD
                    </a>
                    <span style={{ color: "#4ade80", fontSize: 10, fontWeight: 900, flexShrink: 0 }}>SECURE</span>
                  </>
              )}
              <button 
                onClick={() => handleDelete(f.name)}
                style={{ background: "none", border: "none", color: "#f87171", cursor: "pointer", fontSize: 14, padding: 0.5, opacity: 0.7 }}
                title="Delete file"
              >
                🗑️
              </button>
            </div>
          </div>
        )})}
      </div>
    </div>
  );
}

function SecurityVault() {
  const [authStep, setAuthStep] = useState(0); 
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [vaultData, setVaultData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [latestSafeCode, setLatestSafeCode] = useState(null);
  const [customCode, setCustomCode] = useState("");
  const [registry, setRegistry] = useState({}); // Stores { fileId: decryptedCode }
  const [registryUnlocked, setRegistryUnlocked] = useState(false);
  const vaultFileInputRef = useRef(null);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/vault/status`);
      const data = await res.json();
      setVaultData(data);
    } catch (e) {
      console.error("Failed to fetch vault status", e);
    }
  }, []);

  useEffect(() => {
    if (authStep === 3) {
      fetchStatus();
      const interval = setInterval(fetchStatus, 3000);
      return () => clearInterval(interval);
    }
  }, [authStep, fetchStatus]);

  const handlePasswordAuth = async () => {
    setError("");
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/vault/auth/password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password })
      });
      const data = await res.json();
      if (data.success) setAuthStep(1);
      else setError(data.error);
    } catch (e) { setError("Connection failed"); }
    setLoading(false);
  };

  const handleOTPAuth = async () => {
    setError("");
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/vault/auth/otp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ otp })
      });
      const data = await res.json();
      if (data.success) setAuthStep(2);
      else setError(data.error);
    } catch (e) { setError("Connection failed"); }
    setLoading(false);
  };

  const handleBiometric = () => {
    setLoading(true);
    setTimeout(() => {
      setLoading(false);
      setAuthStep(3);
    }, 1500);
  };

  const handleUnfreeze = async () => {
    try {
      await fetch(`${API_BASE_URL}/vault/unfreeze`, { method: "POST" });
      fetchStatus();
    } catch (e) { console.error(e); }
  };

  const handleUnlockRegistry = async () => {
    const pw = window.prompt("Enter Master Vault Password to unlock your Secret Codes:");
    if (!pw) return;
    
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/vault/registry`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: pw })
      });
      const data = await res.json();
      if (data.success) {
        setRegistry(data.codes);
        setRegistryUnlocked(true);
      } else {
        alert(data.error || "Failed to unlock registry.");
      }
    } catch (e) { console.error(e); }
    setLoading(false);
  };
  const handleUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const formData = new FormData();
    formData.append("file", file);
    if (customCode) formData.append("custom_code", customCode);
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/vault/upload`, {
        method: "POST",
        body: formData
      });
      const data = await res.json();
      if (data.success) {
        setLatestSafeCode(data.safety_code);
        setCustomCode("");
        fetchStatus();
      }
      else alert(data.error);
    } catch (e) { console.error(e); }
    setLoading(false);
    if (vaultFileInputRef.current) vaultFileInputRef.current.value = "";
  };

  const handleDownload = async (fileId, filename) => {
    const code = window.prompt(`Enter SECRETE CODE to identify and decrypt ${filename}:`);
    if (!code) return;

    try {
      const res = await fetch(`${API_BASE_URL}/vault/download`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ file_id: fileId, safety_code: code })
      });
      
      if (!res.ok) {
        const err = await res.json();
        alert(err.error || "Download failed");
        return;
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (e) {
      alert("Decryption Error: System failure.");
    }
  };

  const handleRestore = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/vault/restore-all`, {
        method: "POST"
      });
      const data = await res.json();
      if (data.success) fetchStatus();
      else alert(data.error);
    } catch (e) { console.error(e); }
    setLoading(false);
  };

  const handleDelete = async (fileId, filename) => {
    if (!window.confirm(`Permanently remove ${filename} from vault?`)) return;
    try {
      const res = await fetch(`${API_BASE_URL}/vault/delete`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ file_id: fileId })
      });
      const data = await res.json();
      if (data.success) fetchStatus();
      else alert(data.error);
    } catch (e) { console.error(e); }
  };

  if (authStep < 3) {
    return (
      <div style={{ background: "#061325", border: "1px solid #1e3a5f", borderRadius: 12, padding: 40, textAlign: "center", minHeight: 400, display: "flex", flexDirection: "column", justifyContent: "center" }}>
        <div style={{ fontSize: 40, marginBottom: 20 }}>{authStep === 0 ? "🔒" : authStep === 1 ? "📱" : "👁️"}</div>
        <div style={{ fontSize: 18, fontWeight: 700, color: "#0ea5e9", marginBottom: 8 }}>
          {authStep === 0 ? "Multi-Level Vault Authentication" : authStep === 1 ? "Two-Factor Verification" : "Biometric Identity Confirmation"}
        </div>
        <div style={{ color: "#475569", fontSize: 12, marginBottom: 24 }}>
          {authStep === 0 ? "Enter master vault credentials to proceed." : authStep === 1 ? "Enter 6-digit OTP sent to your secured device." : "Align biometric sensor for retinal/fingerprint scan."}
        </div>

        <div style={{ maxWidth: 300, margin: "0 auto", width: "100%" }}>
          {authStep === 0 && (
            <input type="password" placeholder="Master Password" value={password} onChange={e => setPassword(e.target.value)} onKeyDown={e => e.key === "Enter" && handlePasswordAuth()} className="cyber-input" style={{ textAlign: "center" }} />
          )}
          {authStep === 1 && (
            <input type="text" placeholder="######" value={otp} onChange={e => setOtp(e.target.value)} onKeyDown={e => e.key === "Enter" && handleOTPAuth()} className="cyber-input" style={{ textAlign: "center", letterSpacing: 8, fontSize: 18 }} />
          )}
          {authStep === 2 && (
            <div style={{ height: 100, border: "2px solid #0ea5e940", borderRadius: 8, position: "relative", overflow: "hidden", display: "flex", alignItems: "center", justifyContent: "center", background: "#020817" }}>
              <div style={{ position: "absolute", top: 0, left: 0, width: "100%", height: 2, background: "#0ea5e9", boxShadow: "0 0 15px #0ea5e9", animation: "scanLine 2s infinite" }} />
              <div style={{ color: "#0ea5e9", fontSize: 10, fontWeight: 700 }}>{loading ? "ANALYZING BIOMETRIC..." : "READY TO SCAN"}</div>
            </div>
          )}

          {error && <div style={{ color: "#f87171", fontSize: 10, marginTop: 12 }}>⚠ {error}</div>}

          <button onClick={authStep === 0 ? handlePasswordAuth : authStep === 1 ? handleOTPAuth : handleBiometric} disabled={loading} style={{ marginTop: 24, width: "100%", padding: 12, borderRadius: 8, background: "#0ea5e9", color: "#fff", border: "none", fontWeight: 700, cursor: "pointer" }}>
            {loading ? "VERIFYING..." : "CONTINUE"}
          </button>
          
          <div style={{ marginTop: 16, fontSize: 10, color: "#334155" }}>
            Hint for demo: admin123 / 123456
          </div>
        </div>
      </div>
    );
  }

  const isFrozen = vaultData?.isFrozen;
  const threatLevel = vaultData?.threatLevel || "LOW";
  const colors = THREAT_COLORS[threatLevel];

  const getStage = () => {
    if (isFrozen) return { label: "SYSTEM FROZEN", color: "#f87171", icon: "🧊" };
    if (threatLevel === "CRITICAL") return { label: "ATTACK DETECTED", color: "#ef4444", icon: "🚨" };
    if (threatLevel === "MEDIUM") return { label: "SUSPICIOUS ACTIVITY", color: "#f59e0b", icon: "⚠️" };
    return { label: "OPTIMAL MONITORING", color: "#4ade80", icon: "🛡️" };
  };

  const stage = getStage();

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Secret Code Success Modal */}
      {latestSafeCode && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.85)", backdropFilter: "blur(12px)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
          <div style={{ maxWidth: 450, width: "100%", background: "#0ea5e905", border: "2px solid #0ea5e960", borderRadius: 16, padding: 32, textAlign: "center", boxShadow: "0 0 50px #0ea5e920" }}>
            <div style={{ fontSize: 40, marginBottom: 16 }}>🛡️</div>
            <div style={{ fontSize: 20, fontWeight: 900, color: "#fff", marginBottom: 8, letterSpacing: 1 }}>FILE SECURED SUCCESSFULLY</div>
            <div style={{ color: "#94a3b8", fontSize: 13, marginBottom: 24, lineHeight: 1.5 }}>Your file is encrypted with the following **SECRET CODE**. You will need this to identify and download the file. **No one else—not even hackers—can recover this.**</div>
            
            <div style={{ background: "#020617", border: "1px dashed #0ea5e980", borderRadius: 8, padding: 16, marginBottom: 24, position: "relative" }}>
              <div style={{ fontSize: 10, color: "#0ea5e9", fontWeight: 900, letterSpacing: 2, marginBottom: 8 }}>YOUR UNIQUE SECRET CODE</div>
              <div style={{ fontSize: 28, color: "#fff", fontWeight: 700, letterSpacing: 4, fontFamily: "monospace", wordBreak: "break-all" }}>{latestSafeCode}</div>
            </div>

            <div style={{ display: "flex", gap: 12 }}>
              <button onClick={() => { navigator.clipboard.writeText(latestSafeCode); alert("Secret Code copied to clipboard!"); }} style={{ flex: 1, padding: "12px 0", background: "#1e293b", color: "#fff", border: "1px solid #1e3a5f", borderRadius: 8, fontWeight: 800, cursor: "pointer", fontSize: 13 }}>COPY CODE</button>
              <button onClick={() => setLatestSafeCode(null)} style={{ flex: 1, padding: "12px 0", background: "#0ea5e9", color: "#fff", border: "none", borderRadius: 8, fontWeight: 800, cursor: "pointer", fontSize: 13 }}>I'VE SAVED IT</button>
            </div>
          </div>
        </div>
      )}

      {/* Alarm Banner */}
      {threatLevel === "CRITICAL" && (
        <div style={{ background: "#450a0a", border: "2px solid #ef4444", borderRadius: 8, padding: "12px 20px", display: "flex", alignItems: "center", justifyContent: "space-between", animation: "pulseHighlight 1.5s infinite" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span style={{ fontSize: 24 }}>🚨</span>
            <div>
              <div style={{ color: "#fca5a5", fontWeight: 900, fontSize: 13, letterSpacing: 1 }}>CRITICAL: RANSOMWARE ATTACK DETECTED</div>
              <div style={{ color: "#ef4444", fontSize: 10, fontWeight: 600 }}>Multiple encryption/modification events flagged in secure sectors.</div>
            </div>
          </div>
          <div style={{ color: "#fff", border: "1px solid #ef4444", padding: "4px 10px", borderRadius: 4, fontWeight: 900, fontSize: 10 }}>HIGH ALERT</div>
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 340px", gap: 20 }}>
        {/* File Management */}
        <div style={{ background: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 12, padding: 24, position: "relative" }}>
          {isFrozen && (
            <div style={{ position: "absolute", inset: 0, background: "rgba(12, 10, 10, 0.7)", borderRadius: 12, zIndex: 10, backdropFilter: "blur(4px)", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", border: "2px solid #ef444480" }}>
               <div style={{ fontSize: 50, marginBottom: 16, animation: "bounce 2s infinite" }}>🧊</div>
               <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", letterSpacing: 3, textTransform: "uppercase" }}>Vault Frozen</div>
               <div style={{ fontSize: 13, color: "#fca5a5", marginTop: 8, textAlign: "center", padding: "0 40px", maxWidth: 400 }}>Automated containment triggered to prevent further file modification. System is currently in **READ-ONLY** mode.</div>
                <div style={{ marginTop: 20, display: "flex", gap: 12 }}>
                  <button onClick={handleRestore} style={{ padding: "12px 24px", background: "#ef4444", color: "#fff", border: "none", borderRadius: 8, fontWeight: 900, cursor: "pointer", boxShadow: "0 0 20px #ef444480" }}>SECURE RESTORE</button>
                  <button onClick={() => window.location.reload()} style={{ padding: "12px 24px", background: "#1e293b", color: "#fff", border: "none", borderRadius: 8, fontWeight: 900, cursor: "pointer" }}>VIEW LOGS</button>
                </div>
            </div>
          )}


        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ fontSize: 18, fontWeight: 700 }}>Vault Contents</div>
            <span style={{ fontSize: 9, background: "#064e3b", color: "#4ade80", padding: "2px 8px", borderRadius: 4, fontWeight: 900, border: "1px solid #14532d" }}>🟢 IMMUNE TO SIMULATION</span>
          </div>
          <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
            <button 
              onClick={handleUnlockRegistry}
              style={{ background: registryUnlocked ? "#064e3b" : "#1e293b", color: registryUnlocked ? "#4ade80" : "#94a3b8", border: "1px solid " + (registryUnlocked ? "#059669" : "#334155"), borderRadius: 8, padding: "8px 16px", fontSize: 11, fontWeight: 700, cursor: "pointer", display: "flex", alignItems: "center", gap: 8 }}
            >
              {registryUnlocked ? "🔓 REGISTRY UNLOCKED" : "🔐 SHOW MY CODES"}
            </button>
            <div style={{ position: "relative" }}>
               <input 
                  type="text" 
                  placeholder="Set Secret Code (6+ chars)" 
                  value={customCode} 
                  onChange={e => setCustomCode(e.target.value)}
                  style={{ background: "#0c1e35", border: "1px solid #1e3a5f", borderRadius: 8, padding: "8px 12px", fontSize: 11, color: "#fff", width: 200 }}
               />
               <div style={{ fontSize: 8, color: "#475569", marginTop: 4 }}>Optional: Custom code for identification</div>
            </div>
            <button 
              onClick={async () => {
                await fetch(`${API_BASE_URL}/simulate-attack`, { method: "POST" });
                fetchStatus();
              }}
              style={{ background: "#450a0a", color: "#f87171", border: "1px solid #7f1d1d", borderRadius: 8, padding: "8px 16px", fontSize: 11, fontWeight: 700, cursor: "pointer" }}
            >
              🔥 SIMULATE ATTACK
            </button>
            <input type="file" ref={vaultFileInputRef} onChange={handleUpload} style={{ display: "none" }} />
            <button onClick={() => vaultFileInputRef.current?.click()} style={{ background: "#0ea5e9", color: "#fff", border: "none", borderRadius: 8, padding: "8px 16px", fontSize: 11, fontWeight: 700, cursor: "pointer" }}>+ ADD TO VAULT</button>
          </div>
        </div>

        <div style={{ display: "grid", gap: 10 }}>
          {vaultData?.files.map(f => (
            <div key={f.id} style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8, padding: "12px 16px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <span style={{ fontSize: 24 }}>{f.status === "LOCKED (AES)" ? "🔒" : "📄"}</span>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: "#e2e8f0", display: "flex", alignItems: "center", gap: 8 }}>
                    {f.name}
                    <span style={{ fontSize: 9, color: "#475569", fontWeight: 400 }}>({f.size ? (f.size / 1024).toFixed(1) + " KB" : "Unknown size"})</span>
                  </div>
                  <div style={{ fontSize: 10, color: "#475569" }}>ID: {f.obfuscated_name} • {f.upload_time}</div>
                  {registry[f.id] && (
                    <div style={{ fontSize: 10, color: "#0ea5e9", fontWeight: 700, marginTop: 4, background: "#0ea5e910", padding: "2px 6px", borderRadius: 4, display: "inline-block", border: "1px solid #0ea5e930" }}>
                      SECRET CODE: {registry[f.id]}
                    </div>
                  )}
                </div>
              </div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                {f.status === "SECURE" ? (
                  <button 
                    onClick={() => handleDownload(f.id, f.name)}
                    style={{ background: "none", border: "1px solid #0ea5e940", color: "#0ea5e9", fontSize: 10, fontWeight: 900, padding: "2px 6px", borderRadius: 4, cursor: "pointer" }}
                  >
                    SECURE DOWNLOAD
                  </button>
                ) : (
                  <span style={{ fontSize: 9, color: "#f87171", background: "#450a0a", padding: "2px 8px", borderRadius: 4, fontWeight: 900 }}>LOCKED (AES)</span>
                )}
                <button 
                  onClick={() => handleDelete(f.id, f.name)}
                  style={{ background: "none", border: "none", color: "#f87171", cursor: "pointer", fontSize: 14, padding: 0, opacity: 0.7 }}
                >
                  🗑️
                </button>
                <span style={{ fontSize: 9, color: f.status === "LOCKED (AES)" ? "#f87171" : "#4ade80", background: f.status === "LOCKED (AES)" ? "#450a0a" : "#064e3b", padding: "2px 8px", borderRadius: 4, fontWeight: 900 }}>{f.status}</span>
              </div>
            </div>
          ))}
          {vaultData?.files.length === 0 && <div style={{ textAlign: "center", padding: 40, color: "#334155", fontSize: 13 }}>Vault is currently empty. Upload sensitive files for AI monitoring.</div>}
        </div>
      </div>

      {/* Monitoring Dashboard */}
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <div style={{ background: "#0a1628", border: `1px solid ${colors?.border || "#1e3a5f"}`, borderRadius: 12, padding: 20 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: "#94a3b8", letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 12 }}>Monitoring Dash</div>
          <div style={{ background: "#020817", border: "1px solid #1e293b", borderRadius: 8, padding: 16, textAlign: "center", marginBottom: 16 }}>
             <div style={{ fontSize: 24, marginBottom: 8 }}>{stage.icon}</div>
             <div style={{ fontSize: 16, fontWeight: 900, color: stage.color, letterSpacing: 1 }}>{stage.label}</div>
             <div style={{ fontSize: 9, color: "#475569", marginTop: 4 }}>CURRENT PROTECTION STAGE</div>
          </div>
          
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
            <span style={{ fontSize: 10, color: "#475569" }}>Integrity Shield</span>
            <span style={{ fontSize: 10, color: stage.color }}>{isFrozen ? "RESTRICTED" : "ACTIVE"}</span>
          </div>
            <div style={{ height: 4, background: "#1e293b", borderRadius: 2, overflow: "hidden" }}>
              <div style={{ width: isFrozen ? "10%" : "100%", height: "100%", background: isFrozen ? "#ef4444" : "#4ade80", transition: "all 0.5s" }} />
            </div>
          </div>
        </div>

        <div style={{ background: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 12, padding: 20, flex: 1 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: "#94a3b8", letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 12 }}>Activity Log</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 300, overflowY: "auto" }}>
            {vaultData?.logs.map((log, i) => (
              <div key={i} style={{ fontSize: 10, padding: 8, background: "#0c1e35", borderRadius: 6, borderLeft: `2px solid ${log.action === "SYSTEM_FREEZE" ? "#ef4444" : "#0ea5e9"}` }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 2 }}>
                  <span style={{ fontWeight: 700, color: log.action === "SYSTEM_FREEZE" ? "#f87171" : "#e2e8f0" }}>{log.action}</span>
                  <span style={{ color: "#334155" }}>{log.timestamp}</span>
                </div>
                <div style={{ color: "#475569", fontSize: 9 }}>{log.details}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function SignupPage({ onSignup, onSwitchToLogin }) {
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    if (!fullName.trim() || !email.trim() || !password || !confirmPassword) {
      setError("All fields are required.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    if (password.length < 6) {
      setError("Password must be at least 6 characters.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/auth/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ full_name: fullName, email, password })
      });
      const data = await res.json().catch(() => {
        throw new Error("Invalid server response. Is the backend running?");
      });
      if (data.success) {
        onSignup(data.user);
      } else {
        setError(data.error || "Signup failed.");
      }
    } catch {
      setError("Connection failed. Is the server running?");
    }
    setLoading(false);
  };

  return (
    <div className="auth-page">
      {/* Floating particles */}
      {[...Array(6)].map((_, i) => (
        <div key={i} style={{
          position: "absolute",
          width: 4 + i * 2,
          height: 4 + i * 2,
          borderRadius: "50%",
          background: "#0ea5e9",
          opacity: 0.15 + (i * 0.05),
          top: `${15 + i * 14}%`,
          left: `${10 + i * 15}%`,
          animation: `shieldFloat ${3 + i * 0.7}s ease-in-out infinite`,
          animationDelay: `${i * 0.4}s`,
          zIndex: 2
        }} />
      ))}

      {/* Logo */}
      <div className="auth-header" style={{ zIndex: 10 }}>
        <div style={{ fontSize: 48, marginBottom: 8, animation: "shieldFloat 3s ease-in-out infinite, glowPulse 3s ease-in-out infinite" }}>
          🛡️
        </div>
        <div style={{ fontSize: 28, fontWeight: 900, color: "#0ea5e9", letterSpacing: 4, textShadow: "0 0 30px #0ea5e960" }}>
          THREATGUARD AI
        </div>
        <div style={{ color: "#475569", fontSize: 11, letterSpacing: 3, marginTop: 4 }}>
          ADVANCED THREAT DETECTION & CYBERSECURITY
        </div>
      </div>

      {/* Card */}
      <div className="auth-card">
        <h2 style={{ color: "#e2e8f0", fontSize: 22, fontWeight: 700, marginBottom: 6, textAlign: "center" }}>
          Create Your Account
        </h2>
        <p style={{ color: "#475569", fontSize: 12, textAlign: "center", marginBottom: 24 }}>
          Join the next generation of cyber defense
        </p>

        {error && <div className="auth-error">⚠ {error}</div>}

        <form onSubmit={handleSubmit}>
          <input className="auth-input" type="text" placeholder="Full Name" value={fullName} onChange={e => setFullName(e.target.value)} autoComplete="name" />
          <input className="auth-input" type="email" placeholder="Email Address" value={email} onChange={e => setEmail(e.target.value)} autoComplete="email" />
          <input className="auth-input" type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="new-password" />
          <input className="auth-input" type="password" placeholder="Confirm Password" value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)} autoComplete="new-password" />
          <button className="auth-btn" type="submit" disabled={loading}>
            {loading ? "⟳ CREATING ACCOUNT..." : "⬡ SIGN UP"}
          </button>
        </form>

        <div style={{ margin: "20px 0", display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ flex: 1, height: 1, background: "#1e3a5f" }} />
          <div style={{ fontSize: 10, color: "#475569", fontWeight: 700 }}>OR</div>
          <div style={{ flex: 1, height: 1, background: "#1e3a5f" }} />
        </div>

        <div style={{ display: "flex", justifyContent: "center" }}>
          <GoogleLogin 
            onSuccess={credentialResponse => {
              fetch(`${API_BASE_URL}/auth/google`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(credentialResponse)
              }).then(async (r) => {
                const data = await r.json().catch(() => {
                  throw new Error("Invalid server response. Is the backend running?");
                });
                if (data.success) onSignup(data.user);
                else setError(data.error);
              }).catch(err => {
                console.error("Google Signup Error:", err);
                setError("Google Auth Failed: " + (err.message || "Network Error"));
              });
            }}
            onError={() => {
              console.error("Google Login Component Error");
              setError("Google Login Failed: Check Console");
            }}
            theme="filled_black"
            shape="pill"
            text="continue_with"
            width="320"
          />
        </div>

        <div style={{ textAlign: "center", marginTop: 20, fontSize: 13, color: "#94a3b8" }}>
          Already have an account?{" "}
          <span className="auth-link" onClick={onSwitchToLogin}>Log In</span>
        </div>
      </div>

      <div style={{ color: "#1e3a5f", fontSize: 10, letterSpacing: 1, marginTop: 24, zIndex: 10 }}>
        THREATGUARD AI • SECURE ACCESS PORTAL
      </div>
    </div>
  );
}

function LoginPage({ onLogin, onSwitchToSignup }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    if (!email.trim() || !password) {
      setError("Email and password are required.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json().catch(() => {
        throw new Error("Invalid server response. Is the backend running?");
      });
      if (data.success) {
        onLogin(data.user);
      } else {
        setError(data.error || "Login failed.");
      }
    } catch {
      setError("Connection failed. Is the server running?");
    }
    setLoading(false);
  };

  return (
    <div className="auth-page">
      {/* Floating particles */}
      {[...Array(6)].map((_, i) => (
        <div key={i} style={{
          position: "absolute",
          width: 4 + i * 2,
          height: 4 + i * 2,
          borderRadius: "50%",
          background: "#0ea5e9",
          opacity: 0.15 + (i * 0.05),
          top: `${15 + i * 14}%`,
          left: `${10 + i * 15}%`,
          animation: `shieldFloat ${3 + i * 0.7}s ease-in-out infinite`,
          animationDelay: `${i * 0.4}s`,
          zIndex: 2
        }} />
      ))}

      {/* Logo */}
      <div className="auth-header" style={{ zIndex: 10 }}>
        <div style={{ fontSize: 48, marginBottom: 8, animation: "shieldFloat 3s ease-in-out infinite, glowPulse 3s ease-in-out infinite" }}>
          🛡️
        </div>
        <div style={{ fontSize: 28, fontWeight: 900, color: "#0ea5e9", letterSpacing: 4, textShadow: "0 0 30px #0ea5e960" }}>
          THREATGUARD AI
        </div>
        <div style={{ color: "#475569", fontSize: 11, letterSpacing: 3, marginTop: 4 }}>
          ADVANCED THREAT DETECTION & CYBERSECURITY
        </div>
      </div>

      {/* Card */}
      <div className="auth-card">
        <h2 style={{ color: "#e2e8f0", fontSize: 22, fontWeight: 700, marginBottom: 6, textAlign: "center" }}>
          Welcome Back
        </h2>
        <p style={{ color: "#475569", fontSize: 12, textAlign: "center", marginBottom: 24 }}>
          Access your threat intelligence dashboard
        </p>

        {error && <div className="auth-error">⚠ {error}</div>}

        <form onSubmit={handleSubmit}>
          <input className="auth-input" type="email" placeholder="Email Address" value={email} onChange={e => setEmail(e.target.value)} autoComplete="email" />
          <input className="auth-input" type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="current-password" />
          <button className="auth-btn" type="submit" disabled={loading}>
            {loading ? "⟳ AUTHENTICATING..." : "⬡ LOG IN"}
          </button>
        </form>

        <div style={{ margin: "20px 0", display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ flex: 1, height: 1, background: "#1e3a5f" }} />
          <div style={{ fontSize: 10, color: "#475569", fontWeight: 700 }}>OR</div>
          <div style={{ flex: 1, height: 1, background: "#1e3a5f" }} />
        </div>

        <div style={{ display: "flex", justifyContent: "center" }}>
          <GoogleLogin 
            onSuccess={credentialResponse => {
              fetch(`${API_BASE_URL}/auth/google`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(credentialResponse)
              }).then(async (r) => {
                const data = await r.json().catch(() => {
                  throw new Error("Invalid server response. Is the backend running?");
                });
                if (data.success) onLogin(data.user);
                else setError(data.error);
              }).catch(err => {
                console.error("Google Login Error:", err);
                setError("Google Auth Failed: " + (err.message || "Network Error"));
              });
            }}
            onError={() => {
              console.error("Google Login Component Error");
              setError("Google Login Failed: Check Console");
            }}
            theme="filled_black"
            shape="pill"
            text="signin_with"
            width="320"
          />
        </div>

        <div style={{ textAlign: "center", marginTop: 20, fontSize: 13, color: "#94a3b8" }}>
          Don't have an account?{" "}
          <span className="auth-link" onClick={onSwitchToSignup}>Sign Up</span>
        </div>
      </div>

      <div style={{ color: "#1e3a5f", fontSize: 10, letterSpacing: 1, marginTop: 24, zIndex: 10 }}>
        THREATGUARD AI • SECURE ACCESS PORTAL
      </div>
    </div>
  );
}

export default function App() {
  // Auth state
  const [currentPage, setCurrentPage] = useState(() => {
    const saved = localStorage.getItem("tg_user");
    return saved ? "dashboard" : "signup";
  });
  const [currentUser, setCurrentUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem("tg_user")); } catch { return null; }
  });

  const handleAuthSuccess = (user) => {
    setCurrentUser(user);
    localStorage.setItem("tg_user", JSON.stringify(user));
    setCurrentPage("dashboard");
  };

  const handleLogout = () => {
    setCurrentUser(null);
    localStorage.removeItem("tg_user");
    setCurrentPage("login");
  };

  let content;
  if (currentPage === "signup") {
    content = <SignupPage onSignup={handleAuthSuccess} onSwitchToLogin={() => setCurrentPage("login")} />;
  } else if (currentPage === "login") {
    content = <LoginPage onLogin={handleAuthSuccess} onSwitchToSignup={() => setCurrentPage("signup")} />;
  } else {
    content = <Dashboard currentUser={currentUser} onLogout={handleLogout} />;
  }

  return (
    <GoogleOAuthProvider clientId={import.meta.env.VITE_GOOGLE_CLIENT_ID || "684750461179-i1426j2a61vorp7qala0ilhri6ci2jev.apps.googleusercontent.com"}>
      {content}
    </GoogleOAuthProvider>
  );
}

function SecurityCoPilot({ isOpen, onClose, history, onSend, input, setInput, isLoading }) {
  const chatEndRef = useRef(null);
  
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [history]);

  if (!isOpen) return null;

  return (
    <div style={{ position: "fixed", top: 0, right: 0, width: 350, height: "100vh", background: "rgba(2, 12, 26, 0.95)", borderLeft: "1px solid #1e3a5f", zIndex: 10000, display: "flex", flexDirection: "column", backdropFilter: "blur(20px)", animation: "slideInRight 0.3s ease" }}>
      <div style={{ padding: "20px 24px", borderBottom: "1px solid #1e3a5f", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <div style={{ fontSize: 13, fontWeight: 900, color: "#0ea5e9", letterSpacing: 1 }}>🧠 AI SECURITY CO-PILOT</div>
          <div style={{ fontSize: 9, color: "#475569", letterSpacing: 1 }}>NEURAL LINK ACTIVE</div>
        </div>
        <button onClick={onClose} style={{ background: "none", border: "none", color: "#64748b", cursor: "pointer", fontSize: 18 }}>✖</button>
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: 20, display: "flex", flexDirection: "column", gap: 16 }}>
        {history.map((msg, i) => (
          <div key={i} style={{ 
            alignSelf: msg.role === "user" ? "flex-end" : "flex-start",
            maxWidth: "85%",
            background: msg.role === "user" ? "#0ea5e9" : "#0c1e35",
            color: msg.role === "user" ? "#fff" : "#e2e8f0",
            padding: "10px 14px",
            borderRadius: msg.role === "user" ? "14px 14px 2px 14px" : "14px 14px 14px 2px",
            fontSize: 12, lineHeight: 1.5, border: msg.role === "user" ? "none" : "1px solid #1e3a5f"
          }}>
            {msg.content}
          </div>
        ))}
        {isLoading && (
          <div style={{ alignSelf: "flex-start", background: "#0c1e35", padding: "10px 14px", borderRadius: "14px 14px 14px 2px", fontSize: 12, border: "1px solid #1e3a5f" }}>
            <span style={{ animation: "pulse 1s infinite" }}>⚡ Tactical processing...</span>
          </div>
        )}
        <div ref={chatEndRef} />
      </div>

      <form onSubmit={onSend} style={{ padding: 20, borderTop: "1px solid #1e3a5f", background: "#020817" }}>
        <div style={{ position: "relative" }}>
          <input 
            type="text" 
            value={input} 
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask Co-Pilot..."
            style={{ width: "100%", background: "#0c1e35", border: "1px solid #1e3a5f", borderRadius: 20, padding: "10px 45px 10px 16px", color: "#e2e8f0", fontSize: 12, outline: "none" }}
          />
          <button type="submit" style={{ position: "absolute", right: 8, top: 5, background: "#0ea5e9", border: "none", borderRadius: "50%", width: 28, height: 28, color: "#fff", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>
            ➤
          </button>
        </div>
      </form>
    </div>
  );
}

function Dashboard({ currentUser, onLogout }) {
  const [activeModule, setActiveModule] = useState("message");
  const [inputs, setInputs] = useState({ message: "", url: "", qr: "", screenshot: "", ransomware: "" });
  const [results, setResults] = useState({});
  const [loading, setLoading] = useState({});
  const [error, setError] = useState({});
  const [success, setSuccess] = useState({});
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState(null);
  const [lastRefresh, setLastRefresh] = useState("");
  const [isDemoMode, setIsDemoMode] = useState(true);
  const [isSirenActive, setIsSirenActive] = useState(false);
  const [logs, setLogs] = useState({});
  const [isAttackOverlayActive, setIsAttackOverlayActive] = useState(false);
  const [attackLogs, setAttackLogs] = useState([]);
  
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [decryptError, setDecryptError] = useState("");
  const [decryptSuccess, setDecryptSuccess] = useState(false);
  
  const fileInputRef = useRef(null);
  const [qrFileName, setQrFileName] = useState("");
  const screenshotInputRef = useRef(null);
  const [screenshotFileName, setScreenshotFileName] = useState("");
  const [ocrProgress, setOcrProgress] = useState(0);
  const [isOcrLoading, setIsOcrLoading] = useState(false);
  const trainInputRef = useRef(null);
  const [trainFileName, setTrainFileName] = useState("");
  
  // Elite Features Suite State
  const [isCopilotOpen, setIsCopilotOpen] = useState(false);
  const [chatHistory, setChatHistory] = useState([
    { role: "assistant", content: "AI Co-Pilot active. How can I assist with your threat intelligence today?" }
  ]);
  const [chatInput, setChatInput] = useState("");
  const [isChatLoading, setIsChatLoading] = useState(false);

  const loadData = () => {
    fetch(`${API_BASE_URL}/history`).then(r => r.json()).then(data => {
      setHistory(data.map(item => ({ moduleId: item.moduleId, result: item, timestamp: new Date(item.timestamp).toLocaleTimeString() })));
    }).catch(() => {});
    fetch(`${API_BASE_URL}/stats`).then(r => r.json()).then(data => {
      setStats(data);
      setLastRefresh(new Date().toLocaleTimeString());
    }).catch(() => {});
  };

  useEffect(() => {
    loadData();
    // Auto-refresh stats every 30 seconds
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  const playSiren = () => {
    try {
      setIsSirenActive(true);
      const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const duration = 15;
      
      // Master Gain for maximum power
      const masterGain = audioCtx.createGain();
      masterGain.gain.setValueAtTime(1.0, audioCtx.currentTime);
      masterGain.connect(audioCtx.destination);

      const playTone = (freq, type, detune, volume) => {
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = type;
        osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
        osc.detune.setValueAtTime(detune, audioCtx.currentTime);
        
        // Terrifying sweep
        for (let i = 0; i < duration; i++) {
          osc.frequency.exponentialRampToValueAtTime(freq * 2.2, audioCtx.currentTime + i + 0.2);
          osc.frequency.exponentialRampToValueAtTime(freq, audioCtx.currentTime + i + 0.5);
        }
        
        gain.gain.setValueAtTime(volume * 2.5, audioCtx.currentTime); // Boosted volume
        // Maintain full volume until the very end
        gain.gain.setValueAtTime(volume * 2.5, audioCtx.currentTime + duration - 0.1);
        gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + duration);
        
        osc.connect(gain);
        gain.connect(masterGain);
        osc.start();
        osc.stop(audioCtx.currentTime + duration);
      };

      // Boosted high-intensity dissonant cluster
      playTone(300, 'sawtooth', 0, 0.4);
      playTone(317, 'sawtooth', 15, 0.4); 
      playTone(120, 'square', 0, 0.3);    
      playTone(880, 'sine', 0, 0.2);     
      
      setTimeout(() => setIsSirenActive(false), duration * 1000);
    } catch (e) {
      console.error("Audio error:", e);
      setIsSirenActive(false);
    }
  };

  const speakText = (text) => {
    try {
      const utterance = new SpeechSynthesisUtterance(text);
      utterance.volume = 1.0; // Maximize volume
      utterance.rate = 0.95; // Optimal clarity
      utterance.pitch = 1.0;
      window.speechSynthesis.speak(utterance);
    } catch (e) {
      console.error("Speech error:", e);
    }
  };

  const analyze = useCallback(async (moduleId) => {
    let input = inputs[moduleId];
    // Handle text inputs vs file inputs generically
    if (typeof input === 'string') {
        input = input.trim();
    }
    
    if (!input && moduleId !== "qr") return;
    
    // For QR codes and generic file uploads, input is handled differently
    if (moduleId === "qr" && !input) {
      setError(e => ({...e, qr: "Please upload a valid QR code image first."}));
      return;
    }
    if (moduleId === "screenshot" && !input) {
      setError(e => ({...e, screenshot: isOcrLoading ? "OCR processing in progress..." : "Please upload a screenshot for OCR analysis first."}));
      return;
    }
    if (moduleId === "train" && !input) {
      setError(e => ({...e, train: "Please upload a JSON dataset first."}));
      return;
    }

    setLoading(l => ({ ...l, [moduleId]: true }));
    setError(e => ({ ...e, [moduleId]: null }));
    setSuccess(s => ({ ...s, [moduleId]: null }));
    setResults(r => { const n = { ...r }; delete n[moduleId]; return n; });
    const steps = moduleId === "train" 
      ? ["Validating JSON schema...", "Extracting indicators...", "Updating local heuristic matrices...", "Committing to local knowledge base..."]
      : getAnalysisSteps(moduleId);
    setLogs(p => ({ ...p, [moduleId]: [] }));

    for (const step of steps) {
      setLogs(p => ({ ...p, [moduleId]: [...(p[moduleId] || []), step] }));
      await new Promise(r => setTimeout(r, 280 + Math.random() * 300));
    }

    try {
      const result = await fetchAnalysis(moduleId, input, isDemoMode);
      
      if (moduleId === "train") {
         setSuccess(s => ({...s, [moduleId]: result.message}));
         setInputs(i => ({...i, train: ""}));
         setTrainFileName("");
      } else {
         setResults(prev => ({ ...prev, [moduleId]: result }));
      
         // Audio alerts based on threat level
         if (result.threatLevel === "CRITICAL") {
           playSiren();
         } else if (result.threatLevel === "HIGH") {
           speakText("Security Alert. High threat detected. Immediate counter-measures required.");
         } else if (result.threatLevel === "MEDIUM") {
           speakText("Warning: Medium level risk detected. Further investigation required.");
         } else if (result.threatLevel === "LOW") {
           speakText("System scan: No significant threats found. Status: Secure.");
         }
         setHistory(h => [{ moduleId, result, timestamp: new Date().toLocaleTimeString() }, ...h].slice(0, 20));
      }
      loadData();
    } catch (e) {
      setError(err => ({ ...err, [moduleId]: e.message }));
    } finally {
      setLoading(l => ({ ...l, [moduleId]: false }));
    }
  }, [inputs, isDemoMode]);

  const handleQRUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setQrFileName(file.name);
    setError(err => ({ ...err, qr: null }));
    setInputs(i => ({...i, qr: ""})); // Reset input text visually if any
    setResults(r => { const n = { ...r }; delete n.qr; return n; }); // Clear previous results

    const reader = new FileReader();
    reader.onload = (event) => {
      const image = new Image();
      image.onload = () => {
        const canvas = document.createElement("canvas");
        const context = canvas.getContext("2d", { willReadFrequently: true });
        
        // Scale down if too large to improve performance
        const MAX_WIDTH = 800;
        const scale = Math.min(1, MAX_WIDTH / image.width);
        canvas.width = image.width * scale;
        canvas.height = image.height * scale;
        
        context.drawImage(image, 0, 0, canvas.width, canvas.height);
        try {
          const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(imageData.data, imageData.width, imageData.height);
          
          if (code && code.data) {
             setInputs(i => ({...i, qr: code.data}));
             // We can optionally trigger analyze automatically or wait for user to click analyze
          } else {
             setError(err => ({ ...err, qr: "Could not detect a QR code in the uploaded image. Please try another image." }));
             setQrFileName("");
          }
        } catch (error) {
           setError(err => ({ ...err, qr: "Error processing the image." }));
           setQrFileName("");
        }
      };
      image.onerror = () => {
         setError(err => ({ ...err, qr: "Failed to load image." }));
         setQrFileName("");
      };
      image.src = event.target.result;
    };
    reader.onerror = () => {
      setError(err => ({ ...err, qr: "Failed to read file." }));
      setQrFileName("");
    };
    reader.readAsDataURL(file);
  };
  
  const handleScreenshotUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setScreenshotFileName(file.name);
    setError(err => ({ ...err, screenshot: null }));
    setIsOcrLoading(true);
    setOcrProgress(0);
    setInputs(i => ({...i, screenshot: ""}));

    try {
      const result = await Tesseract.recognize(
        file,
        'eng',
        { 
          logger: m => {
            if (m.status === 'recognizing text') {
              setOcrProgress(Math.round(m.progress * 100));
            }
          }
        }
      );
      
      const text = result.data.text.trim();
      if (text) {
        setInputs(i => ({...i, screenshot: text}));
      } else {
        setError(err => ({ ...err, screenshot: "No text detected in the screenshot. Please try another image." }));
      }
    } catch (err) {
      setError(err => ({ ...err, screenshot: "OCR processing failed. " + err.message }));
    } finally {
      setIsOcrLoading(false);
      setOcrProgress(0);
    }
  };

  const handleDatasetUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    setTrainFileName(file.name);
    setError(err => ({ ...err, train: null }));
    setSuccess(s => ({ ...s, train: null }));
    setInputs(i => ({...i, train: file}));
  };

  const downloadForensicsReport = async () => {
    try {
        const res = await fetch(`${API_BASE_URL}/forensics/report`);
        const html = await res.text();
        const blob = new Blob([html], { type: "text/html" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `ThreatGuard_Forensics_Report_${Date.now()}.html`;
        a.click();
    } catch (e) {
        console.error("Report generation failed:", e);
    }
  };

  const handleChatSubmit = async (e) => {
    e.preventDefault();
    if (!chatInput.trim() || isChatLoading) return;

    const userMsg = { role: "user", content: chatInput };
    setChatHistory(prev => [...prev, userMsg]);
    setChatInput("");
    setIsChatLoading(true);

    try {
        const res = await fetch(`${API_BASE_URL}/copilot/chat`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ 
                message: chatInput, 
                history: chatHistory,
                is_demo_mode: isDemoMode 
            })
        });
        const data = await res.json();
        if (data.success) {
            setChatHistory(prev => [...prev, { role: "assistant", content: data.reply }]);
        }
    } catch (e) {
        setChatHistory(prev => [...prev, { role: "assistant", content: "Error communicating with neural link. Deployment failed." }]);
    } finally {
        setIsChatLoading(false);
    }
  };

  const triggerSimulation = async () => {
    setActiveModule("ransomware");
    setInputs(i => ({...i, ransomware: "WARNING: High entropy detected in E:\\Client_Backups\\.\nInitiating vssadmin delete shadows /all /quiet.\nEncrypting core files to .crypt..."}));
    setIsAttackOverlayActive(true);
    setAttackLogs(["Initializing attack vectors...", "Bypassing Windows Defender...", "Accessing target directory..."]);
    
    try {
        const res = await fetch(`${API_BASE_URL}/simulate-attack`, { method: "POST" });
        const data = await res.json();
        
        if (data.success && data.log) {
            // Stream logs dramatically
            for (let i = 0; i < data.log.length; i++) {
                await new Promise(r => setTimeout(r, 400 + Math.random() * 300));
                setAttackLogs(prev => [...prev, data.log[i]]);
            }
            await new Promise(r => setTimeout(r, 600));
            setAttackLogs(prev => [...prev, "Dropping ransom note...", "ATTACK SUCCESSFUL. EXTORTION PHASE ACTIVE."]);
        }
    } catch (e) {
        setAttackLogs(prev => [...prev, "Executing fallback local encryption payload..."]);
    }

    // Auto-trigger analysis for dramatic effect (ThreatGuard AI Intercepts)
    setTimeout(() => {
        setIsAttackOverlayActive(false);
        setAttackLogs([]);
        setDecryptError("");
        setDecryptSuccess(false);
        analyze("ransomware");
    }, 1500);
  };
  
  const handleDecrypt = async (key) => {
    setIsDecrypting(true);
    setDecryptError("");
    setDecryptSuccess(false);
    try {
        const res = await fetch(`${API_BASE_URL}/decrypt`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ key })
        });
        const data = await res.json();
        if (data.success) {
            setDecryptSuccess(true);
            setIsSirenActive(false); // Silence the alarm because threat is neutralized
        } else {
            setDecryptError(data.error || "Decryption failed.");
        }
    } catch (e) {
        setDecryptError(e.message);
    } finally {
        setIsDecrypting(false);
    }
  };

  const exportReport = (result) => {
    const report = {
      generated: new Date().toISOString(),
      platform: "ThreatGuard AI v4.0 Hackathon",
      analysis: result
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `ThreatGuard_Report_${Date.now()}.json`; a.click();
  };

  const activeModuleData = MODULES.find(m => m.id === activeModule);
  const totalScans = stats?.counts?.reduce((a, b) => a + b.count, 0) || 0;

  return (
    <div style={{ 
      minHeight: "100vh", 
      background: isSirenActive ? "#1a0505" : "#020817", 
      color: "#e2e8f0", 
      fontFamily: "'Exo 2', sans-serif",
      transition: "background 0.2s",
      animation: isSirenActive ? "flickerRed 0.5s infinite" : "none"
    }}>
      <SecurityCoPilot 
        isOpen={isCopilotOpen} 
        onClose={() => setIsCopilotOpen(false)}
        history={chatHistory}
        onSend={handleChatSubmit}
        input={chatInput}
        setInput={setChatInput}
        isLoading={isChatLoading}
      />
      {isAttackOverlayActive && (
        <div style={{ position: "fixed", top: 0, left: 0, width: "100vw", height: "100vh", background: "#000", zIndex: 9999, display: "flex", flexDirection: "column", padding: 40, fontFamily: "monospace", color: "#f87171" }}>
           <div style={{ fontSize: 24, fontWeight: 900, marginBottom: 20 }}>RANSOMWARE_PAYLOAD_v3.6.exe - ACTIVE</div>
           <div style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: 8 }}>
               {attackLogs.map((l, i) => (
                   <div key={i} style={{ fontSize: 16 }}>{'>'} {l}</div>
               ))}
               <div style={{ animation: "pulse 0.5s infinite" }}>_</div>
           </div>
           <div style={{ position: "absolute", top: "50%", left: "50%", transform: "translate(-50%, -50%)", fontSize: 120, opacity: 0.1, color: "#ef4444", fontWeight: 900, pointerEvents: "none" }}>ENCRYPTING</div>
        </div>
      )}
      {isSirenActive && (
        <style>
          {`
            @keyframes flickerRed {
              0% { opacity: 1; }
              50% { opacity: 0.7; background: #330000; }
              100% { opacity: 1; }
            }
          `}
        </style>
      )}
      {/* Header */}
      <div style={{ borderBottom: "1px solid #0f2a4a", background: "linear-gradient(180deg, #020c1a 0%, #020817 100%)", padding: "16px 24px" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
          <div>
            <div style={{ fontSize: 24, fontWeight: 900, color: "#0ea5e9", letterSpacing: 3, textShadow: "0 0 20px #0ea5e980" }}>⬡ THREATGUARD AI</div>
            <div style={{ color: "#475569", fontSize: 10, letterSpacing: 4, marginTop: 2 }}>GLOBAL THREAT INTELLIGENCE PLATFORM</div>
          </div>
          <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
            <div style={{ background: "#0c1e35", border: "1px solid #1e3a5f", borderRadius: 8, padding: "8px 14px", fontSize: 11 }}>
              <span style={{ color: "#475569" }}>TOTAL SCANS </span>
              <span style={{ color: "#0ea5e9", fontWeight: 700, fontFamily: "monospace" }}>{totalScans}</span>
            </div>
            
            <button onClick={downloadForensicsReport} style={{ background: "#0c1e35", border: "1px solid #1e3a5f", borderRadius: 8, padding: "8px 14px", fontSize: 10, fontWeight: 700, color: "#94a3b8", cursor: "pointer", letterSpacing: 1 }}>
               📂 FORENSICS REPORT
            </button>

            <button onClick={() => setIsCopilotOpen(true)} style={{ background: "linear-gradient(135deg, #0369a1, #0ea5e9)", border: "none", borderRadius: 8, padding: "8px 14px", fontSize: 10, fontWeight: 700, color: "#fff", cursor: "pointer", letterSpacing: 1, display: "flex", alignItems: "center", gap: 6 }}>
               <span>🧠</span> CO-PILOT
            </button>
            <div style={{ display: "flex", alignItems: "center", gap: 8, background: "#0c1e35", padding: "6px 12px", borderRadius: 20, border: "1px solid #1e3a5f" }}>
              <span style={{ fontSize: 10, fontWeight: 700, color: isDemoMode ? "#0ea5e9" : "#475569", letterSpacing: 1 }}>DEMO</span>
              <button onClick={() => setIsDemoMode(!isDemoMode)} style={{ width: 34, height: 18, borderRadius: 10, background: isDemoMode ? "#0ea5e9" : "#1e293b", position: "relative", border: "none", cursor: "pointer", padding: 0 }}>
                <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#fff", position: "absolute", top: 3, left: isDemoMode ? 19 : 3, transition: "0.3s" }} />
              </button>
            </div>
            <button onClick={triggerSimulation} style={{ background: "#7f1d1d", color: "#fca5a5", border: "1px solid #ef4444", borderRadius: 8, padding: "8px 14px", fontSize: 11, fontWeight: 700, cursor: "pointer", display: "flex", alignItems: "center", gap: 6, animation: "pulse 2s infinite" }}>
                <span>🔥</span> SIMULATE LIVE ATTACK
            </button>
            {currentUser && (
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <div style={{ background: "#0c1e35", border: "1px solid #1e3a5f", borderRadius: 8, padding: "8px 12px", fontSize: 11, display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ fontSize: 14 }}>👤</span>
                  <span style={{ color: "#94a3b8" }}>{currentUser.name}</span>
                </div>
                <button onClick={onLogout} style={{ background: "#1e293b", color: "#94a3b8", border: "1px solid #334155", borderRadius: 8, padding: "8px 12px", fontSize: 10, fontWeight: 700, cursor: "pointer", letterSpacing: 1, transition: "all 0.2s" }}
                  onMouseOver={e => { e.currentTarget.style.background = "#7f1d1d"; e.currentTarget.style.color = "#fca5a5"; e.currentTarget.style.borderColor = "#ef4444"; }}
                  onMouseOut={e => { e.currentTarget.style.background = "#1e293b"; e.currentTarget.style.color = "#94a3b8"; e.currentTarget.style.borderColor = "#334155"; }}
                >
                  LOGOUT
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      <div style={{ maxWidth: 1200, margin: "0 auto", padding: "20px 16px", display: "grid", gridTemplateColumns: "1fr 300px", gap: 20 }}>
        {/* Left: Analysis Area */}
        <div>
          {/* Module Tabs */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, marginBottom: 20 }}>
            {MODULES.map(mod => {
              const hasResult = !!results[mod.id];
              const isActive = activeModule === mod.id;
              const level = hasResult ? results[mod.id].threatLevel : null;
              return (
                <button key={mod.id} onClick={() => setActiveModule(mod.id)} style={{
                  background: isActive ? "#0c1e35" : "#0a1628",
                  border: `1px solid ${isActive ? "#0ea5e9" : "#1e3a5f"}`,
                  borderRadius: 10, padding: 12, cursor: "pointer",
                  color: isActive ? "#e2e8f0" : "#64748b", textAlign: "left"
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ fontSize: 20 }}>{mod.icon}</span>
                    {hasResult && <span style={{ width: 8, height: 8, borderRadius: "50%", background: THREAT_COLORS[level]?.dot, display: "block", animation: "pulse 2s infinite" }} />}
                  </div>
                  <div style={{ fontSize: 11, fontWeight: 700, marginTop: 4, letterSpacing: 0.5 }}>{mod.label}</div>
                  <div style={{ fontSize: 9, opacity: 0.6, marginTop: 2 }}>{mod.desc}</div>
                </button>
              );
            })}
          </div>

          {/* Analysis Panel */}
          <div style={{ background: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 12, padding: 24 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
              <span style={{ fontSize: 26 }}>{activeModuleData.icon}</span>
              <div>
                <div style={{ fontSize: 16, fontWeight: 700 }}>{activeModuleData.label} Analyzer</div>
                <div style={{ color: "#475569", fontSize: 12 }}>{activeModuleData.desc}</div>
              </div>
            </div>

            {activeModule === "vault" ? (
              <SecurityVault />
            ) : (
              <>
                {activeModuleData.inputType === "textarea" ? (
                  <textarea className="cyber-input" rows={4} value={inputs[activeModule]}
                    onChange={e => setInputs(i => ({ ...i, [activeModule]: e.target.value }))}
                    placeholder={activeModuleData.placeholder} />
                ) : activeModuleData.inputType === "image" ? (
                   <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                     <div 
                       onClick={() => {
                         if (activeModule === "qr") fileInputRef.current?.click();
                         else screenshotInputRef.current?.click();
                       }}
                       style={{
                         border: `2px dashed ${activeModule === "qr" ? "#1e3a5f" : "#0369a1"}`, borderRadius: 8, padding: 30, textAlign: "center", cursor: "pointer",
                         background: "rgba(12, 30, 53, 0.5)", color: "#94a3b8", transition: "all 0.2s"
                       }}
                       onMouseOver={e => e.currentTarget.style.borderColor = activeModule === "qr" ? "#0ea5e9" : "#38bdf8"}
                       onMouseOut={e => e.currentTarget.style.borderColor = activeModule === "qr" ? "#1e3a5f" : "#0369a1"}
                     >
                       <input type="file" accept="image/*" ref={fileInputRef} onChange={handleQRUpload} style={{ display: "none" }} />
                       <input type="file" accept="image/*" ref={screenshotInputRef} onChange={handleScreenshotUpload} style={{ display: "none" }} />
                       <div style={{ fontSize: 32, marginBottom: 10 }}>{activeModule === "qr" ? "▦" : "📸"}</div>
                       <div style={{ fontWeight: 700, color: "#e2e8f0" }}>{activeModule === "qr" ? "Click to upload QR Image" : "Click to upload Screenshot"}</div>
                       <div style={{ fontSize: 11, marginTop: 4 }}>Supports JPG, PNG, WEBP</div>
                     </div>
                     
                     {(activeModule === "qr" ? qrFileName : screenshotFileName) && (
                       <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", background: "#0c1e35", padding: "8px 12px", borderRadius: 6, border: "1px solid #1e3a5f" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                             <span style={{ fontSize: 16 }}>{activeModule === "qr" ? "📸" : "📄"}</span>
                             <span style={{ fontSize: 12, color: "#e2e8f0", fontFamily: "monospace", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{activeModule === "qr" ? qrFileName : screenshotFileName}</span>
                          </div>
                          <button onClick={() => { 
                            if (activeModule === "qr") { setQrFileName(""); setInputs(i => ({...i, qr: ""})); }
                            else { setScreenshotFileName(""); setInputs(i => ({...i, screenshot: ""})); }
                          }} style={{ background: "none", border: "none", color: "#f87171", cursor: "pointer", fontSize: 14 }}>✖</button>
                        </div>

                        {activeModule === "screenshot" && isOcrLoading && (
                          <div style={{ background: "#0c1e35", borderRadius: 6, padding: "8px 12px", border: "1px solid #1e3a5f" }}>
                             <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                               <span style={{ fontSize: 10, color: "#94a3b8", fontWeight: 700, letterSpacing: 1 }}>EXTRACTING TEXT...</span>
                               <span style={{ fontSize: 10, color: "#0ea5e9", fontWeight: 700, fontFamily: "monospace" }}>{ocrProgress}%</span>
                             </div>
                             <div style={{ height: 4, background: "#020817", borderRadius: 2, overflow: "hidden" }}>
                               <div style={{ width: `${ocrProgress}%`, height: "100%", background: "#0ea5e9", transition: "width 0.3s" }} />
                             </div>
                          </div>
                        )}
                       </div>
                     )}
                     
                     {inputs[activeModule] && (
                       <div style={{ background: "#020817", padding: "8px 12px", borderRadius: 6, border: "1px solid #0f2a4a" }}>
                           <div style={{ fontSize: 10, color: "#0ea5e9", fontWeight: 700, marginBottom: 4, letterSpacing: 1, textTransform: "uppercase" }}>{activeModule === "qr" ? "Decoded Target" : "Extracted Intelligence"}</div>
                           <div style={{ fontSize: 12, color: "#a5b4fc", fontFamily: "monospace", wordBreak: "break-all", maxHeight: 100, overflowY: "auto" }}>{inputs[activeModule]}</div>
                       </div>
                     )}
                   </div>
                ) : activeModuleData.inputType === "dataset" ? (
                   <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                     <div 
                       onClick={() => trainInputRef.current?.click()}
                       style={{
                         border: "2px dashed #1e3a5f", borderRadius: 8, padding: 30, textAlign: "center", cursor: "pointer",
                         background: "rgba(12, 30, 53, 0.5)", color: "#94a3b8", transition: "all 0.2s"
                       }}
                       onMouseOver={e => e.currentTarget.style.borderColor = "#c084fc"}
                       onMouseOut={e => e.currentTarget.style.borderColor = "#1e3a5f"}
                     >
                       <input type="file" accept=".json" ref={trainInputRef} onChange={handleDatasetUpload} style={{ display: "none" }} />
                       <div style={{ fontSize: 32, marginBottom: 10 }}>📊</div>
                       <div style={{ fontWeight: 700, color: "#e2e8f0" }}>Upload JSON Dataset</div>
                       <div style={{ fontSize: 11, marginTop: 4 }}>Must match threat indicator schema</div>
                     </div>
                     
                     {trainFileName && (
                       <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", background: "#1a0a2b", padding: "8px 12px", borderRadius: 6, border: "1px solid #4a044e" }}>
                         <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <span style={{ fontSize: 16 }}>📄</span>
                            <span style={{ fontSize: 12, color: "#c084fc", fontFamily: "monospace", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{trainFileName}</span>
                         </div>
                         <button onClick={() => { setTrainFileName(""); setInputs(i => ({...i, train: ""})); }} style={{ background: "none", border: "none", color: "#f87171", cursor: "pointer", fontSize: 14 }}>✖</button>
                       </div>
                     )}
                   </div>
                ) : (
                   <input className="cyber-input" type="text" value={inputs[activeModule]}
                     onChange={e => setInputs(i => ({ ...i, [activeModule]: e.target.value }))}
                     onKeyDown={e => e.key === "Enter" && analyze(activeModule)}
                     placeholder={activeModuleData.placeholder} />
                 )}
                <button onClick={() => analyze(activeModule)} 
                  disabled={loading[activeModule] || (!inputs[activeModule] || (typeof inputs[activeModule] === 'string' && !inputs[activeModule].trim())) && activeModule !== "qr"}
                  style={{ marginTop: 12, width: "100%", padding: 12, borderRadius: 8, border: "none", cursor: "pointer", fontWeight: 700, fontSize: 13, letterSpacing: 1, color: "#fff", background: loading[activeModule] ? "#0f2a4a" : "linear-gradient(135deg, #0369a1, #0ea5e9)" }}>
                  {loading[activeModule] ? "⚡ ANALYZING..." : "⬡ AUTHORIZE ANALYSIS"}
                </button>


                {loading[activeModule] && logs[activeModule] && (
                  <div style={{ marginTop: 12, background: "#0c1e35", borderRadius: 8, padding: 12, fontFamily: "monospace", fontSize: 10 }}>
                    {logs[activeModule].map((log, i) => (
                      <div key={i} style={{ color: i === logs[activeModule].length - 1 ? "#0ea5e9" : "#334155", marginBottom: 2 }}>
                        {i === logs[activeModule].length - 1 ? "▶" : "✓"} {log}
                      </div>
                    ))}
                    <div style={{ animation: "pulse 0.8s infinite", color: "#0ea5e9" }}>_</div>
                  </div>
                )}

                {error[activeModule] && (
                  <div style={{ marginTop: 10, color: "#f87171", background: "#2b0f0a", padding: "8px 12px", borderRadius: 6, fontSize: 12 }}>
                    ⚠ {error[activeModule]}
                  </div>
                )}
                
                {success[activeModule] && (
                  <div style={{ marginTop: 10, color: "#4ade80", background: "#0d2b1a", padding: "8px 12px", borderRadius: 6, fontSize: 12, border: "1px solid #166534" }}>
                    ✓ {success[activeModule]}
                  </div>
                )}

                {results[activeModule] && (
                  <ResultCard 
                    result={results[activeModule]} 
                    onExport={() => exportReport(results[activeModule])} 
                    onDecrypt={handleDecrypt}
                    decrypting={isDecrypting}
                    decryptError={decryptError}
                    decryptSuccess={decryptSuccess}
                  />
                )}
              </>
            )}
          </div>
        </div>

        {/* Right: Live Intelligence Panel */}
        <div>
          <SmartFolderProtection isSirenActive={isSirenActive} />
          <GlobalThreatMap />
          <ThreatTrendChart history={history} />
          <SOCStatsPanel stats={stats} lastRefresh={lastRefresh} />

          {/* Recent Feed */}
          {history.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{ color: "#94a3b8", fontSize: 11, fontWeight: 700, letterSpacing: 2, textTransform: "uppercase", marginBottom: 12 }}>
                📂 Live Intelligence Feed
              </div>
              <div style={{ display: "grid", gap: 6 }}>
                {history.slice(0, 6).map((item, i) => {
                  const c = THREAT_COLORS[item.result?.threatLevel] || THREAT_COLORS.MEDIUM;
                  const mod = MODULES.find(m => m.id === item.moduleId);
                  return (
                    <div key={i} style={{ background: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 6, padding: "8px 10px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                          <span>{mod?.icon}</span>
                          <span style={{ color: "#e2e8f0", fontSize: 11, fontWeight: 600 }}>{item.result?.category || "Unknown"}</span>
                        </div>
                        <span style={{ color: c.text, fontSize: 9, fontWeight: 700, background: c.badge, padding: "1px 6px", borderRadius: 8 }}>{item.result?.threatLevel}</span>
                      </div>
                      <div style={{ color: "#334155", fontSize: 9, marginTop: 2, fontFamily: "monospace" }}>{item.timestamp}</div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>

      <div style={{ textAlign: "center", color: "#1e3a5f", fontSize: 10, paddingBottom: 30, letterSpacing: 1 }}>
        THREATGUARD AI • INTERNAL USE ONLY
      </div>
    </div>
  );
}
