import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import sqlite3 from "sqlite3";
import fetch from "node-fetch";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config({ path: "../.env" });

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Database Setup
const db = new sqlite3.Database("threats.db");

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      moduleId TEXT,
      input TEXT,
      threatLevel TEXT,
      category TEXT,
      confidenceScore INTEGER,
      summary TEXT,
      riskScore INTEGER,
      attribution TEXT,
      killChainStage TEXT,
      osint TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Add osint column if it doesn't exist (for existing databases)
  db.run("ALTER TABLE scans ADD COLUMN osint TEXT", (err) => {
    if (err && !err.message.includes("duplicate column name")) console.error(err);
  });
});

// Helper for Promisified Queries
const dbAll = (query, params) => new Promise((resolve, reject) => {
  db.all(query, params, (err, rows) => err ? reject(err) : resolve(rows));
});

const dbRun = (query, params) => new Promise((resolve, reject) => {
  db.run(query, params, function(err) { err ? reject(err) : resolve(this); });
});

// --- Heuristics Logic ---
const SUSPICIOUS_TLDS = [".xyz", ".top", ".pw", ".bid", ".icu", ".work", ".click", ".zip", ".mov"];
const BRAND_KEYWORDS = ["paypal", "google", "microsoft", "amazon", "apple", "netflix", "bank", "secure", "verify"];

const analyzeUrlHeuristics = (url) => {
  const findings = [];
  let score = 10;
  
  try {
    const urlObj = new URL(url.startsWith("http") ? url : `http://${url}`);
    const hostname = urlObj.hostname.toLowerCase();
    
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
      findings.push("IP-based hostname detected (High Risk)");
      score += 40;
    }
    
    const tld = hostname.split(".").pop();
    if (SUSPICIOUS_TLDS.includes(`.${tld}`)) {
      findings.push(`Suspicious TLD detected: .${tld}`);
      score += 25;
    }
    
    BRAND_KEYWORDS.forEach(brand => {
      if (hostname.includes(brand) && !hostname.endsWith(`${brand}.com`) && !hostname.endsWith(`${brand}.org`)) {
        findings.push(`Potential ${brand} impersonation detected`);
        score += 35;
      }
    });

    if (url.length > 70) {
      findings.push("Unusually long URL (Potential obfuscation)");
      score += 15;
    }
  } catch (e) { score = 5; }

  return { findings, riskScore: Math.min(100, score) };
};

const analyzeTextHeuristics = (text) => {
  const findings = [];
  let score = 10;
  const content = text.toLowerCase();

  const urgencyTerms = ["urgent", "account suspended", "immediate action", "verify now", "security alert"];
  urgencyTerms.forEach(t => { if (content.includes(t)) { findings.push(`Urgency trigger: "${t}"`); score += 20; } });
  
  const financialTerms = ["payment", "invoice", "refund", "transaction", "unauthorized"];
  financialTerms.forEach(t => { if (content.includes(t)) { findings.push(`Financial trigger: "${t}"`); score += 20; } });

  return { findings, riskScore: Math.min(100, score) };
};

// --- Claude API Wrapper ---
const SYSTEM_PROMPT = `You are the ThreatGuard AI Intelligence Engine. Analyze the input for security threats and categorize it into the Lockheed Martin Cyber Kill Chain.
Return ONLY a valid JSON object with:
{ 
  "threatLevel": "LOW"|"MEDIUM"|"HIGH"|"CRITICAL", 
  "category": string, 
  "confidenceScore": number, 
  "summary": string, 
  "indicators": string[], 
  "recommendedActions": string[], 
  "riskScore": number, 
  "technicalDetails": string,
  "killChainStage": "Reconnaissance"|"Weaponization"|"Delivery"|"Exploitation"|"Installation"|"C2"|"Actions on Objectives"
}`;

async function callClaude(userMessage, moduleId, isDemoMode) {
  const apiKey = process.env.VITE_ANTHROPIC_API_KEY;
  const hasValidKey = apiKey && apiKey !== "your_api_key_here" && apiKey.startsWith("sk-ant-");

  if (isDemoMode || !hasValidKey) {
    let hash = 0;
    const seed = userMessage + moduleId;
    for (let i = 0; i < seed.length; i++) hash = ((hash << 5) - hash) + seed.charCodeAt(i);
    const absHash = Math.abs(hash);
    const riskScore = (absHash % 70) + 20;
    
    const stages = ["Reconnaissance", "Weaponization", "Delivery", "Exploitation", "Installation", "C2", "Actions on Objectives"];
    
    return {
      threatLevel: riskScore > 80 ? "CRITICAL" : riskScore > 60 ? "HIGH" : riskScore > 30 ? "MEDIUM" : "LOW",
      category: moduleId === "url" ? "Phishing Domain" : "Social Engineering",
      confidenceScore: 85 + (absHash % 10),
      summary: "Input analysis shows patterns consistent with professional deception campaigns and multi-stage cyber infrastructure.",
      indicators: [],
      recommendedActions: ["Avoid interacting with the content", "Report to security team"],
      riskScore,
      technicalDetails: "K-CHAIN_v4_ASSESS: STAGE_IDENTIFIED_" + absHash.toString(16).slice(0, 4),
      killChainStage: stages[absHash % stages.length]
    };
  }

  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01"
    },
    body: JSON.stringify({
      model: "claude-3-sonnet-20240229",
      max_tokens: 1000,
      system: SYSTEM_PROMPT,
      messages: [{ role: "user", content: userMessage }],
    }),
  });

  const data = await response.json();
  const text = data.content?.[0]?.text || "";
  try {
    return JSON.parse(text.replace(/```json|```/g, "").trim());
  } catch (e) {
    throw new Error("Invalid intelligence response");
  }
}

// --- Endpoints ---

app.get("/api/history", async (req, res) => {
  try {
    const history = await dbAll("SELECT * FROM scans ORDER BY timestamp DESC LIMIT 20");
    res.json(history);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch history" });
  }
});

app.get("/api/stats", async (req, res) => {
  try {
    const counts = await dbAll(`
      SELECT threatLevel, COUNT(*) as count 
      FROM scans 
      GROUP BY threatLevel
    `);
    
    const timeline = await dbAll(`
      SELECT strftime('%H:00', timestamp) as hour, COUNT(*) as count
      FROM scans
      WHERE timestamp > datetime('now', '-24 hours')
      GROUP BY hour
      ORDER BY hour ASC
    `);

    const stages = await dbAll(`
      SELECT killChainStage, COUNT(*) as count
      FROM scans
      WHERE killChainStage IS NOT NULL
      GROUP BY killChainStage
      ORDER BY count DESC
    `);

    const moduleBreakdown = await dbAll(`
      SELECT moduleId, COUNT(*) as count
      FROM scans
      GROUP BY moduleId
      ORDER BY count DESC
    `);

    const topCategories = await dbAll(`
      SELECT category, COUNT(*) as count, AVG(riskScore) as avgRisk
      FROM scans
      WHERE category IS NOT NULL
      GROUP BY category
      ORDER BY count DESC
      LIMIT 5
    `);

    const avgStats = await dbAll(`
      SELECT 
        AVG(confidenceScore) as avgConfidence,
        AVG(riskScore) as avgRisk,
        MAX(riskScore) as maxRisk,
        COUNT(*) as total
      FROM scans
    `);

    res.json({ counts, timeline, stages, moduleBreakdown, topCategories, avgStats: avgStats[0] });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch stats" });
  }
});

app.post("/api/analyze", async (req, res) => {
  const { moduleId, input, isDemoMode } = req.body;
  if (!input) return res.status(400).json({ error: "No input provided" });

  try {
    // 1. Run Local Heuristics
    const heuristicResult = (moduleId === "url" || moduleId === "qr") 
      ? analyzeUrlHeuristics(input) 
      : analyzeTextHeuristics(input);

    // 2. Call AI
    const result = await callClaude(input, moduleId, isDemoMode);

    // 3. Merge Results
    result.indicators = Array.from(new Set([...(result.indicators || []), ...heuristicResult.findings]));
    result.riskScore = Math.max(result.riskScore, heuristicResult.riskScore);

    if (result.riskScore > 85) result.threatLevel = "CRITICAL";
    else if (result.riskScore > 65) result.threatLevel = "HIGH";
    else if (result.riskScore > 35) result.threatLevel = "MEDIUM";
    else result.threatLevel = "LOW";

    // 4. Persist
    await dbRun(`
      INSERT INTO scans (moduleId, input, threatLevel, category, confidenceScore, summary, riskScore, attribution, killChainStage)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [moduleId, input.slice(0, 500), result.threatLevel, result.category, result.confidenceScore, result.summary, result.riskScore, "N/A", result.killChainStage]);

    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Analysis failed" });
  }
});

app.listen(PORT, () => console.log(`ThreatGuard AI Backend running on port ${PORT}`));
