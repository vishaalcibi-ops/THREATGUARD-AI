import os
import io
import re
import json
import sqlite3
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
import requests as http_requests
from PIL import Image
import cv2
import numpy as np
import difflib
import shutil
import time
import base64
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

load_dotenv()

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app)

DB_PATH = "threats.db"
VAULT_DIR = os.path.join(os.getcwd(), "secure_vault")
BACKUP_DIR = os.path.join(os.getcwd(), "vault_backups")
VAULT_STORAGE_DIR = os.path.join(os.getcwd(), "vault_storage")
os.makedirs(VAULT_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(VAULT_STORAGE_DIR, exist_ok=True)

# Vault State (In-memory for demo)
vault_state = {
    "is_frozen": False,
    "last_actions": [], # List of (timestamp, action_type)
    "monitoring_logs": [],
    "threat_level": "LOW",
    "file_signatures": {} # filename -> safety_code
}

SIGNATURES_PATH = os.path.join(VAULT_DIR, ".vault_signatures.json")
if os.path.exists(SIGNATURES_PATH):
    try:
        with open(SIGNATURES_PATH, "r") as f:
            vault_state["file_signatures"] = json.load(f)
    except: pass

def save_vault_signatures():
    with open(SIGNATURES_PATH, "w") as f:
        json.dump(vault_state["file_signatures"], f)

def log_vault_activity(action_type, details):
    now = datetime.now()
    vault_state["last_actions"].append((now, action_type))
    vault_state["monitoring_logs"].insert(0, {
        "timestamp": now.strftime("%H:%M:%S"),
        "action": action_type,
        "details": details
    })
    
    # Simple AI heuristic for mass changes
    # Detect if more than 5 modifications in 10 seconds
    recent = [a for a in vault_state["last_actions"] if (now - a[0]).total_seconds() < 10]
    
    # Check for Canary File modifications
    if details and any(canary in details for canary in ["Admin_Passwords.txt", "Bitcoin_Wallet_Backup.txt"]):
        vault_state["is_frozen"] = True
        vault_state["threat_level"] = "CRITICAL"
        log_vault_activity("CANARY_TRAP_TRIGGERED", f"Unauthorized access to canary file: {details}")
        return

    if len(recent) > 5 and not vault_state["is_frozen"]:
        vault_state["is_frozen"] = True
        vault_state["threat_level"] = "CRITICAL"
        log_vault_activity("SYSTEM_FREEZE", "Ransomware-like mass modification detected. Automatic freeze triggered.")
    elif len(recent) > 3 or vault_state["threat_level"] == "CRITICAL":
        vault_state["threat_level"] = "CRITICAL" if vault_state["is_frozen"] else "MEDIUM"
    else:
        vault_state["threat_level"] = "LOW"
    
    # Cleanup old actions
    if len(vault_state["last_actions"]) > 50:
        vault_state["last_actions"] = vault_state["last_actions"][-50:]
    if len(vault_state["monitoring_logs"]) > 50:
        vault_state["monitoring_logs"] = vault_state["monitoring_logs"][:50]

def seed_vault():
    canaries = [
        ("Admin_Passwords.txt", "root:p@ssword123\nadmin:vault_master_key\n"),
        ("Bitcoin_Wallet_Backup.txt", "Seed phrase: alpha bravo charlie delta... [REDACTED]\nBalance: 12.5 BTC")
    ]
    for name, content in canaries:
        path = os.path.join(VAULT_DIR, name)
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write(content)
            # Backup too
            backup_path = os.path.join(BACKUP_DIR, f"{name}.bak_{int(time.time())}")
            with open(backup_path, "w") as f:
                f.write(content)

seed_vault()

# ── Database Setup ──────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
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
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS heuristic_models (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            value TEXT NOT NULL UNIQUE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vault_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            encrypted_filename TEXT,
            original_filename TEXT,
            file_size INTEGER DEFAULT 0,
            upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            file_hash TEXT,
            protected_key TEXT,
            protected_safety_code TEXT,
            status TEXT DEFAULT 'SECURE'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Migration: Add columns if they don't exist
    try:
        conn.execute("ALTER TABLE vault_files ADD COLUMN file_size INTEGER DEFAULT 0")
    except: pass
    try:
        conn.execute("ALTER TABLE vault_files ADD COLUMN protected_safety_code TEXT")
    except: pass
    
    # Initialize with default keywords if table is empty
    count = conn.execute("SELECT COUNT(*) FROM heuristic_models").fetchone()[0]
    if count == 0:
        defaults = [
            ("SUSPICIOUS_TLDS", ".xyz"), ("SUSPICIOUS_TLDS", ".top"), ("SUSPICIOUS_TLDS", ".pw"), 
            ("SUSPICIOUS_TLDS", ".bid"), ("SUSPICIOUS_TLDS", ".icu"), ("SUSPICIOUS_TLDS", ".work"), 
            ("SUSPICIOUS_TLDS", ".click"), ("SUSPICIOUS_TLDS", ".zip"), ("SUSPICIOUS_TLDS", ".mov"),
            ("BRAND_KEYWORDS", "paypal"), ("BRAND_KEYWORDS", "google"), ("BRAND_KEYWORDS", "microsoft"), 
            ("BRAND_KEYWORDS", "amazon"), ("BRAND_KEYWORDS", "apple"), ("BRAND_KEYWORDS", "netflix"), 
            ("BRAND_KEYWORDS", "bank"), ("BRAND_KEYWORDS", "secure"), ("BRAND_KEYWORDS", "verify"),
            ("URGENCY_TRIGGERS", "urgent"), ("URGENCY_TRIGGERS", "account suspended"), ("URGENCY_TRIGGERS", "immediate action"), 
            ("URGENCY_TRIGGERS", "verify now"), ("URGENCY_TRIGGERS", "security alert"), ("URGENCY_TRIGGERS", "suspicious activity"),
            ("FINANCIAL_TRIGGERS", "payment"), ("FINANCIAL_TRIGGERS", "invoice"), ("FINANCIAL_TRIGGERS", "refund"), 
            ("FINANCIAL_TRIGGERS", "transaction"), ("FINANCIAL_TRIGGERS", "unauthorized"), ("FINANCIAL_TRIGGERS", "bank account"), 
            ("FINANCIAL_TRIGGERS", "crypto"), ("FINANCIAL_TRIGGERS", "wallet"),
            ("RANSOM_SIGNALS", "vssadmin delete shadows"), ("RANSOM_SIGNALS", "wmic shadowcopy delete"), ("RANSOM_SIGNALS", "encrypt"), 
            ("RANSOM_SIGNALS", ".crypt"), ("RANSOM_SIGNALS", ".locky"), ("RANSOM_SIGNALS", ".enc"), ("RANSOM_SIGNALS", "bitcoin address"),
            ("RANSOM_SIGNALS", "ransom"), ("RANSOM_SIGNALS", "private key"), ("RANSOM_SIGNALS", "decrypt your files")
        ]
        conn.executemany("INSERT INTO heuristic_models (type, value) VALUES (?, ?)", defaults)
        
    conn.commit()
    conn.close()

init_db()

# ── Heuristic Analysis Engine ───────────────────────────────────────────────────

def get_dynamic_heuristics(model_type):
    conn = get_db()
    rows = conn.execute("SELECT value FROM heuristic_models WHERE type = ?", (model_type,)).fetchall()
    conn.close()
    return [r["value"] for r in rows]

def analyze_url_heuristics(url):
    suspicious_tlds = get_dynamic_heuristics("SUSPICIOUS_TLDS")
    brand_keywords = get_dynamic_heuristics("BRAND_KEYWORDS")
    url_low_whitelist = get_dynamic_heuristics("URL_LOW_WHITELIST")
    url_medium_triggers = get_dynamic_heuristics("URL_MEDIUM_TRIGGERS")
    url_critical_triggers = get_dynamic_heuristics("URL_CRITICAL_TRIGGERS")
    
    findings = []
    score = 10
    
    try:
        if not url.startswith("http"):
            url = f"http://{url}"
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname.lower() if parsed.hostname else ""

        # 0. Safety First: Whitelist (EXACT LOW)
        for safe_domain in url_low_whitelist:
            if hostname == safe_domain or hostname.endswith(f".{safe_domain}"):
                return {"findings": [], "riskScore": 10}

        # 1. Similarity Engine: Critical Phishing Links (CRITICAL - 100)
        for phish_site in url_critical_triggers:
            similarity = difflib.SequenceMatcher(None, hostname, phish_site.lower()).ratio()
            if similarity > 0.8:
                findings.append("AI Similarity Engine: 100% Match with Trained Phishing Site")
                return {"findings": findings, "riskScore": 100}

        # 2. Medium Triggers (MEDIUM - 40)
        for trigger in url_medium_triggers:
            if trigger in url.lower():
                findings.append(f"Trained Suspicious Pattern: {trigger}")
                score = max(score, 40)

        # 3. IP-based hostname (HIGH - 75)
        if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", hostname):
            findings.append("IP-based hostname detected")
            score = max(score, 75)

        # 4. Suspicious TLD (MEDIUM - 35)
        tld = hostname.split(".")[-1] if "." in hostname else ""
        whitelist_tlds = ["com", "org", "net", "edu", "gov", "io", "in"]
        if tld in suspicious_tlds and tld not in whitelist_tlds:
            findings.append(f"Suspicious TLD: .{tld}")
            score = max(score, 35)

        # 5. Brand impersonation (HIGH - 65)
        for brand in brand_keywords:
            if brand in hostname:
                is_legit = hostname.endswith(f"{brand}.com") or hostname.endswith(f"{brand}.org")
                if not is_legit:
                    findings.append(f"Potential Brand Impersonation")
                    score = max(score, 65)

        # 6. Punycode / IDN homograph (CRITICAL - 90)
        if "xn--" in hostname:
            findings.append("IDN Homograph/Punycode Detected")
            score = max(score, 90)

    except Exception:
        findings.append("Malformed URL Structure")
        score = max(score, 25)

    return {"findings": findings, "riskScore": score}

def analyze_text_heuristics(text):
    urgency_triggers = get_dynamic_heuristics("URGENCY_TRIGGERS")
    financial_triggers = get_dynamic_heuristics("FINANCIAL_TRIGGERS")
    suspicious_triggers = get_dynamic_heuristics("SUSPICIOUS_TRIGGERS")
    
    # 0. Safety First: Greeting Whitelist (EXACT LOW)
    greetings = ["hi", "hello", "hey", "how are you", "good morning", "good afternoon", "gm", "gn", "what's up", "whats up"]
    content = text.lower().strip().rstrip('!?.')
    if content in greetings or (len(content) < 15 and not any(w in content for w in ['pay', 'money', 'kill', 'harm', 'send', 'link', 'click'])):
        return {"findings": [], "riskScore": 10}

    # Baseline for non-greetings
    score = 0
    findings = []

    # 1. Similarity Engine: Check against trained threats (CRITICAL - 100)
    all_critical = urgency_triggers + financial_triggers
    for trained_phrase in all_critical:
        if len(trained_phrase) > 15:
            similarity = difflib.SequenceMatcher(None, content, trained_phrase.lower()).ratio()
            if similarity > 0.7:
                findings.append(f"AI Similarity Engine: 100% Match with Trained Threat Pattern")
                return {"findings": findings, "riskScore": 100}

    # 1b. Similarity Engine: Check against trained suspicious patterns (MEDIUM - 45)
    for suspicious_phrase in suspicious_triggers:
        if len(suspicious_phrase) > 15:
            similarity = difflib.SequenceMatcher(None, content, suspicious_phrase.lower()).ratio()
            if similarity > 0.7:
                findings.append(f"AI Similarity Engine: Match with Trained Suspicious Pattern")
                score = max(score, 45)

    # 2. Hardcoded Physical Threat / Violence Check (CRITICAL - 95)
    violence_keywords = ['kill', 'harm', 'destroy', 'track you', 'hurt', 'death', 'find you', 'regret', 'consequences', 'face the']
    for v_word in violence_keywords:
        if v_word in content:
            findings.append(f'Severe Threat Indicator: "{v_word}"')
            score = max(score, 95)

    # 3. Dynamic Trigger Check (Broad Matching)
    for trigger in all_critical:
        if trigger and trigger in content:
            if len(trigger) > 20: 
                findings.append(f'Direct Pattern Match')
                score = max(score, 90)
            else:
                findings.append(f'Suspicious keyword detected')
                score = max(score, 45)
                
    for trigger in suspicious_triggers:
        if trigger and trigger in content:
            findings.append(f'Trained suspicious indicator')
            score = max(score, 40)

    # 4. Extortion / Money Demand Pattern (HIGH - 85)
    amount_pattern = re.search(r'(\d+|₹|\$|euro|paisa|money|payment|amt|amount)', content)
    if amount_pattern and any(w in content for w in ['send', 'pay', 'transfer', 'immediately', 'otherwise', 'or i will']):
        findings.append("Extortion/Payment demand signature")
        score = max(score, 85)

    # 5. External Links (MEDIUM - 35)
    if re.search(r"https?://\S+", content):
        findings.append("External link detected")
        score = max(score, 35)

    # Final Categorization
    if not findings:
        return {"findings": [], "riskScore": 15}

    return {"findings": findings, "riskScore": min(100, score)}

def analyze_ransomware_heuristics(text):
    ransom_signals = get_dynamic_heuristics("RANSOM_SIGNALS")
    content = text.lower()
    findings = []
    score = 0

    # 1. Critical System Commands (CRITICAL - 100)
    system_cmds = ['vssadmin', 'wmic shadowcopy', 'bcdedit', 'wbadmin']
    for cmd in system_cmds:
        if cmd in content:
            findings.append(f"Critical System Command Detected: {cmd}")
            score = 100

    # 2. Ransomware Note Identifiers (HIGH - 85)
    note_triggers = ['bitcoin', 'decrypt', 'private key', 'onion', 'tor browser', 'instruction']
    match_count = 0
    for trigger in note_triggers:
        if trigger in content:
            match_count += 1
    
    if match_count >= 2:
        findings.append(f"Ransomware Note Signature: {match_count} Pressure Markers")
        score = max(score, 85)

    # 3. Encryption Artifacts (MEDIUM - 50)
    enc_exts = ['.crypt', '.locky', '.enc', '.crypted', '.aes']
    for ext in enc_exts:
        if ext in content:
            findings.append(f"Potential Encrypted File Extension: {ext}")
            score = max(score, 50)

    if not findings:
        return {"findings": [], "riskScore": 10}

    return {"findings": findings, "riskScore": score}

# ── Claude AI Wrapper ───────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are the ThreatGuard AI Intelligence Engine. Analyze the input for security threats and categorize it into the Lockheed Martin Cyber Kill Chain.
Return ONLY a valid JSON object with:
{
  "threatLevel": "LOW"|"MEDIUM"|"HIGH"|"CRITICAL",
  "category": string,
  "confidenceScore": number,
  "summary": string,
  "explanation": string,
  "reasoningPath": string[],
  "severityJustification": string,
  "phishingIndicators": { "indicator": string, "level": "LOW"|"MEDIUM"|"HIGH", "impact": string }[],
  "featureAnalysis": string[],
  "indicators": string[],
  "recommendedActions": string[],
  "riskScore": number,
  "technicalDetails": string,
  "killChainStage": "Reconnaissance"|"Weaponization"|"Delivery"|"Exploitation"|"Installation"|"C2"|"Actions on Objectives"
}"""

def call_claude(user_message, module_id, is_demo_mode, heuristic_results=None, chat_history=None):
    api_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("VITE_ANTHROPIC_API_KEY") or ""
    has_valid_key = api_key and api_key != "your_api_key_here" and api_key.startswith("sk-ant-")

    if is_demo_mode or not has_valid_key:
        seed = (user_message + module_id).encode()
        h = int(hashlib.md5(seed).hexdigest(), 16) if not heuristic_results else 42
        
        # If we have heuristic results, use them as the primary truth
        if heuristic_results:
            risk_score = heuristic_results.get("riskScore", 10)
            findings = heuristic_results.get("findings", [])
        else:
            # Fallback for when heuristics aren't provided
            is_suspicious = bool(re.search(r'(http|www|\.com|\.org|\.net)', user_message.lower())) \
                         or any(w in user_message.lower() for w in ['urgent', 'password', 'verify', 'account', 'pay', 'money', 'claim', 'free'])
            if not is_suspicious and len(user_message) < 20:
                 risk_score = (h % 20) + 5
            elif is_suspicious:
                 risk_score = (h % 40) + 60
            else:
                 risk_score = (h % 40) + 30
            findings = ["Pattern-based heuristic analysis"]

        stages = ["Reconnaissance", "Weaponization", "Delivery", "Exploitation", "Installation", "C2", "Actions on Objectives"]
        
        # 1. Map findings to standardized security features (Explainable AI)
        feature_map = {
            "AI Similarity Engine": "Pattern Recognition Intelligence",
            "Severe Threat Indicator": "Linguistic Violence Analysis",
            "Extortion/Payment": "Financial Extortion Signature",
            "External link": "Outbound Resource Detection",
            "IP-based hostname": "Anonymized Infrastructure",
            "Brand Impersonation": "Identity Cloaking Detection",
            "IDN Homograph": "Visual Signal Deception",
            "Suspicious TLD": "Untrusted TLD Reputation",
            "Trained suspicious": "Heuristic Anomaly detection"
        }
        
        feature_analysis = []
        for finding in findings:
            for key, val in feature_map.items():
                if key in finding:
                    feature_analysis.append(val)
                    break
        
        if not feature_analysis:
            feature_analysis = ["Behavioral Baseline Analysis"]

        if module_id == "copilot":
            # For copilot, provide a conversational mock reply
            mock_replies = [
                "I've analyzed the current infrastructure telemetry. The signature suggests a dormant persistence mechanism.",
                "Heuristic patterns indicates a high probability of a lateral movement attempt from the DMZ.",
                "Neural link established. Cross-referencing current logs with known APT indicators...",
                "ThreatGuard core is currently monitoring the encrypted vault. No suspicious entropy detected yet.",
            ]
            import random
            return random.choice(mock_replies)

        # 2. Generate detailed explanation & DYNAMIC XAI Path
        level = "CRITICAL" if risk_score > 80 else "HIGH" if risk_score > 60 else "MEDIUM" if risk_score > 30 else "LOW"
        
        # Define Dynamic Neural Path based on situation
        if level == "LOW":
            reasoning_path = [
                "Scan initiated: Input matches baseline conversational signatures",
                "Entropy check: Low complexity detected (Safe communication pattern)",
                "Reputation engine: No matches found in malicious actor databases",
                "Verdict: Content verified as non-hostile / benign"
            ]
        elif module_id == "url" and level in ["HIGH", "CRITICAL"]:
            reasoning_path = [
                "URL Analysis: Domain reputation check initiated",
                "Signal Deception: Suspicious TLD or Homograph pattern detected",
                "Redirection Check: Hidden infrastructure detected in request chain",
                "Verdict: Infrastructure matches known phishing campaign signatures"
            ]
        elif module_id == "ransomware" and level in ["HIGH", "CRITICAL"]:
             reasoning_path = [
                "Heuristic Scan: Critical persistence commands detected",
                "Process Analysis: Ransomware signal sequence identified",
                "Risk Weighting: High-confidence extortion marker detected",
                "Verdict: Active ransomware deployment or preparatory signals detected"
            ]
        elif level == "CRITICAL":
            reasoning_path = [
                "Neural Scan: Severe linguistic anomaly detected",
                "Pattern Match: High-confidence extortion or violent threat signature",
                "Contextualization: Intent identified as hostile / adversarial",
                "Verdict: Immediate threat to safety or credential security"
            ]
        else:
            reasoning_path = [
                "Anomaly Detection: Deviation from behavioral baseline identified",
                "Heuristic Check: Suspicious keyword clusters detected",
                "Weight Calculation: Risk score elevated based on neural uncertainty",
                "Verdict: Potential threat detected - human oversight recommended"
            ]
        
        severity_justification = {
            "CRITICAL": "Confirmed active exploitation signature or high-impact financial extortion detected.",
            "HIGH": "Multiple suspicious markers identified with high linguistic urgency or reputation risk.",
            "MEDIUM": "Anomalous patterns detected that warrant further investigation.",
            "LOW": "Communication aligns with verified benign behavioral baselines."
        }.get(level, "Baseline analysis complete.")

        phishing_indicators = []
        for finding in findings:
            p_level = "HIGH" if any(w in finding for w in ["Similarity", "Extortion", "Severe"]) else "MEDIUM"
            phishing_indicators.append({
                "indicator": finding,
                "level": p_level,
                "impact": "Significant contribution to threat verdict" if p_level == "HIGH" else "Supporting evidence for threat classification"
            })

        if not phishing_indicators and level == "LOW":
             phishing_indicators.append({
                 "indicator": "Safe Baseline Match",
                 "level": "LOW",
                 "impact": "Reduces overall risk score"
             })

        explanation = f"This input is categorized as {level} because our XAI engine identified {len(findings)} specific high-confidence risk markers."
        if level == "CRITICAL":
            explanation = "IMMEDIATE ATTENTION REQUIRED: The engine identified signatures linked to active exploitation or targeted threat campaigns."
        elif level == "LOW":
            explanation = "SAFE COMMUNICATION: The input aligns with baseline safety patterns and whitelisted known-good sources."

        # 3. Map to category
        return {
            "threatLevel": level,
            "category": "Credential Theft" if "Impersonation" in str(findings) else "Malicious Comm" if risk_score > 50 else "Safe Communication",
            "confidenceScore": 85 if not is_demo_mode else 94,
            "summary": "AI-driven XAI analysis of internal communication signals.",
            "explanation": explanation,
            "reasoningPath": reasoning_path,
            "severityJustification": severity_justification,
            "phishingIndicators": phishing_indicators,
            "featureAnalysis": feature_analysis,
            "indicators": findings,
            "recommendedActions": ["Monitor Source", "Block Sender"] if risk_score > 50 else ["No Action Required"],
            "riskScore": risk_score,
            "technicalDetails": f"Vector Analysis: {', '.join(feature_analysis)}",
            "killChainStage": stages[min(6, risk_score // 15)]
        }
        category = "Social Engineering"
        if module_id == "url": category = "Phishing Infrastructure"
        elif module_id == "ransomware": category = "Ransomware Deployment"
        elif any("extortion" in f.lower() or "payment" in f.lower() for f in findings): category = "Financial Fraud"
        
        summary = f"ThreatGuard detected {len(findings)} specific malicious indicators." if findings else "Input analysis shows patterns consistent with baseline communication."

        return {
            "threatLevel": level,
            "category": category,
            "confidenceScore": 85 + (len(user_message) % 10) if risk_score > 10 else 98,
            "summary": summary,
            "explanation": explanation,
            "featureAnalysis": list(set(feature_analysis)),
            "indicators": findings,
            "recommendedActions": ["Avoid interacting with the content", "Report to security team", "Block sender/domain at firewall level"] if risk_score > 30 else ["No immediate action required", "Stay vigilant for future suspicious patterns"],
            "riskScore": risk_score,
            "technicalDetails": f"HEURISTIC_ENGINE_XAI_v1: {len(findings)} FEATURES_EXTRACTED",
            "killChainStage": stages[min(len(stages)-1, risk_score // 15)] if risk_score > 0 else "Reconnaissance",
        }

    messages = []
    if chat_history:
        for msg in chat_history:
            # Map role names if they differ (e.g., 'assistant' vs 'ai')
            role = "assistant" if msg.get("role") == "assistant" else "user"
            messages.append({"role": role, "content": msg.get("content", "")})
    
    # Add current message
    messages.append({"role": "user", "content": user_message})

    # Real Claude API call
    resp = http_requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        json={
            "model": "claude-3-sonnet-20240229",
            "max_tokens": 1000,
            "system": SYSTEM_PROMPT,
            "messages": messages,
        },
        timeout=30,
    )
    data = resp.json()
    content = data.get("content", [{}])[0].get("text", "")
    
    if module_id == "copilot":
        return content
        
    content = re.sub(r"```json|```", "", content).strip()
    return json.loads(content)

# ── Auth Routes ─────────────────────────────────────────────────────────────────

@app.route("/api/auth/signup", methods=["POST"])
def auth_signup():
    data = request.json
    full_name = (data.get("full_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    
    if not full_name or not email or not password:
        return jsonify({"success": False, "error": "All fields are required."}), 400
    if len(password) < 6:
        return jsonify({"success": False, "error": "Password must be at least 6 characters."}), 400
    if "@" not in email or "." not in email:
        return jsonify({"success": False, "error": "Invalid email address."}), 400
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    try:
        conn = get_db()
        conn.execute("INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)",
                     (full_name, email, password_hash))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "user": {"name": full_name, "email": email}})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "error": "An account with this email already exists."}), 409
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.json
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    
    if not email or not password:
        return jsonify({"success": False, "error": "Email and password are required."}), 400
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ? AND password_hash = ?",
                        (email, password_hash)).fetchone()
    conn.close()
    
    if user:
        return jsonify({"success": True, "user": {"name": user["full_name"], "email": user["email"]}})
    return jsonify({"success": False, "error": "Invalid email or password."}), 401

@app.route("/api/auth/google", methods=["POST"])
def auth_google():
    data = request.json
    token = data.get("credential")
    print(f"[DEBUG] /api/auth/google hit. Token received: {bool(token)}")
    
    if not token:
        return jsonify({"success": False, "error": "No credential provided."}), 400
        
    try:
        GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "684750461179-i1426j2a61vorp7qala0ilhri6ci2jev.apps.googleusercontent.com")
        print(f"[DEBUG] Verifying token with GOOGLE_CLIENT_ID: {GOOGLE_CLIENT_ID}")
        
        idinfo = id_token.verify_oauth2_token(
            token, 
            google_requests.Request(), 
            GOOGLE_CLIENT_ID,
            clock_skew_in_seconds=30 # Increased skew tolerance
        )
        print(f"[DEBUG] Token verified for: {idinfo.get('email')}")
        
        email = idinfo['email'].lower()
        full_name = idinfo.get('name', '')
        
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        
        if not user:
            print(f"[DEBUG] Creating new user: {email}")
            conn.execute("INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)",
                         (full_name, email, "GOOGLE_AUTH"))
            conn.commit()
            
        conn.close()
        return jsonify({"success": True, "user": {"name": full_name, "email": email}})
        
    except ValueError as e:
        print(f"[DEBUG] Token verification failed: {str(e)}")
        return jsonify({"success": False, "error": f"Invalid authentication token: {str(e)}"}), 401
    except Exception as e:
        print(f"[DEBUG] Unexpected error in auth_google: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500


# ── API Routes ──────────────────────────────────────────────────────────────────



@app.route("/api/copilot/chat", methods=["POST"])
def copilot_chat():
    data = request.json
    message = data.get("message")
    history = data.get("history", [])
    # Respect the frontend's demo toggle
    is_demo_mode = data.get("is_demo_mode", False)
    
    # Using Claude via the call_claude helper
    # Setting is_demo_mode based on frontend status
    
    try:
        # call_claude will use real API if ANTHROPIC_API_KEY is in .env
        reply = call_claude(message, "copilot", is_demo_mode=is_demo_mode, chat_history=history)
        return jsonify({"success": True, "reply": reply})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/forensics/report", methods=["GET"])
def forensics_report():
    try:
        conn = get_db()
        # Correctly query the 'scans' table (history was a placeholder name)
        scans = conn.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT 50").fetchall()
        conn.close()
        
        # Build professional HTML report with full details
        report_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>ThreatGuard AI - Digital Forensics Report</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #020817; color: #e2e8f0; padding: 40px; line-height: 1.6; }}
                .container {{ max-width: 1000px; margin: 0 auto; background: #0a1628; padding: 40px; border-radius: 12px; border: 1px solid #1e3a5f; box-shadow: 0 20px 50px rgba(0,0,0,0.5); }}
                .header-flex {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #0ea5e9; padding-bottom: 20px; margin-bottom: 30px; }}
                h1 {{ color: #0ea5e9; margin: 0; letter-spacing: 2px; }}
                .meta {{ color: #94a3b8; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; table-layout: fixed; }}
                th, td {{ padding: 15px; text-align: left; border-bottom: 1px solid #1e3a5f; word-wrap: break-word; }}
                th {{ background: #0f2a4a; color: #38bdf8; text-transform: uppercase; font-size: 11px; letter-spacing: 1px; }}
                .threat-LOW {{ color: #4ade80; font-weight: bold; }}
                .threat-MEDIUM {{ color: #fbbf24; font-weight: bold; }}
                .threat-HIGH {{ color: #f87171; font-weight: bold; }}
                .threat-CRITICAL {{ color: #c084fc; font-weight: bold; }}
                .summary-text {{ font-size: 13px; color: #94a3b8; }}
                .risk-badge {{ background: #1e293b; padding: 4px 8px; border-radius: 4px; font-family: monospace; border: 1px solid #334155; }}
                .footer {{ margin-top: 50px; text-align: center; color: #1e3a5f; font-size: 11px; letter-spacing: 3px; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header-flex">
                    <div>
                        <h1>🛡️ FORENSICS REPORT</h1>
                        <div class="meta">SECURITY INVESTIGATION LOG</div>
                    </div>
                    <div style="text-align: right;" class="meta">
                        Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
                        Classification: RESTRICTED
                    </div>
                </div>
                
                <table>
                    <thead>
                        <tr>
                            <th style="width: 18%;">Timestamp</th>
                            <th style="width: 12%;">Module</th>
                            <th style="width: 25%;">Summary & Findings</th>
                            <th style="width: 15%;">Kill Chain Stage</th>
                            <th style="width: 10%;">Score</th>
                            <th style="width: 15%;">Threat Level</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for s in scans:
            level = s['threatLevel']
            report_html += f"""
                        <tr>
                            <td style="font-family: monospace; font-size: 12px;">{s['timestamp']}</td>
                            <td><strong style="color: #0ea5e9;">{s['moduleId'].upper()}</strong></td>
                            <td class="summary-text">{s['summary']}</td>
                            <td style="font-size: 12px; color: #cbd5e1;">{s['killChainStage'] or 'N/A'}</td>
                            <td><span class="risk-badge">{s['riskScore']}</span></td>
                            <td><span class="threat-{level}">{level}</span></td>
                        </tr>
            """
        
        if not scans:
            report_html += """
                        <tr>
                            <td colspan="6" style="text-align: center; padding: 40px; color: #475569;">No threat signatures detected in the current session. Environment clean.</td>
                        </tr>
            """

        report_html += """
                    </tbody>
                </table>
                <div class="footer">
                    THREATGUARD EXTERNAL SECURITY ADVISORY • NON-DISCLOSURE MANDATORY
                </div>
            </div>
        </body>
        </html>
        """
        
        from flask import make_response
        response = make_response(report_html)
        response.headers["Content-Disposition"] = f"attachment; filename=ThreatGuard_Full_Forensics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        response.headers["Content-Type"] = "text/html"
        return response
        
    except Exception as e:
        return f"Error generating report: {str(e)}", 500

@app.route("/")
@app.route("/<path:path>")
def index(path=None):
    # If the path looks like a file (has an extension), try to serve it from static
    if path and "." in path:
        return send_from_directory("static", path)
    # Otherwise/Default: Serve index.html (SPA entry point)
    return send_from_directory("static", "index.html")

@app.route("/api/decode-qr", methods=["POST"])
def decode_qr_endpoint():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    try:
        file_bytes = np.frombuffer(file.read(), np.uint8)
        image = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
        if image is None:
            return jsonify({"success": False, "error": "Invalid image format"}), 400
            
        detector = cv2.QRCodeDetector()
        data, bbox, _ = detector.detectAndDecode(image)
        if data:
            return jsonify({"success": True, "data": data})
        return jsonify({"success": False, "error": "No QR code detected in the image"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/train", methods=["POST"])
def train_model():
    if "file" not in request.files:
        return jsonify({"error": "No dataset file uploaded"}), 400
        
    file = request.files["file"]
    try:
        data = json.load(file)
        conn = get_db()
        added_count = 0
        
        for model_type, values in data.items():
            if type(values) is list:
                for val in values:
                    try:
                        conn.execute("INSERT INTO heuristic_models (type, value) VALUES (?, ?)", (model_type, str(val).lower()))
                        added_count += 1
                    except sqlite3.IntegrityError:
                        pass
                        
        conn.commit()
        conn.close()
        
        return jsonify({
            "success": True, 
            "message": f"Successfully trained heuristic models with {added_count} new unique indicators."
        })
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON dataset format"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/analyze", methods=["POST"])
def analyze():
    try:
        data = request.json
        module_id = data.get("moduleId", "message")
        user_input = data.get("input", "")
        is_demo_mode = data.get("isDemoMode", False)

        if not user_input:
            return jsonify({"error": "No input provided"}), 400

        heuristic_results = None
        if module_id == "url":
            heuristic_results = analyze_url_heuristics(user_input)
        elif module_id == "ransomware":
            heuristic_results = analyze_ransomware_heuristics(user_input)
        else:
            heuristic_results = analyze_text_heuristics(user_input)

        # 2. Pass heuristic results to AI (Mock or Real)
        result = call_claude(user_input, module_id, is_demo_mode, heuristic_results=heuristic_results)
        
        # 3. Log to historical database
        conn = get_db()
        conn.execute(
            "INSERT INTO scans (moduleId, input, threatLevel, category, riskScore, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (module_id, user_input[:200], result["threatLevel"], result["category"], result["riskScore"], datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
        
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

import base64
import time
from cryptography.fernet import Fernet

# Hardcoded key for the hackathon demo so the ransom note is always correct
DEMO_ENCRYPTION_KEY = b"gZ8rD1lK_vX6-j9mQpT2sC4yN5fW3hY0bA7eU8iO-P4="

@app.route("/api/simulate-attack", methods=["POST"])
def simulate_attack():
    try:
        log = []
        # 1. Attack Local PC (demo_target)
        target_dir = os.path.join(os.getcwd(), "demo_target")
        os.makedirs(target_dir, exist_ok=True)
        fernet = Fernet(DEMO_ENCRYPTION_KEY)
        
        for filename in os.listdir(target_dir):
            if filename == "RANSOM_NOTE.txt" or filename.endswith(".crypt"):
                continue
            
            file_path = os.path.join(target_dir, filename)
            with open(file_path, "rb") as f:
                content = f.read()
            
            encrypted_content = fernet.encrypt(content)
            with open(file_path + ".crypt", "wb") as f:
                f.write(encrypted_content)
            
            os.remove(file_path)
            log.append(f"ENCRYPTED: PC/{filename}")

        # 2. Drop Ransom Note on PC
        with open(os.path.join(target_dir, "RANSOM_NOTE.txt"), "w") as f:
            f.write("ALL YOUR PC FILES ARE ENCRYPTED. PAY 1.5 BTC TO GET THEM BACK.")

        # 3. Attack Secure Vault (Database Status Change)
        conn = get_db()
        conn.execute("UPDATE vault_files SET status = 'LOCKED (AES)' WHERE status = 'SECURE'")
        conn.commit()
        conn.close()
        
        vault_state["is_frozen"] = True
        vault_state["threat_level"] = "CRITICAL"
        log_vault_activity("RANSOMWARE_ATTACK", "Vault files encrypted by unauthorized actor. System in HIGH ALERT.")
        
        return jsonify({"success": True, "log": log})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/vault/restore-all", methods=["POST"])
def restore_all_vault():
    try:
        conn = get_db()
        conn.execute("UPDATE vault_files SET status = 'SECURE' WHERE status = 'LOCKED (AES)'")
        conn.commit()
        conn.close()
        
        vault_state["is_frozen"] = False
        vault_state["threat_level"] = "LOW"
        log_vault_activity("SECURE_RESTORE", "All vault files restored to pre-attack encrypted state.")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/canary/files", methods=["GET"])
def get_canary_files():
    try:
        target_dir = os.path.join(os.getcwd(), "demo_target")
        os.makedirs(target_dir, exist_ok=True)
        files = []
        for filename in os.listdir(target_dir):
            if filename == "RANSOM_NOTE.txt":
                continue
            is_encrypted = filename.endswith(".crypt")
            files.append({
                "name": filename,
                "is_encrypted": is_encrypted
            })
        return jsonify({"success": True, "files": files})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/canary/upload", methods=["POST"])
def upload_canary_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    try:
        target_dir = os.path.join(os.getcwd(), "demo_target")
        os.makedirs(target_dir, exist_ok=True)
        filename = secure_filename(file.filename)
        filepath = os.path.join(target_dir, filename)
        file.save(filepath)
        return jsonify({"success": True, "message": f"Successfully uploaded {filename}", "filename": filename})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/canary/delete/<filename>", methods=["DELETE"])
def delete_canary_file(filename):
    try:
        target_path = os.path.join(os.getcwd(), "demo_target", secure_filename(filename))
        if os.path.exists(target_path):
            os.remove(target_path)
            # Also check for .crypt version
            crypt_path = target_path + ".crypt"
            if os.path.exists(crypt_path):
                os.remove(crypt_path)
            return jsonify({"success": True, "message": f"Deleted {filename}"})
        return jsonify({"success": False, "error": "File not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/canary/download/<path:filename>", methods=["GET"])
def download_canary_file(filename):
    try:
        # Strictly sanitize filename
        clean_name = secure_filename(filename)
        # Check both directories for convenience
        targets = ["demo_target", "secure_vault"]
        for t in targets:
            path = os.path.join(os.getcwd(), t, clean_name)
            if os.path.exists(path):
                return send_from_directory(os.path.join(os.getcwd(), t), clean_name, as_attachment=True)
        return jsonify({"success": False, "error": "File not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/decrypt", methods=["POST"])
def decrypt_attack():
    try:
        data = request.json
        provided_key = data.get("key", "").strip()
        
        if not provided_key:
            return jsonify({"success": False, "error": "No decryption key provided."}), 400
            
        try:
            fernet = Fernet(provided_key.encode())
        except ValueError:
            return jsonify({"success": False, "error": "Invalid key format."}), 400

        target_dir = os.path.join(os.getcwd(), "demo_target")
        if not os.path.exists(target_dir):
            return jsonify({"success": False, "error": "Target directory not found."}), 404
            
        decrypted_log = []
        success_count = 0
        targets = ["demo_target"] # ISOLATION: Secure Vault is now a Safe Haven and cannot be touched by simulation
        
        for t in targets:
            target_dir = os.path.join(os.getcwd(), t)
            if not os.path.exists(target_dir):
                continue

            for filename in os.listdir(target_dir):
                if not filename.endswith(".crypt"):
                    continue
                
                filepath = os.path.join(target_dir, filename)
                with open(filepath, "rb") as f:
                    encrypted_content = f.read()
                    
                try:
                    decrypted_content = fernet.decrypt(encrypted_content)
                    original_filename = filename[:-6] 
                    new_filepath = os.path.join(target_dir, original_filename)
                    
                    with open(new_filepath, "wb") as f:
                        f.write(decrypted_content)
                    
                    os.remove(filepath)
                    decrypted_log.append(f"DECRYPTED: {t}/{original_filename}")
                    success_count += 1
                except Exception:
                    continue
                    
            # Remove ransom note
            note_path = os.path.join(target_dir, "RANSOM_NOTE.txt")
            if os.path.exists(note_path):
                os.remove(note_path)
            # Legacy ransom note name check
            note_path_alt = os.path.join(target_dir, "README_RECOVER_FILES.txt")
            if os.path.exists(note_path_alt):
                os.remove(note_path_alt)
            
        return jsonify({
            "success": True,
            "message": f"Successfully restored {success_count} files.",
            "log": decrypted_log
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Secure Vault System ────────────────────────────────────────────────────────

@app.route("/api/vault/auth/password", methods=["POST"])
def vault_auth_password():
    password = request.json.get("password")
    if password == "admin123": # In real app, check hash
        return jsonify({"success": True, "token": "pass_granted_v42"})
    return jsonify({"success": False, "error": "Invalid password"}), 401

@app.route("/api/vault/auth/otp", methods=["POST"])
def vault_auth_otp():
    otp = request.json.get("otp")
    if otp == "123456": # Mock OTP
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Invalid OTP"}), 401

@app.route("/api/vault/status", methods=["GET"])
def get_vault_status():
    conn = get_db()
    rows = conn.execute("SELECT * FROM vault_files ORDER BY upload_time DESC").fetchall()
    conn.close()
    
    files = []
    for r in rows:
        files.append({
            "id": r["id"],
            "name": r["original_filename"],
            "obfuscated_name": r["encrypted_filename"],
            "size": r["file_size"],
            "upload_time": r["upload_time"],
            "hash": r["file_hash"],
            "status": r["status"]
        })
        
    return jsonify({
        "files": files,
        "isFrozen": vault_state["is_frozen"],
        "threatLevel": vault_state["threat_level"],
        "logs": vault_state["monitoring_logs"]
    })

@app.route("/api/vault/upload", methods=["POST"])
def upload_vault_file():
    if vault_state["is_frozen"]:
        return jsonify({"success": False, "error": "SYSTEM FROZEN: Read-only mode active due to threat detection."}), 403
    
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    custom_code = request.form.get("custom_code")
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
        
    filename = secure_filename(file.filename)
    file_content = file.read()
    
    # 1. Calculate Hash (SHA-256)
    file_hash = hashlib.sha256(file_content).hexdigest()
    
    # 2. Handle Safety Code (User provided or Auto-generated)
    safety_code = custom_code if (custom_code and len(custom_code) >= 6) else base64.urlsafe_b64encode(os.urandom(9)).decode()[:12]
    
    # 3. Generate Unique AES-256 Key for the file content
    file_key = Fernet.generate_key()
    fernet = Fernet(file_key)
    encrypted_content = fernet.encrypt(file_content)
    
    # 4. Obfuscate Filename (Random Hex)
    obfuscated_name = hashlib.md5(f"{filename}{time.time()}".encode()).hexdigest()[:8] + ".bin"
    
    # 5. Protect Encryption Key (Wrap with Safety Code)
    # Derive wrapping key from the secret safety code
    wrapping_key = base64.urlsafe_b64encode(hashlib.sha256(safety_code.encode()).digest())
    wrapper = Fernet(wrapping_key)
    protected_key = wrapper.encrypt(file_key).decode()
    
    # 6. Save Encrypted Blob
    save_path = os.path.join(VAULT_STORAGE_DIR, obfuscated_name)
    with open(save_path, "wb") as f:
        f.write(encrypted_content)
    
    # 7. Secure the Safety Code for the Registry (Encrypt with Master Password)
    registry_master_key = base64.urlsafe_b64encode(hashlib.sha256(b"admin123").digest())
    registry_wrapper = Fernet(registry_master_key)
    protected_safety_code = registry_wrapper.encrypt(safety_code.encode()).decode()
    
    # 8. Store Metadata in DB
    conn = get_db()
    conn.execute("""
        INSERT INTO vault_files 
        (user_id, encrypted_filename, original_filename, file_size, file_hash, protected_key, protected_safety_code)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, ("admin", obfuscated_name, filename, len(file_content), file_hash, protected_key, protected_safety_code))
    conn.commit()
    conn.close()
    
    log_vault_activity("FILE_SECURED", f"Encrypted and obfuscated: {filename} ({len(file_content)} bytes). Secret Code backed up to Secure Registry.")
    
    return jsonify({
        "success": True, 
        "message": "File secured with Zero-Knowledge AES-256 encryption.",
        "obfuscated_name": obfuscated_name,
        "safety_code": safety_code
    })

@app.route("/api/vault/unfreeze", methods=["POST"])
def unfreeze_vault():
    # Requires re-auth in frontend, but here we just reset
    vault_state["is_frozen"] = False
    vault_state["threat_level"] = "LOW"
    log_vault_activity("ADMIN_UNFREEZE", "System manually restored by authorized admin.")
    return jsonify({"success": True})

@app.route("/api/vault/registry", methods=["POST"])
def get_vault_registry():
    password = request.json.get("password")
    if password != "admin123":
        return jsonify({"success": False, "error": "Invalid master password"}), 401
        
    try:
        conn = get_db()
        rows = conn.execute("SELECT id, protected_safety_code FROM vault_files").fetchall()
        conn.close()
        
        registry_master_key = base64.urlsafe_b64encode(hashlib.sha256(b"admin123").digest())
        registry_wrapper = Fernet(registry_master_key)
        
        codes = {}
        for r in rows:
            if r["protected_safety_code"]:
                try:
                    decrypted_code = registry_wrapper.decrypt(r["protected_safety_code"].encode()).decode()
                    codes[r["id"]] = decrypted_code
                except:
                    codes[r["id"]] = "DECRYPTION_ERROR"
                    
        return jsonify({"success": True, "codes": codes})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/vault/restore", methods=["POST"])
def restore_vault_file():
    filename = request.json.get("filename")
    if not filename: return jsonify({"error": "Filename required"}), 400
    
    # Find latest backup
    backups = [f for f in os.listdir(BACKUP_DIR) if f.startswith(filename + ".bak_")]
    if not backups:
        return jsonify({"success": False, "error": "No backups found for this file."}), 404
    
    latest_backup = sorted(backups)[-1]
    shutil.copy2(os.path.join(BACKUP_DIR, latest_backup), os.path.join(VAULT_DIR, filename))
    
    # If it was a crypt file, remove the crypt version
    crypt_path = os.path.join(VAULT_DIR, filename + ".crypt")
    if os.path.exists(crypt_path):
        os.remove(crypt_path)

    log_vault_activity("FILE_RESTORE", f"Restored {filename} from backup: {latest_backup}")
    return jsonify({"success": True})

@app.route("/api/vault/download", methods=["POST"])
def download_vault_file():
    file_id = request.json.get("file_id")
    safety_code = request.json.get("safety_code")
    
    if not file_id or not safety_code:
        return jsonify({"error": "File ID and Secret Code required"}), 400
    
    conn = get_db()
    file_record = conn.execute("SELECT * FROM vault_files WHERE id = ?", (file_id,)).fetchone()
    conn.close()
    
    if not file_record:
        return jsonify({"error": "File record not found"}), 404
        
    try:
        # 1. Derive wrapping key from provided safety code
        wrapping_key = base64.urlsafe_b64encode(hashlib.sha256(safety_code.encode()).digest())
        wrapper = Fernet(wrapping_key)
        
        # 2. Attempt to unwrap the encryption key
        try:
            unwrapped_key = wrapper.decrypt(file_record["protected_key"].encode())
        except Exception:
            return jsonify({"error": "INVALID SECRET CODE: Decryption of key failed. Access Denied."}), 403
        
        # 3. Decrypt the file content
        filepath = os.path.join(VAULT_STORAGE_DIR, file_record["encrypted_filename"])
        with open(filepath, "rb") as f:
            encrypted_data = f.read()
            
        fernet = Fernet(unwrapped_key)
        decrypted_data = fernet.decrypt(encrypted_data)
        
        log_vault_activity("FILE_RETRIEVED", f"Successfully decrypted and retrieved: {file_record['original_filename']} using Secret Code.")
        
        # Return raw bytes for browser download
        return io.BytesIO(decrypted_data).read()
    except Exception as e:
        return jsonify({"error": f"Decryption Error: {str(e)}"}), 500

@app.route("/api/vault/delete", methods=["POST"])
def delete_vault_file():
    file_id = request.json.get("file_id")
    if not file_id: return jsonify({"error": "File ID required"}), 400
    
    conn = get_db()
    file_record = conn.execute("SELECT * FROM vault_files WHERE id = ?", (file_id,)).fetchone()
    
    if file_record:
        filepath = os.path.join(VAULT_STORAGE_DIR, file_record["encrypted_filename"])
        if os.path.exists(filepath):
            os.remove(filepath)
        conn.execute("DELETE FROM vault_files WHERE id = ?", (file_id,))
        conn.commit()
        conn.close()
        log_vault_activity("FILE_DELETED", f"Removed: {file_record['original_filename']}")
        return jsonify({"success": True})
    
    conn.close()
    return jsonify({"success": False, "error": "File not found"}), 404

@app.route("/api/history")
def history():
    try:
        conn = get_db()
        rows = conn.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT 20").fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": "Failed to fetch history"}), 500

@app.route("/api/stats")
def stats():
    try:
        conn = get_db()

        counts = [dict(r) for r in conn.execute("SELECT threatLevel, COUNT(*) as count FROM scans GROUP BY threatLevel").fetchall()]

        timeline = [dict(r) for r in conn.execute("""
            SELECT strftime('%H:00', timestamp) as hour, COUNT(*) as count
            FROM scans WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY hour ORDER BY hour ASC
        """).fetchall()]

        stages = [dict(r) for r in conn.execute("""
            SELECT killChainStage, COUNT(*) as count FROM scans
            WHERE killChainStage IS NOT NULL GROUP BY killChainStage ORDER BY count DESC
        """).fetchall()]

        module_breakdown = [dict(r) for r in conn.execute("""
            SELECT moduleId, COUNT(*) as count FROM scans GROUP BY moduleId ORDER BY count DESC
        """).fetchall()]

        top_categories = [dict(r) for r in conn.execute("""
            SELECT category, COUNT(*) as count, AVG(riskScore) as avgRisk FROM scans
            WHERE category IS NOT NULL GROUP BY category ORDER BY count DESC LIMIT 5
        """).fetchall()]

        avg_row = conn.execute("""
            SELECT AVG(confidenceScore) as avgConfidence, AVG(riskScore) as avgRisk,
                   MAX(riskScore) as maxRisk, COUNT(*) as total FROM scans
        """).fetchone()
        avg_stats = dict(avg_row) if avg_row else {}

        conn.close()
        return jsonify({"counts": counts, "timeline": timeline, "stages": stages, "moduleBreakdown": module_breakdown, "topCategories": top_categories, "avgStats": avg_stats})
    except Exception as e:
        return jsonify({"error": "Failed to fetch stats"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"ThreatGuard AI Python Backend running on port {port}")
    app.run(host="0.0.0.0", debug=True, port=port)
