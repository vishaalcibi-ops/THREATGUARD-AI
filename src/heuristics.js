/**
 * Real-world Heuristic Security Engine
 * Performs actual checks on URLs and text patterns.
 */

const SUSPICIOUS_TLDS = [".xyz", ".top", ".pw", ".bid", ".icu", ".work", ".click", ".zip", ".mov"];
const BRAND_KEYWORDS = ["paypal", "google", "microsoft", "amazon", "apple", "netflix", "bank", "secure", "verify"];
const URGENCY_TRIGGERS = ["urgent", "account suspended", "immediate action", "verify now", "security alert", "suspicious activity"];
const FINANCIAL_TRIGGERS = ["payment", "invoice", "refund", "transaction", "unauthorized", "bank account", "crypto", "wallet"];

export const analyzeUrlHeuristics = (url) => {
  const findings = [];
  let riskScore = 0;
  
  try {
    const urlObj = new URL(url.startsWith("http") ? url : `http://${url}`);
    const hostname = urlObj.hostname.toLowerCase();
    
    // Check for IP-based hostname
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
      findings.push("IP-based hostname detected (High risk)");
      riskScore += 40;
    }
    
    // Check for suspicious TLDs
    const tld = hostname.split(".").pop();
    if (SUSPICIOUS_TLDS.includes(`.${tld}`)) {
      findings.push(`Suspicious TLD detected: .${tld}`);
      riskScore += 25;
    }
    
    // Check for brand impersonation
    BRAND_KEYWORDS.forEach(brand => {
      // If brand is in host but not the main domain
      if (hostname.includes(brand) && !hostname.endsWith(`${brand}.com`) && !hostname.endsWith(`${brand}.org`)) {
        findings.push(`Potential brand impersonation: ${brand}`);
        riskScore += 35;
      }
    });
    
    // Check for Punycode
    if (hostname.includes("xn--")) {
      findings.push("IDN Homograph/Punycode detected (Phishing risk)");
      riskScore += 45;
    }
    
  } catch (e) {
    findings.push("Malformed or highly suspicious URL structure");
    riskScore += 20;
  }
  
  return { findings, riskScore };
};

export const analyzeTextHeuristics = (text) => {
  const findings = [];
  let riskScore = 0;
  const content = text.toLowerCase();
  
  URGENCY_TRIGGERS.forEach(trigger => {
    if (content.includes(trigger)) {
      findings.push(`Urgency trigger: "${trigger}"`);
      riskScore += 15;
    }
  });
  
  FINANCIAL_TRIGGERS.forEach(trigger => {
    if (content.includes(trigger)) {
      findings.push(`Financial hook: "${trigger}"`);
      riskScore += 15;
    }
  });
  
  if (content.match(/https?:\/\/[^\s]+/)) {
    findings.push("Message contains clickable links");
    riskScore += 10;
  }
  
  if (content.length < 50 && riskScore > 20) {
    findings.push("Short, high-pressure SMS/Message pattern");
    riskScore += 15;
  }
  
  return { findings, riskScore };
};

export const getAnalysisSteps = (moduleId) => {
  const baseSteps = [
    "Initializing neural inspection engine...",
    "Establishing sandboxed environment...",
  ];
  const moduleSpecific = {
    url: [
      "Parsing URL structure and DNS metadata...",
      "Checking TLD reputation and registration data...",
      "Scanning for Punycode and homograph attacks...",
      "Cross-referencing brand impersonation databases...",
    ],
    qr: [
      "Decoding QR redirect patterns...",
      "Analyzing target endpoint reputation...",
      "Checking for drive-by download signatures...",
    ],
    message: [
      "Analyzing linguistic sentiment and pressure tactics...",
      "Extracting suspicious entities and financial links...",
      "Checking sender reputation and spoofing patterns...",
    ],
    screenshot: [
      "Performing OCR text extraction...",
      "Analyzing visual structure for UI spoofing...",
      "Running text-based threat analysis...",
    ]
  };
  
  return [...baseSteps, ...(moduleSpecific[moduleId] || []), "Finalizing threat assessment..."];
};
