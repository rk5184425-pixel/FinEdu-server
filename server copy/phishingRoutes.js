import fetch from "node-fetch";

const VT_API_KEY = process.env.VT_API_KEY;

const redFlagDomains = [
  "xyz",
  "tk",
  "ml",
  "phishing.com",
  "scamlink.net",
  "secure-login.com",
  "bank-secure-update.com",
  "login-alert.net",
  "verify-payment.net",
  "signin-now.com",
  "customer-support-online.com",
  "secure-access.cloud",
];
const suspiciousEmails = [
  "support@paypal.verify.com",
  "admin@updatemybank.ru",
  "secure@m1crosoft.com",
  "verify@paypa1.com",
  "help@goog1e.com",
  "alerts@chase-online-update.com",
  "billing@netfIix.com",
];
const phishingKeywords = [
  "urgent",
  "verify account",
  "suspended",
  "click here",
  "act now",
  "limited time",
  "congratulations",
  "you've won",
  "claim now",
  "update payment",
  "confirm identity",
  "security alert",
  "unusual activity",
  "account locked",
  "expires today",
  "final notice",
  "immediate action",
  "verify now",
  "account closure",
  "refund pending",
  "tax refund",
  "free gift",
  "prize",
  "login to continue",
  "unauthorized access",
  "confirm your password",
  "new device login",
  "reset your account",
  "your action is required",
  "we noticed suspicious login",
];
const suspiciousPatterns = [
  /\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b/, // Credit card pattern
  /\b\d{3}[-\s]\d{2}[-\s]\d{4}\b/, // SSN pattern
  /password.*[:=]\s*\w+/i, // Password requests
  /pin.*[:=]\s*\d+/i, // PIN requests
  /routing.*number/i, // Banking info
  /account.*number/i, // Account numbers
  /(?:\d{6})/, // OTP codes
  /\b(?:\d{2,4})[- ]?(?:\d{2,4})[- ]?(?:\d{2,4})[- ]?(?:\d{2,4})\b/, // Flexible card numbers
  /cvv.*[:=]?\s*\d{3,4}/i, // CVV capture
  /dob.*[:=]?\s*\d{2}[-/]\d{2}[-/]\d{4}/i, // Date of birth
  /ssn.*[:=]?\s*\d{3}[- ]?\d{2}[- ]?\d{4}/i, // Another SSN pattern
  /login.*here/i, // Login link
  /enter.*account.*info/i,
  /provide.*credentials/i,
];

function isEmail(input) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input);
}

function customCheck(input) {
  input = input.toLowerCase();
  let score = 100;
  let message = "Looks safe.";
  let flags = [];
  let customMessages = [];

  if (isEmail(input)) {
    if (suspiciousEmails.includes(input)) {
      score = 10;
      message = "❌ Suspicious Email Address!";
      flags.push("Suspicious sender");
      customMessages.push(
        "❌ This email is flagged as suspicious due to a known history of phishing or fraud."
      );
    } else if (input.includes(".ru") || input.includes(".xyz")) {
      score = 50;
      message = "⚠️ High-risk domain in email!";
      flags.push("High-risk domain");
      customMessages.push(
        "⚠️ This email uses a domain (.ru/.xyz) frequently associated with scam or spam campaigns."
      );
    } else {
      message = "✅ Email seems legit.";
    }
    phishingKeywords.forEach((kw) => {
      if (input.includes(kw)) {
        score -= 10;
        flags.push(`Keyword: ${kw}`);
        customMessages.push(
          "⚠️ This email includes keywords (e.g., 'verify', 'update', 'login') commonly used in phishing attempts."
        );
      }
    });
    suspiciousPatterns.forEach((pat) => {
      if (pat.test(input)) {
        score -= 20;
        flags.push("Pattern match");
        customMessages.push(
          "⚠️ The email matches known phishing patterns (e.g., random strings, impersonating domains, zero-width characters)."
        );
      }
    });
    if (!input.split("@")[1] || !input.split("@")[1].includes(".")) {
      customMessages.push(
        "⚠️ The email domain seems unusual or malformed, possibly used to spoof legitimate services."
      );
    }
    if (score < 10) score = 10;
    return { score, message, flags, customMessages };
  }

  // Check website
  try {
    const url = new URL(input.startsWith("http") ? input : `https://${input}`);
    const hostname = url.hostname;
    for (let red of redFlagDomains) {
      if (hostname.endsWith(`.${red}`) || hostname.includes(red)) {
        score = 10;
        message = "❌ Fraudulent website detected!";
        flags.push("Red flag domain");
        customMessages.push(
          "❌ This domain is associated with reported fraud, malware distribution, or phishing campaigns."
        );
      }
    }
    if (!input.startsWith("https")) {
      score = Math.min(score, 50);
      message = "⚠️ Site is not using HTTPS!";
      flags.push("No HTTPS");
      customMessages.push(
        "⚠️ This website does not use secure HTTPS, making it vulnerable to eavesdropping or tampering."
      );
    }
    phishingKeywords.forEach((kw) => {
      if (input.includes(kw)) {
        score -= 10;
        flags.push(`Keyword: ${kw}`);
        customMessages.push(
          "⚠️ The URL contains common phishing terms like 'secure-login', 'verify-now', or 'free-gift' to trick users."
        );
      }
    });
    suspiciousPatterns.forEach((pat) => {
      if (pat.test(input)) {
        score -= 20;
        flags.push("Pattern match");
        customMessages.push(
          "⚠️ This site uses tricks like replacing letters with numbers (e.g., amaz0n.com), often used in spoofing attacks."
        );
      }
    });
    if (!hostname.split(".").pop()) {
      customMessages.push(
        "❌ This URL is missing a standard TLD (.com, .org), which is a sign of a potentially fake or unsafe site."
      );
    }
    if (input.length > 100) {
      customMessages.push(
        "⚠️ Extremely long URLs are often used to hide malicious payloads or redirect to shady destinations."
      );
    }
    // Subdomain spoofing
    if (hostname.split(".").length > 3) {
      customMessages.push(
        "⚠️ The URL structure tries to appear as a legitimate site by hiding the real domain in subdomains."
      );
    }
    if (score < 10) score = 10;
    return { score, message, flags, customMessages };
  } catch (err) {
    customMessages.push("⚠️ The URL or email is malformed or invalid.");
    return {
      score: 10,
      message: "Invalid input. Not a valid URL or email.",
      flags: ["Invalid input"],
      customMessages,
    };
  }
}

function extractUrls(text) {
  const urlRegex = /https?:\/\/[\S"'<>()]+/g;
  return text.match(urlRegex) || [];
}

function extractEmails(text) {
  const emailRegex = /[^\s@]+@[^\s@]+\.[^\s@]+/g;
  return text.match(emailRegex) || [];
}

function customHeuristicScore(body) {
  let score = 100;
  let reasons = [];
  phishingKeywords.forEach((kw) => {
    if (body.toLowerCase().includes(kw)) {
      score -= 10;
      reasons.push(`Contains suspicious keyword: '${kw}'`);
    }
  });
  const socialEngineeringPhrases = [
    "act now",
    "immediately",
    "your account has been locked",
    "confirm your identity",
    "verify your account",
    "reset your password",
    "security alert",
    "urgent action required",
  ];
  socialEngineeringPhrases.forEach((phrase) => {
    if (body.toLowerCase().includes(phrase)) {
      score -= 20;
      reasons.push(`Contains social engineering phrase: '${phrase}'`);
    }
  });
  extractUrls(body).forEach((url) => {
    if (url.startsWith("http://")) {
      score -= 15;
      reasons.push(`Uses insecure URL: ${url}`);
    }
    if (url.match(/\d+\.\d+\.\d+\.\d+/)) {
      score -= 15;
      reasons.push(`URL contains IP address: ${url}`);
    }
    if (url.match(/\.xyz/)) {
      score -= 20;
      reasons.push(`URL uses suspicious TLD: .xyz`);
    }
    if (url.length > 100) {
      score -= 10;
      reasons.push(`Unusually long URL: ${url}`);
    }
  });
  extractEmails(body).forEach((email) => {
    if (email.endsWith(".gq") || email.endsWith(".ru")) {
      score -= 20;
      reasons.push(`Email from suspicious domain: ${email}`);
    }
  });
  return { score: Math.max(score, 10), reasons };
}

function calcVTScore(malicious, suspicious, harmless) {
  const total = malicious + suspicious + harmless;
  if (malicious > 0) return 10;
  if (suspicious >= 2) return 30;
  if (harmless > 60 && suspicious === 0) return 90;
  return 60;
}

async function virusTotalUrlScore(url) {
  const submitRes = await fetch("https://www.virustotal.com/api/v3/urls", {
    method: "POST",
    headers: {
      "x-apikey": VT_API_KEY,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: `url=${encodeURIComponent(url)}`,
  });
  const submitData = await submitRes.json();
  const analysisId = submitData.data.id;

  let reportData;
  for (let i = 0; i < 5; i++) {
    await new Promise((res) => setTimeout(res, 3000));
    const reportRes = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: { "x-apikey": VT_API_KEY },
      }
    );
    reportData = await reportRes.json();
    if (
      reportData.data &&
      reportData.data.attributes &&
      reportData.data.attributes.status === "completed"
    ) {
      break;
    }
  }

  if (
    !reportData.data ||
    !reportData.data.attributes ||
    reportData.data.attributes.status !== "completed"
  ) {
    return {
      vtScore: 60,
      message: "VirusTotal report not ready or unavailable",
      stats: null,
    };
  }

  const stats = reportData.data.attributes.stats;
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const vtScore = calcVTScore(malicious, suspicious, harmless);
  let message = "";
  if (malicious > 0)
    message = `⚠️ VirusTotal flagged ${malicious} malicious report(s)`;
  else if (suspicious >= 2)
    message = `⚠️ VirusTotal flagged as suspicious by ${suspicious} engines`;
  else if (harmless > 60 && suspicious === 0)
    message = `✅ VirusTotal found no issues (harmless: ${harmless})`;
  else message = `⚠️ VirusTotal returned mixed results`;
  return { vtScore, message, stats };
}

async function virusTotalDomainScore(domain) {
  const vtUrl = `https://www.virustotal.com/api/v3/domains/${domain}`;
  const response = await fetch(vtUrl, {
    headers: { "x-apikey": VT_API_KEY },
  });
  const data = await response.json();
  if (data && data.data && data.data.attributes) {
    const stats = data.data.attributes.last_analysis_stats;
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const vtScore = calcVTScore(malicious, suspicious, harmless);
    let message = "";
    if (malicious > 0) message = `⚠️ Domain flagged as malicious by VirusTotal`;
    else if (suspicious >= 2)
      message = `⚠️ Domain flagged as suspicious by VirusTotal`;
    else if (harmless > 60 && suspicious === 0)
      message = `✅ Domain found harmless by VirusTotal`;
    else message = `⚠️ Domain returned mixed results`;
    return { vtScore, message, stats };
  }
  return { vtScore: 60, message: "No data found for domain.", stats: null };
}

export default function (app) {
  app.post("/api/check", async (req, res) => {
    const { input } = req.body;
    const urls = extractUrls(input);
    const emails = extractEmails(input);

    const { score: customScore, reasons: customReasons } =
      customHeuristicScore(input);

    let dangerousLinks = [];
    let vtReasons = [];
    for (const url of urls) {
      const vt = await virusTotalUrlScore(url);
      if (vt.vtScore <= 30) {
        dangerousLinks.push({
          url,
          virustotal_score: vt.vtScore,
          message: vt.message,
        });
        vtReasons.push(vt.message);
      }
    }

    let senderDomain = null;
    if (emails.length > 0) {
      senderDomain = emails[0].split("@")[1];
    }
    let senderDomainVT = null;
    if (senderDomain) {
      senderDomainVT = await virusTotalDomainScore(senderDomain);
      if (senderDomainVT.vtScore <= 30) {
        vtReasons.push(senderDomainVT.message);
      }
    }

    const allReasons = [...customReasons, ...vtReasons];

    let vtScore =
      dangerousLinks.length > 0
        ? Math.min(...dangerousLinks.map((l) => l.virustotal_score))
        : senderDomainVT
        ? senderDomainVT.vtScore
        : 60;
    const finalScore = (customScore * 0.6 + vtScore * 0.4) / 1.0;
    let verdict = "✅ Safe";
    if (finalScore < 50) verdict = "❌ Dangerous / Phishing";
    else if (finalScore < 80) verdict = "⚠️ Caution";

    res.json({
      final_score: Math.round(finalScore),
      verdict,
      reason: allReasons,
      dangerous_links: dangerousLinks,
    });
  });

  app.get("/test", (req, res) => res.json({ msg: "test ok" }));
  app.get("/health", (req, res) => res.json({ status: "ok" }));
}
