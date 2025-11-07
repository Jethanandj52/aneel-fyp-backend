const express = require("express");
const router = express.Router();
const { URL } = require("url");
const PhishHistory = require("../modles/PhishHistory"); // note: folder 'models'
const punycode = require("punycode/");

// Suspicious tokens list
const SUSPICIOUS_TOKENS = [
  "login","secure","account","update","verify","bank","confirm","webscr",
  "signin","paypal","appleid","facebook","google","ebay","password","transaction"
];

function safeNormalize(raw) {
  if (!raw || typeof raw !== "string") return null;
  let s = raw.trim();
  // if missing scheme, assume https
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  try {
    return new URL(s);
  } catch {
    return null;
  }
}

function isIpHost(hostname) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
}
function containsPunycode(hostname) {
  return hostname.includes("xn--");
}
function hasAtSymbol(raw) {
  return raw.includes("@");
}
function longUrl(raw) {
  return raw.length > 75;
}
function countDots(hostname) {
  return (hostname.match(/\./g) || []).length;
}
function findSuspiciousTokens(raw) {
  const l = raw.toLowerCase();
  return SUSPICIOUS_TOKENS.filter(t => l.includes(t));
}

// stronger token-influence scoring (tunable)
function computeConfidence(flags) {
  let score = 0;
  if (flags.has_at) score += 0.25;
  if (flags.is_ip) score += 0.25;
  if (flags.punycode) score += 0.2;
  if (flags.long_url) score += 0.1;
  if (flags.count_dots >= 4) score += 0.05;
  // stronger token weight (each token ~0.12, cap 0.6)
  score += Math.min(0.6, (flags.suspicious_tokens || []).length * 0.12);
  return Math.min(1, score);
}

async function handleScan(req, res) {
  try {
    const { url: rawUrl } = req.body || {};
    if (!rawUrl) return res.status(400).json({ error: "URL is required" });

    const parsed = safeNormalize(rawUrl);
    if (!parsed) return res.status(400).json({ error: "Invalid URL format. Include http:// or https:// or a valid domain" });

    const hostname = (parsed.hostname || "").toLowerCase();
    const decodedHost = punycode.toUnicode(hostname);

    const heuristics = {
      url: parsed.href,
      host: decodedHost,
      has_at: hasAtSymbol(rawUrl),
      is_ip: isIpHost(hostname),
      punycode: containsPunycode(hostname),
      long_url: longUrl(rawUrl),
      suspicious_tokens: findSuspiciousTokens(rawUrl),
      count_dots: countDots(hostname),
      length: rawUrl.length
    };

    const confidence = computeConfidence(heuristics);

    // strong rules: if >=2 suspicious tokens OR brand-hyphen pattern -> phishing
    function hasBrandHyphen(host) {
      const brands = ["paypal","google","facebook","amazon","microsoft"];
      return brands.some(b => host.includes(b) && host.includes("-"));
    }

    let label = "safe";
    if (heuristics.suspicious_tokens.length >= 2) {
      label = "phishing";
    } else if (hasBrandHyphen(heuristics.host)) {
      label = "phishing";
    } else if (confidence >= 0.5) {
      label = "phishing";
    } else if (confidence >= 0.25) {
      label = "suspicious";
    }

    const reason = heuristics.suspicious_tokens.length
      ? `Suspicious tokens: ${heuristics.suspicious_tokens.join(", ")}`
      : (heuristics.has_at ? "Contains @ symbol" : "No phishing signs detected");

    // Save to DB (best-effort)
    let saved = null;
    try {
      const history = new PhishHistory({
        url: heuristics.url,
        domain: decodedHost,
        isPhishing: label === "phishing",
        reason,
        heuristics,
        label,
        confidence
      });
      saved = await history.save();
    } catch (dbErr) {
      console.warn("DB save failed:", dbErr.message || dbErr);
    }

    return res.json({
      url: heuristics.url,
      label,
      confidence,
      heuristics,
      reason,
      dbId: saved ? saved._id : null,
    });
  } catch (err) {
    console.error("handleScan error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
}

router.post("/scan", handleScan);
router.post("/check", handleScan); // alias
router.get("/history", async (req, res) => {
  try {
    const list = await PhishHistory.find().sort({ createdAt: -1 }).limit(50).lean();
    res.json({ count: list.length, data: list });
  } catch (err) {
    console.error("history error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

module.exports = router;
