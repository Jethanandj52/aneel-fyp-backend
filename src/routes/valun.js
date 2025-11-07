// valunRouter.js
const express = require("express");
const axios = require("axios");
const { exec } = require("child_process");
const sslChecker = require("ssl-checker");

const valunRouter = express.Router();

// ------------------- SOFTWARE SCAN -------------------
valunRouter.post("/scan", async (req, res) => {
  let { target, scanType = "light" } = req.body;

  if (!target || typeof target !== "string" || target.trim() === "") {
    return res.status(400).json({ error: "Target (software name) is required" });
  }

  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(target)}`;
    const response = await axios.get(url, { timeout: 15000 });
    const data = response.data;

    if (!data || !Array.isArray(data.vulnerabilities) || data.vulnerabilities.length === 0) {
      return res.json({ target, results: [], message: `No vulnerabilities found for ${target}` });
    }

    let results = data.vulnerabilities.map((item) => {
      const cve = item.cve || {};
      const id = cve.id || "Unknown CVE";
      const desc = (cve.descriptions && cve.descriptions[0] && cve.descriptions[0].value) || "No description available";
      const severity =
        (cve.metrics &&
          (cve.metrics.cvssMetricV31?.[0]?.cvssData?.baseSeverity ||
            cve.metrics.cvssMetricV30?.[0]?.cvssData?.baseSeverity)) ||
        "Unknown";

      return { vulnerability: id, severity, location: target, description: desc, status: "Detected" };
    });

    if (scanType === "light") results = results.filter((r) => r.severity === "HIGH");
    else if (scanType === "custom") results = results.filter((r) => r.severity && r.severity !== "Unknown");

    if (results.length === 0) {
      return res.json({ target, results: [], message: `No matching vulnerabilities found for ${target} with scanType='${scanType}'` });
    }

    return res.json({ target, results });
  } catch (err) {
    console.error("❌ Error fetching CVE:", err?.response?.data || err?.message || err);
    return res.status(500).json({ error: "Failed to fetch vulnerabilities", details: err?.message || "unknown error" });
  }
});

// ------------------- WEBSITE SCAN -------------------

// helper: SSL check
async function checkSSL(url) {
  try {
    const hostname = new URL(url).hostname;
    const info = await sslChecker(hostname, { method: "GET" });
    return { ok: true, issuer: info.issuer || null, validFrom: info.validFrom || null, validTo: info.validTo || null, valid: typeof info.valid === "boolean" ? info.valid : null };
  } catch (err) {
    return { ok: false, error: String(err.message || err) };
  }
}

// helper: dir listing
async function checkDir(url) {
  try {
    const res = await axios.get(url, { timeout: 8000, validateStatus: null });
    const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data).slice(0, 2000);
    const listing = (body && (body.includes("Index of") || body.includes("<title>Index of"))) ? true : false;
    return { listing, status_code: res.status };
  } catch (err) {
    return { error: String(err.message || err) };
  }
}

// helper: Nmap scan
function runNmap(hostname, ports = "80,443,8080,8443", timeout = 180000) {
  return new Promise((resolve) => {
    exec(`nmap -sV -sC -p ${ports} ${hostname}`, { timeout }, (err, stdout, stderr) => {
      if (err) return resolve({ ok: false, error: String(err.message || stderr || "nmap error") });
      return resolve({ ok: true, output: stdout });
    });
  });
}

// helper: SQLMap scan (optional)
function runSqlmap(targetUrl, timeout = 300000) {
  return new Promise((resolve) => {
    const cmd = `sqlmap -u "${targetUrl}" --batch --random-agent --level=1 --risk=1 --crawl=2 --forms`;
    exec(cmd, { timeout, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        const msg = String(err.message || stderr || "sqlmap error");
        if (err.code === 'ENOENT') return resolve({ ok: false, error: "sqlmap not installed", vulnerable: false, summary: ["sqlmap missing, skipped"] });
        return resolve({ ok: false, error: msg, vulnerable: false, summary: [msg] });
      }
      const out = String(stdout || "") + "\n" + String(stderr || "");
      const low = out.toLowerCase();
      const vulnerable = low.includes("is injectable") || low.includes("is vulnerable") || low.includes("following injection point");
      const summary = vulnerable ? ["SQL Injection likely detected (sqlmap output)."] : ["sqlmap finished — no obvious injection found in quick scan."];
      return resolve({ ok: true, output: out.slice(0, 8000), vulnerable, summary });
    });
  });
}

// website scan route
valunRouter.post("/scan-website", async (req, res) => {
  const { target } = req.body;
  if (!target || typeof target !== "string" || target.trim() === "") return res.status(400).json({ error: "Target (website URL) required" });

  const fullUrl = target.startsWith("http://") || target.startsWith("https://") ? target.trim() : "http://" + target.trim();
  let hostname;
  try { hostname = new URL(fullUrl).hostname; } catch (e) { return res.status(400).json({ error: "Invalid URL" }); }

  const result = { target: fullUrl, timestamp: new Date().toISOString(), checks: {} };
  try {
    if (fullUrl.startsWith("https://")) result.checks.ssl = await checkSSL(fullUrl);
    result.checks.dir_root = await checkDir(fullUrl);
    result.checks.dir_uploads = await checkDir(fullUrl.replace(/\/+$/, "") + "/uploads/");
    result.checks.nmap = await runNmap(hostname);
    result.checks.sqlmap = await runSqlmap(fullUrl);
    return res.json(result);
  } catch (err) {
    console.error("scan-website error:", err);
    return res.status(500).json({ error: "Scan failed", details: String(err.message || err) });
  }
});

module.exports = valunRouter;
