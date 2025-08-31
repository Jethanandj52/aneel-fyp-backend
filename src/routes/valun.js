// valun.js
const express = require("express");
const axios = require("axios");

const valunRouter = express.Router();

valunRouter.post("/scan", async (req, res) => {
  const { target = "wordpress", scanType = "light" } = req.body;

  try {
    // 🔹 NVD API call
    const response = await axios.get(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(
        target
      )}`
    );

    const data = response.data;

    if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
      return res.json({
        target,
        message: `No vulnerabilities found for ${target}`,
        results: [],
      });
    }

    let results = data.vulnerabilities.map((item) => {
      const cveId = item.cve?.id || "Unknown CVE";
      const severity =
        item.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ||
        item.cve?.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity ||
        "Unknown";
      const description =
        item.cve?.descriptions?.[0]?.value || "No description available";

      return {
        vulnerability: cveId,
        severity,
        location: target || "N/A",
        description,
        status: "Detected",
      };
    });

    // 🔹 scanType filter
    if (scanType === "light") {
      results = results.filter((r) => r.severity === "HIGH");
    } else if (scanType === "deep") {
      // deep → sab results, no filter
    } else if (scanType === "custom") {
      // custom → user ke hisaab se advanced filter
      results = results.filter((r) => r.severity !== "Unknown"); // example
    }

    return res.json({ target, results });
  } catch (err) {
    console.error("❌ Error fetching CVE:", err.response?.data || err.message);
    return res.status(500).json({
      error: "Failed to fetch vulnerabilities",
      details: err.message,
    });
  }
});

module.exports = valunRouter;
