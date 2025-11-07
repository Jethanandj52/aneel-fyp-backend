// src/routes/valunHistory.js
 const express = require("express");
 const VulnerabilityHistory = require("../modles/ValunerbilityHistory");

const router = express.Router();

// ✅ Save AI Summary with scan results
router.post("/save-scan", async (req, res) => {
  try {
    const { target, scanType, mode, results, aiResponse } = req.body;

    const newScan = new VulnerabilityHistory({
      target,
      scanType,
      mode,
      results,
      aiResponse,
    });

    await newScan.save();

    res.status(201).json({
      success: true,
      message: "Scan saved successfully!",
      data: newScan,
    });
  } catch (err) {
    console.error("❌ Error saving scan:", err);
    res.status(500).json({
      success: false,
      message: "Error saving scan",
      error: err.message,
    });
  }
});

// ✅ Fetch all saved scans (history)
router.get("/history", async (req, res) => {
  try {
    const history = await VulnerabilityHistory.find().sort({ createdAt: -1 });

    res.json({
      success: true,
      count: history.length,
      data: history,
    });
  } catch (err) {
    console.error("❌ Error fetching history:", err);
    res.status(500).json({
      success: false,
      message: "Error fetching history",
      error: err.message,
    });
  }
});

module.exports = router;