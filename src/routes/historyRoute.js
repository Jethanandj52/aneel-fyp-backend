const express = require("express");
const router = express.Router();
const History = require("../modles/historyModel");

// ✅ Save scan history
router.post("/save", async (req, res) => {
  try {
    const newHistory = new History(req.body);
    await newHistory.save();
    res.json({ success: true, message: "History saved successfully" });
  } catch (err) {
    console.error("Save history error:", err);
    res.status(500).json({ success: false, error: "Failed to save history" });
  }
});

// ✅ Get user history
router.get("/:userId", async (req, res) => {
  try {
    const history = await History.find({ userId: req.params.userId }).sort({ createdAt: -1 });
    res.json(history);
  } catch (err) {
    res.status(500).json({ success: false, error: "Failed to fetch history" });
  }
});

module.exports = router;
