const express = require("express");
const router = express.Router();
const SSLHistory = require("../modles/SSLHistory");

// ✅ save SSL scan result
router.post("/save", async (req, res) => {
  try {
    const { userId, domain, protocol, sslData, aiResponse, scannedAt } = req.body;

    if (!userId || !domain) {
      return res.status(400).json({ error: "Missing required fields: userId or domain" });
    }

    const newRecord = new SSLHistory({
      userId,
      domain,
      protocol,
      sslData,
      aiResponse,
      scannedAt: scannedAt || new Date().toISOString(),
    });

    await newRecord.save();
    res.json({ message: "✅ SSL history saved successfully", data: newRecord });
  } catch (err) {
    console.error("❌ Error saving SSL history:", err);
    res.status(500).json({ error: "Failed to save SSL history" });
  }
});

// ✅ get user's SSL scan history
router.get("/user/:userId", async (req, res) => {
  try {
    const history = await SSLHistory.find({ userId: req.params.userId })
      .sort({ createdAt: -1 })
      .limit(50);
    res.json(history);
  } catch (err) {
    console.error("❌ Error fetching SSL history:", err);
    res.status(500).json({ error: "Failed to fetch SSL history" });
  }
});

// ✅ delete record
router.delete("/:id", async (req, res) => {
  try {
    await SSLHistory.findByIdAndDelete(req.params.id);
    res.json({ message: "🗑️ Record deleted successfully" });
  } catch (err) {
    console.error("❌ Delete error:", err);
    res.status(500).json({ error: "Failed to delete record" });
  }
});

module.exports = router;
