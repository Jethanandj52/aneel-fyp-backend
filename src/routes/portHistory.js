const express = require("express");
const PortHistory = require("../modles/PortHistory");
const router = express.Router();

// ✅ Save Port Scan History
router.post("/save", async (req, res) => {
  try {
    const history = new PortHistory(req.body);
    await history.save();
    res.json({ success: true, message: "Port history saved!" });
  } catch (err) {
    console.error("Error saving port history:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ✅ Get all history for a user
router.get("/all/:userId", async (req, res) => {
  try {
    const data = await PortHistory.find({ userId: req.params.userId })
      .sort({ createdAt: -1 })
      .limit(20);
    res.json(data);
  } catch (err) {
    console.error("Error fetching port history:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ✅ Delete a specific entry
router.delete("/delete/:id", async (req, res) => {
  try {
    await PortHistory.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: "Deleted successfully!" });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
