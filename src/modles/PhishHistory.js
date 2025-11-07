const mongoose = require("mongoose");

const PhishHistorySchema = new mongoose.Schema({
  userId: { type: String, default: null },
  url: { type: String, required: true },
  domain: { type: String, default: null },
  heuristics: { type: Object, default: {} },
  ml: { type: Object, default: {} }, // future use
  virusTotal: { type: Object, default: null },
  aiSummary: { type: String, default: null },
  reason: { type: String, default: null },
  isPhishing: { type: Boolean, default: false },
  label: { type: String, default: "unknown" },
  confidence: { type: Number, default: 0 },
}, { timestamps: true });

// Prevent OverwriteModelError in dev/hot-reload
module.exports =
  mongoose.models.PhishHistory || mongoose.model("PhishHistory", PhishHistorySchema);
