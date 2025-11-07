// models/VulnerabilityHistory.js
const mongoose = require("mongoose");

const vulnerabilitySchema = new mongoose.Schema(
  {
    target: String,
    scanType: String,
    mode: String,
    results: Array,
    aiResponse: String,
  },
  { timestamps: true }
);

module.exports = mongoose.model("VulnerabilityHistory", vulnerabilitySchema);
