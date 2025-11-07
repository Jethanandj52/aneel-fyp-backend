const mongoose = require("mongoose");

const PhishHistorySchema = new mongoose.Schema({
  url: String,
  domain: String,
  isPhishing: Boolean,
  reason: String,
  timestamp: { type: Date, default: Date.now },
});

module.exports = mongoose.model("PhishHistory", PhishHistorySchema);
