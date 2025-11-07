const mongoose = require("mongoose");

const sslHistorySchema = new mongoose.Schema(
  {
    userId: { type: String, required: true }, // user ka id
    domain: { type: String, required: true },
    protocol: { type: String },
    sslData: { type: Object }, // complete SSL scan result
    aiResponse: { type: String }, // AI summary text
    scannedAt: { type: Date, default: Date.now }, // scan time
  },
  { timestamps: true }
);

module.exports = mongoose.model("SSLHistory", sslHistorySchema);
