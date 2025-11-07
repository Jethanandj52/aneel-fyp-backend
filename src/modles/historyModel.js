const mongoose = require("mongoose");

const historySchema = new mongoose.Schema(
  {
    userId: { type: String, required: true },
    networkRange: String,
    mode: String,
    summary: {
      totalScanned: Number,
      activeHosts: Number,
      totalPorts: Number,
      scannedAt: String,
      duration: String,
      mode: String,
    },
    scanResults: Array, // 👈 ye poora nmap ka result store karega
    aiResponse: String, // 👈 ye poora AI ka summary store karega
  },
  { timestamps: true }
);

 


module.exports = mongoose.model("History", historySchema);
