// portScan.js
const express = require("express");
const net = require("net");

const portRouter = express.Router();

// Function to scan a single port
const scanPort = (host, port, timeout = 2000) => {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let status = "closed"; // default

    socket.setTimeout(timeout);

    socket.on("connect", () => {
      status = "open";
      socket.destroy();
    });

    socket.on("timeout", () => {
      status = "closed";
      socket.destroy();
    });

    socket.on("error", () => {
      status = "closed";
    });

    socket.on("close", () => {
      resolve({
        port,
        status,
        service: commonPorts[port] || "unknown",
        protocol: "tcp",
      });
    });

    socket.connect(port, host);
  });
};

// Common ports list (expandable)
const commonPorts = {
  21: "ftp",
  22: "ssh",
  25: "smtp",
  53: "dns",
  80: "http",
  110: "pop3",
  143: "imap",
  443: "https",
  3306: "mysql",
  8080: "http-alt",
};

// Scan route
portRouter.post("/scan", async (req, res) => {
  const { target, scanType, startPort = 1, endPort = 1024 } = req.body;

  if (!target) {
    return res.status(400).json({ error: "Target IP/hostname is required" });
  }

  let portsToScan = [];

  // Decide scan type
  if (scanType === "quick") {
    portsToScan = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 8080];
  } else if (scanType === "full") {
    portsToScan = Array.from({ length: 1024 }, (_, i) => i + 1);
  } else if (scanType === "custom") {
    portsToScan = Array.from({ length: endPort - startPort + 1 }, (_, i) => startPort + i);
  } else {
    // default quick
    portsToScan = [22, 80, 443];
  }

  const startTime = Date.now();

  const results = [];
  for (let port of portsToScan) {
    try {
      const result = await scanPort(target, port);
      results.push(result);
    } catch (err) {
      results.push({ port, status: "error", error: err.message });
    }
  }

  const scanTime = ((Date.now() - startTime) / 1000).toFixed(2) + "s";

  res.json({
    target,
    scanType,
    totalPorts: results.length,
    openPorts: results.filter((r) => r.status === "open").length,
    closedPorts: results.filter((r) => r.status === "closed").length,
    scanTime,
    results,
  });
});

module.exports = portRouter;
