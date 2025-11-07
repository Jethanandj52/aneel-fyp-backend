// routes/portRouter.js
const express = require("express");
const net = require("net");
const tls = require("tls");

const portRouter = express.Router();

/* =============================
   🧭 COMMON PORTS & SERVICE MAP
   (service scan uses these)
============================= */
const commonPorts = {
  20: "ftp-data",
  21: "ftp",
  22: "ssh",
  23: "telnet",
  25: "smtp",
  53: "dns",
  67: "dhcp-server",
  68: "dhcp-client",
  69: "tftp",
  80: "http",
  110: "pop3",
  143: "imap",
  443: "https",
  465: "smtps",
  993: "imaps",
  995: "pop3s",
  1433: "mssql",
  1521: "oracle",
  3306: "mysql",
  3389: "rdp",
  5432: "postgres",
  5900: "vnc",
  6379: "redis",
  8080: "http-alt",
  8443: "https-alt",
  9000: "php-fpm",
  9200: "elasticsearch",
  11211: "memcached",
  3000: "node-dev",
};

const TLS_PORTS = new Set([443, 8443, 993, 995, 465]);
const UDP_PORTS = new Set([53, 67, 68, 69, 123, 161]);

function guessService(port) {
  return commonPorts[port] || "service";
}

function protocolLabelForPort(port) {
  if (TLS_PORTS.has(port)) return "tcp+tls";
  if (UDP_PORTS.has(port)) return "udp";
  return "tcp";
}

function inferFromBanner(raw) {
  const txt = (raw || "").toString();
  const clean = txt
    .replace(/\r/g, "")
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)
    .join(" | ");
  const out = { service: null, version: null, banner: clean || "-" };

  if (/ssh/i.test(txt)) out.service = "ssh";
  if (/http/i.test(txt) || /server:/i.test(txt)) out.service = "http";
  if (/mysql/i.test(txt)) out.service = "mysql";
  if (/smtp/i.test(txt)) out.service = "smtp";
  if (/ftp/i.test(txt)) out.service = "ftp";
  if (/imap/i.test(txt)) out.service = "imap";
  if (/pop3/i.test(txt)) out.service = "pop3";
  if (/redis/i.test(txt)) out.service = "redis";

  const version = txt.match(/(\d+\.\d+\.\d+)/);
  if (version) out.version = version[1];
  return out;
}

/* =============================
   ⚙️ SCAN A SINGLE PORT
   - Service-specific small probes added
   - TLS gets handshake probe
   - For closed/no-response -> return closed
============================= */
const scanPort = (host, port, opts = {}) => {
  const { timeout = 1200, serviceMode = false } = opts;

  return new Promise((resolve) => {
    const result = {
      port,
      service: guessService(port),
      status: "closed",
      protocol: protocolLabelForPort(port),
      banner: "-",
      version: "-",
      method: "tcp-connect",
    };

    let done = false;
    const finish = (update = {}) => {
      if (done) return;
      done = true;
      const merged = { ...result, ...update };
      if (merged.status !== "open") {
        merged.banner = "-";
        merged.version = "-";
      }
      resolve(merged);
    };

    // TLS ports: attempt TLS handshake then small probe
    if (TLS_PORTS.has(port)) {
      try {
        const sock = tls.connect(
          { host, port, servername: host, rejectUnauthorized: false, timeout },
          () => {
            // after handshake try a simple HTTP HEAD
            try {
              sock.write("HEAD / HTTP/1.0\r\n\r\n");
            } catch (e) {
              // ignore write errors
            }
          }
        );
        let banner = "";
        sock.setEncoding("utf8");
        sock.on("data", (chunk) => {
          banner += chunk;
          const inf = inferFromBanner(banner);
          finish({
            status: "open",
            banner: inf.banner,
            version: inf.version,
            service: inf.service || guessService(port),
            method: "tls-handshake",
          });
          sock.destroy();
        });
        sock.on("error", () => finish({ status: "open" })); // TLS often doesn't send payloads; mark open
        sock.on("timeout", () => finish({ status: "open" }));
        sock.on("close", () => finish({}));
      } catch (e) {
        finish({ status: "closed" });
      }
      return;
    }

    // TCP connect & banner grabs
    const socket = new net.Socket();
    socket.setTimeout(timeout);

    let banner = "";

    socket.on("connect", () => {
      // for some protocols (SSH) server usually sends banner first,
      // for others we try sending small protocol-specific probes if in serviceMode or always small HEAD.
      // We'll send conservative probes to encourage a response without breaking protocols.
      try {
        // Service mode: try specific small probes to get better banners
        if (serviceMode) {
          if (port === 80 || port === 8080 || port === 3000) {
            socket.write("HEAD / HTTP/1.0\r\nHost: " + host + "\r\n\r\n");
          } else if (port === 25) {
            // SMTP expects server banner first; but try EHLO if nothing arrives quickly later.
            // We still wait for banner.
          } else if (port === 21) {
            // FTP typically sends banner; after connect we can send QUIT if need be.
            setTimeout(() => {
              try { socket.write("QUIT\r\n"); } catch(e) {}
            }, 200);
          } else if (port === 110 || port === 143) {
            // POP3/IMAP often send banner; but we attempt a newline to prompt.
            try { socket.write("\r\n"); } catch(e) {}
          } else {
            // default small HEAD to elicit HTTP-like banners if present
            try { socket.write("HEAD / HTTP/1.0\r\n\r\n"); } catch(e) {}
          }
        } else {
          // non-service quick probe: small HTTP HEAD (safe)
          try { socket.write("HEAD / HTTP/1.0\r\n\r\n"); } catch(e) {}
        }
      } catch (e) {
        // ignore any write errors (some services close on unexpected writes)
      }
    });

    socket.on("data", (data) => {
      banner += data.toString();
      const inf = inferFromBanner(banner);
      finish({
        status: "open",
        banner: inf.banner,
        version: inf.version,
        service: inf.service || guessService(port),
        method: serviceMode ? "tcp-service-probe" : "tcp-banner",
      });
      socket.destroy();
    });

    socket.on("error", () => finish({ status: "closed" }));
    socket.on("timeout", () => finish({ status: "closed" }));
    socket.on("close", () => finish({}));

    socket.connect(port, host);
  });
};

/* =============================
   ⚡ CONCURRENT SCAN
   - supports serviceMode option (longer timeouts + different probes)
============================= */
const parallelScan = async (ports, host, concurrency = 100, timeout = 1200, serviceMode = false) => {
  const results = [];
  let i = 0;

  const runWorker = async () => {
    while (i < ports.length) {
      const port = ports[i++];
      try {
        const res = await scanPort(host, port, { timeout: serviceMode ? Math.max(timeout, 1500) : timeout, serviceMode });
        results.push(res);
      } catch {
        results.push({ port, status: "closed", service: guessService(port), banner: "-", version: "-" });
      }
    }
  };

  const workers = Array(Math.min(concurrency, ports.length)).fill(0).map(runWorker);
  await Promise.all(workers);
  return results.sort((a, b) => a.port - b.port);
};

/* =============================
   🚀 ROUTE
   - NOTE: "full" scan is intentionally disabled for now.
     - scanType "quick" and "service" are active.
     - If future: allow full by sending startPort/endPort and raising concurrency/timeouts.
============================= */
portRouter.post("/scan", async (req, res) => {
  try {
    const {
      target,
      scanType = "quick",
      startPort = 1,
      endPort = 1024,
      concurrency = 100,
      timeout = 1200,
    } = req.body;

    if (!target) return res.status(400).json({ error: "Target required" });

    // Determine ports based on scanType
    let ports = [];

    // If user requested 'full' — we are currently disabling full scan to avoid wide-range scans.
    // Treat it as quick (use commonPorts) and keep the code here so it can be enabled later if needed.
    if (scanType === "quick" || scanType === "full") {
      // Quick scan uses commonPorts; full is currently disabled (treated same as quick).
      ports = Object.keys(commonPorts).map(Number);
    } else if (scanType === "service") {
      // Service scan: same ports as commonPorts but run with serviceMode (better probes/timeouts).
      ports = Object.keys(commonPorts).map(Number);
    } else {
      // fallback to range (custom)
      const s = Number(startPort) || 1;
      const e = Number(endPort) || 1024;
      if (e < s) return res.status(400).json({ error: "endPort must be >= startPort" });
      // defensive: limit how many ports can be scanned in custom to prevent abuse
      const maxRange = 2000;
      if (e - s + 1 > maxRange) return res.status(400).json({ error: `Port range too large (max ${maxRange})` });
      ports = Array.from({ length: e - s + 1 }, (_, i) => s + i);
    }

    const serviceMode = scanType === "service";

    const t0 = Date.now();
    const results = await parallelScan(ports, target, concurrency, timeout, serviceMode);
    const timeTaken = ((Date.now() - t0) / 1000).toFixed(2) + "s";

    res.json({
      target,
      scanType,
      totalPorts: results.length,
      openPorts: results.filter((r) => r.status === "open").length,
      closedPorts: results.filter((r) => r.status === "closed").length,
      scanTime: timeTaken,
      results,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = portRouter;
