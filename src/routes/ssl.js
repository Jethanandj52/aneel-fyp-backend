const express = require("express");
const tls = require("tls");

const sslRouter = express.Router();

const PROTOCOL_PORTS = {
  https: 443,
  smtp: 465,
  imap: 993,
  pop3: 995,
};

function toISODate(d) {
  if (!d) return null;
  try {
    return new Date(d).toISOString().split("T")[0];
  } catch {
    return null;
  }
}

function getDaysUntil(dateStr) {
  try {
    const to = new Date(dateStr);
    const now = new Date();
    return Math.max(0, Math.round((to - now) / (1000 * 60 * 60 * 24)));
  } catch {
    return null;
  }
}

function gradeFrom(daysLeft, isExpired) {
  if (isExpired) return "F";
  if (daysLeft >= 90) return "A+";
  if (daysLeft >= 30) return "A";
  if (daysLeft >= 14) return "B";
  if (daysLeft >= 7) return "C";
  return "D";
}

function normalizeSANs(cert) {
  const san = cert?.subjectaltname;
  if (!san) return [];
  return san
    .split(",")
    .map((s) => s.trim().replace(/^DNS:/i, "").trim())
    .filter(Boolean);
}

function fetchCertificate({ host, port, timeoutMs = 8000 }) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const socket = tls.connect(
      {
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
        ALPNProtocols: ["http/1.1", "h2"],
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const proto = socket.getProtocol();
          const cipher = socket.getCipher();

          if (!cert || Object.keys(cert).length === 0) {
            socket.end();
            return reject(new Error("No certificate returned by server"));
          }

          const validFrom = toISODate(cert.valid_from);
          const validTo = toISODate(cert.valid_to);
          const daysUntilExpiry = getDaysUntil(validTo);
          const isExpired = new Date(validTo) < new Date();

          const resp = {
            host,
            port,
            tlsProtocol: proto || null,
            cipherSuite: cipher?.name || null,
            issuer: cert.issuer?.O || cert.issuer?.CN || "Unknown",
            subjectCN: cert.subject?.CN || null,
            subjectO: cert.subject?.O || null,
            sanDNS: normalizeSANs(cert),
            validFrom,
            validTo,
            status: isExpired ? "Expired" : "Valid",
            daysUntilExpiry,
            grade: gradeFrom(daysUntilExpiry ?? 0, isExpired),
            serialNumber: cert.serialNumber || null,
            signatureAlgorithm: cert.signatureAlgorithm || null,
            publicKeyAlgorithm:
              cert.pubkey?.alg || cert.publicKeyAlgorithm || null,
            publicKeyBits: cert.bits || null,
            isSelfSigned:
              !!cert.issuerCertificate &&
              cert.issuerCertificate.fingerprint === cert.fingerprint,
            checkElapsedMs: Date.now() - started,
          };

          socket.end();
          resolve(resp);
        } catch (e) {
          socket.end();
          reject(e);
        }
      }
    );

    socket.setTimeout(timeoutMs, () => {
      socket.destroy(new Error("TLS connection timed out"));
    });

    socket.on("error", reject);
  });
}

sslRouter.post("/check", async (req, res) => {
  try {
    let { domain, protocol } = req.body || {};
    if (!domain || typeof domain !== "string") {
      return res.status(400).json({ error: "domain is required" });
    }

    protocol = (protocol || "https").toLowerCase();
    if (protocol === "http") {
      return res.json({
        domain,
        protocol,
        status: "No SSL",
        message: "HTTP does not support SSL/TLS (port 80).",
      });
    }

    const port = PROTOCOL_PORTS[protocol];
    if (!port) {
      return res.status(400).json({
        error: `Unsupported protocol '${protocol}'. Supported: ${Object.keys(PROTOCOL_PORTS).join(", ")}`,
      });
    }

    domain = domain.replace(/^https?:\/\//i, "").trim();

    const certInfo = await fetchCertificate({ host: domain, port });
    return res.json({
      domain,
      protocol,
      ...certInfo,
    });
  } catch (err) {
    console.error("❌ SSL CHECK ERROR:", err);
    return res.status(500).json({
      error: err?.message || "Failed to fetch SSL/TLS certificate",
    });
  }
});

module.exports = sslRouter;
