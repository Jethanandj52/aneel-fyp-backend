// networkRouter.js
const express = require("express");
const { spawn } = require("child_process");
const xml2js = require("xml2js");
const net = require("net");
const dns = require("dns").promises; // <- for reverse DNS fallback

const networkRouter = express.Router();

function isValidCIDRorIP(input) {
  if (!input || typeof input !== "string") return false;
  if (net.isIP(input)) return true;
  if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(input)) return true;
  if (/^\d{1,3}(\.\d{1,3}){3}\-\d{1,3}$/.test(input)) return true;
  return false;
}

function isPrivateIPStr(ip) {
  if (!net.isIP(ip)) return false;
  const [a, b] = ip.split(".").map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

networkRouter.post("/networkApi", async (req, res) => {
  try {
    const { ip, mode } = req.body;
    if (!ip || !isValidCIDRorIP(ip)) {
      return res.status(400).json({ error: "Valid IP or CIDR required" });
    }

    let requestedMode = mode === "full" ? "full" : "quick";
    let safeMode = requestedMode;
    let downgraded = false;

    if (requestedMode === "full" && net.isIP(ip) && !isPrivateIPStr(ip)) {
      safeMode = "quick";
      downgraded = true;
    }

    // Toggle: agar true rakho to kuch extra nmap scripts run karwa dega (NetBIOS/mDNS etc).
    // Note: scripts can be louder and slower; use only on trusted/private networks.
    const scriptsEnabled = false;

    let args = [];

    if (safeMode === "full") {
      // Full scan: aggressive flags but avoid extremely noisy flags for public IPs (we already guard above)
      // -A => OS + version + scripts, -p- => all TCP ports, -T4 => faster
      // -R/-PR kept (reverse DNS / ARP ping)
      args = ["-A", "-T4", "-p-", "-R", "-PR", ip, "-oX", "-"];
      if (scriptsEnabled) {
        // add a few safe scripts for hostname discovery / smb / mdns
        args = ["--script", "smb-os-discovery,nbstat,broadcast-mdns-discovery", ...args];
      }
    } else {
      // Quick scan: TCP SYN top ports + light version/os detection (-sV -O) + fast
      // -F uses fast mode (top ports)
      args = ["-sS", "-sV", "-O", "-T4", "-F", "-R", "-PR", ip, "-oX", "-"];
      if (scriptsEnabled) {
        args = ["--script", "nbstat,broadcast-dhcp-discover", ...args];
      }
    }

    console.log("Running:", ["nmap", ...args].join(" "));

    const nmap = spawn("nmap", args, { stdio: ["ignore", "pipe", "pipe"] });

    let xml = "";
    let errBuf = "";

    nmap.stdout.on("data", chunk => (xml += chunk.toString()));
    nmap.stderr.on("data", chunk => (errBuf += chunk.toString()));

    nmap.on("error", e => {
      console.error("nmap start error:", e);
      return res.status(500).json({ error: "Failed to start nmap", details: e.message });
    });

    nmap.on("close", async () => {
      if (!xml.trim()) {
        console.error("No XML output. Error:", errBuf);
        return res.status(500).json({ error: "No scan results. Try full mode or private network.", details: errBuf });
      }

      xml2js.parseString(xml, async (err, result) => {
        if (err) {
          console.error("XML parse error:", err);
          return res.status(500).json({ error: "Failed to parse nmap XML" });
        }

        try {
          const hosts = result?.nmaprun?.host || [];

          // Convert hosts to a preliminary structure
          const preliminary = hosts.map(h => {
            const addrIPv4 = h.address?.find(a => a.$.addrtype === "ipv4")?.$.addr || "Unknown";
            const macAddrObj = h.address?.find(a => a.$.addrtype === "mac");
            const macAddr = macAddrObj?.$.addr || "Not detected";
            const vendor = macAddrObj?.$.vendor || "Not detected";
            const hostnameFromNmap = h.hostnames?.[0]?.hostname?.[0]?.$?.name || null;

            const ports = [];
            if (h.ports?.[0]?.port) {
              h.ports[0].port.forEach(p => {
                const portid = p.$.portid;
                const proto = p.$.protocol;
                const state = p.state?.[0]?.$.state || "-";
                const service = p.service?.[0]?.$.name || "-";
                const version = (p.service && p.service[0] && (p.service[0].$.version || p.service[0].$.product)) || "-";
                ports.push({ port: `${portid}/${proto}`, service, state, version });
              });
            }

            // OS detection if present
            let os = "Not detected";
            if (h.os?.[0]?.osmatch?.length) {
              const bestOS = h.os[0].osmatch[0].$;
              os = `${bestOS.name || "Unknown"} (${bestOS.accuracy || "?"}% match)`;
            }

            const status = h.status?.[0]?.$.state === "up" ? "Active" : "Inactive";

            return {
              rawHost: h,
              ip: addrIPv4,
              mac: macAddr,
              vendor,
              hostnameFromNmap,
              hostname: hostnameFromNmap || "Not resolved",
              status,
              ports,
              os
            };
          });

          // Now try to improve hostname info using reverse DNS where missing
          const enhanced = await Promise.all(preliminary.map(async (entry) => {
            if (entry.hostname !== "Not resolved") return entry;

            // Try reverse DNS lookup
            try {
              const names = await dns.reverse(entry.ip);
              if (Array.isArray(names) && names.length > 0) {
                entry.hostname = names[0];
                return entry;
              }
            } catch (e) {
              // ignore reverse DNS errors (common on private LAN)
            }

            // If still unresolved, keep "Not resolved"
            return entry;
          }));

          // Build final scanResults (strip rawHost)
          const scanResults = enhanced.map(e => ({
            ip: e.ip,
            mac: e.mac,
            vendor: e.vendor,
            hostname: e.hostname,
            status: e.status,
            ports: e.ports,
            os: e.os
          }));

          return res.json({
            scanResults,
            summary: {
              totalScanned: hosts.length,
              activeHosts: scanResults.filter(h => h.status === "Active").length,
              scannedAt: new Date().toISOString(),
              mode: safeMode,
              requestedMode,
              downgraded
            },
          });
        } catch (parseErr) {
          console.error("Parsing Error:", parseErr);
          return res.status(500).json({ error: "Failed to process scan results", details: parseErr.message });
        }
      });
    });

  } catch (err) {
    console.error("Server error:", err);
    return res.status(500).json({ error: "Internal server error", details: err.message });
  }
});

module.exports = networkRouter;
