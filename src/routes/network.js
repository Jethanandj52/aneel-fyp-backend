const express = require("express");
const { exec } = require("child_process");
const xml2js = require("xml2js");

const networkRouter = express.Router();

networkRouter.post("/networkApi", async (req, res) => {
    try {
        const { ip } = req.body;
        if (!ip || typeof ip !== "string") {
            return res.status(400).json({ error: "Valid IP / Range is required" });
        }

        // ✅ Full port scan (1-65535) and detect open/closed/filtered ports
        const command = `nmap -A -p- -T4 -oX - ${ip}`;

        exec(command, { maxBuffer: 1024 * 1024 * 10 }, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error: ${error.message}`);
                return res.status(500).json({ error: "Nmap scanning failed", details: error.message });
            }

            xml2js.parseString(stdout, (err, result) => {
                if (err) {
                    console.error("XML Parse Error:", err.message);
                    return res.status(500).json({ error: "Failed to parse scan results" });
                }

                try {
                    const hosts = result.nmaprun.host || [];
                    const scanResults = [];

                    hosts.forEach((host) => {
                        const addr = host.address?.[0]?.$.addr || "Unknown";
                        const status = host.status?.[0]?.$.state || "unknown";

                        // Ports as objects with state
                        const ports = [];
                        if (host.ports && host.ports[0] && host.ports[0].port) {
                            host.ports[0].port.forEach((p) => {
                                const proto = p.$.protocol;
                                const portid = p.$.portid;
                                const state = p.state?.[0]?.$.state || "-";
                                const service = p.service?.[0]?.$.name || "-";
                                const version = p.service?.[0]?.$.version || p.service?.[0]?.$.product || "-";

                                ports.push({ port: `${portid}/${proto}`, service, version, state });
                            });
                        }

                        // OS Detection
                        let os = "Unknown";
                        if (host.os && host.os[0] && host.os[0].osmatch) {
                            os = host.os[0].osmatch[0]?.$.name || "Unknown";
                        }

                        scanResults.push({
                            ip: addr,
                            status: status === "up" ? "Active" : "Inactive",
                            ports,
                            os,
                        });
                    });

                    const response = {
                        scanResults,
                        summary: {
                            totalScanned: hosts.length,
                            activeHosts: scanResults.filter((h) => h.status === "Active").length,
                            totalPorts: scanResults.reduce((acc, h) => acc + h.ports.length, 0),
                            scannedAt: new Date().toISOString(),
                        },
                    };

                    res.json(response);
                } catch (parseErr) {
                    console.error("Parsing Error:", parseErr.message);
                    res.status(500).json({ error: "Failed to process scan results" });
                }
            });
        });

    } catch (err) {
        console.error("Server Error:", err.message);
        res.status(500).json({ error: "Internal server error", details: err.message });
    }
});

module.exports = networkRouter;
