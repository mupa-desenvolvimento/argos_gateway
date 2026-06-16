const http = require("http");
const crypto = require("crypto");
const { execSync } = require("child_process");

const PORT = parseInt(process.env.WEBHOOK_PORT || "9000", 10);
const SECRET = process.env.WEBHOOK_SECRET || "argos-deploy-2024";

const server = http.createServer((req, res) => {
  if (req.method !== "POST" || req.url !== "/deploy") {
    res.writeHead(404);
    res.end("not found");
    return;
  }

  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    // Verify GitHub signature
    const sig = req.headers["x-hub-signature-256"] || "";
    if (SECRET && sig) {
      const expected = "sha256=" + crypto.createHmac("sha256", SECRET).update(body).digest("hex");
      if (sig !== expected) {
        console.log("[webhook] Invalid signature");
        res.writeHead(403);
        res.end("forbidden");
        return;
      }
    }

    let payload;
    try {
      payload = JSON.parse(body);
    } catch (e) {
      res.writeHead(400);
      res.end("bad json");
      return;
    }

    const ref = payload.ref || "";
    if (ref !== "refs/heads/main") {
      console.log(`[webhook] Ignoring push to ${ref}`);
      res.writeHead(200);
      res.end("ignored");
      return;
    }

    console.log(`[webhook] Push to main by ${payload.pusher?.name || "unknown"} — deploying...`);
    res.writeHead(200);
    res.end("deploying");

    try {
      execSync("bash /opt/argos-remote-gateway/deploy.sh", {
        stdio: "inherit",
        timeout: 60000,
      });
      console.log("[webhook] Deploy complete");
    } catch (e) {
      console.error("[webhook] Deploy failed:", e.message);
    }
  });
});

server.listen(PORT, () => {
  console.log(`[argos-webhook] listening on :${PORT}`);
});
