const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { Server } = require("socket.io");
const pg = require("pg");

const VIEWS_DIR = path.join(__dirname, "views");
function loadView(name) { return fs.readFileSync(path.join(VIEWS_DIR, name), "utf-8"); }

const PORT = parseInt(process.env.PORT || "8080", 10);
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

const JWT_SECRET = process.env.ARGOS_REMOTE_JWT_SECRET || "";
const DATABASE_URL = process.env.DATABASE_URL || "";

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(cors({ origin: CORS_ORIGIN, credentials: true }));

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: CORS_ORIGIN, credentials: true },
  maxHttpBufferSize: 5 * 1024 * 1024
});

/** @type {pg.Pool | null} */
let pool = null;
if (DATABASE_URL) {
  pool = new pg.Pool({ connectionString: DATABASE_URL });
}

/** deviceId -> { socketId, device, connectedAt, lastSeenAt } */
const devices = new Map();

/** deviceId -> { device, lastSeenAt } — persists after disconnect */
const knownDevices = new Map();

/** sessionId -> { deviceId, userId, operatorSocketId, startedAt, dbId } */
const sessions = new Map();

function nowIso() {
  return new Date().toISOString();
}

function isNonEmptyString(v) {
  return typeof v === "string" && v.trim().length > 0;
}

function getClientIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (typeof xf === "string" && xf.length > 0) return xf.split(",")[0].trim();
  return req.socket.remoteAddress || "";
}

function requireOperatorAuth(req, res, next) {
  if (!JWT_SECRET) return res.status(500).json({ error: "server_not_configured" });
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice("Bearer ".length) : "";
  if (!token) return res.status(401).json({ error: "missing_token" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    return next();
  } catch (e) {
    return res.status(401).json({ error: "invalid_token" });
  }
}

async function dbInsertSession({ deviceId, userId, ip }) {
  if (!pool) return null;
  const q = `
    insert into remote_sessions (device_id, user_id, started_at, ip, status)
    values ($1, $2, now(), nullif($3,'' )::inet, 'started')
    returning id
  `;
  const r = await pool.query(q, [deviceId, userId, ip]);
  return r.rows[0]?.id ?? null;
}

async function dbEndSession({ dbId, status }) {
  if (!pool || !dbId) return;
  const q = `
    update remote_sessions
    set ended_at = now(),
        duration = extract(epoch from (now() - started_at))::int,
        status = $2
    where id = $1
  `;
  await pool.query(q, [dbId, status]);
}

function getDeviceSocket(deviceId) {
  const entry = devices.get(deviceId);
  if (!entry) return null;
  const s = io.sockets.sockets.get(entry.socketId);
  return s || null;
}

function registerDevice(socket, hello) {
  const device = hello?.device;
  const deviceId = device?.id;
  if (!isNonEmptyString(deviceId)) return { ok: false, error: "missing_device_id" };

  devices.set(deviceId, {
    socketId: socket.id,
    device,
    connectedAt: Date.now(),
    lastSeenAt: Date.now()
  });

  knownDevices.set(deviceId, { device, lastSeenAt: Date.now() });

  socket.data.role = "device";
  socket.data.deviceId = deviceId;
  socket.join(`device:${deviceId}`);

  socket.emit("msg", {
    type: "hello_ack",
    ts: Date.now(),
    serverTime: nowIso()
  });

  return { ok: true, deviceId };
}

function verifyOperatorToken(token) {
  if (!JWT_SECRET) return { ok: false, error: "server_not_configured" };
  if (!isNonEmptyString(token)) return { ok: false, error: "missing_token" };
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return { ok: true, payload };
  } catch (e) {
    return { ok: false, error: "invalid_token" };
  }
}

function createSessionId() {
  return crypto.randomUUID();
}

async function startSession({ deviceId, userId, operatorSocketId, ip }) {
  const deviceSocket = getDeviceSocket(deviceId);
  if (!deviceSocket) return { ok: false, error: "device_offline" };

  const sessionId = createSessionId();
  const dbId = await dbInsertSession({ deviceId, userId, ip });
  sessions.set(sessionId, {
    deviceId,
    userId,
    operatorSocketId,
    startedAt: Date.now(),
    dbId
  });

  const operatorSocket = io.sockets.sockets.get(operatorSocketId);
  if (operatorSocket) operatorSocket.join(`session:${sessionId}`);

  io.to(`device:${deviceId}`).emit("msg", { type: "session_start", sessionId, userId });
  return { ok: true, sessionId };
}

async function stopSession({ sessionId, status }) {
  const session = sessions.get(sessionId);
  if (!session) return { ok: false, error: "session_not_found" };
  sessions.delete(sessionId);
  await dbEndSession({ dbId: session.dbId, status: status || "ended" });
  io.to(`device:${session.deviceId}`).emit("msg", { type: "session_stop", sessionId });
  return { ok: true };
}

// ─── Web UI ───────────────────────────────────────────────────────────────────

function devToken() {
  if (!JWT_SECRET) return "";
  return jwt.sign({ sub: "web-operator", role: "operator" }, JWT_SECRET, { expiresIn: "24h" });
}

app.get("/", (_req, res) => {
  const svgDevice = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12" y2="18.01"/></svg>`;
  const onlineIds = new Set(devices.keys());
  const allIds = new Set([...devices.keys(), ...knownDevices.keys()]);
  const onlineCount = onlineIds.size;
  const offlineCount = allIds.size - onlineCount;

  const stats = `<div class="stats">
    <div class="stat total"><div class="num">${allIds.size}</div><div class="label">Total</div></div>
    <div class="stat online"><div class="num">${onlineCount}</div><div class="label">Online</div></div>
    <div class="stat offline"><div class="num">${offlineCount}</div><div class="label">Offline</div></div>
  </div>`;

  const cards = [];
  // Online devices first
  for (const [deviceId, v] of devices.entries()) {
    const model = v.device?.model || "Dispositivo";
    const mfg = v.device?.manufacturer || "";
    const seen = new Date(v.lastSeenAt).toLocaleString("pt-BR");
    const displayName = (mfg ? mfg + " " : "") + model;
    cards.push(`<div class="device-card" onclick="openDevice('/device_id/${deviceId}')" data-status="online" data-name="${displayName}" data-id="${deviceId}">
      <span class="badge online">Online</span>
      <div class="top"><div class="icon">${svgDevice}</div><div><div class="name">${displayName}</div><div class="id">${deviceId}</div></div></div>
      <div class="bottom"><div class="dot on"></div>Conectado &middot; ${seen}</div>
    </div>`);
  }
  // Offline (known but not connected)
  for (const [deviceId, v] of knownDevices.entries()) {
    if (onlineIds.has(deviceId)) continue;
    const model = v.device?.model || "Dispositivo";
    const mfg = v.device?.manufacturer || "";
    const seen = new Date(v.lastSeenAt).toLocaleString("pt-BR");
    const displayName = (mfg ? mfg + " " : "") + model;
    cards.push(`<div class="device-card offline" onclick="openDevice('/device_id/${deviceId}')" data-status="offline" data-name="${displayName}" data-id="${deviceId}">
      <span class="badge offline">Offline</span>
      <div class="top"><div class="icon">${svgDevice}</div><div><div class="name">${displayName}</div><div class="id">${deviceId}</div></div></div>
      <div class="bottom"><div class="dot off"></div>Última vez &middot; ${seen}</div>
    </div>`);
  }

  const content = cards.length > 0
    ? `<div class="device-grid">${cards.join("")}</div>`
    : `<div class="empty">
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">${svgDevice}</svg>
        <div class="msg">Nenhum dispositivo registrado</div>
        <div class="sub">Instale o ARGOS Remote APK e aponte para este gateway</div>
      </div>`;

  const html = loadView("index.html")
    .replace("{{STATS}}", stats)
    .replace("{{CONTENT}}", content);
  res.type("html").send(html);
});

app.get("/device_id/:id", (req, res) => {
  const deviceId = req.params.id;
  const token = devToken();
  const short = deviceId.length > 12 ? deviceId.slice(0, 12) + "…" : deviceId;
  const html = loadView("device.html")
    .replace(/\{\{DEVICE_ID\}\}/g, deviceId)
    .replace(/\{\{DEVICE_ID_SHORT\}\}/g, short)
    .replace(/\{\{TOKEN\}\}/g, token);
  res.type("html").send(html);
});

app.get("/health", (_req, res) => res.json({ ok: true }));

app.get("/api/remote/devices", requireOperatorAuth, (_req, res) => {
  const list = [];
  for (const [deviceId, v] of devices.entries()) {
    list.push({
      deviceId,
      lastSeenAt: v.lastSeenAt,
      connectedAt: v.connectedAt,
      device: v.device
    });
  }
  res.json({ devices: list });
});

app.post("/api/remote/sessions/start", requireOperatorAuth, async (req, res) => {
  const deviceId = req.body?.deviceId;
  const userId = req.user?.sub || req.user?.user_id || req.user?.id || "unknown";
  if (!isNonEmptyString(deviceId)) return res.status(400).json({ error: "missing_deviceId" });

  const ip = getClientIp(req);
  const r = await startSession({ deviceId, userId, operatorSocketId: "__rest__", ip });
  if (!r.ok) return res.status(409).json({ error: r.error });
  res.json({ sessionId: r.sessionId });
});

app.post("/api/remote/sessions/:id/stop", requireOperatorAuth, async (req, res) => {
  const r = await stopSession({ sessionId: req.params.id, status: "ended" });
  if (!r.ok) return res.status(404).json({ error: r.error });
  res.json({ ok: true });
});

io.on("connection", (socket) => {
  socket.on("hello", (hello) => {
    const r = registerDevice(socket, hello);
    if (!r.ok) socket.disconnect(true);
  });

  socket.on("msg", async (msg) => {
    if (typeof msg === "string") {
      try {
        msg = JSON.parse(msg);
      } catch (e) {
        return;
      }
    }
    if (!msg || typeof msg !== "object") return;

    if (socket.data.role === "device") {
      const deviceId = socket.data.deviceId;
      const entry = devices.get(deviceId);
      if (entry) entry.lastSeenAt = Date.now();

      const type = msg.type;
      if (type === "frame" || type === "screenshot") {
        const sessionId = msg.sessionId;
        if (!isNonEmptyString(sessionId)) return;
        io.to(`session:${sessionId}`).emit("msg", msg);
        return;
      }

      if (type === "device_info" || type === "heartbeat" || type === "ping") {
        return;
      }

      return;
    }

    const token = socket.handshake.auth?.token || "";
    const v = verifyOperatorToken(token);
    if (!v.ok) return;

    const type = msg.type;
    if (type === "session_start") {
      const deviceId = msg.deviceId;
      const userId = v.payload?.sub || v.payload?.user_id || v.payload?.id || "unknown";
      if (!isNonEmptyString(deviceId)) return;
      const ip = socket.handshake.address || "";
      const r = await startSession({ deviceId, userId, operatorSocketId: socket.id, ip });
      if (r.ok) socket.emit("session_started", { sessionId: r.sessionId, deviceId });
      else socket.emit("session_error", { error: r.error });
      return;
    }

    if (type === "session_stop") {
      const sessionId = msg.sessionId;
      if (!isNonEmptyString(sessionId)) return;
      const session = sessions.get(sessionId);
      if (!session) return;
      if (session.operatorSocketId !== socket.id) return;
      await stopSession({ sessionId, status: "ended" });
      socket.emit("session_stopped", { sessionId });
      return;
    }

    if (type === "key" || type === "text" || type === "screenshot" || type === "config" || type === "tap" || type === "long_press" || type === "swipe" || type === "scroll" || type === "app_command") {
      const sessionId = msg.sessionId;
      if (!isNonEmptyString(sessionId)) return;
      const session = sessions.get(sessionId);
      if (!session) return;
      if (session.operatorSocketId !== socket.id) return;
      io.to(`device:${session.deviceId}`).emit("msg", msg);
      return;
    }
  });

  socket.on("disconnect", async () => {
    if (socket.data.role === "device" && socket.data.deviceId) {
      const deviceId = socket.data.deviceId;
      const entry = devices.get(deviceId);
      if (entry?.socketId === socket.id) devices.delete(deviceId);

      for (const [sessionId, session] of sessions.entries()) {
        if (session.deviceId === deviceId) {
          sessions.delete(sessionId);
          await dbEndSession({ dbId: session.dbId, status: "device_disconnected" });
          io.to(`session:${sessionId}`).emit("msg", { type: "session_stop", sessionId });
        }
      }
      return;
    }

    for (const [sessionId, session] of sessions.entries()) {
      if (session.operatorSocketId === socket.id) {
        sessions.delete(sessionId);
        await dbEndSession({ dbId: session.dbId, status: "operator_disconnected" });
        io.to(`device:${session.deviceId}`).emit("msg", { type: "session_stop", sessionId });
      }
    }
  });
});

server.listen(PORT, () => {
  console.log(`[argos-remote-gateway] listening on :${PORT}`);
  if (!JWT_SECRET) console.log("[argos-remote-gateway] missing ARGOS_REMOTE_JWT_SECRET (operators will be rejected)");
  if (!DATABASE_URL) console.log("[argos-remote-gateway] missing DATABASE_URL (remote_sessions disabled)");
});

