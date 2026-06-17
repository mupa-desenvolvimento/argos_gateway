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
const DATA_DIR = path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function loadView(name) { return fs.readFileSync(path.join(VIEWS_DIR, name), "utf-8"); }

const PORT = parseInt(process.env.PORT || "8080", 10);
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
const JWT_SECRET = process.env.ARGOS_REMOTE_JWT_SECRET || "argos-dev-secret-2024";
const DATABASE_URL = process.env.DATABASE_URL || "";

// ─── Data Store (JSON files) ─────────────────────────────────────────────────

function loadData(name) {
  const p = path.join(DATA_DIR, name + ".json");
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, "utf-8")); } catch { return null; }
}

function saveData(name, data) {
  fs.writeFileSync(path.join(DATA_DIR, name + ".json"), JSON.stringify(data, null, 2));
}

function hashPw(password, salt) {
  salt = salt || crypto.randomBytes(16).toString("hex");
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, "sha512").toString("hex");
  return { hash, salt };
}

function verifyPw(password, hash, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, "sha512").toString("hex") === hash;
}

// Seed master user
(function seedMaster() {
  let users = loadData("users") || [];
  const master = users.find(u => u.role === "master");
  if (!master) {
    const { hash, salt } = hashPw("#Mu040816Pa050223$");
    users.push({
      id: crypto.randomUUID(),
      email: "antunes@mupa.app",
      name: "Master",
      role: "master",
      companyId: null,
      passwordHash: hash,
      passwordSalt: salt,
      createdAt: new Date().toISOString()
    });
    saveData("users", users);
    console.log("[auth] master user seeded");
  }
  if (!loadData("companies")) saveData("companies", []);
  if (!loadData("groups")) saveData("groups", []);
})();

function esc(s) { return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }

// ─── Express Setup ───────────────────────────────────────────────────────────

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(cors({ origin: CORS_ORIGIN, credentials: true }));
app.use(express.static(path.join(__dirname, "public")));

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: CORS_ORIGIN, credentials: true },
  maxHttpBufferSize: 5 * 1024 * 1024
});

/** @type {pg.Pool | null} */
let pool = null;
if (DATABASE_URL) { pool = new pg.Pool({ connectionString: DATABASE_URL }); }

const devices = new Map();
const knownDevices = new Map();
const sessions = new Map();

function nowIso() { return new Date().toISOString(); }
function isNonEmptyString(v) { return typeof v === "string" && v.trim().length > 0; }

// ─── Cookie Auth ─────────────────────────────────────────────────────────────

function parseCookies(req) {
  const c = {};
  (req.headers.cookie || "").split(";").forEach(p => {
    const [k, ...v] = p.split("=");
    if (k) c[k.trim()] = decodeURIComponent(v.join("=").trim());
  });
  return c;
}

function webAuth(req, res, next) {
  const cookies = parseCookies(req);
  const token = cookies.argos_token;
  if (!token) return res.redirect("/login");
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.clearCookie("argos_token");
    res.redirect("/login");
  }
}

function apiAuth(req, res, next) {
  const cookies = parseCookies(req);
  const token = cookies.argos_token || ((req.headers.authorization || "").startsWith("Bearer ") ? req.headers.authorization.slice(7) : "");
  if (!token) return res.status(401).json({ error: "not_authenticated" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "invalid_token" });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user?.role)) return res.status(403).json({ error: "forbidden" });
    next();
  };
}

// ─── Auth Routes ─────────────────────────────────────────────────────────────

app.get("/login", (_req, res) => {
  const cookies = parseCookies(_req);
  if (cookies.argos_token) {
    try { jwt.verify(cookies.argos_token, JWT_SECRET); return res.redirect("/"); } catch {}
  }
  res.type("html").send(loadView("login.html"));
});

app.post("/auth/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Preencha todos os campos" });
  const users = loadData("users") || [];
  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase().trim());
  if (!user) return res.status(401).json({ error: "Credenciais inválidas" });
  if (!verifyPw(password, user.passwordHash, user.passwordSalt)) return res.status(401).json({ error: "Credenciais inválidas" });

  const token = jwt.sign({
    sub: user.id, email: user.email, name: user.name, role: user.role, companyId: user.companyId
  }, JWT_SECRET, { expiresIn: "7d" });

  res.cookie("argos_token", token, { httpOnly: true, maxAge: 7 * 24 * 3600 * 1000, sameSite: "lax" });
  res.json({ ok: true, user: { email: user.email, name: user.name, role: user.role } });
});

app.post("/auth/logout", (_req, res) => {
  res.clearCookie("argos_token");
  res.json({ ok: true });
});

app.get("/auth/me", apiAuth, (req, res) => {
  res.json({ email: req.user.email, name: req.user.name, role: req.user.role, companyId: req.user.companyId });
});

// ─── Admin API ───────────────────────────────────────────────────────────────

// Companies CRUD (master only)
app.get("/api/admin/companies", apiAuth, (req, res) => {
  const companies = loadData("companies") || [];
  if (req.user.role === "master") return res.json(companies);
  return res.json(companies.filter(c => c.id === req.user.companyId));
});

app.post("/api/admin/companies", apiAuth, requireRole("master"), (req, res) => {
  const { name } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "Nome obrigatório" });
  const companies = loadData("companies") || [];
  const company = { id: crypto.randomUUID(), name: name.trim(), createdAt: nowIso() };
  companies.push(company);
  saveData("companies", companies);
  res.json(company);
});

app.delete("/api/admin/companies/:id", apiAuth, requireRole("master"), (req, res) => {
  let companies = loadData("companies") || [];
  companies = companies.filter(c => c.id !== req.params.id);
  saveData("companies", companies);
  let users = loadData("users") || [];
  users = users.filter(u => u.companyId !== req.params.id || u.role === "master");
  saveData("users", users);
  let groups = loadData("groups") || [];
  groups = groups.filter(g => g.companyId !== req.params.id);
  saveData("groups", groups);
  res.json({ ok: true });
});

// Users CRUD (master creates any, company_admin sees own company)
app.get("/api/admin/users", apiAuth, (req, res) => {
  const users = (loadData("users") || []).map(u => ({
    id: u.id, email: u.email, name: u.name, role: u.role, companyId: u.companyId, createdAt: u.createdAt
  }));
  if (req.user.role === "master") return res.json(users);
  return res.json(users.filter(u => u.companyId === req.user.companyId));
});

app.post("/api/admin/users", apiAuth, requireRole("master"), (req, res) => {
  const { email, password, name, role, companyId } = req.body;
  if (!email?.trim() || !password || !name?.trim()) return res.status(400).json({ error: "Campos obrigatórios: email, senha, nome" });
  const validRoles = ["company_admin", "operator"];
  if (!validRoles.includes(role)) return res.status(400).json({ error: "Role inválido. Use: company_admin ou operator" });
  const users = loadData("users") || [];
  if (users.find(u => u.email.toLowerCase() === email.toLowerCase().trim())) return res.status(409).json({ error: "Email já existe" });
  const { hash, salt } = hashPw(password);
  const user = {
    id: crypto.randomUUID(), email: email.trim().toLowerCase(), name: name.trim(),
    role, companyId: companyId || null, passwordHash: hash, passwordSalt: salt, createdAt: nowIso()
  };
  users.push(user);
  saveData("users", users);
  res.json({ id: user.id, email: user.email, name: user.name, role: user.role, companyId: user.companyId });
});

app.delete("/api/admin/users/:id", apiAuth, requireRole("master"), (req, res) => {
  let users = loadData("users") || [];
  const target = users.find(u => u.id === req.params.id);
  if (target?.role === "master") return res.status(403).json({ error: "Não é possível remover o master" });
  users = users.filter(u => u.id !== req.params.id);
  saveData("users", users);
  res.json({ ok: true });
});

// Groups CRUD (company_admin manages own company, master manages all)
app.get("/api/admin/groups", apiAuth, (req, res) => {
  const groups = loadData("groups") || [];
  if (req.user.role === "master") return res.json(groups);
  return res.json(groups.filter(g => g.companyId === req.user.companyId));
});

app.post("/api/admin/groups", apiAuth, (req, res) => {
  const { name, companyId } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "Nome obrigatório" });
  const cid = req.user.role === "master" ? (companyId || null) : req.user.companyId;
  if (req.user.role === "company_admin" && !req.user.companyId) return res.status(403).json({ error: "Sem empresa vinculada" });
  const groups = loadData("groups") || [];
  const group = { id: crypto.randomUUID(), name: name.trim(), companyId: cid, deviceIds: [], createdAt: nowIso() };
  groups.push(group);
  saveData("groups", groups);
  res.json(group);
});

app.put("/api/admin/groups/:id", apiAuth, (req, res) => {
  const groups = loadData("groups") || [];
  const group = groups.find(g => g.id === req.params.id);
  if (!group) return res.status(404).json({ error: "Grupo não encontrado" });
  if (req.user.role !== "master" && group.companyId !== req.user.companyId) return res.status(403).json({ error: "forbidden" });
  if (req.body.name) group.name = req.body.name.trim();
  if (Array.isArray(req.body.deviceIds)) group.deviceIds = req.body.deviceIds;
  saveData("groups", groups);
  res.json(group);
});

app.delete("/api/admin/groups/:id", apiAuth, (req, res) => {
  let groups = loadData("groups") || [];
  const group = groups.find(g => g.id === req.params.id);
  if (!group) return res.status(404).json({ error: "Grupo não encontrado" });
  if (req.user.role !== "master" && group.companyId !== req.user.companyId) return res.status(403).json({ error: "forbidden" });
  groups = groups.filter(g => g.id !== req.params.id);
  saveData("groups", groups);
  res.json({ ok: true });
});

// ─── Web UI (protected) ─────────────────────────────────────────────────────

function devToken(user) {
  return jwt.sign({ sub: user?.sub || "web-operator", email: user?.email, role: user?.role || "operator" }, JWT_SECRET, { expiresIn: "24h" });
}

app.get("/admin", webAuth, (req, res) => {
  res.type("html").send(loadView("admin.html").replace(/\{\{USER_NAME\}\}/g, req.user.name || req.user.email).replace(/\{\{USER_ROLE\}\}/g, req.user.role));
});

function getClientIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (typeof xf === "string" && xf.length > 0) return xf.split(",")[0].trim();
  return req.socket.remoteAddress || "";
}

app.get("/", webAuth, (_req, res) => {
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
  for (const [deviceId, v] of devices.entries()) {
    const model = esc(v.device?.model || "Dispositivo");
    const mfg = esc(v.device?.manufacturer || "");
    const seen = new Date(v.lastSeenAt).toLocaleString("pt-BR");
    const alias = esc(v.device?.alias || aliasStore[deviceId] || "");
    const hwName = (mfg ? mfg + " " : "") + model;
    const displayName = alias || hwName;
    const subtitle = alias ? `${hwName} · ${deviceId}` : deviceId;
    cards.push(`<div class="device-card" onclick="openDevice('/device_id/${deviceId}')" data-status="online" data-name="${displayName} ${hwName}" data-id="${deviceId}">
      <span class="badge online">Online</span>
      <div class="top"><div class="icon">${svgDevice}</div><div><div class="name">${displayName}</div><div class="id">${subtitle}</div></div></div>
      <div class="bottom"><div class="dot on"></div>Conectado &middot; ${seen}</div>
    </div>`);
  }
  for (const [deviceId, v] of knownDevices.entries()) {
    if (onlineIds.has(deviceId)) continue;
    const model = esc(v.device?.model || "Dispositivo");
    const mfg = esc(v.device?.manufacturer || "");
    const seen = new Date(v.lastSeenAt).toLocaleString("pt-BR");
    const alias = esc(v.device?.alias || aliasStore[deviceId] || "");
    const hwName = (mfg ? mfg + " " : "") + model;
    const displayName = alias || hwName;
    const subtitle = alias ? `${hwName} · ${deviceId}` : deviceId;
    cards.push(`<div class="device-card offline" onclick="openDevice('/device_id/${deviceId}')" data-status="offline" data-name="${displayName} ${hwName}" data-id="${deviceId}">
      <span class="badge offline">Offline</span>
      <div class="top"><div class="icon">${svgDevice}</div><div><div class="name">${displayName}</div><div class="id">${subtitle}</div></div></div>
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
    .replace("{{CONTENT}}", content)
    .replace("{{USER_NAME}}", _req.user.name || _req.user.email)
    .replace("{{USER_ROLE}}", _req.user.role);
  res.type("html").send(html);
});

app.get("/device_id/:id", webAuth, (req, res) => {
  const deviceId = req.params.id;
  const token = devToken(req.user);
  const short = deviceId.length > 12 ? deviceId.slice(0, 12) + "…" : deviceId;
  const alias = aliasStore[deviceId] || devices.get(deviceId)?.device?.alias || knownDevices.get(deviceId)?.device?.alias || "";
  const entry = devices.get(deviceId) || knownDevices.get(deviceId) || {};
  const dev = entry.device || {};
  const health = entry.health || {};
  const isOnline = devices.has(deviceId);
  const healthJson = JSON.stringify({
    online: isOnline,
    accessibility_active: health.accessibility_active ?? dev.accessibility_active ?? null,
    projection_granted: health.projection_granted ?? dev.projection_granted ?? null,
    auto_consent: health.auto_consent ?? dev.auto_consent ?? null,
    version: health.version ?? dev.app_version ?? "",
    version_code: health.version_code ?? dev.app_version_code ?? 0,
    session_active: health.session_active ?? false,
    ram_avail: health.ram_avail ?? dev.ram_avail ?? null,
    ram_total: health.ram_total ?? dev.ram_total ?? null,
    manufacturer: dev.manufacturer ?? "",
    model: dev.model ?? "",
    device_family: dev.device_family ?? "",
    health_ts: health.ts ?? null,
  }).replace(/</g, "\\u003c");
  const html = loadView("device.html")
    .replace(/\{\{DEVICE_ID\}\}/g, deviceId)
    .replace(/\{\{DEVICE_ID_SHORT\}\}/g, short)
    .replace(/\{\{TOKEN\}\}/g, token)
    .replace(/\{\{DEVICE_ALIAS\}\}/g, alias)
    .replace(/\{\{HEALTH_JSON\}\}/g, healthJson);
  res.type("html").send(html);
});

app.get("/preview/:id", (req, res) => {
  const deviceId = req.params.id;
  const token = devToken({});
  const short = deviceId.length > 12 ? deviceId.slice(0, 12) + "…" : deviceId;
  const html = loadView("preview.html")
    .replace(/\{\{DEVICE_ID\}\}/g, deviceId)
    .replace(/\{\{DEVICE_ID_SHORT\}\}/g, short)
    .replace(/\{\{TOKEN\}\}/g, token);
  res.type("html").send(html);
});

app.get("/api/remote/preview/:id", (_req, res) => {
  const deviceId = _req.params.id;
  const entry = devices.get(deviceId);
  const known = knownDevices.get(deviceId);
  if (!entry && !known) return res.status(404).json({ error: "device_not_found" });
  const online = !!entry;
  const device = entry?.device || known?.device || {};
  res.json({ deviceId, online, previewUrl: `/preview/${deviceId}`, device, lastSeenAt: entry?.lastSeenAt || known?.lastSeenAt || null });
});

// Alias management
const aliasStore = loadData("aliases") || {};

function getAlias(deviceId) {
  return aliasStore[deviceId] || "";
}

function setAlias(deviceId, alias) {
  if (alias) aliasStore[deviceId] = alias.trim();
  else delete aliasStore[deviceId];
  saveData("aliases", aliasStore);
}

app.get("/api/remote/aliases", apiAuth, (_req, res) => {
  res.json(aliasStore);
});

app.put("/api/remote/alias/:id", apiAuth, (req, res) => {
  const deviceId = req.params.id;
  const alias = (req.body?.alias || "").trim().slice(0, 100);
  setAlias(deviceId, alias);
  const entry = devices.get(deviceId);
  if (entry?.device) entry.device.alias = alias;
  const known = knownDevices.get(deviceId);
  if (known?.device) known.device.alias = alias;
  res.json({ ok: true, deviceId, alias });
});

app.get("/api/remote/health/:id", apiAuth, (req, res) => {
  const deviceId = req.params.id;
  const entry = devices.get(deviceId) || knownDevices.get(deviceId);
  if (!entry) return res.status(404).json({ error: "device_not_found" });
  const health = entry.health || {};
  const device = entry.device || {};
  res.json({
    deviceId,
    online: devices.has(deviceId),
    health,
    device: {
      accessibility_active: device.accessibility_active,
      projection_granted: device.projection_granted,
      auto_consent: device.auto_consent,
      app_version: device.app_version,
      app_version_code: device.app_version_code,
      manufacturer: device.manufacturer,
      model: device.model,
      device_family: device.device_family,
    },
  });
});

app.get("/health", (_req, res) => res.json({ ok: true }));

app.get("/api/remote/devices", apiAuth, (_req, res) => {
  const list = [];
  for (const [deviceId, v] of devices.entries()) {
    list.push({ deviceId, lastSeenAt: v.lastSeenAt, connectedAt: v.connectedAt, device: v.device });
  }
  res.json({ devices: list });
});

app.post("/api/remote/sessions/start", apiAuth, async (req, res) => {
  const deviceId = req.body?.deviceId;
  const userId = req.user?.sub || req.user?.email || "unknown";
  if (!isNonEmptyString(deviceId)) return res.status(400).json({ error: "missing_deviceId" });
  const ip = getClientIp(req);
  const r = await startSession({ deviceId, userId, operatorSocketId: "__rest__", ip });
  if (!r.ok) return res.status(409).json({ error: r.error });
  res.json({ sessionId: r.sessionId });
});

app.post("/api/remote/sessions/:id/stop", apiAuth, async (req, res) => {
  const r = await stopSession({ sessionId: req.params.id, status: "ended" });
  if (!r.ok) return res.status(404).json({ error: r.error });
  res.json({ ok: true });
});

// ─── Database helpers ────────────────────────────────────────────────────────

async function dbInsertSession({ deviceId, userId, ip }) {
  if (!pool) return null;
  const q = `insert into remote_sessions (device_id, user_id, started_at, ip, status) values ($1, $2, now(), nullif($3,'')::inet, 'started') returning id`;
  const r = await pool.query(q, [deviceId, userId, ip]);
  return r.rows[0]?.id ?? null;
}

async function dbEndSession({ dbId, status }) {
  if (!pool || !dbId) return;
  await pool.query(`update remote_sessions set ended_at=now(), duration=extract(epoch from (now()-started_at))::int, status=$2 where id=$1`, [dbId, status]);
}

function getDeviceSocket(deviceId) {
  const entry = devices.get(deviceId);
  if (!entry) return null;
  return io.sockets.sockets.get(entry.socketId) || null;
}

function registerDevice(socket, hello) {
  const device = hello?.device;
  const deviceId = device?.id;
  if (!isNonEmptyString(deviceId)) return { ok: false, error: "missing_device_id" };
  devices.set(deviceId, { socketId: socket.id, device, connectedAt: Date.now(), lastSeenAt: Date.now() });
  knownDevices.set(deviceId, { device, lastSeenAt: Date.now() });
  socket.data.role = "device";
  socket.data.deviceId = deviceId;
  socket.join(`device:${deviceId}`);
  socket.emit("msg", { type: "hello_ack", ts: Date.now(), serverTime: nowIso() });
  return { ok: true, deviceId };
}

function verifyOperatorToken(token) {
  if (!isNonEmptyString(token)) return { ok: false, error: "missing_token" };
  try { return { ok: true, payload: jwt.verify(token, JWT_SECRET) }; } catch { return { ok: false, error: "invalid_token" }; }
}

async function startSession({ deviceId, userId, operatorSocketId, ip }) {
  const deviceSocket = getDeviceSocket(deviceId);
  if (!deviceSocket) return { ok: false, error: "device_offline" };
  const sessionId = crypto.randomUUID();
  const dbId = await dbInsertSession({ deviceId, userId, ip });
  sessions.set(sessionId, { deviceId, userId, operatorSocketId, startedAt: Date.now(), dbId });
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

// ─── Socket.IO ───────────────────────────────────────────────────────────────

io.on("connection", (socket) => {
  socket.on("hello", (hello) => {
    const r = registerDevice(socket, hello);
    if (!r.ok) socket.disconnect(true);
  });

  socket.on("msg", async (msg) => {
    if (typeof msg === "string") { try { msg = JSON.parse(msg); } catch { return; } }
    if (!msg || typeof msg !== "object") return;

    if (socket.data.role === "device") {
      const deviceId = socket.data.deviceId;
      const entry = devices.get(deviceId);
      if (entry) entry.lastSeenAt = Date.now();
      const type = msg.type;
      if (type === "alias_updated") {
        const known = knownDevices.get(deviceId);
        if (known?.device) known.device.alias = msg.alias;
        const entry2 = devices.get(deviceId);
        if (entry2?.device) entry2.device.alias = msg.alias;
      }
      if (type === "heartbeat" && msg.health) {
        if (entry) entry.health = { ...msg.health, ts: Date.now() };
        const known = knownDevices.get(deviceId);
        if (known) known.health = { ...msg.health, ts: Date.now() };
      }
      if (type === "device_info" && msg.device) {
        const allowed = ["model","manufacturer","android","sdk","serial","ip","mac","wifi_ssid","alias",
          "accessibility_active","projection_granted","auto_consent","app_version","app_version_code",
          "ram_total","ram_available","battery_level","battery_status","screen_width","screen_height"];
        const safe = {};
        for (const k of allowed) { if (msg.device[k] !== undefined) safe[k] = msg.device[k]; }
        if (entry) entry.device = { ...(entry.device || {}), ...safe };
        const known = knownDevices.get(deviceId);
        if (known) known.device = { ...(known.device || {}), ...safe };
      }
      if (type === "frame" || type === "screenshot" || type === "exec_result" || type === "alias_updated") {
        const sessionId = msg.sessionId;
        if (!isNonEmptyString(sessionId)) return;
        io.to(`session:${sessionId}`).emit("msg", msg);
      }
      return;
    }

    const token = socket.handshake.auth?.token || "";
    const v = verifyOperatorToken(token);
    if (!v.ok) return;
    const type = msg.type;

    if (type === "session_start") {
      const deviceId = msg.deviceId;
      const userId = v.payload?.sub || v.payload?.email || "unknown";
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
      if (!session || session.operatorSocketId !== socket.id) return;
      await stopSession({ sessionId, status: "ended" });
      socket.emit("session_stopped", { sessionId });
      return;
    }

    if (["key","text","screenshot","config","tap","long_press","swipe","scroll","app_command","exec","set_alias"].includes(type)) {
      const sessionId = msg.sessionId;
      if (!isNonEmptyString(sessionId)) return;
      const session = sessions.get(sessionId);
      if (!session || session.operatorSocketId !== socket.id) return;
      io.to(`device:${session.deviceId}`).emit("msg", msg);
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
  if (!DATABASE_URL) console.log("[argos-remote-gateway] missing DATABASE_URL (remote_sessions disabled)");
});
