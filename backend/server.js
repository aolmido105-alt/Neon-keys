
const express = require("express");
const crypto = require("node:crypto");
const { Pool } = require("pg");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(helmet());
app.use(express.json({ limit: "8kb" }));

const required = ["DATABASE_URL", "ADMIN_TOKEN", "GAME_SECRET"];
for (const name of required) {
  if (!process.env[name]) throw new Error("Missing " + name);
}

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "disable"
    ? false : { rejectUnauthorized: false }
});

app.use("/api/", rateLimit({
  windowMs: 60000,
  limit: 30
}));

function hash(key) {
  return crypto.createHash("sha256").update(key).digest("hex");
}

function matches(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function token(req) {
  const h = req.get("authorization") || "";
  return h.startsWith("Bearer ") ? h.slice(7) : "";
}

async function init() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS neon_keys (
      key_hash TEXT PRIMARY KEY,
      expires_at TIMESTAMPTZ NOT NULL,
      bound_user_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

app.get("/api/health", (req, res) => {
  res.json({ online: true, service: "NEON KEYS" });
});

app.post("/api/admin/keys", async (req, res) => {
  if (!matches(token(req), process.env.ADMIN_TOKEN)) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const hours = Number(req.body?.hours ?? 24);
  if (!Number.isInteger(hours) || hours < 1 || hours > 720) {
    return res.status(400).json({ error: "Hours must be 1-720" });
  }

  const key = "NEON-" +
    crypto.randomBytes(24).toString("hex").toUpperCase();
  const expiry = new Date(Date.now() + hours * 3600000);

  try {
    await db.query(
      "INSERT INTO neon_keys (key_hash, expires_at) VALUES ($1, $2)",
      [hash(key), expiry]
    );
    res.status(201).json({
      key,
      expiresAt: expiry.toISOString()
    });
  } catch {
    res.status(500).json({ error: "Could not create key" });
  }
});

app.post("/api/verify", async (req, res) => {
  if (!matches(token(req), process.env.GAME_SECRET)) {
    return res.status(401).json({ valid: false });
  }

  const key = req.body?.key;
  const userId = req.body?.userId;

  if (
    typeof key !== "string" ||
    !/^NEON-[A-F0-9]{48}$/.test(key) ||
    typeof userId !== "string" ||
    !/^\d{1,20}$/.test(userId)
  ) {
    return res.status(400).json({ valid: false });
  }

  const client = await db.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      `SELECT expires_at, bound_user_id
       FROM neon_keys WHERE key_hash = $1 FOR UPDATE`,
      [hash(key)]
    );

    if (result.rowCount !== 1) {
      await client.query("ROLLBACK");
      return res.json({ valid: false });
    }

    const record = result.rows[0];

    if (new Date(record.expires_at).getTime() <= Date.now()) {
      await client.query("ROLLBACK");
      return res.json({ valid: false, reason: "expired" });
    }

    if (record.bound_user_id &&
        record.bound_user_id !== userId) {
      await client.query("ROLLBACK");
      return res.json({ valid: false, reason: "already_used" });
    }

    if (!record.bound_user_id) {
      await client.query(
        "UPDATE neon_keys SET bound_user_id = $1 WHERE key_hash = $2",
        [userId, hash(key)]
      );
    }

    await client.query("COMMIT");
    res.json({ valid: true });
  } catch {
    await client.query("ROLLBACK").catch(() => {});
    res.status(500).json({ valid: false });
  } finally {
    client.release();
  }
});

app.listen(Number(process.env.PORT || 3000), "0.0.0.0", () => {
  console.log("NEON KEYS started");
});

init().catch(() => {
  console.error("Database initialization failed");
  process.exit(1);
});
