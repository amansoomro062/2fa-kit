// Reference Node.js server for the 2fa-kit SDK.
// Plain node:http, no framework, no dependencies besides 2fa-kit itself.

import { createServer } from "node:http";
import { readFile, writeFile } from "node:fs/promises";
import {
  createVault,
  generateSecret,
  buildUri,
  verifyTotp,
  generateBackupCodes,
  sha256Hex,
} from "2fa-kit";

// --- tiny .env reader (no dotenv dep) --------------------------------------
// Real env vars win over the file. Missing lines and comments are skipped.
try {
  const text = await readFile(new URL("./.env", import.meta.url), "utf8");
  for (const line of text.split("\n")) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (m && !line.trim().startsWith("#") && process.env[m[1]] === undefined) {
      process.env[m[1]] = m[2];
    }
  }
} catch {
  // no .env file is fine; vars can come from the real environment
}

const PORT = Number(process.env.PORT || 3000);
if (!process.env.MASTER_KEY) {
  console.error("MASTER_KEY is not set. Copy .env.example to .env, or run:");
  console.error('  MASTER_KEY=$(node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))") node index.js');
  process.exit(1);
}

const vault = await createVault(process.env.MASTER_KEY);

// --- JSON file db (db.json) ------------------------------------------------
// Shape: { users: { [email]: { encrypted, salt, backupHashes: string[] } } }
const DB_FILE = new URL("./db.json", import.meta.url);

async function loadDb() {
  try {
    return JSON.parse(await readFile(DB_FILE, "utf8"));
  } catch {
    return { users: {} };
  }
}

async function saveDb(db) {
  await writeFile(DB_FILE, JSON.stringify(db, null, 2));
}

// --- naive in-memory rate limiter ------------------------------------------
// Max 5 failed verify attempts per email per 10 minutes.
const WINDOW_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;
const failures = new Map(); // email -> number[] of failure timestamps

function isRateLimited(email) {
  const now = Date.now();
  const recent = (failures.get(email) || []).filter((t) => now - t < WINDOW_MS);
  failures.set(email, recent);
  return recent.length >= MAX_FAILURES;
}

function recordFailure(email) {
  const now = Date.now();
  const recent = (failures.get(email) || []).filter((t) => now - t < WINDOW_MS);
  recent.push(now);
  failures.set(email, recent);
}

// --- request helpers --------------------------------------------------------
async function readJson(req) {
  let body = "";
  for await (const chunk of req) body += chunk;
  if (body.length > 64 * 1024) throw new Error("body too large");
  try {
    return JSON.parse(body || "{}");
  } catch {
    throw new Error("invalid JSON body");
  }
}

function send(res, status, obj) {
  const data = JSON.stringify(obj);
  res.writeHead(status, { "content-type": "application/json" });
  res.end(data);
}

// --- routes ------------------------------------------------------------------
const server = createServer(async (req, res) => {
  try {
    if (req.method !== "POST") return send(res, 404, { error: "not found" });
    const body = await readJson(req);
    const email = typeof body.email === "string" ? body.email.toLowerCase() : null;
    if (!email) return send(res, 400, { error: "email is required" });

    const db = await loadDb();

    switch (req.url) {
      case "/enrol": {
        // 2fa-kit: generateSecret -> buildUri -> vault.encrypt
        const secret = await generateSecret();
        const uri = buildUri({ label: email, secret, issuer: "2fa-kit-demo" });
        const { encrypted, salt } = await vault.encrypt(secret);
        db.users[email] = { encrypted, salt, backupHashes: [] };
        await saveDb(db);
        return send(res, 200, { uri });
      }

      case "/verify": {
        const user = db.users[email];
        if (!user) return send(res, 404, { error: "unknown user" });
        if (isRateLimited(email)) {
          return send(res, 429, { error: "too many failed attempts, try later" });
        }
        // 2fa-kit: vault.decrypt -> verifyTotp (default +/-1 step window)
        const secret = await vault.decrypt(user.encrypted, user.salt);
        const ok = await verifyTotp(secret, String(body.code ?? ""));
        if (!ok) recordFailure(email);
        return send(res, 200, { ok });
      }

      case "/backup-codes": {
        const user = db.users[email];
        if (!user) return send(res, 404, { error: "unknown user" });
        // 2fa-kit: generateBackupCodes returns raw codes + SHA-256 digests.
        // Store only the digests; the raw codes are returned to the user once.
        const { codes, hashed } = await generateBackupCodes();
        user.backupHashes = hashed;
        await saveDb(db);
        return send(res, 200, { codes });
      }

      case "/recover": {
        const user = db.users[email];
        if (!user) return send(res, 404, { error: "unknown user" });
        // 2fa-kit: sha256Hex of the presented code, compared to stored digests.
        const hash = await sha256Hex(String(body.code ?? "").toUpperCase());
        const idx = (user.backupHashes || []).indexOf(hash);
        if (idx === -1) return send(res, 200, { ok: false });
        user.backupHashes.splice(idx, 1); // single-use: delete on success
        await saveDb(db);
        return send(res, 200, { ok: true });
      }

      default:
        return send(res, 404, { error: "not found" });
    }
  } catch (err) {
    return send(res, 400, { error: err.message });
  }
});

server.listen(PORT, () => {
  console.log(`2fa-kit demo server listening on http://localhost:${PORT}`);
});
