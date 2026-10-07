// Snip v3 — private-by-default pastebin with accounts. Production-ready.
// Zero dependencies. Requires Node 22+.
// One process serves the frontend + JSON API + raw text output.
// Data: single SQLite file (snip.db), auto-created + migrated on boot.
//
// Privacy model:
//   - Every paste belongs to an account's private space (or a guest link).
//   - visibility = 'private'  → only the owner can open it.
//   - visibility = 'unlisted' → anyone with the link can open it.
//   - There is NO public listing. Nobody can discover another user's pastes.

const http = require('node:http');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const VERSION = '5.0.0';
const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'snip.db');
const PUBLIC = path.join(__dirname, 'public');
const MAX_CONTENT = 512 * 1024;   // max paste size, in characters
const MAX_BODY = 1024 * 1024;     // max request body, in bytes
const GUEST_MAX_AGE = 7 * 86400 * 1000; // guest pastes auto-delete after 7 days
const SESSION_AGE = 30 * 86400 * 1000;  // login sessions last 30 days
// CDN purge-on-update (optional, env-gated — no-ops when unset):
// When an unlisted paste changes, Snip tells Cloudflare to drop the cached
// /raw/:id copy so the next request gets the fresh version within seconds.
const CF_API_TOKEN = process.env.CF_API_TOKEN || '';
const CF_ZONE_ID = process.env.CF_ZONE_ID || '';
const CF_PURGE_PREFIX = (process.env.CF_PURGE_PREFIX || '').replace(/\/+$/, ''); // e.g. https://cfg.nctti.tech

// ---------------------------------------------------------------- database
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA busy_timeout = 5000');
db.exec(`CREATE TABLE IF NOT EXISTS pastes (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL DEFAULT '',
  content TEXT NOT NULL,
  syntax TEXT NOT NULL DEFAULT 'plaintext',
  visibility TEXT NOT NULL DEFAULT 'private',
  created_at INTEGER NOT NULL,
  updated_at INTEGER,
  expires_at INTEGER,
  views INTEGER NOT NULL DEFAULT 0,
  user_id TEXT
)`);
db.exec(`CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  pw TEXT NOT NULL,
  created_at INTEGER NOT NULL
)`);
db.exec(`CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
)`);
// migrations (v1 → v2 → v3), idempotent
{
  const cols = db.prepare(`PRAGMA table_info(pastes)`).all().map((c) => c.name);
  if (!cols.includes('user_id')) db.exec(`ALTER TABLE pastes ADD COLUMN user_id TEXT`);
  if (!cols.includes('updated_at')) db.exec(`ALTER TABLE pastes ADD COLUMN updated_at INTEGER`);
  db.exec(`UPDATE pastes SET updated_at = created_at WHERE updated_at IS NULL`);
  // v3: no public listing anymore — old public pastes become link-only
  db.exec(`UPDATE pastes SET visibility = 'unlisted' WHERE visibility = 'public'`);
  db.exec(`UPDATE pastes SET visibility = 'unlisted' WHERE user_id IS NULL AND visibility <> 'unlisted'`);
}
db.exec(`CREATE INDEX IF NOT EXISTS idx_pastes_user ON pastes (user_id, updated_at DESC)`);

const SYNTAXES = new Set([
  'plaintext','bash','javascript','typescript','python','java','c','cpp',
  'csharp','go','rust','php','ruby','html','css','json','yaml','sql',
  'markdown','diff',
]);
const EXPIRY_OPTIONS = new Set([600, 3600, 86400, 604800]); // 10m 1h 1d 1w
const VISIBILITIES = new Set(['private', 'unlisted']);

// ------------------------------------------------------------------ auth
function hashPassword(pw) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16);
    crypto.scrypt(pw, salt, 64, (err, dk) => {
      if (err) return reject(err);
      resolve(`scrypt$${salt.toString('hex')}$${dk.toString('hex')}`);
    });
  });
}
function verifyPassword(pw, stored) {
  return new Promise((resolve, reject) => {
    const parts = String(stored).split('$');
    if (parts.length !== 3 || parts[0] !== 'scrypt') return resolve(false);
    const salt = Buffer.from(parts[1], 'hex');
    const expected = Buffer.from(parts[2], 'hex');
    crypto.scrypt(pw, salt, 64, (err, dk) => {
      if (err) return reject(err);
      resolve(dk.length === expected.length && crypto.timingSafeEqual(dk, expected));
    });
  });
}
function parseCookies(req) {
  const out = {};
  const h = req.headers.cookie;
  if (!h) return out;
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
const sessionStmt = db.prepare(
  `SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id
   WHERE s.token = ? AND s.expires_at > ?`
);
function authUser(req) {
  const tok = parseCookies(req).snip_session;
  if (!tok || !/^[a-f0-9]{64}$/.test(tok)) return null;
  const digest = crypto.createHash('sha256').update(tok).digest('hex');
  return sessionStmt.get(digest, Date.now()) || null;
}
function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const digest = crypto.createHash('sha256').update(token).digest('hex');
  const now = Date.now();
  db.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .run(digest, userId, now, now + SESSION_AGE);
  return token;
}
function destroySession(req) {
  const tok = parseCookies(req).snip_session;
  if (tok && /^[a-f0-9]{64}$/.test(tok)) {
    db.prepare('DELETE FROM sessions WHERE token = ?')
      .run(crypto.createHash('sha256').update(tok).digest('hex'));
  }
}
function sessionCookieHeaders(req, token) {
  const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  const value = token === null
    ? `snip_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0${secure}`
    : `snip_session=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${SESSION_AGE / 1000}${secure}`;
  return { 'Set-Cookie': value };
}

// ------------------------------------------------------------------ pastes
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
function genId(n = 7) {
  const buf = crypto.randomBytes(n);
  let s = '';
  for (const b of buf) s += ALPHABET[b % 62];
  return s;
}
const insertStmt = db.prepare(
  `INSERT INTO pastes (id, title, content, syntax, visibility, created_at, updated_at, expires_at, user_id)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
);
function createPaste({ title, content, syntax, visibility, expiresIn, userId }) {
  const now = Date.now();
  let expiresAt = expiresIn ? now + expiresIn * 1000 : null;
  if (!userId) {
    // guests: link-only + auto-delete after 7 days no matter what
    visibility = 'unlisted';
    const cap = now + GUEST_MAX_AGE;
    expiresAt = expiresAt ? Math.min(expiresAt, cap) : cap;
  }
  for (let i = 0; i < 5; i++) {
    const id = genId();
    try {
      insertStmt.run(id, title, content, syntax, visibility, now, now, expiresAt, userId || null);
      return { id, expiresAt };
    } catch (e) {
      if (!/UNIQUE|PRIMARY/i.test(String(e && e.message))) throw e;
    }
  }
  throw new Error('id generation failed');
}
const getStmt = db.prepare('SELECT * FROM pastes WHERE id = ?');
const delStmt = db.prepare('DELETE FROM pastes WHERE id = ?');
// View counts are batched in memory and flushed to SQLite every 10s — one
// flood-era UPDATE per paste per view would serialize all writes on the DB.
const pendingViews = new Map(); // id -> increments since last flush
function bumpViews(id) { pendingViews.set(id, (pendingViews.get(id) || 0) + 1); }
function flushViews() {
  if (!pendingViews.size) return;
  const batch = [...pendingViews];
  pendingViews.clear();
  const stmt = db.prepare('UPDATE pastes SET views = views + ? WHERE id = ?');
  for (const [id, n] of batch) {
    try { stmt.run(n, id); } catch (e) { console.error('view flush failed for', id, e.message); }
  }
}
setInterval(flushViews, 10 * 1000).unref();
function getPaste(id) {
  const row = getStmt.get(id);
  if (!row) return null;
  if (row.expires_at && row.expires_at < Date.now()) {
    delStmt.run(id); // lazy expiry
    return null;
  }
  return row;
}
// Privacy gate: private → owner only; unlisted → anyone with the link.
function canView(row, user) {
  if (user && row.user_id && row.user_id === user.id) return true;
  return row.visibility === 'unlisted';
}
function publicPaste(row, user) {
  return {
    id: row.id, title: row.title, content: row.content, syntax: row.syntax,
    visibility: row.visibility, created_at: row.created_at, updated_at: row.updated_at,
    expires_at: row.expires_at, views: row.views,
    mine: !!(user && row.user_id && row.user_id === user.id),
  };
}

// sweeps: expired pastes + stale sessions
function cleanup() {
  const now = Date.now();
  db.prepare('DELETE FROM pastes WHERE expires_at IS NOT NULL AND expires_at < ?').run(now);
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
}
cleanup();
setInterval(cleanup, 60 * 60 * 1000).unref();

// ------------------------------------------------------------- rate limit
const hits = new Map(); // key -> timestamps[]
function limited(key, max, windowMs) {
  const now = Date.now();
  let arr = (hits.get(key) || []).filter((t) => now - t < windowMs);
  if (arr.length >= max) return true;
  arr.push(now);
  hits.set(key, arr);
  return false;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, arr] of hits) {
    const f = arr.filter((t) => now - t < 10 * 60 * 1000);
    if (f.length) hits.set(k, f); else hits.delete(k);
  }
}, 10 * 60 * 1000).unref();

// ---------------------------------------------------------------- helpers
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
};
const CSP = "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; " +
  "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src https://fonts.gstatic.com; " +
  "img-src 'self' data:; connect-src 'self'";
const COMPRESSIBLE = /^(text\/|application\/(json|javascript))|svg\+xml/;
function send(res, status, body, type = 'text/plain; charset=utf-8', extra = {}) {
  let buf = Buffer.isBuffer(body) ? body : Buffer.from(body);
  const headers = {
    'Content-Type': type,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  };
  if (type.startsWith('text/html')) headers['Content-Security-Policy'] = CSP;
  // gzip: browsers/CDNs ask for it; ~70-80% smaller text payloads, near-zero CPU
  const ae = String((res.req && res.req.headers && res.req.headers['accept-encoding']) || '');
  if (COMPRESSIBLE.test(type) && buf.length >= 1024 && /\bgzip\b/.test(ae)) {
    buf = zlib.gzipSync(buf);
    headers['Content-Encoding'] = 'gzip';
    headers['Vary'] = 'Accept-Encoding';
  }
  headers['Content-Length'] = buf.length;
  res.writeHead(status, Object.assign(headers, extra));
  res.end(buf);
}
const sendJSON = (res, status, obj, extra) =>
  send(res, status, JSON.stringify(obj), 'application/json; charset=utf-8', extra);

// Purge the CDN-cached /raw/:id copy after an unlisted paste changes.
// Env-gated: silently skips when CF_API_TOKEN/CF_ZONE_ID/CF_PURGE_PREFIX
// are unset (e.g. local dev, or no CDN in front yet). Fire-and-forget — a
// purge failure must never break the API response.
function purgeRawCache(id) {
  if (!CF_API_TOKEN || !CF_ZONE_ID || !CF_PURGE_PREFIX) return;
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 8000);
  fetch(`https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/purge_cache`, {
    method: 'POST',
    signal: ctl.signal,
    headers: { 'Authorization': `Bearer ${CF_API_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ files: [`${CF_PURGE_PREFIX}/raw/${id}`] }),
  }).then(async (r) => {
    clearTimeout(t);
    if (!r.ok) console.error(`[purge] CF purge failed for ${id}: HTTP ${r.status}`);
  }).catch((e) => {
    clearTimeout(t);
    console.error(`[purge] CF purge error for ${id}: ${e.message || e}`);
  });
}

function serveFile(res, filePath, extra = {}) {
  const safe = path.normalize(filePath);
  if (!safe.startsWith(PUBLIC + path.sep) && safe !== PUBLIC) return send(res, 403, 'forbidden');
  fs.readFile(safe, (err, data) => {
    if (err) return send(res, 404, 'not found');
    // index.html = SPA shell, always revalidate so deploys reach users instantly;
    // other static files: cache 1h, serve stale up to 1d while revalidating.
    const cc = path.basename(safe) === 'index.html'
      ? 'no-cache'
      : 'public, max-age=3600, stale-while-revalidate=86400';
    send(res, 200, data, MIME[path.extname(safe).toLowerCase()] || 'application/octet-stream',
      Object.assign({ 'Cache-Control': cc }, extra));
  });
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
function validUsername(u) { return typeof u === 'string' && /^[A-Za-z0-9_]{3,20}$/.test(u); }
function pasteInput(data, forUpdate) {
  const out = {};
  if (data.title !== undefined || !forUpdate)
    out.title = typeof data.title === 'string' ? data.title.trim().slice(0, 120) : '';
  if (data.content !== undefined || !forUpdate) {
    const c = typeof data.content === 'string' ? data.content : '';
    if (!c.trim()) return { error: 'Content is empty.' };
    if (c.length > MAX_CONTENT) return { error: 'Paste is too large (max 512 KB).' };
    out.content = c;
  }
  if (data.syntax !== undefined || !forUpdate)
    out.syntax = SYNTAXES.has(data.syntax) ? data.syntax : 'plaintext';
  if (data.visibility !== undefined || !forUpdate)
    out.visibility = VISIBILITIES.has(data.visibility) ? data.visibility : 'private';
  if (data.expires_in !== undefined || !forUpdate)
    out.expiresIn = data.expires_in === null ? null
      : EXPIRY_OPTIONS.has(data.expires_in) ? data.expires_in : null;
  return out;
}

// ---------------------------------------------------------------- routes
const server = http.createServer(async (req, res) => {
  const t0 = Date.now();
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  const method = req.method;
  const ip = req.socket.remoteAddress || 'unknown';
  res.on('finish', () => {
    if (process.env.LOG_REQUESTS)
      console.log(new Date().toISOString(), method, p, res.statusCode, Date.now() - t0 + 'ms');
  });

  try {
    // ---------------- health ----------------
    if (method === 'GET' && p === '/api/health') {
      return sendJSON(res, 200, { ok: true, version: VERSION, time: Date.now() });
    }

    // ---------------- auth ----------------
    if (method === 'POST' && p === '/api/auth/signup') {
      if (limited('auth:' + ip, 10, 10 * 60 * 1000))
        return sendJSON(res, 429, { error: 'Too many attempts. Try again later.' });
      let data;
      try { data = JSON.parse(await readBody(req)); }
      catch { return sendJSON(res, 400, { error: 'Invalid JSON body.' }); }
      const username = typeof data.username === 'string' ? data.username.trim() : '';
      const password = typeof data.password === 'string' ? data.password : '';
      if (!validUsername(username))
        return sendJSON(res, 400, { error: 'Username must be 3–20 characters: letters, numbers, underscore.' });
      if (password.length < 8)
        return sendJSON(res, 400, { error: 'Password must be at least 8 characters.' });
      if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username))
        return sendJSON(res, 409, { error: 'Username is taken.' });
      const id = genId(12);
      const pw = await hashPassword(password);
      db.prepare('INSERT INTO users (id, username, pw, created_at) VALUES (?, ?, ?, ?)')
        .run(id, username, pw, Date.now());
      const token = createSession(id);
      return sendJSON(res, 201, { username }, sessionCookieHeaders(req, token));
    }

    if (method === 'POST' && p === '/api/auth/login') {
      if (limited('auth:' + ip, 10, 10 * 60 * 1000))
        return sendJSON(res, 429, { error: 'Too many attempts. Try again later.' });
      let data;
      try { data = JSON.parse(await readBody(req)); }
      catch { return sendJSON(res, 400, { error: 'Invalid JSON body.' }); }
      const username = typeof data.username === 'string' ? data.username.trim() : '';
      const password = typeof data.password === 'string' ? data.password : '';
      const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
      const ok = user && await verifyPassword(password, user.pw);
      if (!ok) return sendJSON(res, 401, { error: 'Invalid username or password.' });
      const token = createSession(user.id);
      return sendJSON(res, 200, { username: user.username }, sessionCookieHeaders(req, token));
    }

    if (method === 'POST' && p === '/api/auth/logout') {
      destroySession(req);
      return sendJSON(res, 200, { ok: true }, sessionCookieHeaders(req, null));
    }

    if (method === 'GET' && p === '/api/auth/me') {
      const u = authUser(req);
      return u ? sendJSON(res, 200, { username: u.username })
               : sendJSON(res, 401, { error: 'Not logged in.' });
    }

    if (method === 'POST' && p === '/api/auth/change-password') {
      const user = authUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Not logged in.' });
      let data;
      try { data = JSON.parse(await readBody(req)); }
      catch { return sendJSON(res, 400, { error: 'Invalid JSON body.' }); }
      const current = typeof data.current === 'string' ? data.current : '';
      const next = typeof data.new === 'string' ? data.new : '';
      if (next.length < 8)
        return sendJSON(res, 400, { error: 'New password must be at least 8 characters.' });
      const row = db.prepare('SELECT pw FROM users WHERE id = ?').get(user.id);
      if (!row || !(await verifyPassword(current, row.pw)))
        return sendJSON(res, 401, { error: 'Current password is incorrect.' });
      db.prepare('UPDATE users SET pw = ? WHERE id = ?').run(await hashPassword(next), user.id);
      db.prepare('DELETE FROM sessions WHERE user_id = ? AND token <> ?')
        .run(user.id, crypto.createHash('sha256')
          .update(parseCookies(req).snip_session || '').digest('hex'));
      return sendJSON(res, 200, { ok: true });
    }

    if (method === 'DELETE' && p === '/api/auth/account') {
      const user = authUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Not logged in.' });
      let data;
      try { data = JSON.parse(await readBody(req)); }
      catch { return sendJSON(res, 400, { error: 'Invalid JSON body.' }); }
      const password = typeof data.password === 'string' ? data.password : '';
      const row = db.prepare('SELECT pw FROM users WHERE id = ?').get(user.id);
      if (!row || !(await verifyPassword(password, row.pw)))
        return sendJSON(res, 401, { error: 'Password is incorrect.' });
      db.prepare('DELETE FROM pastes WHERE user_id = ?').run(user.id);
      db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
      db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
      return sendJSON(res, 200, { ok: true }, sessionCookieHeaders(req, null));
    }

    if (method === 'GET' && p === '/api/export') {
      const user = authUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Not logged in.' });
      const rows = db.prepare(
        `SELECT id, title, content, syntax, visibility, created_at, updated_at, expires_at, views
         FROM pastes WHERE user_id = ? ORDER BY created_at`
      ).all(user.id);
      return send(res, 200,
        JSON.stringify({ exported_at: Date.now(), username: user.username, pastes: rows }, null, 2),
        'application/json; charset=utf-8',
        { 'Content-Disposition': 'attachment; filename="snip-export.json"' });
    }

    // ---------------- pastes ----------------
    if (method === 'POST' && p === '/api/paste') {
      if (limited('paste:' + ip, 20, 10 * 60 * 1000))
        return sendJSON(res, 429, { error: 'Too many pastes. Try again in a few minutes.' });
      let data;
      try { data = JSON.parse(await readBody(req)); }
      catch { return sendJSON(res, 400, { error: 'Invalid JSON body.' }); }
      const input = pasteInput(data, false);
      if (input.error) return sendJSON(res, input.error.includes('large') ? 413 : 400, { error: input.error });
      const user = authUser(req);
      const { id, expiresAt } = createPaste({
        title: input.title, content: input.content, syntax: input.syntax,
        visibility: input.visibility, expiresIn: input.expiresIn,
        userId: user ? user.id : null,
      });
      if (input.visibility === 'unlisted') purgeRawCache(id); // fresh paste → drop any stale CDN copy
      return sendJSON(res, 201, {
        id, url: '/' + id, raw_url: '/raw/' + id,
        expires_at: expiresAt, guest: !user,
      });
    }

    if (method === 'GET' && p.startsWith('/api/paste/')) {
      const id = p.slice('/api/paste/'.length);
      if (!/^[A-Za-z0-9]{7}$/.test(id)) return sendJSON(res, 404, { error: 'Paste not found.' });
      const user = authUser(req);
      const row = getPaste(id);
      if (!row || !canView(row, user))
        return sendJSON(res, 404, { error: 'Paste not found or expired.' });
      bumpViews(id); // batched — DB flush every 10s, no per-view write lock
      const out = publicPaste(row, user);
      out.views = row.views + (pendingViews.get(id) || 0);
      // private pastes: never cached. unlisted: 60s cache + stale-while-revalidate.
      const cc = row.visibility === 'unlisted'
        ? 'public, max-age=60, stale-while-revalidate=300'
        : 'no-store';
      return sendJSON(res, 200, out, { 'Cache-Control': cc });
    }

    if (method === 'PUT' && p.startsWith('/api/paste/')) {
      const user = authUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Log in to edit pastes.' });
      const id = p.slice('/api/paste/'.length);
      if (!/^[A-Za-z0-9]{7}$/.test(id)) return sendJSON(res, 404, { error: 'Paste not found.' });
      const row = getPaste(id);
      if (!row || row.user_id !== user.id)
        return sendJSON(res, 404, { error: 'Paste not found.' });
      let data;
      try { data = JSON.parse(await readBody(req)); }
      catch { return sendJSON(res, 400, { error: 'Invalid JSON body.' }); }
      const input = pasteInput(data, true);
      if (input.error) return sendJSON(res, input.error.includes('large') ? 413 : 400, { error: input.error });
      const now = Date.now();
      const patch = {
        title: input.title !== undefined ? input.title : row.title,
        content: input.content !== undefined ? input.content : row.content,
        syntax: input.syntax !== undefined ? input.syntax : row.syntax,
        visibility: input.visibility !== undefined ? input.visibility : row.visibility,
        expires_at: input.expiresIn !== undefined
          ? (input.expiresIn ? now + input.expiresIn * 1000 : null) : row.expires_at,
      };
      db.prepare(`UPDATE pastes SET title=?, content=?, syntax=?, visibility=?, expires_at=?, updated_at=?
                  WHERE id=?`)
        .run(patch.title, patch.content, patch.syntax, patch.visibility, patch.expires_at, now, id);
      // purge when the paste was or still is unlisted: edits go out in seconds,
      // and a paste flipped to private must not linger in the CDN cache.
      if (row.visibility === 'unlisted' || patch.visibility === 'unlisted') purgeRawCache(id);
      return sendJSON(res, 200, { ok: true, id });
    }

    if (method === 'DELETE' && p.startsWith('/api/paste/')) {
      const user = authUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Log in to delete pastes.' });
      const id = p.slice('/api/paste/'.length);
      if (!/^[A-Za-z0-9]{7}$/.test(id)) return sendJSON(res, 404, { error: 'Paste not found.' });
      const row = getPaste(id);
      if (!row || row.user_id !== user.id)
        return sendJSON(res, 404, { error: 'Paste not found.' });
      const wasUnlisted = row.visibility === 'unlisted';
      delStmt.run(id);
      if (wasUnlisted) purgeRawCache(id); // deleted → don't let the CDN keep serving it
      return sendJSON(res, 200, { ok: true });
    }

    if (method === 'GET' && p === '/api/my') {
      const user = authUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Log in to see your pastes.' });
      const q = (url.searchParams.get('q') || '').trim().slice(0, 60).replace(/[%_]/g, '');
      const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 1), 100);
      const offset = Math.max(parseInt(url.searchParams.get('offset') || '0', 10) || 0, 0);
      const like = `%${q}%`;
      const rows = db.prepare(
        `SELECT id, title, syntax, visibility, created_at, updated_at, expires_at, views
         FROM pastes
         WHERE user_id = ? AND (expires_at IS NULL OR expires_at > ?)
           AND (? = '' OR title LIKE ? OR content LIKE ?)
         ORDER BY updated_at DESC LIMIT ? OFFSET ?`
      ).all(user.id, Date.now(), q, like, like, limit, offset);
      const total = db.prepare(
        `SELECT COUNT(*) AS c FROM pastes
         WHERE user_id = ? AND (expires_at IS NULL OR expires_at > ?)
           AND (? = '' OR title LIKE ? OR content LIKE ?)`
      ).get(user.id, Date.now(), q, like, like).c;
      return sendJSON(res, 200, { pastes: rows, total, limit, offset });
    }

    if (method === 'GET' && p.startsWith('/raw/')) {
      const id = p.slice('/raw/'.length);
      if (!/^[A-Za-z0-9]{7}$/.test(id)) return send(res, 404, 'not found');
      const user = authUser(req);
      const row = getPaste(id);
      if (!row || !canView(row, user)) return send(res, 404, 'not found or expired');
      const etag = '"' + crypto.createHash('sha1').update(row.content).digest('hex') + '"';
      if (req.headers['if-none-match'] === etag) {
        res.writeHead(304, { 'ETag': etag });
        return res.end();
      }
      const cc = row.visibility === 'unlisted'
        ? 'public, max-age=60, stale-while-revalidate=300'
        : 'no-store';
      return send(res, 200, row.content, 'text/plain; charset=utf-8',
        { 'X-Robots-Tag': 'noindex, nofollow', 'Cache-Control': cc, 'ETag': etag });
    }

    // ---------------- frontend (SPA) ----------------
    if (method === 'GET' && (
      p === '/' || p === '/new' || p === '/login' || p === '/signup' ||
      p === '/my' || p === '/settings' ||
      /^\/[A-Za-z0-9]{7}$/.test(p) || /^\/[A-Za-z0-9]{7}\/edit$/.test(p)
    )) {
      const extra = /^\/[A-Za-z0-9]{7}/.test(p) ? { 'X-Robots-Tag': 'noindex, nofollow' } : {};
      return serveFile(res, path.join(PUBLIC, 'index.html'), extra);
    }

    if (method === 'GET' && !p.startsWith('/api/')) {
      const file = path.join(PUBLIC, decodeURIComponent(p));
      if (p !== '/' && fs.existsSync(file) && fs.statSync(file).isFile()) return serveFile(res, file);
    }

    return sendJSON(res, 404, { error: 'Not found.' });
  } catch (e) {
    console.error(e);
    return sendJSON(res, 500, { error: 'Internal error.' });
  }
});

server.listen(PORT, () => {
  console.log(`Snip v${VERSION} running on http://localhost:${PORT} (db: ${DB_PATH})`);
});
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down…');
  flushViews(); // never lose batched view counts on a deploy/restart
  server.close(() => { db.close(); process.exit(0); });
  setTimeout(() => process.exit(0), 8000).unref();
});
