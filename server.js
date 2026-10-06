// Snip v2 — minimal pastebin with accounts.
// Zero dependencies. Requires Node 22+.
// One process serves the frontend + JSON API + raw text output.
// Data: single SQLite file (snip.db), auto-created + migrated on boot.

const http = require('node:http');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'snip.db');
const PUBLIC = path.join(__dirname, 'public');
const MAX_CONTENT = 512 * 1024;   // max paste size, in characters
const MAX_BODY = 1024 * 1024;     // max request body, in bytes
const GUEST_MAX_AGE = 7 * 86400 * 1000; // guest pastes auto-delete after 7 days
const SESSION_AGE = 30 * 86400 * 1000;  // login sessions last 30 days

// ---------------------------------------------------------------- database
const db = new DatabaseSync(DB_PATH);
db.exec(`CREATE TABLE IF NOT EXISTS pastes (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL DEFAULT '',
  content TEXT NOT NULL,
  syntax TEXT NOT NULL DEFAULT 'plaintext',
  visibility TEXT NOT NULL DEFAULT 'public',
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  views INTEGER NOT NULL DEFAULT 0
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
// v1 → v2 migration
{
  const cols = db.prepare(`PRAGMA table_info(pastes)`).all().map((c) => c.name);
  if (!cols.includes('user_id')) db.exec(`ALTER TABLE pastes ADD COLUMN user_id TEXT`);
  if (!cols.includes('updated_at')) db.exec(`ALTER TABLE pastes ADD COLUMN updated_at INTEGER`);
  db.exec(`UPDATE pastes SET updated_at = created_at WHERE updated_at IS NULL`);
}
db.exec(`CREATE INDEX IF NOT EXISTS idx_pastes_recent ON pastes (visibility, created_at DESC)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_pastes_user ON pastes (user_id, updated_at DESC)`);

const SYNTAXES = new Set([
  'plaintext','bash','javascript','typescript','python','java','c','cpp',
  'csharp','go','rust','php','ruby','html','css','json','yaml','sql',
  'markdown','diff',
]);
const EXPIRY_OPTIONS = new Set([600, 3600, 86400, 604800]); // 10m 1h 1d 1w

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
  // token === null → clear the cookie
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
    // guests: pastes auto-delete after 7 days no matter what
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
const viewStmt = db.prepare('UPDATE pastes SET views = views + 1 WHERE id = ?');
function getPaste(id, countView) {
  const row = getStmt.get(id);
  if (!row) return null;
  if (row.expires_at && row.expires_at < Date.now()) {
    delStmt.run(id); // lazy expiry
    return null;
  }
  if (countView) viewStmt.run(id);
  return row;
}
function publicPaste(row) {
  return {
    id: row.id, title: row.title, content: row.content, syntax: row.syntax,
    visibility: row.visibility, created_at: row.created_at, updated_at: row.updated_at,
    expires_at: row.expires_at, views: row.views,
    owner: !!row.user_id,
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
function send(res, status, body, type = 'text/plain; charset=utf-8', extra = {}) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(body);
  res.writeHead(status, Object.assign({
    'Content-Type': type,
    'Content-Length': buf.length,
    'X-Content-Type-Options': 'nosniff',
  }, extra));
  res.end(buf);
}
const sendJSON = (res, status, obj, extra) =>
  send(res, status, JSON.stringify(obj), 'application/json; charset=utf-8', extra);

function serveFile(res, filePath) {
  const safe = path.normalize(filePath);
  if (!safe.startsWith(PUBLIC + path.sep) && safe !== PUBLIC) return send(res, 403, 'forbidden');
  fs.readFile(safe, (err, data) => {
    if (err) return send(res, 404, 'not found');
    send(res, 200, data, MIME[path.extname(safe).toLowerCase()] || 'application/octet-stream');
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
    out.visibility = data.visibility === 'unlisted' ? 'unlisted' : 'public';
  if (data.expires_in !== undefined || !forUpdate)
    out.expiresIn = data.expires_in === null ? null
      : EXPIRY_OPTIONS.has(data.expires_in) ? data.expires_in : null;
  return out;
}

// ---------------------------------------------------------------- routes
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  const method = req.method;
  const ip = req.socket.remoteAddress || 'unknown';

  try {
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
      // constant-ish timing on failure; generic message either way
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
      return sendJSON(res, 201, {
        id, url: '/' + id, raw_url: '/raw/' + id,
        expires_at: expiresAt, guest: !user,
      });
    }

    if (method === 'GET' && p.startsWith('/api/paste/')) {
      const id = p.slice('/api/paste/'.length);
      if (!/^[A-Za-z0-9]{7}$/.test(id)) return sendJSON(res, 404, { error: 'Paste not found.' });
      const row = getPaste(id, true);
      if (!row) return sendJSON(res, 404, { error: 'Paste not found or expired.' });
      const out = publicPaste(row);
      out.views = row.views + 1;
      const user = authUser(req);
      out.mine = !!(user && row.user_id && row.user_id === user.id);
      return sendJSON(res, 200, out);
    }

    if (method === 'PUT' && p.startsWith('/api/paste/')) {
      const user = authUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Log in to edit pastes.' });
      const id = p.slice('/api/paste/'.length);
      if (!/^[A-Za-z0-9]{7}$/.test(id)) return sendJSON(res, 404, { error: 'Paste not found.' });
      const row = getPaste(id, false);
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
      return sendJSON(res, 200, { ok: true, id });
    }

    if (method === 'DELETE' && p.startsWith('/api/paste/')) {
      const user = authUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Log in to delete pastes.' });
      const id = p.slice('/api/paste/'.length);
      if (!/^[A-Za-z0-9]{7}$/.test(id)) return sendJSON(res, 404, { error: 'Paste not found.' });
      const row = getPaste(id, false);
      if (!row || row.user_id !== user.id)
        return sendJSON(res, 404, { error: 'Paste not found.' });
      delStmt.run(id);
      return sendJSON(res, 200, { ok: true });
    }

    if (method === 'GET' && p === '/api/my') {
      const user = authUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Log in to see your pastes.' });
      const rows = db.prepare(
        `SELECT id, title, syntax, visibility, created_at, updated_at, expires_at, views
         FROM pastes WHERE user_id = ? AND (expires_at IS NULL OR expires_at > ?)
         ORDER BY updated_at DESC`
      ).all(user.id, Date.now());
      return sendJSON(res, 200, { pastes: rows });
    }

    if (method === 'GET' && p === '/api/recent') {
      const rows = db.prepare(
        `SELECT id, title, syntax, created_at, views FROM pastes
         WHERE visibility = 'public' AND (expires_at IS NULL OR expires_at > ?)
         ORDER BY created_at DESC LIMIT 20`
      ).all(Date.now());
      return sendJSON(res, 200, { pastes: rows });
    }

    if (method === 'GET' && p.startsWith('/raw/')) {
      const id = p.slice('/raw/'.length);
      if (!/^[A-Za-z0-9]{7}$/.test(id)) return send(res, 404, 'not found');
      const row = getPaste(id, false);
      if (!row) return send(res, 404, 'not found or expired');
      return send(res, 200, row.content, 'text/plain; charset=utf-8');
    }

    // ---------------- frontend (SPA) ----------------
    if (method === 'GET' && (
      p === '/' || p === '/new' || p === '/login' || p === '/signup' || p === '/my' ||
      /^\/[A-Za-z0-9]{7}$/.test(p) || /^\/[A-Za-z0-9]{7}\/edit$/.test(p)
    )) {
      return serveFile(res, path.join(PUBLIC, 'index.html'));
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
  console.log(`Snip v2 running on http://localhost:${PORT} (db: ${DB_PATH})`);
});
