// Snip v1 — minimal pastebin. Zero dependencies. Requires Node 22+.
// One process serves the frontend + JSON API + raw text output.
// Data: single SQLite file (snip.db), auto-created on first run.

const http = require('node:http');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'snip.db');
const PUBLIC = path.join(__dirname, 'public');
const MAX_CONTENT = 512 * 1024; // max paste size, in characters
const MAX_BODY = 1024 * 1024;   // max request body, in bytes

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
db.exec(`CREATE INDEX IF NOT EXISTS idx_pastes_recent ON pastes (visibility, created_at DESC)`);

const SYNTAXES = new Set([
  'plaintext','bash','javascript','typescript','python','java','c','cpp',
  'csharp','go','rust','php','ruby','html','css','json','yaml','sql',
  'markdown','diff',
]);
const EXPIRY_OPTIONS = new Set([600, 3600, 86400, 604800]); // 10m 1h 1d 1w

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
function genId(n = 7) {
  const buf = crypto.randomBytes(n);
  let s = '';
  for (const b of buf) s += ALPHABET[b % 62];
  return s;
}

const insertStmt = db.prepare(
  'INSERT INTO pastes (id, title, content, syntax, visibility, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
);
function createPaste({ title, content, syntax, visibility, expiresIn }) {
  const now = Date.now();
  const expiresAt = expiresIn ? now + expiresIn * 1000 : null;
  for (let i = 0; i < 5; i++) {
    const id = genId();
    try {
      insertStmt.run(id, title, content, syntax, visibility, now, expiresAt);
      return id;
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

// periodic cleanup of expired pastes
function cleanup() {
  db.prepare('DELETE FROM pastes WHERE expires_at IS NOT NULL AND expires_at < ?').run(Date.now());
}
cleanup();
setInterval(cleanup, 60 * 60 * 1000).unref();

// ------------------------------------------------------------- rate limit
const hits = new Map(); // ip -> timestamps[]
const RL_WINDOW = 10 * 60 * 1000;
const RL_MAX = 20; // creates per window per ip
function rateLimited(ip) {
  const now = Date.now();
  let arr = (hits.get(ip) || []).filter((t) => now - t < RL_WINDOW);
  if (arr.length >= RL_MAX) return true;
  arr.push(now);
  hits.set(ip, arr);
  return false;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, arr] of hits) {
    const f = arr.filter((t) => now - t < RL_WINDOW);
    if (f.length) hits.set(ip, f); else hits.delete(ip);
  }
}, RL_WINDOW).unref();

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
function send(res, status, body, type = 'text/plain; charset=utf-8') {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(body);
  res.writeHead(status, {
    'Content-Type': type,
    'Content-Length': buf.length,
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(buf);
}
const sendJSON = (res, status, obj) => send(res, status, JSON.stringify(obj), 'application/json; charset=utf-8');

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

// ---------------------------------------------------------------- routes
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  const method = req.method;

  try {
    // --- create paste
    if (method === 'POST' && p === '/api/paste') {
      const ip = req.socket.remoteAddress || 'unknown';
      if (rateLimited(ip)) return sendJSON(res, 429, { error: 'Too many pastes. Try again in a few minutes.' });
      let data;
      try { data = JSON.parse(await readBody(req)); }
      catch { return sendJSON(res, 400, { error: 'Invalid JSON body.' }); }

      const content = typeof data.content === 'string' ? data.content : '';
      if (!content.trim()) return sendJSON(res, 400, { error: 'Content is empty.' });
      if (content.length > MAX_CONTENT) return sendJSON(res, 413, { error: 'Paste is too large (max 512 KB).' });

      const title = typeof data.title === 'string' ? data.title.trim().slice(0, 120) : '';
      const syntax = SYNTAXES.has(data.syntax) ? data.syntax : 'plaintext';
      const visibility = data.visibility === 'unlisted' ? 'unlisted' : 'public';
      const expiresIn = EXPIRY_OPTIONS.has(data.expires_in) ? data.expires_in : null;

      const id = createPaste({ title, content, syntax, visibility, expiresIn });
      return sendJSON(res, 201, { id, url: '/' + id, raw_url: '/raw/' + id });
    }

    // --- read paste (JSON, counts a view)
    if (method === 'GET' && p.startsWith('/api/paste/')) {
      const id = p.slice('/api/paste/'.length);
      if (!/^[A-Za-z0-9]{7}$/.test(id)) return sendJSON(res, 404, { error: 'Paste not found.' });
      const row = getPaste(id, true);
      if (!row) return sendJSON(res, 404, { error: 'Paste not found or expired.' });
      return sendJSON(res, 200, {
        id: row.id, title: row.title, content: row.content, syntax: row.syntax,
        visibility: row.visibility, created_at: row.created_at,
        expires_at: row.expires_at, views: row.views + 1,
      });
    }

    // --- recent public pastes
    if (method === 'GET' && p === '/api/recent') {
      const rows = db.prepare(
        `SELECT id, title, syntax, created_at, views FROM pastes
         WHERE visibility = 'public' AND (expires_at IS NULL OR expires_at > ?)
         ORDER BY created_at DESC LIMIT 20`
      ).all(Date.now());
      return sendJSON(res, 200, { pastes: rows });
    }

    // --- raw text output
    if (method === 'GET' && p.startsWith('/raw/')) {
      const id = p.slice('/raw/'.length);
      if (!/^[A-Za-z0-9]{7}$/.test(id)) return send(res, 404, 'not found');
      const row = getPaste(id, false);
      if (!row) return send(res, 404, 'not found or expired');
      return send(res, 200, row.content, 'text/plain; charset=utf-8');
    }

    // --- frontend: home + view page (client-side routing)
    if (method === 'GET' && (p === '/' || p === '/new' || /^[A-Za-z0-9]{7}$/.test(p.slice(1)))) {
      return serveFile(res, path.join(PUBLIC, 'index.html'));
    }

    // --- static assets
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
  console.log(`Snip running on http://localhost:${PORT} (db: ${DB_PATH})`);
});
