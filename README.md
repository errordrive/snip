# Snip v3 — private pastebin · paste · share · raw

A minimal pastebin **with private spaces**. Every account gets its own private space —
nobody can see another user's pastes. A paste is visible to others **only** via its link.

**Privacy model**
- `private` (default) — only you can open it, even with the link.
- `unlisted` — anyone with the link can open it. Not listed anywhere.
- There is **no public feed**. Nothing is discoverable.

**Stack:** Node.js (zero dependencies, built-in `node:sqlite`) + single SQLite file (WAL mode).
One process serves the frontend, the JSON API, and raw output.

## Features

- **Accounts** — sign up / log in; your pastes follow you to any device you log in on.
- **My Pastes** — dashboard with search, edit, delete.
- **Edit & delete** — owners can edit title/content/syntax/visibility/expiry.
- **Expiry** — 10 min / 1 hour / 1 day / 1 week / never. Expired pastes auto-delete.
- **Guest pastes auto-delete after 7 days**, even if "never" was chosen.
- **Public / unlisted** visibility, recent public feed, view counts.
- Minimal monochrome UI (Space Grotesk + Inter + JetBrains Mono), English only, light/dark mode.

## Run locally

Requires **Node 22+**.

```bash
node server.js
# → http://localhost:3000
```

The SQLite file `snip.db` is created automatically on first run (v1 databases migrate cleanly).

## Deploy

**Render** (free): New Web Service → connect repo → Start Command `node server.js`.
Add a persistent disk mounted at the project dir if you want pastes to survive restarts,
or set `DB_PATH` env to the disk path.

**VPS** (any Linux):

```bash
# install Node 22+, then:
node server.js
# keep alive with pm2:
pm2 start server.js --name snip
```

**Anywhere Node runs:** set `PORT` env if needed (`PORT=8080 node server.js`).
No build step, no `npm install`.

## API

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Health check → `{ok, version}` |
| `POST` | `/api/auth/signup` | `{username, password}` → creates account + session |
| `POST` | `/api/auth/login` | `{username, password}` → session |
| `POST` | `/api/auth/logout` | Destroys session |
| `GET` | `/api/auth/me` | Current user or 401 |
| `POST` | `/api/auth/change-password` | `{current, new}` → also logs out other devices |
| `DELETE` | `/api/auth/account` | `{password}` → deletes account + all pastes + sessions |
| `GET` | `/api/export` | Download all your pastes as JSON |
| `POST` | `/api/paste` | Create. `{title, content, syntax, visibility, expires_in}` → `{id, url, raw_url}` |
| `GET` | `/api/paste/:id` | Paste JSON (access-checked, counts a view) |
| `PUT` | `/api/paste/:id` | Edit (owner only) |
| `DELETE` | `/api/paste/:id` | Delete (owner only) |
| `GET` | `/api/my?q=&limit=&offset=` | Your pastes, searchable, paginated |
| `GET` | `/raw/:id` | Raw `text/plain` (access-checked) |
| `GET` | `/:id` | View page |

`visibility` is `private` (default) or `unlisted`. `expires_in` is seconds
(`600` / `3600` / `86400` / `604800`) or `null` for never.
Guest pastes are always link-only and auto-delete after 7 days. Max paste size 512 KB.

## Production notes

- Passwords: scrypt hashing. Sessions: 30-day HttpOnly + SameSite=Lax cookies (Secure on HTTPS), sha256-stored tokens.
- Rate limits: 20 pastes / 10 min / IP, 10 auth attempts / 10 min / IP.
- Security headers on all responses (nosniff, DENY framing, no-referrer, CSP on HTML);
  paste pages and raw output send `X-Robots-Tag: noindex, nofollow`.
- SQLite WAL mode + busy timeout; expired pastes and sessions swept hourly;
  graceful shutdown on SIGTERM.
- Expired pastes are deleted lazily on read + by the hourly sweep.
