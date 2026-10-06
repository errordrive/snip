# Snip v2 — paste · share · raw

A minimal pastebin **with accounts**. Paste text or code, get a short link, share it.
Raw view serves pure `text/plain` — perfect for `curl`.

**Stack:** Node.js (zero dependencies, built-in `node:sqlite`) + single SQLite file.
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
| `POST` | `/api/paste` | Create. Body: `{title, content, syntax, visibility, expires_in}` → `{id, url, raw_url}` |
| `GET` | `/api/paste/:id` | Paste JSON (counts a view) |
| `GET` | `/api/recent` | 20 latest public pastes |
| `GET` | `/raw/:id` | Raw `text/plain` content |
| `GET` | `/:id` | View page |

`expires_in` is seconds: `600` / `3600` / `86400` / `604800`, or `null` for never.
`visibility` is `public` or `unlisted`. Max paste size 512 KB.
Creating is rate-limited: 20 pastes / 10 min / IP.

## Notes

- Expired pastes are deleted lazily on read + by an hourly sweep.
- Syntax highlighting via highlight.js (CDN) with a minimal monochrome theme.
- English-only UI, light/dark mode, no account needed.
