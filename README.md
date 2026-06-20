# Cleo POS — Phase 1

A multi-tenant SaaS point-of-sale system. Zero npm dependencies — runs on Node's built-in HTTP server and SQLite. Any business signs up, gets an isolated workspace, and sells from the browser.

## What's in Phase 1

- **Accounts & multi-tenancy** — each business is an isolated tenant; signup creates the business + an owner
- **Roles** — owner / manager / cashier, enforced on every write
- **Items** — products, categories, barcodes, SKU, cost, stock, low-stock alerts, per-item tax flag
- **Till (Sell)** — search/scan, cart, quantity controls, cash tendering with change + quick-cash buttons, card, on-screen/printable receipt
- **Sales** — full history, drill-in receipts, refund with auto-restock
- **Stats** — today's revenue, transaction count, average sale, 7-day chart, top sellers, low-stock list
- **Setup** — business name, currency, tax rate, receipt footer
- **Staff** — invite managers/cashiers, owner can remove members

Money is stored as integer cents throughout (no floating-point drift). Every query is scoped by the authenticated user's `tenant_id`.

## Run locally

Requires **Node.js 22.5+** (uses the built-in `node:sqlite` module).

```bash
cd pos
npm start          # or: node server.js
```

Open http://localhost:3000 → create a business account → you're on the till.

### Environment variables

| Var           | Default              | Notes                                  |
|---------------|----------------------|----------------------------------------|
| `PORT`        | `3000`               |                                        |
| `DB_PATH`     | `./pos.db`           | SQLite file location                   |
| `AUTH_SECRET` | dev placeholder      | **Set a long random value in prod**    |

## Deploy on Railway

1. Push this folder to a GitHub repo.
2. New Railway project → Deploy from repo.
3. Set variables: `AUTH_SECRET` (random 32+ chars). Railway sets `PORT` automatically.
4. Add a persistent volume mounted at e.g. `/data` and set `DB_PATH=/data/pos.db` so the database survives redeploys.
5. Railway uses `npm start`. Done.

The frontend is served by the same Node process, so there's nothing separate to host. (You can alternatively put `public/` on Netlify and point it at the API by changing `const API` in the HTML files.)

## Architecture notes

- `server.js` — the whole backend: schema, auth (scrypt + HMAC tokens), routing, all API handlers.
- `public/index.html` — login / signup.
- `public/app.html` — the operator app (till + admin), single file, vanilla JS.
- DB is SQLite via `node:sqlite`. Migration path to Postgres is clean when tenant volume grows — the schema is standard SQL and money is already integer cents.

## What's next (not in Phase 1)

Card gateway (Stripe), customers + loyalty, email/SMS receipts, shift/Z-reports, CSV export, subscription billing for the SaaS layer, multi-location, variants/modifiers, and offline mode with sync.
