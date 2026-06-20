'use strict';
/**
 * Cleo POS — zero-dependency multi-tenant SaaS POS backend.
 * Runtime: Node.js 22+ (uses built-in node:sqlite, node:crypto, node:http).
 * No npm install required.
 */

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'pos.db');
const SECRET = process.env.AUTH_SECRET || 'dev-secret-change-me-in-production';
const PUBLIC_DIR = path.join(__dirname, 'public');
const TOKEN_TTL = 1000 * 60 * 60 * 24 * 7; // 7 days

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

db.exec(`
CREATE TABLE IF NOT EXISTS tenants (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  currency      TEXT NOT NULL DEFAULT 'USD',
  tax_rate      REAL NOT NULL DEFAULT 0,
  receipt_note  TEXT NOT NULL DEFAULT '',
  plan          TEXT NOT NULL DEFAULT 'trial',
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id          TEXT PRIMARY KEY,
  tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  email       TEXT NOT NULL,
  pass_hash   TEXT NOT NULL,
  role        TEXT NOT NULL DEFAULT 'cashier',
  active      INTEGER NOT NULL DEFAULT 1,
  created_at  INTEGER NOT NULL,
  UNIQUE(email)
);

CREATE TABLE IF NOT EXISTS categories (
  id          TEXT PRIMARY KEY,
  tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
  id           TEXT PRIMARY KEY,
  tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  category_id  TEXT REFERENCES categories(id) ON DELETE SET NULL,
  name         TEXT NOT NULL,
  sku          TEXT,
  barcode      TEXT,
  price_cents  INTEGER NOT NULL DEFAULT 0,
  cost_cents   INTEGER NOT NULL DEFAULT 0,
  stock        INTEGER NOT NULL DEFAULT 0,
  low_stock    INTEGER NOT NULL DEFAULT 5,
  taxable      INTEGER NOT NULL DEFAULT 1,
  active       INTEGER NOT NULL DEFAULT 1,
  created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_products_tenant ON products(tenant_id);
CREATE INDEX IF NOT EXISTS idx_products_barcode ON products(tenant_id, barcode);

CREATE TABLE IF NOT EXISTS sales (
  id              TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id         TEXT REFERENCES users(id) ON DELETE SET NULL,
  number          INTEGER NOT NULL,
  subtotal_cents  INTEGER NOT NULL,
  discount_cents  INTEGER NOT NULL DEFAULT 0,
  tax_cents       INTEGER NOT NULL DEFAULT 0,
  total_cents     INTEGER NOT NULL,
  paid_cents      INTEGER NOT NULL,
  change_cents    INTEGER NOT NULL DEFAULT 0,
  pay_method      TEXT NOT NULL DEFAULT 'cash',
  status          TEXT NOT NULL DEFAULT 'completed',
  created_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sales_tenant ON sales(tenant_id, created_at);

CREATE TABLE IF NOT EXISTS sale_items (
  id           TEXT PRIMARY KEY,
  sale_id      TEXT NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
  product_id   TEXT,
  name         TEXT NOT NULL,
  qty          INTEGER NOT NULL,
  price_cents  INTEGER NOT NULL,
  line_cents   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_items_sale ON sale_items(sale_id);
`);

// ---------------------------------------------------------------------------
// Helpers: ids, hashing, tokens
// ---------------------------------------------------------------------------
const uid = () => crypto.randomBytes(16).toString('hex');
const now = () => Date.now();

function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pw, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(pw, stored) {
  const [salt, hash] = stored.split(':');
  const test = crypto.scryptSync(pw, salt, 64).toString('hex');
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(test, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
function sign(payload) {
  const body = b64({ ...payload, exp: now() + TOKEN_TTL });
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  let payload;
  try { payload = JSON.parse(Buffer.from(body, 'base64url').toString()); }
  catch { return null; }
  if (!payload.exp || payload.exp < now()) return null;
  return payload;
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------
function send(res, code, data) {
  const body = JSON.stringify(data);
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (c) => { raw += c; if (raw.length > 1e6) req.destroy(); });
    req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}
class HttpError extends Error { constructor(code, msg) { super(msg); this.code = code; } }
const bad = (msg) => { throw new HttpError(400, msg); };

function auth(req) {
  const h = req.headers['authorization'] || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  const payload = verifyToken(token);
  if (!payload) throw new HttpError(401, 'Not authenticated');
  const user = db.prepare('SELECT * FROM users WHERE id=? AND active=1').get(payload.uid);
  if (!user) throw new HttpError(401, 'Account not found');
  return user;
}
function requireRole(user, ...roles) {
  if (!roles.includes(user.role)) throw new HttpError(403, 'Insufficient permissions');
}

// ---------------------------------------------------------------------------
// Money / shaping
// ---------------------------------------------------------------------------
const tenantOf = (id) => db.prepare('SELECT * FROM tenants WHERE id=?').get(id);
function publicUser(u) {
  return { id: u.id, name: u.name, email: u.email, role: u.role, tenant_id: u.tenant_id };
}
function publicTenant(t) {
  return { id: t.id, name: t.name, currency: t.currency, tax_rate: t.tax_rate, receipt_note: t.receipt_note, plan: t.plan };
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------
const routes = [];
const route = (method, pattern, handler) => routes.push({ method, pattern, handler });

// --- Auth ---
route('POST', '/api/auth/signup', async (req, res) => {
  const b = await readBody(req);
  const business = (b.business || '').trim();
  const name = (b.name || '').trim();
  const email = (b.email || '').trim().toLowerCase();
  const password = b.password || '';
  if (!business || !name || !email || password.length < 6) bad('All fields required; password min 6 chars');
  if (db.prepare('SELECT id FROM users WHERE email=?').get(email)) bad('Email already registered');

  const tId = uid(), uId = uid();
  db.prepare('INSERT INTO tenants(id,name,currency,tax_rate,receipt_note,plan,created_at) VALUES(?,?,?,?,?,?,?)')
    .run(tId, business, b.currency || 'USD', 0, 'Thank you!', 'trial', now());
  db.prepare('INSERT INTO users(id,tenant_id,name,email,pass_hash,role,active,created_at) VALUES(?,?,?,?,?,?,1,?)')
    .run(uId, tId, name, email, hashPassword(password), 'owner', now());

  const user = db.prepare('SELECT * FROM users WHERE id=?').get(uId);
  send(res, 201, { token: sign({ uid: uId, tid: tId }), user: publicUser(user), tenant: publicTenant(tenantOf(tId)) });
});

route('POST', '/api/auth/login', async (req, res) => {
  const b = await readBody(req);
  const email = (b.email || '').trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE email=? AND active=1').get(email);
  if (!user || !verifyPassword(b.password || '', user.pass_hash)) throw new HttpError(401, 'Invalid email or password');
  send(res, 200, { token: sign({ uid: user.id, tid: user.tenant_id }), user: publicUser(user), tenant: publicTenant(tenantOf(user.tenant_id)) });
});

route('GET', '/api/me', async (req, res) => {
  const user = auth(req);
  send(res, 200, { user: publicUser(user), tenant: publicTenant(tenantOf(user.tenant_id)) });
});

// --- Categories ---
route('GET', '/api/categories', async (req, res) => {
  const u = auth(req);
  send(res, 200, db.prepare('SELECT id,name FROM categories WHERE tenant_id=? ORDER BY name').all(u.tenant_id));
});
route('POST', '/api/categories', async (req, res) => {
  const u = auth(req); requireRole(u, 'owner', 'manager');
  const b = await readBody(req);
  if (!b.name) bad('Name required');
  const id = uid();
  db.prepare('INSERT INTO categories(id,tenant_id,name,created_at) VALUES(?,?,?,?)').run(id, u.tenant_id, b.name.trim(), now());
  send(res, 201, { id, name: b.name.trim() });
});
route('DELETE', '/api/categories/:id', async (req, res, params) => {
  const u = auth(req); requireRole(u, 'owner', 'manager');
  db.prepare('DELETE FROM categories WHERE id=? AND tenant_id=?').run(params.id, u.tenant_id);
  send(res, 200, { ok: true });
});

// --- Products ---
route('GET', '/api/products', async (req, res) => {
  const u = auth(req);
  const rows = db.prepare('SELECT * FROM products WHERE tenant_id=? AND active=1 ORDER BY name').all(u.tenant_id);
  send(res, 200, rows);
});
route('POST', '/api/products', async (req, res) => {
  const u = auth(req); requireRole(u, 'owner', 'manager');
  const b = await readBody(req);
  if (!b.name) bad('Name required');
  const id = uid();
  db.prepare(`INSERT INTO products(id,tenant_id,category_id,name,sku,barcode,price_cents,cost_cents,stock,low_stock,taxable,active,created_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?)`)
    .run(id, u.tenant_id, b.category_id || null, b.name.trim(), b.sku || null, b.barcode || null,
         Math.round(b.price_cents || 0), Math.round(b.cost_cents || 0), Math.round(b.stock || 0),
         Math.round(b.low_stock ?? 5), b.taxable === false ? 0 : 1, now());
  send(res, 201, db.prepare('SELECT * FROM products WHERE id=?').get(id));
});
route('PUT', '/api/products/:id', async (req, res, params) => {
  const u = auth(req); requireRole(u, 'owner', 'manager');
  const b = await readBody(req);
  const p = db.prepare('SELECT * FROM products WHERE id=? AND tenant_id=?').get(params.id, u.tenant_id);
  if (!p) throw new HttpError(404, 'Product not found');
  db.prepare(`UPDATE products SET category_id=?,name=?,sku=?,barcode=?,price_cents=?,cost_cents=?,stock=?,low_stock=?,taxable=? WHERE id=? AND tenant_id=?`)
    .run(b.category_id ?? p.category_id, (b.name ?? p.name).trim(), b.sku ?? p.sku, b.barcode ?? p.barcode,
         Math.round(b.price_cents ?? p.price_cents), Math.round(b.cost_cents ?? p.cost_cents),
         Math.round(b.stock ?? p.stock), Math.round(b.low_stock ?? p.low_stock),
         b.taxable === undefined ? p.taxable : (b.taxable ? 1 : 0), params.id, u.tenant_id);
  send(res, 200, db.prepare('SELECT * FROM products WHERE id=?').get(params.id));
});
route('DELETE', '/api/products/:id', async (req, res, params) => {
  const u = auth(req); requireRole(u, 'owner', 'manager');
  db.prepare('UPDATE products SET active=0 WHERE id=? AND tenant_id=?').run(params.id, u.tenant_id);
  send(res, 200, { ok: true });
});

// --- Checkout / Sales ---
route('POST', '/api/sales', async (req, res) => {
  const u = auth(req);
  const b = await readBody(req);
  const items = Array.isArray(b.items) ? b.items : [];
  if (!items.length) bad('Cart is empty');
  const tenant = tenantOf(u.tenant_id);

  let subtotal = 0, taxBase = 0;
  const resolved = [];
  for (const it of items) {
    const prod = db.prepare('SELECT * FROM products WHERE id=? AND tenant_id=?').get(it.product_id, u.tenant_id);
    if (!prod) bad(`Product not found: ${it.product_id}`);
    const qty = Math.max(1, Math.round(it.qty || 1));
    const line = prod.price_cents * qty;
    subtotal += line;
    if (prod.taxable) taxBase += line;
    resolved.push({ prod, qty, line });
  }
  const discount = Math.max(0, Math.round(b.discount_cents || 0));
  const taxableAfterDiscount = Math.max(0, taxBase - discount);
  const tax = Math.round(taxableAfterDiscount * (tenant.tax_rate || 0) / 100);
  const total = Math.max(0, subtotal - discount + tax);
  const paid = Math.round(b.paid_cents ?? total);
  if (paid < total) bad('Amount paid is less than total');
  const change = paid - total;

  const number = (db.prepare('SELECT COALESCE(MAX(number),0) n FROM sales WHERE tenant_id=?').get(u.tenant_id).n) + 1;
  const saleId = uid();

  const writeSale = db.prepare(`INSERT INTO sales(id,tenant_id,user_id,number,subtotal_cents,discount_cents,tax_cents,total_cents,paid_cents,change_cents,pay_method,status,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  const writeItem = db.prepare('INSERT INTO sale_items(id,sale_id,product_id,name,qty,price_cents,line_cents) VALUES(?,?,?,?,?,?,?)');
  const decStock = db.prepare('UPDATE products SET stock = stock - ? WHERE id=? AND tenant_id=?');

  const run = db.prepare('BEGIN'); run.run();
  try {
    writeSale.run(saleId, u.tenant_id, u.id, number, subtotal, discount, tax, total, paid, change, b.pay_method || 'cash', 'completed', now());
    for (const r of resolved) {
      writeItem.run(uid(), saleId, r.prod.id, r.prod.name, r.qty, r.prod.price_cents, r.line);
      decStock.run(r.qty, r.prod.id, u.tenant_id);
    }
    db.prepare('COMMIT').run();
  } catch (e) {
    db.prepare('ROLLBACK').run();
    throw e;
  }
  send(res, 201, fullSale(saleId, u.tenant_id));
});

function fullSale(id, tenantId) {
  const sale = db.prepare('SELECT * FROM sales WHERE id=? AND tenant_id=?').get(id, tenantId);
  if (!sale) return null;
  sale.items = db.prepare('SELECT name,qty,price_cents,line_cents FROM sale_items WHERE sale_id=?').all(id);
  const cashier = db.prepare('SELECT name FROM users WHERE id=?').get(sale.user_id);
  sale.cashier = cashier ? cashier.name : '—';
  return sale;
}

route('GET', '/api/sales', async (req, res) => {
  const u = auth(req);
  const rows = db.prepare(`SELECT s.*, COALESCE(us.name,'—') cashier FROM sales s LEFT JOIN users us ON us.id=s.user_id
    WHERE s.tenant_id=? ORDER BY s.created_at DESC LIMIT 100`).all(u.tenant_id);
  send(res, 200, rows);
});
route('GET', '/api/sales/:id', async (req, res, params) => {
  const u = auth(req);
  const s = fullSale(params.id, u.tenant_id);
  if (!s) throw new HttpError(404, 'Sale not found');
  send(res, 200, s);
});
route('POST', '/api/sales/:id/refund', async (req, res, params) => {
  const u = auth(req); requireRole(u, 'owner', 'manager');
  const s = db.prepare('SELECT * FROM sales WHERE id=? AND tenant_id=?').get(params.id, u.tenant_id);
  if (!s) throw new HttpError(404, 'Sale not found');
  if (s.status === 'refunded') bad('Already refunded');
  db.prepare('BEGIN').run();
  try {
    db.prepare('UPDATE sales SET status=? WHERE id=?').run('refunded', s.id);
    const items = db.prepare('SELECT product_id,qty FROM sale_items WHERE sale_id=?').all(s.id);
    const restock = db.prepare('UPDATE products SET stock = stock + ? WHERE id=? AND tenant_id=?');
    for (const it of items) if (it.product_id) restock.run(it.qty, it.product_id, u.tenant_id);
    db.prepare('COMMIT').run();
  } catch (e) { db.prepare('ROLLBACK').run(); throw e; }
  send(res, 200, fullSale(s.id, u.tenant_id));
});

// --- Dashboard ---
route('GET', '/api/dashboard', async (req, res) => {
  const u = auth(req);
  const startOfDay = new Date(); startOfDay.setHours(0, 0, 0, 0);
  const t0 = startOfDay.getTime();
  const today = db.prepare(`SELECT COUNT(*) txns, COALESCE(SUM(total_cents),0) revenue
    FROM sales WHERE tenant_id=? AND status='completed' AND created_at>=?`).get(u.tenant_id, t0);
  const top = db.prepare(`SELECT si.name, SUM(si.qty) qty, SUM(si.line_cents) revenue
    FROM sale_items si JOIN sales s ON s.id=si.sale_id
    WHERE s.tenant_id=? AND s.status='completed' AND s.created_at>=?
    GROUP BY si.name ORDER BY qty DESC LIMIT 5`).all(u.tenant_id, t0 - 6 * 864e5);
  const low = db.prepare('SELECT name,stock,low_stock FROM products WHERE tenant_id=? AND active=1 AND stock<=low_stock ORDER BY stock LIMIT 10').all(u.tenant_id);
  // last 7 days revenue series
  const series = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(); d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - i);
    const s = d.getTime(), e = s + 864e5;
    const r = db.prepare(`SELECT COALESCE(SUM(total_cents),0) v FROM sales WHERE tenant_id=? AND status='completed' AND created_at>=? AND created_at<?`).get(u.tenant_id, s, e);
    series.push({ day: d.toLocaleDateString(undefined, { weekday: 'short' }), revenue: r.v });
  }
  send(res, 200, { today, top, low, series });
});

// --- Settings ---
route('PUT', '/api/settings', async (req, res) => {
  const u = auth(req); requireRole(u, 'owner', 'manager');
  const b = await readBody(req);
  const t = tenantOf(u.tenant_id);
  db.prepare('UPDATE tenants SET name=?,currency=?,tax_rate=?,receipt_note=? WHERE id=?')
    .run((b.name ?? t.name).trim(), b.currency ?? t.currency, Number(b.tax_rate ?? t.tax_rate), b.receipt_note ?? t.receipt_note, t.id);
  send(res, 200, publicTenant(tenantOf(u.tenant_id)));
});

// --- Staff ---
route('GET', '/api/staff', async (req, res) => {
  const u = auth(req); requireRole(u, 'owner', 'manager');
  send(res, 200, db.prepare('SELECT id,name,email,role,active FROM users WHERE tenant_id=? ORDER BY created_at').all(u.tenant_id));
});
route('POST', '/api/staff', async (req, res) => {
  const u = auth(req); requireRole(u, 'owner', 'manager');
  const b = await readBody(req);
  const email = (b.email || '').trim().toLowerCase();
  if (!b.name || !email || (b.password || '').length < 6) bad('Name, email, and password (6+ chars) required');
  if (db.prepare('SELECT id FROM users WHERE email=?').get(email)) bad('Email already registered');
  const role = ['manager', 'cashier'].includes(b.role) ? b.role : 'cashier';
  const id = uid();
  db.prepare('INSERT INTO users(id,tenant_id,name,email,pass_hash,role,active,created_at) VALUES(?,?,?,?,?,?,1,?)')
    .run(id, u.tenant_id, b.name.trim(), email, hashPassword(b.password), role, now());
  send(res, 201, { id, name: b.name.trim(), email, role, active: 1 });
});
route('DELETE', '/api/staff/:id', async (req, res, params) => {
  const u = auth(req); requireRole(u, 'owner');
  if (params.id === u.id) bad('You cannot remove yourself');
  db.prepare('UPDATE users SET active=0 WHERE id=? AND tenant_id=?').run(params.id, u.tenant_id);
  send(res, 200, { ok: true });
});

// ---------------------------------------------------------------------------
// Static files
// ---------------------------------------------------------------------------
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.json': 'application/json' };
function serveStatic(req, res, pathname) {
  let rel = pathname === '/' ? '/index.html' : pathname;
  if (rel.endsWith('/app')) rel = '/app.html';
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(file, (err, data) => {
    if (err) {
      // SPA-ish fallback to app shell for unknown non-API GETs
      if (!rel.includes('.')) {
        return fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (e2, d2) =>
          e2 ? (res.writeHead(404), res.end('Not found')) : (res.writeHead(200, { 'Content-Type': 'text/html' }), res.end(d2)));
      }
      res.writeHead(404); return res.end('Not found');
    }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------
function matchRoute(method, pathname) {
  for (const r of routes) {
    if (r.method !== method) continue;
    const pp = r.pattern.split('/'), up = pathname.split('/');
    if (pp.length !== up.length) continue;
    const params = {};
    let ok = true;
    for (let i = 0; i < pp.length; i++) {
      if (pp[i].startsWith(':')) params[pp[i].slice(1)] = decodeURIComponent(up[i]);
      else if (pp[i] !== up[i]) { ok = false; break; }
    }
    if (ok) return { handler: r.handler, params };
  }
  return null;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  if (!pathname.startsWith('/api/')) return serveStatic(req, res, pathname);

  const m = matchRoute(req.method, pathname);
  if (!m) return send(res, 404, { error: 'Not found' });
  try {
    await m.handler(req, res, m.params);
  } catch (e) {
    if (e instanceof HttpError) return send(res, e.code, { error: e.message });
    console.error(e);
    return send(res, 500, { error: 'Server error' });
  }
});

server.listen(PORT, () => console.log(`Cleo POS running on http://localhost:${PORT}`));
