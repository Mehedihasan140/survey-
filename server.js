'use strict';
// Surveyra backend: Node 22+, no npm packages needed. Run: node server.js
const http = require('node:http'), fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const C = {
  port: +process.env.PORT || 3000,
  dataDir: process.env.DATA_DIR || path.join(__dirname, 'data'),
  adminKey: process.env.ADMIN_KEY || '',
  trustProxy: process.env.TRUST_PROXY === '1',       // set to 1 behind nginx/Render/Railway
  coinsPerUsd: 100, welcome: 50, refPct: 10, maxSignupsPerIpPerDay: 3,
  minSurveySecondsFloor: +process.env.SURVEY_SEC_FLOOR || 8,   // anti-speeding
  minSurveySecondsPerQ: +process.env.SURVEY_SEC_PER_Q || 3,
  minWithdraw: { bKash: 500, Nagad: 500, PayPal: 1000, Bitcoin: 1500, USDT: 1500 },
};

fs.mkdirSync(C.dataDir, { recursive: true });
const secretFile = path.join(C.dataDir, '.secret');
if (!fs.existsSync(secretFile)) fs.writeFileSync(secretFile, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
const SECRET = process.env.SECRET || fs.readFileSync(secretFile, 'utf8');

const db = new DatabaseSync(path.join(C.dataDir, 'surveyra.db'));
db.exec(`
PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  pass TEXT NOT NULL, balance INTEGER NOT NULL DEFAULT 0 CHECK(balance>=0), earned INTEGER NOT NULL DEFAULT 0,
  code TEXT NOT NULL UNIQUE, referred_by INTEGER, streak INTEGER NOT NULL DEFAULT 0, last_bonus TEXT NOT NULL DEFAULT '',
  banned INTEGER NOT NULL DEFAULT 0, ip TEXT, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), delta INTEGER NOT NULL,
  reason TEXT NOT NULL, ref TEXT UNIQUE, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS surveys(id INTEGER PRIMARY KEY, title TEXT NOT NULL, cat TEXT NOT NULL, minutes INTEGER NOT NULL,
  coins INTEGER NOT NULL, questions TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS runs(user_id INTEGER NOT NULL, survey_id INTEGER NOT NULL, started INTEGER NOT NULL,
  done INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(user_id,survey_id));
CREATE TABLE IF NOT EXISTS withdrawals(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), method TEXT NOT NULL,
  coins INTEGER NOT NULL, account TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created TEXT NOT NULL, updated TEXT);
CREATE INDEX IF NOT EXISTS ix_ledger_user ON ledger(user_id);
`);

// ---- SAMPLE SURVEYS (seeded once). Replace via the admin API or delete rows in the surveys table. ----
if (!db.prepare('SELECT 1 FROM surveys').get()) {
  const S = [
    ['Everyday Shopping Habits', 'Lifestyle', 3, 60, [['Where do you buy most of your groceries?', ['Local market', 'Supermarket', 'Online', 'A mix of all']], ['How much do you spend on groceries each week?', ['Very little', 'A moderate amount', 'Quite a lot', 'I do not track it']], ['What matters most when you shop?', ['Price', 'Freshness', 'Convenience', 'Brand']]]],
    ['Phones and Apps', 'Technology', 4, 90, [['How many hours a day do you use your phone?', ['Under 2', '2 to 4', '4 to 6', 'More than 6']], ['Which type of app do you use most?', ['Social media', 'Video', 'Games', 'Messaging']], ['How often do you upgrade your phone?', ['Every year', 'Every 2 years', 'Every 3+ years', 'Only when it breaks']]]],
    ['Food Delivery Preferences', 'Food', 4, 80, [['How often do you order food online?', ['Never', 'Monthly', 'Weekly', 'Several times a week']], ['What puts you off ordering?', ['Delivery fees', 'Slow delivery', 'Food quality', 'Nothing']], ['When do you order most?', ['Breakfast', 'Lunch', 'Dinner', 'Late night']]]],
  ];
  const ins = db.prepare('INSERT INTO surveys(title,cat,minutes,coins,questions) VALUES(?,?,?,?,?)');
  for (const s of S) ins.run(s[0], s[1], s[2], s[3], JSON.stringify(s[4]));
}

// ---- helpers ----
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const bad = (m, s = 400) => { throw new HttpError(s, m); };
const now = () => new Date().toISOString();
const today = (off = 0) => new Date(Date.now() - off * 864e5).toISOString().slice(0, 10);
const md5 = s => crypto.createHash('md5').update(s).digest('hex');
const hmac = (k, s) => crypto.createHmac('sha256', k).update(s).digest('hex');
const safeEq = (a, b) => { a = Buffer.from(String(a)); b = Buffer.from(String(b)); return a.length === b.length && crypto.timingSafeEqual(a, b); };
function tx(fn) { db.exec('BEGIN IMMEDIATE'); try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; } }

const hashPw = pw => { const s = crypto.randomBytes(16); return s.toString('hex') + ':' + crypto.scryptSync(pw, s, 64).toString('hex'); };
const checkPw = (pw, st) => { const [s, h] = st.split(':'); return safeEq(crypto.scryptSync(pw, Buffer.from(s, 'hex'), 64).toString('hex'), h); };

function sign(p) { const d = Buffer.from(JSON.stringify(p)).toString('base64url'); return d + '.' + crypto.createHmac('sha256', SECRET).update(d).digest('base64url'); }
function verify(t) {
  if (!t || !t.includes('.')) return null; const [d, s] = t.split('.');
  if (!safeEq(s, crypto.createHmac('sha256', SECRET).update(d).digest('base64url'))) return null;
  try { const p = JSON.parse(Buffer.from(d, 'base64url')); return p.exp > Date.now() ? p : null; } catch { return null; }
}

const hits = new Map();
function limit(key, max, ms) {
  const n = Date.now(), a = (hits.get(key) || []).filter(t => n - t < ms);
  if (a.length >= max) bad('Too many attempts. Try again later.', 429);
  a.push(n); hits.set(key, a);
}

// Ledger: every balance change goes through here. `ref` makes it idempotent (same ref is never applied twice).
function credit(uid, delta, reason, ref, countEarned = true) {
  if (ref && db.prepare('SELECT 1 FROM ledger WHERE ref=?').get(ref)) return false;
  db.prepare('INSERT INTO ledger(user_id,delta,reason,ref,created) VALUES(?,?,?,?,?)').run(uid, delta, reason, ref || null, now());
  db.prepare('UPDATE users SET balance=balance+?, earned=earned+? WHERE id=?').run(delta, countEarned ? Math.max(delta, 0) : 0, uid);
  return true;
}
function earn(uid, coins, reason, ref) {            // credit + referral commission to the inviter
  if (!credit(uid, coins, reason, ref)) return false;
  const u = db.prepare('SELECT referred_by r FROM users WHERE id=?').get(uid);
  if (u && u.r && coins > 0) { const c = Math.floor(coins * C.refPct / 100); if (c > 0) credit(u.r, c, 'Referral commission', ref ? 'ref:' + ref : null); }
  return true;
}
const pub = u => ({ id: u.id, name: u.name, email: u.email, coins: u.balance, earned: u.earned, level: 1 + Math.floor(u.earned / 300),
  streak: u.streak, bonusReady: u.last_bonus !== today(), code: u.code });
const int = (v, lo, hi) => { const n = Number(v); if (!Number.isInteger(n) || n < lo || n > hi) bad('Invalid number.'); return n; };
const str = (v, lo, hi, what) => { v = typeof v === 'string' ? v.trim() : ''; if (v.length < lo || v.length > hi) bad(`Invalid ${what}.`); return v; };

// ---- request handling ----
function readBody(req) {
  return new Promise((ok, no) => {
    let b = ''; req.on('data', c => { b += c; if (b.length > 2e5) { no(new HttpError(413, 'Too large')); req.destroy(); } });
    req.on('end', () => { if (!b) return ok({}); try { ok(JSON.parse(b)); } catch { no(new HttpError(400, 'Invalid JSON')); } });
  });
}
function json(res, status, data, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...headers });
  res.end(JSON.stringify(data));
}
const cookie = (t, maxAge) => `sid=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`;
function authUser(req) {
  const m = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie || ''); const p = verify(m && m[1]);
  const u = p && db.prepare('SELECT * FROM users WHERE id=?').get(p.uid);
  if (!u || u.banned) bad('Please log in.', 401); return u;
}
function adminOnly(req) { if (!C.adminKey || !safeEq(req.headers['x-admin-key'] || '', C.adminKey)) bad('Forbidden', 403); }

function verifyPostback(provider, q) {
  const sec = process.env['POSTBACK_SECRET_' + provider.toUpperCase()]; if (!sec) return false;
  // Each provider signs differently. "cpx" below follows CPX Research's md5(trans_id-secret): check your provider's docs.
  const calc = provider === 'cpx' ? md5(`${q.trans_id}-${sec}`) : hmac(sec, `${q.user_id}|${q.trans_id}|${q.amount}|${q.status || 'completed'}`);
  return safeEq(String(q.hash || '').toLowerCase(), calc);
}

async function api(req, res, url, ip) {
  const M = req.method, P = url.pathname; let m;
  const body = M === 'POST' ? await readBody(req) : {};
  if (M === 'POST' && !P.startsWith('/postback/') && !/json/.test(req.headers['content-type'] || '')) bad('Content-Type must be application/json.', 415);
  const ok = (d = {}) => json(res, 200, { ok: true, ...d });

  // --- auth ---
  if (M === 'POST' && P === '/api/signup') {
    limit('su:' + ip, C.maxSignupsPerIpPerDay, 864e5);
    const name = str(body.name, 2, 40, 'name'), email = str(body.email, 5, 120, 'email').toLowerCase(), pw = str(body.password, 6, 100, 'password');
    if (!/^\S+@\S+\.\S+$/.test(email)) bad('Enter a valid email address.');
    if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) bad('This email is already registered.', 409);
    const inviter = body.ref ? db.prepare('SELECT id FROM users WHERE code=?').get(String(body.ref).toUpperCase()) : null;
    const uid = tx(() => {
      const r = db.prepare('INSERT INTO users(name,email,pass,code,referred_by,ip,created) VALUES(?,?,?,?,?,?,?)')
        .run(name, email, hashPw(pw), crypto.randomBytes(4).toString('hex').toUpperCase(), inviter ? inviter.id : null, ip, now());
      credit(Number(r.lastInsertRowid), C.welcome, 'Welcome bonus', 'welcome:' + r.lastInsertRowid);
      return Number(r.lastInsertRowid);
    });
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(uid);
    return json(res, 200, { ok: true, user: pub(u) }, { 'Set-Cookie': cookie(sign({ uid, exp: Date.now() + 30 * 864e5 }), 30 * 86400) });
  }
  if (M === 'POST' && P === '/api/login') {
    limit('li:' + ip, 10, 15 * 60e3);
    const u = db.prepare('SELECT * FROM users WHERE email=?').get(String(body.email || '').trim().toLowerCase());
    if (!u || !checkPw(String(body.password || ''), u.pass)) bad('Wrong email or password.', 401);
    if (u.banned) bad('This account is suspended.', 403);
    return json(res, 200, { ok: true, user: pub(u) }, { 'Set-Cookie': cookie(sign({ uid: u.id, exp: Date.now() + 30 * 864e5 }), 30 * 86400) });
  }
  if (M === 'POST' && P === '/api/logout') return json(res, 200, { ok: true }, { 'Set-Cookie': cookie('', 0) });

  // --- provider postback (no cookie; verified by signature) ---
  if ((m = /^\/postback\/([a-z0-9_]+)$/.exec(P))) {
    const q = { ...Object.fromEntries(url.searchParams), ...body };
    if (!verifyPostback(m[1], q)) bad('Bad signature', 403);
    const uid = int(q.user_id, 1, 1e12), coins = int(q.amount, 1, 1e7), ref = `${m[1]}:${String(q.trans_id).slice(0, 80)}`;
    if (!q.trans_id || !db.prepare('SELECT 1 FROM users WHERE id=?').get(uid)) bad('Unknown user or transaction');
    const reversed = ['reversed', 'canceled', 'cancelled', '2'].includes(String(q.status || '').toLowerCase());
    tx(() => {
      if (!reversed) earn(uid, coins, `Survey (${m[1]})`, ref);
      else if (db.prepare('SELECT 1 FROM ledger WHERE ref=?').get(ref)) {
        const bal = db.prepare('SELECT balance b FROM users WHERE id=?').get(uid).b;
        credit(uid, -Math.min(coins, bal), `Reversal (${m[1]})`, ref + ':rev', false);
      }
    });
    res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('OK');
  }

  // --- admin ---
  if (P.startsWith('/api/admin/')) {
    adminOnly(req);
    if (M === 'GET' && P === '/api/admin/withdrawals') {
      const st = url.searchParams.get('status') || 'pending';
      return ok({ items: db.prepare('SELECT w.*, u.email FROM withdrawals w JOIN users u ON u.id=w.user_id WHERE w.status=? ORDER BY w.id').all(st) });
    }
    if (M === 'POST' && (m = /^\/api\/admin\/withdrawals\/(\d+)$/.exec(P))) {
      const st = body.status; if (!['paid', 'rejected'].includes(st)) bad('status must be paid or rejected');
      tx(() => {
        const w = db.prepare('SELECT * FROM withdrawals WHERE id=?').get(+m[1]);
        if (!w || w.status !== 'pending') bad('Withdrawal not found or already handled.', 409);
        db.prepare('UPDATE withdrawals SET status=?, updated=? WHERE id=?').run(st, now(), w.id);
        if (st === 'rejected') credit(w.user_id, w.coins, 'Withdrawal refund', 'wdrefund:' + w.id, false);
      });
      return ok();
    }
    if (M === 'POST' && P === '/api/admin/surveys') {
      const qs = body.questions; if (!Array.isArray(qs) || !qs.length || qs.some(q => !Array.isArray(q) || typeof q[0] !== 'string' || !Array.isArray(q[1]) || q[1].length < 2)) bad('questions must be [[text,[options...]], ...]');
      const r = db.prepare('INSERT INTO surveys(title,cat,minutes,coins,questions) VALUES(?,?,?,?,?)')
        .run(str(body.title, 2, 80, 'title'), str(body.cat, 2, 30, 'category'), int(body.minutes, 1, 60), int(body.coins, 1, 100000), JSON.stringify(qs));
      return ok({ id: Number(r.lastInsertRowid) });
    }
    if (M === 'POST' && (m = /^\/api\/admin\/surveys\/(\d+)$/.exec(P))) { db.prepare('UPDATE surveys SET active=? WHERE id=?').run(body.active ? 1 : 0, +m[1]); return ok(); }
    if (M === 'POST' && (m = /^\/api\/admin\/users\/(\d+)\/ban$/.exec(P))) { db.prepare('UPDATE users SET banned=? WHERE id=?').run(body.banned ? 1 : 0, +m[1]); return ok(); }
    bad('Not found', 404);
  }

  // --- everything below needs a logged-in user ---
  if (M === 'GET' && P === '/api/leaderboard') {
    const rows = db.prepare('SELECT name, earned FROM users WHERE banned=0 ORDER BY earned DESC LIMIT 10').all();
    return ok({ items: rows.map(r => ({ name: r.name.split(' ')[0] + ' ' + (r.name.split(' ')[1] || '').slice(0, 1), earned: r.earned })) });
  }
  const u = authUser(req);

  if (M === 'GET' && P === '/api/me') return ok({ user: pub(u) });
  if (M === 'GET' && P === '/api/ledger') return ok({ items: db.prepare('SELECT delta,reason,created FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 50').all(u.id) });

  if (M === 'GET' && P === '/api/surveys') {
    const done = new Set(db.prepare('SELECT survey_id s FROM runs WHERE user_id=? AND done=1').all(u.id).map(r => r.s));
    return ok({ items: db.prepare('SELECT id,title,cat,minutes,coins FROM surveys WHERE active=1 ORDER BY id').all().map(s => ({ ...s, done: done.has(s.id) })) });
  }
  if (M === 'POST' && (m = /^\/api\/surveys\/(\d+)\/start$/.exec(P))) {
    const s = db.prepare('SELECT * FROM surveys WHERE id=? AND active=1').get(+m[1]); if (!s) bad('Survey not found.', 404);
    const run = db.prepare('SELECT done FROM runs WHERE user_id=? AND survey_id=?').get(u.id, s.id);
    if (run && run.done) bad('You already completed this survey.', 409);
    db.prepare('INSERT INTO runs(user_id,survey_id,started) VALUES(?,?,?) ON CONFLICT(user_id,survey_id) DO UPDATE SET started=excluded.started').run(u.id, s.id, Date.now());
    return ok({ survey: { id: s.id, title: s.title, coins: s.coins, questions: JSON.parse(s.questions) } });
  }
  if (M === 'POST' && (m = /^\/api\/surveys\/(\d+)\/complete$/.exec(P))) {
    const s = db.prepare('SELECT * FROM surveys WHERE id=? AND active=1').get(+m[1]); if (!s) bad('Survey not found.', 404);
    const qs = JSON.parse(s.questions), a = body.answers;
    if (!Array.isArray(a) || a.length !== qs.length || a.some((x, i) => !Number.isInteger(x) || x < 0 || x >= qs[i][1].length)) bad('Answer every question.');
    const run = db.prepare('SELECT * FROM runs WHERE user_id=? AND survey_id=?').get(u.id, s.id);
    if (!run) bad('Start the survey first.'); if (run.done) bad('You already completed this survey.', 409);
    const need = Math.max(C.minSurveySecondsFloor, qs.length * C.minSurveySecondsPerQ);
    if ((Date.now() - run.started) / 1000 < need) bad('That was too fast. Please read each question and try again.', 422);
    tx(() => {
      if (db.prepare('UPDATE runs SET done=1 WHERE user_id=? AND survey_id=? AND done=0').run(u.id, s.id).changes)
        earn(u.id, s.coins, 'Survey: ' + s.title, `survey:${u.id}:${s.id}`);
    });
    return ok({ earned: s.coins, user: pub(db.prepare('SELECT * FROM users WHERE id=?').get(u.id)) });
  }

  if (M === 'POST' && P === '/api/bonus') {
    if (u.last_bonus === today()) bad('Bonus already claimed today.', 409);
    const streak = u.last_bonus === today(1) ? u.streak + 1 : 1, b = 20 + 5 * Math.min(streak - 1, 6);
    tx(() => { credit(u.id, b, 'Daily bonus', `bonus:${u.id}:${today()}`); db.prepare('UPDATE users SET streak=?, last_bonus=? WHERE id=?').run(streak, today(), u.id); });
    return ok({ earned: b, user: pub(db.prepare('SELECT * FROM users WHERE id=?').get(u.id)) });
  }

  if (M === 'GET' && P === '/api/withdrawals') return ok({ items: db.prepare('SELECT id,method,coins,status,created FROM withdrawals WHERE user_id=? ORDER BY id DESC').all(u.id) });
  if (M === 'POST' && P === '/api/withdraw') {
    limit('wd:' + u.id, 5, 3600e3);
    const method = body.method, min = C.minWithdraw[method]; if (!min) bad('Unknown payout method.');
    const coins = int(body.coins, min, 10e6), account = str(body.account, 3, 120, 'payout details');
    if (db.prepare("SELECT COUNT(*) n FROM withdrawals WHERE user_id=? AND status='pending'").get(u.id).n >= 3) bad('You have too many pending withdrawals.', 409);
    tx(() => {
      const r = db.prepare('UPDATE users SET balance=balance-? WHERE id=? AND balance>=?').run(coins, u.id, coins);
      if (!r.changes) bad('You do not have enough coins.');
      db.prepare('INSERT INTO ledger(user_id,delta,reason,created) VALUES(?,?,?,?)').run(u.id, -coins, 'Withdrawal via ' + method, now());
      db.prepare('INSERT INTO withdrawals(user_id,method,coins,account,created) VALUES(?,?,?,?,?)').run(u.id, method, coins, account, now());
    });
    return ok({ user: pub(db.prepare('SELECT * FROM users WHERE id=?').get(u.id)) });
  }
  bad('Not found', 404);
}

// ---- static files (put your frontend in ./public) ----
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
function serveStatic(req, res, url) {
  const root = path.join(__dirname, 'public'); let f = path.normalize(path.join(root, decodeURIComponent(url.pathname)));
  if (!f.startsWith(root)) bad('Forbidden', 403);
  if (!fs.existsSync(f) || fs.statSync(f).isDirectory()) f = path.join(root, 'index.html');
  if (!fs.existsSync(f)) bad('Not found', 404);
  res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff' });
  fs.createReadStream(f).pipe(res);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const ip = (C.trustProxy && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || '?';
    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/postback/')) await api(req, res, url, ip);
    else serveStatic(req, res, url);
  } catch (e) {
    if (e instanceof HttpError) return json(res, e.status, { error: e.message });
    console.error(e); json(res, 500, { error: 'Server error' });
  }
});
if (require.main === module) server.listen(C.port, () => console.log(`Surveyra backend on http://localhost:${C.port}`));
module.exports = { server, C };
