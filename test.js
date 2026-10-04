'use strict';
// Run: node test.js   (starts its own server on a temp database)
const os = require('node:os'), fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'sv-'));
process.env.ADMIN_KEY = 'adminkey123'; process.env.POSTBACK_SECRET_TESTP = 'sekret';
process.env.SURVEY_SEC_FLOOR = '2'; process.env.SURVEY_SEC_PER_Q = '1';
const { server } = require('./server.js');
let pass = 0, fail = 0;
const t = (name, cond) => { cond ? pass++ : fail++; console.log((cond ? 'PASS ' : 'FAIL ') + name); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

server.listen(0, async () => {
  const base = 'http://localhost:' + server.address().port;
  const mk = () => { let ck = ''; return async (m, p, b, h = {}) => {
    const r = await fetch(base + p, { method: m, headers: { 'Content-Type': 'application/json', cookie: ck, ...h }, body: b ? JSON.stringify(b) : undefined });
    const sc = r.headers.get('set-cookie'); if (sc) ck = sc.split(';')[0];
    const txt = await r.text(); let j; try { j = JSON.parse(txt); } catch { j = { raw: txt }; } return { s: r.status, ...j }; }; };
  const A = mk(), B = mk(), anon = mk();

  let r = await A('POST', '/api/signup', { name: 'Test User', email: 'a@x.com', password: 'secret1' });
  t('signup gives welcome bonus', r.s === 200 && r.user.coins === 50);
  r = await A('POST', '/api/signup', { name: 'Dup', email: 'A@x.com', password: 'secret1' });
  t('duplicate email rejected', r.s === 409);
  t('unauthenticated /me rejected', (await anon('GET', '/api/me')).s === 401);
  t('wrong password rejected', (await anon('POST', '/api/login', { email: 'a@x.com', password: 'nope123' })).s === 401);

  const me = (await A('GET', '/api/me')).user;
  r = await B('POST', '/api/signup', { name: 'Friend Two', email: 'b@x.com', password: 'secret2', ref: me.code });
  t('signup with referral', r.s === 200);

  r = await A('GET', '/api/surveys'); const sv = r.items[0];
  t('lists surveys', r.s === 200 && r.items.length >= 3 && !sv.done);
  t('complete before start rejected', (await A('POST', `/api/surveys/${sv.id}/complete`, { answers: [0, 0, 0] })).s === 400);
  r = await A('POST', `/api/surveys/${sv.id}/start`); t('start returns questions', r.survey.questions.length === 3);
  t('speeding rejected', (await A('POST', `/api/surveys/${sv.id}/complete`, { answers: [0, 0, 0] })).s === 422);
  t('bad answers rejected', (await A('POST', `/api/surveys/${sv.id}/complete`, { answers: [9, 0, 0] })).s === 400);
  await sleep(3200);
  r = await A('POST', `/api/surveys/${sv.id}/complete`, { answers: [0, 1, 2] });
  t('survey credits coins', r.s === 200 && r.user.coins === 50 + sv.coins);
  t('survey cannot be repeated', (await A('POST', `/api/surveys/${sv.id}/complete`, { answers: [0, 1, 2] })).s === 409);
  t('referrer commission paid', (await B('GET', '/api/me')).user.coins === 50);   // friend B unaffected; commission goes to inviter A
  r = await A('POST', '/api/bonus'); t('daily bonus', r.s === 200 && r.earned === 20);
  t('bonus once per day', (await A('POST', '/api/bonus')).s === 409);

  // referral: B earns, A gets 10%
  const before = (await A('GET', '/api/me')).user.coins;
  const sv2 = (await B('GET', '/api/surveys')).items[1];
  await B('POST', `/api/surveys/${sv2.id}/start`); await sleep(3200);
  await B('POST', `/api/surveys/${sv2.id}/complete`, { answers: [0, 0, 0] });
  t('inviter gets 10% commission', (await A('GET', '/api/me')).user.coins === before + Math.floor(sv2.coins / 10));

  // provider postback
  const q = { user_id: me.id, trans_id: 'T1', amount: 200, status: 'completed' };
  q.hash = crypto.createHmac('sha256', 'sekret').update(`${q.user_id}|${q.trans_id}|${q.amount}|${q.status}`).digest('hex');
  const qs = '?' + new URLSearchParams(q);
  const c0 = (await A('GET', '/api/me')).user.coins;
  t('postback bad signature rejected', (await anon('GET', '/postback/testp' + qs.replace(/hash=\w+/, 'hash=bad'))).s === 403);
  t('postback credits', (await anon('GET', '/postback/testp' + qs)).s === 200 && (await A('GET', '/api/me')).user.coins === c0 + 200);
  await anon('GET', '/postback/testp' + qs);
  t('postback is idempotent', (await A('GET', '/api/me')).user.coins === c0 + 200);
  const qr = { ...q, status: 'reversed' }; qr.hash = crypto.createHmac('sha256', 'sekret').update(`${qr.user_id}|${qr.trans_id}|${qr.amount}|${qr.status}`).digest('hex');
  await anon('GET', '/postback/testp?' + new URLSearchParams(qr));
  t('postback reversal deducts', (await A('GET', '/api/me')).user.coins === c0);

  // withdrawals
  t('withdraw below minimum rejected', (await A('POST', '/api/withdraw', { method: 'bKash', coins: 100, account: '01700000000' })).s === 400);
  t('withdraw more than balance rejected', (await A('POST', '/api/withdraw', { method: 'bKash', coins: 999999, account: '01700000000' })).s === 400);
  await anon('GET', '/postback/testp?' + new URLSearchParams((() => { const x = { user_id: me.id, trans_id: 'T2', amount: 1000, status: 'completed' }; x.hash = crypto.createHmac('sha256', 'sekret').update(`${x.user_id}|${x.trans_id}|${x.amount}|${x.status}`).digest('hex'); return x; })()));
  const bal = (await A('GET', '/api/me')).user.coins;
  r = await A('POST', '/api/withdraw', { method: 'bKash', coins: 500, account: '01700000000' });
  t('withdraw deducts balance', r.s === 200 && r.user.coins === bal - 500);
  t('admin endpoint needs key', (await A('GET', '/api/admin/withdrawals')).s === 403);
  const H = { 'x-admin-key': 'adminkey123' };
  const list = await anon('GET', '/api/admin/withdrawals', null, H); t('admin lists pending', list.items.length === 1);
  t('admin reject refunds', (await anon('POST', `/api/admin/withdrawals/${list.items[0].id}`, { status: 'rejected' }, H)).s === 200 && (await A('GET', '/api/me')).user.coins === bal);
  t('cannot handle twice', (await anon('POST', `/api/admin/withdrawals/${list.items[0].id}`, { status: 'paid' }, H)).s === 409);
  t('leaderboard works', (await A('GET', '/api/leaderboard')).items.length >= 2);

  console.log(`\n${pass} passed, ${fail} failed`); server.close(); process.exit(fail ? 1 : 0);
});
