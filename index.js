// index.js — REST-only + solo carrelli + blocchi annullati/duplicati

const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const admin = require('firebase-admin');
const crypto = require('crypto');

// ───────────────────────────────────────────────────────────────────────────────
// App base
// ───────────────────────────────────────────────────────────────────────────────
const app = express();
app.use(cors()); // se serve: limitare con ALLOWED_ORIGINS
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

// ───────────────────────────────────────────────────────────────────────────────
// Firebase Admin
// ───────────────────────────────────────────────────────────────────────────────
const SA_JSON = process.env.FIREBASE_SERVICE_ACCOUNT || '{}';
let creds;
try { creds = JSON.parse(SA_JSON); } catch { creds = {}; }
if (admin.apps.length === 0) {
  admin.initializeApp({ credential: admin.credential.cert(creds) });
}
const db = admin.firestore();

// ───────────────────────────────────────────────────────────────────────────────
// Token HMAC per prefill/registrazione
// ───────────────────────────────────────────────────────────────────────────────
const SECRET = process.env.ADMIN_API_KEY || '';
const PREFILL_TTL_MS = Number(process.env.PREFILL_TTL_MS || 45 * 60 * 1000); // 45 min

function safeEqHex(a, b) {
  const A = Buffer.from(String(a || ''), 'utf8');
  const B = Buffer.from(String(b || ''), 'utf8');
  if (A.length !== B.length) {
    const max = Math.max(A.length, B.length);
    const Ap = Buffer.alloc(max, 0); A.copy(Ap);
    const Bp = Buffer.alloc(max, 0); B.copy(Bp);
    return crypto.timingSafeEqual(Ap, Bp);
  }
  return crypto.timingSafeEqual(A, B);
}
function createPrefillToken(orderRef, email) {
  const t = Date.now();
  const e = (email || '').toLowerCase();
  const msg = `${orderRef}|${e}|${t}`;
  const sig = crypto.createHmac('sha256', SECRET).update(msg).digest('hex');
  return `${t}.${sig}.${encodeURIComponent(orderRef)}.${encodeURIComponent(e)}`;
}
function verifyPrefillToken(token, orderRefFromBody, emailFromBody) {
  if (!SECRET) return { ok:false, reason:'NO_SECRET' };
  const raw = String(token || '');
  const parts = raw.split('.');
  if (parts.length < 4) return { ok:false, reason:'BAD_FORMAT' };

  const [tStr, sig, refEnc, ...emailParts] = parts;
  const t = Number(tStr);
  let ref, em;
  try {
    ref = decodeURIComponent(refEnc || '');
    em  = decodeURIComponent(emailParts.join('.') || '').toLowerCase();
  } catch {
    return { ok:false, reason:'DECODE_FAIL' };
  }
  if (!t || !sig || !ref) return { ok:false, reason:'BAD_FIELDS' };
  if (Date.now() - t > PREFILL_TTL_MS) return { ok:false, reason:'EXPIRED' };

  const msg = `${ref}|${em}|${t}`;
  const expect = crypto.createHmac('sha256', SECRET).update(msg).digest('hex');
  if (!safeEqHex(sig, expect)) return { ok:false, reason:'BAD_HMAC' };

  const normRefBody   = String(orderRefFromBody || '').trim();
  const normEmailBody = String(emailFromBody || '').trim().toLowerCase();

  const emailOk = !normEmailBody || normEmailBody === em;
  const refOk   = !normRefBody   || normRefBody   === ref;

  return { ok: emailOk && refOk, reason: emailOk ? (refOk ? 'OK' : 'ORDERREF_MISMATCH') : 'EMAIL_MISMATCH', decoded: { t, ref, em } };
}
function pickToken(req) {
  const auth  = req.get('authorization') || '';
  const bear  = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const xhdr  = req.get('x-prefill-token') || '';
  const q     = req.query?.token || '';
  const b1    = req.body?.prefillToken || '';
  const b2    = req.body?.token || '';
  const candidates = [xhdr, bear, q, b1, b2].filter(Boolean);
  const norm = candidates.map(t => { try { return /%[0-9A-Fa-f]{2}/.test(t) ? decodeURIComponent(t) : t; } catch { return t; } });
  return { raw: candidates, norm, chosen: norm[0] || '' };
}

// ───────────────────────────────────────────────────────────────────────────────
// SOLO CARRELLI
// ───────────────────────────────────────────────────────────────────────────────
const STRICT_CARRELLI = /^(true|1|yes)$/i.test(String(process.env.STRICT_CARRELLI || 'false'));

// “Carrello …” in testa al titolo + famiglie note (follow/remote/x10/x9/q-…)
const TITLE_RE = /(carrell|trolley|follow|remote|^x[0-9]+|^q[-\s]?\w+|^r1s?)/i;
// parole che escludono (ricambi, accessori, gusci, ruote, batterie…)
const NEG_RE = /\b(ricambi|spare|accessor(i|y|ies)|guscio|cover|ruota|wheel|batter(y|ia)|charger|caricatore|bag|sacca)\b/i;

function isCarrelloMeta({ title, productType }) {
  const ttl = String(title || '').trim();
  const pty = String(productType || '').trim();
  if (/\bcarrello\b/i.test(ttl)) return true;      // “Carrello …” passa subito
  if (NEG_RE.test(ttl) || NEG_RE.test(pty)) return false;
  const titleOk = TITLE_RE.test(ttl);
  const typeOk  = TITLE_RE.test(pty) || /\bgolf\s*trolley\b/i.test(pty);
  return titleOk || typeOk;
}

// ───────────────────────────────────────────────────────────────────────────────
// Shopify REST helpers (global fetch: Node 18+)
// ───────────────────────────────────────────────────────────────────────────────
const API_VERSION = process.env.SHOPIFY_API_VERSION || '2024-07';
const STORE = process.env.SHOPIFY_STORE_DOMAIN;
const TOKEN = process.env.SHOPIFY_ADMIN_API_TOKEN;

async function restGetOrderByName(name) {
  const url = `https://${STORE}/admin/api/${API_VERSION}/orders.json?status=any&name=${encodeURIComponent(name)}`;
  const r = await fetch(url, { headers: { 'X-Shopify-Access-Token': TOKEN, 'Content-Type':'application/json' }});
  if (!r.ok) return { ok:false, status:r.status, json:{} };
  const json = await r.json().catch(()=>({}));
  return { ok:true, status:r.status, json };
}
async function restGetProduct(pid) {
  const url = `https://${STORE}/admin/api/${API_VERSION}/products/${pid}.json`;
  const r = await fetch(url, { headers: { 'X-Shopify-Access-Token': TOKEN, 'Content-Type':'application/json' }});
  if (!r.ok) return { ok:false, status:r.status, json:{} };
  const json = await r.json().catch(()=>({}));
  return { ok:true, status:r.status, json };
}

function guardOrderState(order) {
  if (!order) return { ok:false, reason:'ORDINE_NON_TROVATO' };
  if (order.cancelled_at) return { ok:false, reason:'ORDINE_ANNULLATO' };
  const items = order.line_items || [];
  if (!items.length) return { ok:false, reason:'ORDINE_VUOTO' };
  return { ok:true };
}

async function orderHasCarrelloByRefEmail(refInput, emailLower) {
  try {
    if (!STORE || !TOKEN) return { ok:false, reason:'CONFIG_MANCANTE' };

    const name = String(refInput || '').startsWith('#') ? refInput : `#${refInput}`;
    const or = await restGetOrderByName(name);
    if (!or.ok) return { ok:false, reason:'REST_FAIL', status: or.status };

    const order = or.json?.orders?.[0];
    const guard = guardOrderState(order);
    if (!guard.ok) return guard;

    // email match
    const orderEmail = (order.email || '').toLowerCase();
    const custEmail  = (order.customer?.email || '').toLowerCase();
    if (emailLower && !(emailLower === orderEmail || emailLower === custEmail)) {
      return { ok:false, reason:'EMAIL_MISMATCH' };
    }

    const items = order.line_items || [];
    let firstTitle = '';
    let firstPid = null;

    for (const line of items) {
      const pid = line.product_id;
      const titleFallback = String(line.title || '');
      if (!firstTitle) { firstTitle = titleFallback; firstPid = pid || null; }

      // Se non c'è product_id, decidi dal titolo della riga
      if (!pid) {
        if (isCarrelloMeta({ title: titleFallback, productType: '' })) {
          return { ok:true, product:{ id:null, title:titleFallback, type:'', vendor:'' } };
        }
        continue;
      }

      const pr = await restGetProduct(pid);
      const P = pr.json?.product || {};
      const titleToCheck = titleFallback || P.title || '';
      const ptype = P.product_type || '';

      if (isCarrelloMeta({ title: titleToCheck, productType: ptype })) {
        return {
          ok:true,
          product: { id:P.id || null, title:titleToCheck, type:ptype, vendor:P.vendor || '' }
        };
      }
    }

    return { ok:false, reason:'NON_CARRELLO', product:{ title:firstTitle, id:firstPid } };
  } catch (e) {
    return { ok:false, reason:'CHECK_ERROR', error: String(e?.message || e) };
  }
}

// ───────────────────────────────────────────────────────────────────────────────
// Nodemailer (OVH)
// ───────────────────────────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT || 465),
  secure: String(process.env.EMAIL_SECURE || 'true') === 'true',
  auth: (process.env.EMAIL_USER && process.env.EMAIL_PASS)
    ? { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
    : undefined,
});
const EMAIL_FROM  = process.env.EMAIL_FROM || process.env.EMAIL_USER || '';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || '';

function emailHTML(d) {
  return `<div style="font-family:Arial,sans-serif;line-height:1.5">
    <h2>Registrazione garanzia ricevuta</h2>
    <ul>
      <li><b>Nome:</b> ${d.nome||''} ${d.cognome||''}</li>
      <li><b>Email:</b> ${d.email||'-'}</li>
      <li><b>Modello:</b> ${d.modello||'-'}</li>
      <li><b>Seriale:</b> ${d.seriale||'-'}</li>
      <li><b>Ordine:</b> ${d.orderName||d.orderId||'-'}</li>
    </ul>
  </div>`;
}

// ───────────────────────────────────────────────────────────────────────────────
// Utils
// ───────────────────────────────────────────────────────────────────────────────
const normSerial = x => String(x||'').trim().toUpperCase().replace(/\s+/g,'');
const safeId     = x => String(x||'').trim().toUpperCase().replace(/[^A-Z0-9]+/g,'-');
function limitByIp(max, windowMs) {
  const hits = new Map();
  return (req, res, next) => {
    const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
    const now = Date.now();
    const rec = hits.get(ip) || { count: 0, reset: now + windowMs };
    if (now > rec.reset) { rec.count = 0; rec.reset = now + windowMs; }
    rec.count += 1; hits.set(ip, rec);
    if (rec.count > max) return res.status(429).json({ ok:false, error:'RATE_LIMIT' });
    next();
  };
}
const regLimiter = limitByIp(Number(process.env.RATE_LIMIT_REG_MAX || 5),
                             Number(process.env.RATE_LIMIT_REG_WINDOW || 10 * 60 * 1000));

// ───────────────────────────────────────────────────────────────────────────────
// ROUTES
// ───────────────────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ ok:true }));

// Prefill (REST + enforce SOLO CARRELLI se STRICT_CARRELLI=true)
app.get('/shopify/prefill', async (req, res) => {
  try {
    if (!STORE || !TOKEN) return res.status(500).json({ ok:false, error:'CONFIG_MANCANTE' });

    const orderParam = String(req.query.order || '').trim();
    const emailParam = String(req.query.email || '').trim().toLowerCase();
    if (!orderParam || !emailParam) return res.status(400).json({ ok:false, error:'PARAMETRI_MANCANTI' });

    const name = orderParam.startsWith('#') ? orderParam : `#${orderParam}`;

    // 1) Ordine via REST
    const or = await restGetOrderByName(name);
    if (!or.ok) return res.status(502).json({ ok:false, error:'REST_FAIL' });

    const order = or.json?.orders?.[0];
    const guard = guardOrderState(order);
    if (!guard.ok) return res.status(400).json({ ok:false, error: guard.reason });

    const orderEmail = (order.email || '').toLowerCase();
    const custEmail  = (order.customer?.email || '').toLowerCase();
    if (!(emailParam === orderEmail || emailParam === custEmail)) {
      return res.status(400).json({ ok:false, error:'EMAIL_MISMATCH' });
    }

    const ship = order.shipping_address || {};
    const cust = order.customer || {};
    const line = order.line_items?.[0] || {};

    const prefill = {
      nome: ship.first_name || cust.first_name || '',
      cognome: ship.last_name || cust.last_name || '',
      email: order.email || cust.email || '',
      telefono: ship.phone || cust.phone || order.phone || '',
      indirizzo: [ship.address1, ship.address2].filter(Boolean).join(', '),
      citta: ship.city || '', cap: ship.zip || '', provincia: ship.province || '', paese: ship.country || '',
      modello: line.title || '',
      dataOrdine: order.created_at || '',
      orderId: order.id, orderName: order.name
    };

    // 2) Token
    const token = SECRET ? createPrefillToken(prefill.orderName || prefill.orderId, prefill.email) : null;

    // 3) Solo carrelli
    if (STRICT_CARRELLI) {
      const chk = await orderHasCarrelloByRefEmail(prefill.orderName || prefill.orderId, emailParam);
      if (!chk.ok && chk.reason === 'NON_CARRELLO') {
        return res.status(400).json({ ok:false, error:'NON_CARRELLO', product: chk.product || null });
      }
      if (!chk.ok && chk.reason !== 'NON_CARRELLO') {
        return res.status(502).json({ ok:false, error: chk.reason });
      }
    }

    return res.json({ ok:true, prefill, token, ttl: PREFILL_TTL_MS });
  } catch (err) {
    return res.status(500).json({ ok:false, error: String(err?.message || err) });
  }
});

// Registrazione
app.post('/registrazione', regLimiter, async (req, res) => {
  try {
    const p = req.body || {};
    if (p.hp) return res.status(400).json({ ok:false, error:'BOT' });

    // --- Token pick + verifica ---
    const tok = pickToken(req);
    const token = tok.chosen || p.prefillToken || '';
    const orderRef = p.orderName || p.orderId || '';

    if (SECRET) {
      if (!token) return res.status(400).json({ ok:false, error:'PREFILL_OBBLIGATORIO' });
      const v = verifyPrefillToken(token, orderRef, p.email);
      if (!v.ok) {
        return res.status(400).json({
          ok:false, error:'TOKEN_INVALIDO',
          reason: v.reason, decoded: v.decoded,
          provided: { orderRef, email: (p.email || '').toLowerCase() }
        });
      }
      // Solo carrelli / stato ordine (e-mail dal token)
      if (STRICT_CARRELLI) {
        const ref = (v.decoded?.ref || orderRef || '').trim();
        const em  = (v.decoded?.em || p.email || '').toLowerCase().trim();
        const chk = await orderHasCarrelloByRefEmail(ref, em);
        if (!chk.ok) {
          return res.status(400).json({ ok:false, error: chk.reason, details: chk.product || null });
        }
      }
    }

    // campi minimi
    const obbligatori = ['email','modello','seriale'];
    const mancanti = obbligatori.filter(k => !p[k]);
    if (mancanti.length) return res.status(400).json({ ok:false, error:'DATI_INSUFFICIENTI', fields:mancanti });

    const serialeNorm = normSerial(p.seriale);
    const orderRefNorm = String(orderRef || 'SENZA-ORDINE').trim();
    const regId = `${safeId(orderRefNorm)}__${serialeNorm}`;

    // 🔒 blocco 1: già esiste una registrazione per lo stesso ordine (qualsiasi seriale)
    const alreadyForOrder = await db.collection('registrazioni')
      .where('orderRef', '==', orderRefNorm).limit(1).get();
    if (!alreadyForOrder.empty) {
      return res.status(409).json({ ok:false, error:'DUPLICATO_ORDINE' });
    }

    // 🔒 blocco 2: id ordine+seriale (catch ALREADY_EXISTS in race)
    const docRef = db.collection('registrazioni').doc(regId);
    await docRef.create({
      ...p,
      seriale: serialeNorm,
      orderRef: orderRefNorm,
      emailLower: String(p.email || '').toLowerCase(),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
    await db.collection('registrazioni_log').add({
      regId, orderRef: orderRefNorm, seriale: serialeNorm,
      ip, ua: req.headers['user-agent'] || '',
      origin: req.headers['origin'] || '',
      when: admin.firestore.FieldValue.serverTimestamp(),
      ok: true
    });

    try {
      if (transporter.options.host && transporter.options.auth) {
        await transporter.sendMail({
          from: EMAIL_FROM,
          to: p.email,
          bcc: ADMIN_EMAIL || undefined,
          subject: 'Conferma registrazione garanzia',
          html: emailHTML({ ...p, seriale: serialeNorm }),
        });
      }
    } catch (e) { console.error('Email fallita:', e.message); }

    return res.json({ ok:true, id: regId, reset: true });
  } catch (err) {
    if (err && (err.code === 6 || /ALREADY_EXISTS/i.test(String(err.message)))) {
      return res.status(409).json({ ok:false, error:'DUPLICATO' });
    }
    console.error(err);
    return res.status(500).json({ ok:false, error: String(err?.message || err) });
  }
});

// ───────────────────────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || '3000', 10);
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
