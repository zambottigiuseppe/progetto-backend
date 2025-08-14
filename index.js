// index.js
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const admin = require('firebase-admin');
const crypto = require('crypto');

// ───────────────────────────────────────────────────────────────────────────────
// App & parsers
// ───────────────────────────────────────────────────────────────────────────────
const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

// ───────────────────────────────────────────────────────────────────────────────
/** Security headers (API-only) */
// ───────────────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('Referrer-Policy', 'no-referrer');
  res.set('X-DNS-Prefetch-Control', 'off');
  res.set('Content-Security-Policy', "default-src 'none'");
  next();
});

// ───────────────────────────────────────────────────────────────────────────────
/** CORS con allowlist via env ALLOWED_ORIGINS */
// ───────────────────────────────────────────────────────────────────────────────
const ALLOWED = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true); // consenti curl/postman
    cb(null, ALLOWED.includes(origin));
  },
  credentials: false
}));

// ───────────────────────────────────────────────────────────────────────────────
/** Rate limit in-memory */
// ───────────────────────────────────────────────────────────────────────────────
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
app.use(limitByIp(Number(process.env.RATE_LIMIT_MAX || 60),
                  Number(process.env.RATE_LIMIT_WINDOW || 10 * 60 * 1000)));

const regLimiter = limitByIp(Number(process.env.RATE_LIMIT_REG_MAX || 5),
                             Number(process.env.RATE_LIMIT_REG_WINDOW || 10 * 60 * 1000));

// ───────────────────────────────────────────────────────────────────────────────
/** Email (OVH) */
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

// ───────────────────────────────────────────────────────────────────────────────
/** Firebase Admin */
// ───────────────────────────────────────────────────────────────────────────────
const SA_PATH = process.env.FIREBASE_SERVICE_ACCOUNT_PATH;
const SA_JSON = process.env.FIREBASE_SERVICE_ACCOUNT;
let creds;
try {
  if (SA_JSON) creds = JSON.parse(SA_JSON);
  else if (SA_PATH) creds = require(SA_PATH);
  else throw new Error('Config Firebase mancante: imposta FIREBASE_SERVICE_ACCOUNT (consigliato) o FIREBASE_SERVICE_ACCOUNT_PATH.');
} catch (e) {
  console.error('Errore credenziali Firebase:', e.message);
  throw e;
}
if (admin.apps.length === 0) admin.initializeApp({ credential: admin.credential.cert(creds) });
const db = admin.firestore();

// ───────────────────────────────────────────────────────────────────────────────
/** Token HMAC per prefill */
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

  return {
    ok: emailOk && refOk,
    reason: emailOk ? (refOk ? 'OK' : 'ORDERREF_MISMATCH') : 'EMAIL_MISMATCH',
    decoded: { t, ref, em }
  };
}

function pickToken(req) {
  const auth  = req.get('authorization') || '';
  const bear  = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const xhdr  = req.get('x-prefill-token') || '';
  const q     = req.query?.token || '';
  const b1    = req.body?.prefillToken || '';
  const b2    = req.body?.token || '';
  const candidates = [xhdr, bear, q, b1, b2].filter(Boolean);
  const norm = candidates.map(t => {
    try { return /%[0-9A-Fa-f]{2}/.test(t) ? decodeURIComponent(t) : t; }
    catch { return t; }
  });
  return { raw: candidates, norm, chosen: norm[0] || '' };
}

// ───────────────────────────────────────────────────────────────────────────────
/** Solo CARRELLI (config + helpers) */
// ───────────────────────────────────────────────────────────────────────────────
const STRICT_CARRELLI = /^(true|1|yes)$/i.test(String(process.env.STRICT_CARRELLI || 'false'));

// Titoli “positivi” tipici dei carrelli; filtro “negativo” per ricambi/accessori
const TITLE_RE = /(trolley|carrell|^x[0-9]{1,2}\b|^q[-\s]?\w+|follow|remote)/i;
const NEG_RE   = /(ricambi|spare|accessor(i|y|ies)|guscio|cover|ruota|wheel|batter(y|ia)|charger|caricatore|bag|sacca)/i;

function isCarrelloMeta({ title, productType }) {
  const ttl = String(title || '');
  if (NEG_RE.test(ttl)) return false; // ricambi/accessori → NO
  const titleOk = TITLE_RE.test(ttl);
  const t = String(productType || '');
  const typeOk  = /\btrolley\b/i.test(t) || /\bgolf\s*trolley\b/i.test(t);
  return titleOk || typeOk;
}

// fetch JSON con timeout hard (12s)
async function fetchJsonWithTimeout(url, opts = {}, ms = 12000) {
  const ac = new AbortController();
  const to = setTimeout(() => ac.abort(new Error('TIMEOUT')), ms);
  try {
    const r = await fetch(url, { ...opts, signal: ac.signal });
    const j = await r.json().catch(() => ({}));
    return { ok: r.ok, status: r.status, json: j };
  } finally { clearTimeout(to); }
}

// Controlla se l'ordine contiene almeno un carrello (GraphQL una sola chiamata)
async function orderHasCarrelloByRefEmail(refInput, emailLower) {
  try {
    const STORE = process.env.SHOPIFY_STORE_DOMAIN;
    const TOKEN = process.env.SHOPIFY_ADMIN_API_TOKEN;
    const API_VERSION = process.env.SHOPIFY_API_VERSION || '2024-07';
    if (!STORE || !TOKEN) return { ok:false, reason:'CONFIG_MANCANTE' };

    const name = String(refInput || '').startsWith('#') ? refInput : `#${refInput}`;
    const gqlQuery = `
      query($first:Int!, $query:String!) {
        orders(first:$first, query:$query, sortKey:CREATED_AT, reverse:true) {
          edges { node {
            id name email
            customer { email }
            lineItems(first:25) {
              edges { node {
                title
                product { id productType vendor title }
              } }
            }
          } }
        }
      }`;
    const search = `name:${name} AND email:${emailLower || '*'}`;
    const g = await fetchJsonWithTimeout(
      `https://${STORE}/admin/api/${API_VERSION}/graphql.json`,
      {
        method: 'POST',
        headers: { 'X-Shopify-Access-Token': TOKEN, 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: gqlQuery, variables: { first: 1, query: search } })
      },
      12000
    );
    if (!g.ok) return { ok:false, reason:'GRAPHQL_FAIL', status:g.status };

    const order = g.json?.data?.orders?.edges?.[0]?.node;
    if (!order) return { ok:false, reason:'ORDINE_NON_TROVATO' };

    const orderEmail = (order.email || '').toLowerCase();
    const custEmail  = (order.customer?.email || '').toLowerCase();
    if (emailLower && !(emailLower === orderEmail || emailLower === custEmail)) {
      return { ok:false, reason:'EMAIL_MISMATCH' };
    }

    const edges = order.lineItems?.edges || [];
    for (const e of edges) {
      const li   = e?.node || {};
      const prod = li.product || {};
      if (isCarrelloMeta({ title: li.title || prod.title, productType: prod.productType })) {
        return {
          ok: true,
          product: {
            id: prod.id || null,
            title: li.title || prod.title || '',
            type: prod.productType || '',
            vendor: prod.vendor || ''
          }
        };
      }
    }
    const firstTitle = edges[0]?.node?.title || '';
    const firstPid   = edges[0]?.node?.product?.id || null;
    return { ok:false, reason:'NON_CARRELLO', product: { title:firstTitle, id:firstPid } };
  } catch (e) {
    const msg = String(e && e.message || e || '');
    if (msg.includes('TIMEOUT')) return { ok:false, reason:'CHECK_TIMEOUT' };
    return { ok:false, reason:'CHECK_ERROR', error: msg };
  }
}

// ───────────────────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ ok: true }));

// ───────────────────────────────────────────────────────────────────────────────
/** Shopify: prefill (+ enforcement SOLO CARRELLI se abilitato) */
// ───────────────────────────────────────────────────────────────────────────────
app.get('/shopify/prefill', async (req, res) => {
  try {
    const STORE = process.env.SHOPIFY_STORE_DOMAIN;
    const TOKEN = process.env.SHOPIFY_ADMIN_API_TOKEN;
    const API_VERSION = process.env.SHOPIFY_API_VERSION || '2024-07';

    const orderParam = String(req.query.order || '').trim();
    const emailParam = String(req.query.email || '').trim().toLowerCase();
    if (!STORE || !TOKEN)  return res.status(500).json({ ok:false, error:'CONFIG_MANCANTE' });
    if (!orderParam || !emailParam) return res.status(400).json({ ok:false, error:'PARAMETRI_MANCANTI' });

    const name = orderParam.startsWith('#') ? orderParam : `#${orderParam}`;
    let prefill = null;

    // 1) REST per prefill veloce
    const restURL = `https://${STORE}/admin/api/${API_VERSION}/orders.json?status=any&name=${encodeURIComponent(name)}`;
    const r = await fetch(restURL, { headers: { 'X-Shopify-Access-Token': TOKEN, 'Content-Type':'application/json' }});
    if (r.ok) {
      const data = await r.json();
      const order = data?.orders?.[0];
      if (order) {
        const orderEmail = (order.email || '').toLowerCase();
        const custEmail  = (order.customer?.email || '').toLowerCase();
        if (emailParam === orderEmail || emailParam === custEmail) {
          const ship = order.shipping_address || {};
          const cust = order.customer || {};
          const line = order.line_items?.[0] || {};
          prefill = {
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
        }
      }
    }

    // 2) Fallback GraphQL se REST non ha riempito
    if (!prefill) {
      const gqlQuery = `
        query($first:Int!, $query:String!) {
          orders(first:$first, query:$query, sortKey:CREATED_AT, reverse:true) {
            edges { node {
              id name email createdAt
              customer { email firstName lastName phone }
              shippingAddress { firstName lastName address1 address2 city zip province country phone }
              lineItems(first:1){ edges{ node{ title } } }
            } }
          }
        }`;
      const search = `name:${name} AND email:${emailParam}`;
      const g = await fetch(`https://${STORE}/admin/api/${API_VERSION}/graphql.json`, {
        method:'POST',
        headers:{ 'X-Shopify-Access-Token':TOKEN, 'Content-Type':'application/json' },
        body: JSON.stringify({ query: gqlQuery, variables:{ first:1, query:search } })
      });
      const body = await g.json();
      const edge = body?.data?.orders?.edges?.[0]?.node;
      if (edge) {
        const ship = edge.shippingAddress || {};
        prefill = {
          nome: ship.firstName || edge.customer?.firstName || '',
          cognome: ship.lastName || edge.customer?.lastName || '',
          email: edge.email || edge.customer?.email || '',
          telefono: ship.phone || edge.customer?.phone || '',
          indirizzo: [ship.address1, ship.address2].filter(Boolean).join(', '),
          citta: ship.city || '', cap: ship.zip || '', provincia: ship.province || '', paese: ship.country || '',
          modello: edge.lineItems?.edges?.[0]?.node?.title || '',
          dataOrdine: edge.createdAt || '',
          orderId: edge.id, orderName: edge.name
        };
      }
    }

    if (!prefill) return res.status(404).json({ ok:false, error:'ORDINE_NON_TROVATO' });

    const orderRef = prefill.orderName || prefill.orderId;
    const token = SECRET ? createPrefillToken(orderRef, prefill.email) : null;

    // ENFORCE solo carrelli
    if (STRICT_CARRELLI) {
      const chk = await orderHasCarrelloByRefEmail(orderRef, (prefill.email || '').toLowerCase());
      if (!chk.ok) {
        console.warn('[PREFILL_NON_CARRELLO]', { ref: orderRef, email: prefill.email, reason: chk.reason, product: chk.product });
        return res.status(400).json({ ok:false, error:'NON_CARRELLO', product: chk.product || null });
      }
    }

    return res.json({ ok:true, prefill, token, ttl: PREFILL_TTL_MS });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok:false, error: err.message });
  }
});

// ───────────────────────────────────────────────────────────────────────────────
/** Email template */
// ───────────────────────────────────────────────────────────────────────────────
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

const normSerial = x => String(x||'').trim().toUpperCase().replace(/\s+/g,'');
const safeId     = x => String(x||'').trim().toUpperCase().replace(/[^A-Z0-9]+/g,'-');

// ───────────────────────────────────────────────────────────────────────────────
/** Registrazione */
// ───────────────────────────────────────────────────────────────────────────────
app.post('/registrazione', regLimiter, async (req, res) => {
  try {
    const p = req.body || {};
    if (p.hp) return res.status(400).json({ ok:false, error:'BOT' });

    const orderRef = p.orderName || p.orderId || '';

    // Token + log debug
    const tok = pickToken(req);
    console.log('[REG]', new Date().toISOString(), {
      origin: req.get('origin'),
      token_raw: tok.raw,
      token_norm: tok.norm,
      chosen: tok.chosen,
      orderRef, email: p.email, seriale: p.seriale
    });

    if (SECRET) {
      const token = tok.chosen || p.prefillToken || '';
      if (!token) return res.status(400).json({ ok:false, error:'PREFILL_OBBLIGATORIO' });
      const v = verifyPrefillToken(token, orderRef, p.email);
      if (!v.ok) {
        console.warn('[TOKEN_INVALIDO]', {
          reason: v.reason, decoded: v.decoded,
          provided: { orderRef, email: (p.email || '').toLowerCase() }
        });
        return res.status(400).json({
          ok:false, error:'TOKEN_INVALIDO',
          reason: v.reason, decoded: v.decoded,
          provided: { orderRef, email: (p.email || '').toLowerCase() }
        });
      }
      if (STRICT_CARRELLI) {
        const ref = (v.decoded?.ref || orderRef || '').trim();
        const em  = (v.decoded?.em || p.email || '').toLowerCase().trim();
        const chk = await orderHasCarrelloByRefEmail(ref, em);
        if (!chk.ok) {
          console.warn('[NON_CARRELLO]', { ref, em, reason: chk.reason, details: chk.product });
          return res.status(400).json({ ok:false, error: chk.reason, details: chk.product || null });
        }
      }
    }

    const obbligatori = ['email','modello','seriale'];
    const mancanti = obbligatori.filter(k => !p[k]);
    if (mancanti.length) return res.status(400).json({ ok:false, error:'DATI_INSUFFICIENTI', fields:mancanti });

    const serialeNorm = normSerial(p.seriale);
    const regId = `${safeId(orderRef || 'SENZA-ORDINE')}__${serialeNorm}`;
    const docRef = db.collection('registrazioni').doc(regId);

    await docRef.create({
      ...p,
      seriale: serialeNorm,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
    await db.collection('registrazioni_log').add({
      regId, orderRef, seriale: serialeNorm,
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
      try {
        const p = req.body || {};
        const orderRef = p.orderName || p.orderId || '';
        const serialeNorm = normSerial(p.seriale);
        const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
        await db.collection('registrazioni_log').add({
          regId: `${safeId(orderRef || 'SENZA-ORDINE')}__${serialeNorm}`,
          orderRef, seriale: serialeNorm,
          ip, ua: req.headers['user-agent'] || '',
          origin: req.headers['origin'] || '',
          when: admin.firestore.FieldValue.serverTimestamp(),
          ok: false, error: 'DUPLICATO'
        });
      } catch(_) {}
      return res.status(409).json({ ok:false, error:'DUPLICATO' });
    }
    console.error(err);
    return res.status(500).json({ ok:false, error: err.message });
  }
});

// ───────────────────────────────────────────────────────────────────────────────
/** Debug token (per test) */
// ───────────────────────────────────────────────────────────────────────────────
app.post('/debug/token-check', (req, res) => {
  const b = req.body || {};
  const hdr = req.get('x-prefill-token') || (req.get('authorization') || '').replace(/^Bearer\s+/i, '') || '';
  const tok = b.token || b.prefillToken || req.query.token || hdr || '';
  const orderRef = b.orderRef || b.orderName || b.orderId || req.query.orderRef || req.query.orderName || req.query.orderId || '';
  const email = (b.email || req.query.email || '').toLowerCase();
  const v = verifyPrefillToken(tok, orderRef, email);
  res.json({ ok: v.ok, reason: v.reason, decoded: v.decoded, provided: { orderRef, email } });
});

// ───────────────────────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT, 10);
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
