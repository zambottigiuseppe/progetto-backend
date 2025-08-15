// index.js — REST-only + token HMAC + doppio controllo duplicati

const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

// ───────────────────────────────────────────────────────────────────────────────
// App
// ───────────────────────────────────────────────────────────────────────────────
const app = express();
app.use(cors()); // apri pure; se vuoi lista whitelist aggiungiamo origin-check
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

// ───────────────────────────────────────────────────────────────────────────────
// Firebase Admin
// ───────────────────────────────────────────────────────────────────────────────
const SA_JSON = process.env.FIREBASE_SERVICE_ACCOUNT || '{}';
let creds;
try { creds = JSON.parse(SA_JSON); } catch { creds = {}; }
if (admin.apps.length === 0) admin.initializeApp({ credential: admin.credential.cert(creds) });
const db = admin.firestore();

// ───────────────────────────────────────────────────────────────────────────────
// Email (facoltativa; se mancano le env l’invio viene saltato)
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
const emailHTML = (d) => `
  <div style="font-family:Arial,Helvetica,sans-serif;line-height:1.5">
    <h2 style="margin:0 0 10px">Registrazione garanzia ricevuta</h2>
    <ul style="margin:0;padding-left:18px">
      <li><b>Nome:</b> ${d.nome||''} ${d.cognome||''}</li>
      <li><b>Email:</b> ${d.email||'-'}</li>
      <li><b>Modello:</b> ${d.modello||'-'}</li>
      <li><b>Seriale:</b> ${d.seriale||'-'}</li>
      <li><b>Ordine:</b> ${d.orderName||d.orderId||'-'}</li>
    </ul>
  </div>`;

// ───────────────────────────────────────────────────────────────────────────────
// Token HMAC per legare prefill → registrazione
// ───────────────────────────────────────────────────────────────────────────────
const SECRET = process.env.ADMIN_API_KEY || '';                // chiave server
const PREFILL_TTL_MS = Number(process.env.PREFILL_TTL_MS || 45*60*1000); // 45 min

function safeEqHex(a,b){
  const A = Buffer.from(String(a||''), 'utf8');
  const B = Buffer.from(String(b||''), 'utf8');
  if (A.length !== B.length) {
    const n = Math.max(A.length,B.length);
    const Ap = Buffer.alloc(n,0); const Bp = Buffer.alloc(n,0);
    A.copy(Ap); B.copy(Bp);
    return crypto.timingSafeEqual(Ap,Bp);
  }
  return crypto.timingSafeEqual(A,B);
}
function createPrefillToken(orderRef, email){
  const t = Date.now();
  const e = String(email||'').toLowerCase();
  const msg = `${orderRef}|${e}|${t}`;
  const sig = crypto.createHmac('sha256', SECRET).update(msg).digest('hex');
  return `${t}.${sig}.${encodeURIComponent(orderRef)}.${encodeURIComponent(e)}`;
}
function verifyPrefillToken(token, orderRefFromBody, emailFromBody){
  if (!SECRET) return { ok:false, reason:'NO_SECRET' };
  const parts = String(token||'').split('.');
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
  const normEmailBody = String(emailFromBody   || '').trim().toLowerCase();
  const emailOk = !normEmailBody || normEmailBody === em;
  const refOk   = !normRefBody   || normRefBody   === ref;
  return { ok: emailOk && refOk, reason: emailOk ? (refOk ? 'OK' : 'ORDERREF_MISMATCH') : 'EMAIL_MISMATCH', decoded:{ t, ref, em } };
}
function pickToken(req){
  const auth = req.get('authorization') || '';
  const bear = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const list = [
    req.get('x-prefill-token') || '',
    bear,
    req.query?.token || '',
    req.body?.prefillToken || '',
    req.body?.token || ''
  ].filter(Boolean);
  const norm = list.map(t => { try { return /%[0-9A-Fa-f]{2}/.test(t) ? decodeURIComponent(t) : t; } catch { return t; }});
  return { raw:list, norm, chosen: norm[0] || '' };
}

// ───────────────────────────────────────────────────────────────────────────────
// Solo carrelli (euristica “Carrello …” + family Stewart)
// ───────────────────────────────────────────────────────────────────────────────
const STRICT_CARRELLI = /^(true|1|yes)$/i.test(String(process.env.STRICT_CARRELLI || 'true')); // tienila true per i test
const TITLE_RE = /(carrell|trolley|follow|remote|^x[0-9]+|^q[-\s]?\w+|^r1s?)/i;
const NEG_RE   = /\b(ricambi|spare|accessor(i|y|ies)|guscio|cover|ruota|wheel|batter(y|ia)|charger|caricatore|bag|sacca)\b/i;
function isCarrelloMeta({ title, productType }){
  const ttl = String(title||'').trim();
  const pty = String(productType||'').trim();
  if (/\bcarrello\b/i.test(ttl)) return true;
  if (NEG_RE.test(ttl) || NEG_RE.test(pty)) return false;
  return TITLE_RE.test(ttl) || TITLE_RE.test(pty) || /\bgolf\s*trolley\b/i.test(pty);
}

// ───────────────────────────────────────────────────────────────────────────────
// Shopify REST helpers
// ───────────────────────────────────────────────────────────────────────────────
const STORE = process.env.SHOPIFY_STORE_DOMAIN;
const TOKEN = process.env.SHOPIFY_ADMIN_API_TOKEN;
const API_VERSION = process.env.SHOPIFY_API_VERSION || '2024-07';

async function restGetOrderByName(name){
  const url = `https://${STORE}/admin/api/${API_VERSION}/orders.json?status=any&name=${encodeURIComponent(name)}`;
  const r = await fetch(url, { headers: { 'X-Shopify-Access-Token': TOKEN, 'Content-Type':'application/json' }});
  return { ok:r.ok, status:r.status, json: await r.json().catch(()=>({})) };
}
async function restGetProduct(pid){
  const url = `https://${STORE}/admin/api/${API_VERSION}/products/${pid}.json`;
  const r = await fetch(url, { headers: { 'X-Shopify-Access-Token': TOKEN, 'Content-Type':'application/json' }});
  return { ok:r.ok, status:r.status, json: await r.json().catch(()=>({})) };
}

async function orderHasCarrelloByRefEmail(refInput, emailLower){
  try {
    if (!STORE || !TOKEN) return { ok:false, reason:'CONFIG_MANCANTE' };

    const name = String(refInput||'').startsWith('#') ? refInput : `#${refInput}`;
    const or = await restGetOrderByName(name);
    if (!or.ok) return { ok:false, reason:'REST_FAIL', status: or.status };

    const order = or.json?.orders?.[0];
    if (!order) return { ok:false, reason:'ORDINE_NON_TROVATO' };

    const orderEmail = (order.email || '').toLowerCase();
    const custEmail  = (order.customer?.email || '').toLowerCase();
    if (emailLower && !(emailLower === orderEmail || emailLower === custEmail)) {
      return { ok:false, reason:'EMAIL_MISMATCH' };
    }

    // Cerca se almeno una linea è un carrello
    const items = order.line_items || [];
    let firstTitle = ''; let firstPid = null;
    for (const li of items) {
      const pid = li.product_id;
      const fallbackTitle = String(li.title || '');
      if (!firstTitle) { firstTitle = fallbackTitle; firstPid = pid || null; }

      if (!pid) {
        if (isCarrelloMeta({ title: fallbackTitle, productType:'' }))
          return { ok:true, product:{ id:null, title:fallbackTitle, type:'', vendor:'' } };
        continue;
      }
      const pr = await restGetProduct(pid);
      const P = pr.json?.product || {};
      const titleToCheck = fallbackTitle || P.title || '';
      const ptype = P.product_type || '';
      if (isCarrelloMeta({ title:titleToCheck, productType:ptype })) {
        return { ok:true, product:{ id:P.id||null, title:titleToCheck, type:ptype, vendor:P.vendor||'' } };
      }
    }
    return { ok:false, reason:'NON_CARRELLO', product:{ title:firstTitle, id:firstPid } };
  } catch (e) {
    return { ok:false, reason:'CHECK_ERROR', error:String(e?.message||e) };
  }
}

// ───────────────────────────────────────────────────────────────────────────────
// Utilities
// ───────────────────────────────────────────────────────────────────────────────
const normSerial = x => String(x||'').trim().toUpperCase().replace(/\s+/g,'');
const safeId     = x => String(x||'').trim().toUpperCase().replace(/[^A-Z0-9]+/g,'-');

// blocco rate per la registrazione
function limitByIp(max, windowMs){
  const hits = new Map();
  return (req,res,next)=>{
    const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
    const now = Date.now();
    const rec = hits.get(ip) || { count:0, reset: now+windowMs };
    if (now > rec.reset) { rec.count = 0; rec.reset = now+windowMs; }
    rec.count += 1; hits.set(ip, rec);
    if (rec.count > max) return res.status(429).json({ ok:false, error:'RATE_LIMIT' });
    next();
  };
}
const regLimiter = limitByIp(Number(process.env.RATE_LIMIT_REG_MAX || 5),
                             Number(process.env.RATE_LIMIT_REG_WINDOW || 10*60*1000));

const ENFORCE_ONE_PER_ORDER = /^(true|1|yes)$/i.test(String(process.env.ENFORCE_ONE_PER_ORDER || 'true'));

// ───────────────────────────────────────────────────────────────────────────────
// Routes
// ───────────────────────────────────────────────────────────────────────────────
app.get('/health', (_,res)=> res.json({ ok:true }));

// Prefill: verifica ordine + carrello + genera token
app.get('/shopify/prefill', async (req,res)=>{
  try {
    if (!STORE || !TOKEN) return res.status(500).json({ ok:false, error:'CONFIG_MANCANTE' });

    const orderParam = String(req.query.order || '').trim();
    const emailParam = String(req.query.email || '').trim().toLowerCase();
    if (!orderParam || !emailParam) return res.status(400).json({ ok:false, error:'PARAMETRI_MANCANTI' });

    const name = orderParam.startsWith('#') ? orderParam : `#${orderParam}`;

    const or = await restGetOrderByName(name);
    if (!or.ok) return res.status(502).json({ ok:false, error:'REST_FAIL', status: or.status });

    const order = or.json?.orders?.[0];
    if (!order) return res.status(404).json({ ok:false, error:'ORDINE_NON_TROVATO' });

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
      citta: ship.city || '',
      cap: ship.zip || '',
      provincia: ship.province || '',
      paese: ship.country || '',
      modello: line.title || '',
      dataOrdine: order.created_at || '',
      orderId: order.id,
      orderName: order.name
    };

    // Solo carrelli
    if (STRICT_CARRELLI) {
      const chk = await orderHasCarrelloByRefEmail(prefill.orderName, emailParam);
      if (!chk.ok && chk.reason === 'NON_CARRELLO') {
        return res.status(400).json({ ok:false, error:'NON_CARRELLO', product: chk.product||null });
      }
      if (!chk.ok) {
        // errori tecnico/config: 502 per distinguerli lato UI
        return res.status(502).json({ ok:false, error: chk.reason, detail: chk.error||null });
      }
    }

    const token = SECRET ? createPrefillToken(prefill.orderName, prefill.email) : null;
    return res.json({ ok:true, prefill, token, ttl: PREFILL_TTL_MS });
  } catch (e) {
    return res.status(500).json({ ok:false, error:String(e?.message||e) });
  }
});

// Registrazione garanzia
app.post('/registrazione', regLimiter, async (req,res)=>{
  try {
    const p = req.body || {};
    if (p.hp) return res.status(400).json({ ok:false, error:'BOT' });

    // token
    const tok = pickToken(req);
    const token = tok.chosen || p.prefillToken || '';
    if (SECRET) {
      if (!token) return res.status(400).json({ ok:false, error:'TOKEN_INVALIDO', reason:'MISSING' });
      const v = verifyPrefillToken(token, p.orderName||p.orderId, p.email);
      if (!v.ok) return res.status(400).json({ ok:false, error:'TOKEN_INVALIDO', reason:v.reason });
    }

    // campi minimi
    const obbl = ['email','modello','seriale','orderName'];
    const manc = obbl.filter(k=>!p[k]);
    if (manc.length) return res.status(400).json({ ok:false, error:'DATI_INSUFFICIENTI', fields:manc });

    const serialeNorm = normSerial(p.seriale);
    const orderRef    = String(p.orderName || p.orderId || '').trim();
    const regId       = `${safeId(orderRef||'SENZA-ORDINE')}__${serialeNorm}`;

    // blocco: un solo seriale per ordine (anche se cambia seriale)
    if (ENFORCE_ONE_PER_ORDER) {
      const snap = await db.collection('registrazioni')
        .where('orderName','==', orderRef)
        .limit(1).get();
      if (!snap.empty) {
        return res.status(409).json({ ok:false, error:'DUPLICATO_ORDINE' });
      }
    }

    // blocco: stesso ordine + stesso seriale
    const docRef = db.collection('registrazioni').doc(regId);
    await docRef.create({
      ...p,
      seriale: serialeNorm,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // email di conferma (se configurata)
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
    } catch (e) {
      console.error('Email fallita:', e.message);
    }

    return res.json({ ok:true, id: regId, reset:true });
  } catch (err) {
    // dup ordine+seriale
    if (err && (err.code === 6 || /ALREADY_EXISTS/i.test(String(err.message)))) {
      return res.status(409).json({ ok:false, error:'DUPLICATO' });
    }
    console.error(err);
    return res.status(500).json({ ok:false, error:String(err?.message||err) });
  }
});

// ───────────────────────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || '3000', 10);
app.listen(PORT, ()=> console.log(`✅ Server online :${PORT}`));
