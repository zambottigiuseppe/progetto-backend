// index.js — Stewart Garanzia (pulito, completo)
// ──────────────────────────────────────────────────────
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('node:crypto');
const admin = require('firebase-admin');

// opzionale: se esiste, uso il tuo sender esterno per email "nuovo"
let sendConfirmationEmail = null;
try { sendConfirmationEmail = require('./emailSender'); } catch { /* opzionale */ }

const app = express();
app.set('trust proxy', 1);
const port = process.env.PORT || 3000;

// ── Firebase Admin: ENV su Render, file locale in dev
let serviceAccount;
if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
} else if (process.env.FIREBASE_SERVICE_ACCOUNT_PATH) {
  serviceAccount = require(path.resolve(__dirname, process.env.FIREBASE_SERVICE_ACCOUNT_PATH));
} else {
  serviceAccount = require(path.join(__dirname, 'serviceAccountKey.json'));
}
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();
db.settings({ ignoreUndefinedProperties: true });

const ts = () => admin.firestore.FieldValue.serverTimestamp();

// ── Middleware base
app.use(cors({
  origin: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-key', 'x-api-key']
}));
app.use(express.json({ limit: '1mb' }));

// Preflight utili
['/registrazione','/admin/registrazioni','/admin/purge-registrazioni',
 '/auth/unlock','/permute/ritiro','/usato/vendita','/carrelli/lookup',
 '/shopify/prefill'
].forEach(p => app.options(p, cors()));

// ── Static per immagini email
app.use('/email-assets/images', express.static(
  path.join(__dirname, 'email-assets', 'images')
));

// ──────────────────────────────────────────────────────
//  UTILS: token firmato (HS256) + adminAuth
// ──────────────────────────────────────────────────────
const ADMIN_UNLOCK_KEY = process.env.ADMIN_UNLOCK_KEY || process.env.ADMIN_API_KEY || '';
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || ADMIN_UNLOCK_KEY;

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}
function sign(data, secret) {
  return crypto.createHmac('sha256', secret).update(data).digest('base64url');
}
function signToken(payload = {}, expiresInSec = 60 * 30) { // default 30 min
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const body = { iat: now, exp: now + expiresInSec, ...payload };
  const part1 = b64url(header);
  const part2 = b64url(body);
  const sig = sign(`${part1}.${part2}`, ADMIN_JWT_SECRET);
  return `${part1}.${part2}.${sig}`;
}
function verifyToken(token) {
  const [p1, p2, sig] = String(token || '').split('.');
  if (!p1 || !p2 || !sig) throw new Error('bad_token');
  const check = sign(`${p1}.${p2}`, ADMIN_JWT_SECRET);
  if (check !== sig) throw new Error('bad_signature');
  const payload = JSON.parse(Buffer.from(p2, 'base64url').toString('utf8'));
  const now = Math.floor(Date.now() / 1000);
  if (!payload.exp || payload.exp < now) throw new Error('expired');
  return payload;
}

// Accetta: Authorization: Bearer <JWT>  oppure  x-admin-key: <ADMIN_UNLOCK_KEY>
function adminAuth(req, res, next) {
  try {
    const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
    const xkey = req.headers['x-admin-key'] || req.query.key;
    if (xkey && ADMIN_UNLOCK_KEY && xkey === ADMIN_UNLOCK_KEY) return next(); // scorciatoia utile nei test
    if (!bearer) return res.status(401).json({ error: 'no_token' });
    verifyToken(bearer);
    return next();
  } catch (e) {
    return res.status(401).json({ error: 'unauthorized' });
  }
}

// ──────────────────────────────────────────────────────
//  1) AUTH UNLOCK (niente dealer key nei form)
// ──────────────────────────────────────────────────────
app.post('/auth/unlock', (req, res) => {
  try {
    if (!ADMIN_UNLOCK_KEY) return res.status(500).json({ error: 'ADMIN_UNLOCK_KEY non configurata' });
    const bodyKey = req.body && req.body.key;
    const headerKey = req.headers['x-admin-key'];
    const key = bodyKey || headerKey;
    if (!key || key !== ADMIN_UNLOCK_KEY) return res.status(401).json({ error: 'Chiave non valida.' });
    const token = signToken({ sub: 'staff', scopes: ['nuovo', 'permuta', 'usato'] }, 60 * 30);
    return res.json({ token, expiresInSec: 1800, scopes: ['nuovo','permuta','usato'] });
  } catch (e) {
    return res.status(500).json({ error: 'unlock_error' });
  }
});

// ──────────────────────────────────────────────────────
//  2) REGISTRAZIONE "NUOVO" (pubblica) + lookup ordine
// ──────────────────────────────────────────────────────
app.post('/registrazione', async (req, res) => {
  try {
    const dati = req.body || {};
    const required = ['nome','cognome','email','modello','serial','luogo','data_acquisto'];
    for (const f of required) {
      if (!dati[f] || String(dati[f]).trim() === '') {
        return res.status(400).json({ error: `Campo mancante: ${f}` });
      }
    }
    const parseISO = (s) => {
      if (/^\d{2}\/\d{2}\/\d{4}$/.test(s)) {
        const [dd,mm,yyyy] = s.split('/');
        return new Date(`${yyyy}-${mm}-${dd}T00:00:00Z`);
      }
      return new Date(`${s}T00:00:00Z`);
    };
    const d = parseISO(String(dati.data_acquisto));
    if (isNaN(d.getTime())) return res.status(400).json({ error: 'data_acquisto non valida' });

    const scadenza = new Date(d); scadenza.setMonth(scadenza.getMonth() + 24);
    const payload = {
      ...dati,
      tipo_registrazione: 'nuovo',
      data_acquisto: d.toISOString().slice(0,10),
      scadenza_garanzia: scadenza.toISOString().slice(0,10),
      createdAt: new Date().toISOString()
    };
    const docId = dati.ordineShopify && String(dati.ordineShopify).trim();
    if (docId) await db.collection('registrazioni').doc(docId).set(payload);
    else await db.collection('registrazioni').add(payload);

    if (typeof sendConfirmationEmail === 'function') {
      try { await sendConfirmationEmail(payload); } catch (e) { console.error('Email NUOVO fallita:', e.message); }
    }
    res.status(200).json({ message: 'Garanzia registrata con successo' });
  } catch (err) {
    console.error('❌ Errore /registrazione:', err);
    res.status(500).json({ error: 'Errore durante la registrazione' });
  }
});

app.get('/ordini/:numeroOrdine', async (req, res) => {
  try {
    const id = String(req.params.numeroOrdine || '').trim();
    if (!id) return res.status(400).json({ error: 'ID mancante' });
    const snap = await db.collection('registrazioni').doc(id).get();
    if (!snap.exists) return res.status(404).json({ error: 'Ordine non trovato' });
    res.status(200).json(snap.data());
  } catch (err) {
    console.error('❌ Errore /ordini/:id:', err);
    res.status(500).json({ error: 'Errore del server' });
  }
});

// ──────────────────────────────────────────────────────
//  3) SHOPIFY PREFILL (facoltativo, richiede env Shopify)
// ──────────────────────────────────────────────────────
app.post('/shopify/prefill', async (req, res) => {
  try {
    const { ordineShopify, email } = req.body || {};
    if (!ordineShopify || !email) return res.status(400).json({ error: 'ordineShopify ed email richiesti' });

    const STORE = process.env.SHOPIFY_STORE_DOMAIN; // es. mystore.myshopify.com
    const TOKEN = process.env.SHOPIFY_ACCESS_TOKEN;
    const APIV = process.env.SHOPIFY_API_VERSION || '2024-04';

    if (!STORE || !TOKEN) {
      // non configurato: rispondo “not configured”
      return res.status(501).json({ error: 'shopify_not_configured' });
    }

    const name = `#${String(ordineShopify).replace(/[^0-9]/g,'')}`;
    const url = `https://${STORE}/admin/api/${APIV}/orders.json?status=any&name=${encodeURIComponent(name)}`;
    const r = await fetch(url, { headers: { 'X-Shopify-Access-Token': TOKEN } });
    const data = await r.json();
    const order = (data && Array.isArray(data.orders) && data.orders[0]) || null;
    if (!order) return res.status(404).json({ error: 'ordine_non_trovato' });

    // match e-mail
    const mail = (order.email || '').trim().toLowerCase();
    if (mail && mail !== String(email).trim().toLowerCase()) {
      return res.status(401).json({ error: 'email_non_corrispondente' });
    }

    // estraggo un “modello” dal primo line item
    const firstItem = (order.line_items && order.line_items[0]) || {};
    const modello = (firstItem.title || '').trim();

    return res.json({
      nome: (order.customer && order.customer.first_name) || '',
      cognome: (order.customer && order.customer.last_name) || '',
      email: mail || email,
      modello,
      data_acquisto: order.created_at ? order.created_at.slice(0,10) : null,
      ordineShopify: String(ordineShopify)
    });
  } catch (e) {
    console.error('❌ /shopify/prefill error:', e);
    return res.status(500).json({ error: 'prefill_error' });
  }
});

// ──────────────────────────────────────────────────────
//  4) STAFF: LOOKUP / PERMUTA / USATO  (protetti adminAuth)
// ──────────────────────────────────────────────────────
app.get('/carrelli/lookup', adminAuth, async (req, res) => {
  try {
    const seriale = String(req.query.seriale || '').trim();
    if (!seriale) return res.status(400).json({ error: 'param seriale obbligatorio' });

    const carrRef = db.collection('carrelli').doc(seriale);
    const carrSnap = await carrRef.get();
    const carrello = carrSnap.exists ? { id: carrSnap.id, ...carrSnap.data() } : null;

    const regQ = await db.collection('registrazioni').where('serial','==', seriale).get();
    const regs = regQ.docs.map(d => ({ id: d.id, ...d.data() }));

    // deduco garanzia produttore: 24 mesi dalla PRIMA data_acquisto valida
    const validDates = regs
      .map(r => r.data_acquisto)
      .filter(Boolean)
      .map(s => new Date(s))
      .filter(d => !isNaN(d.getTime()))
      .sort((a,b) => a - b);

    let data_acquisto = null, scadenza_garanzia = null, residuo_giorni = null;
    if (validDates.length) {
      const d0 = validDates[0];
      const scad = new Date(d0); scad.setMonth(scad.getMonth() + 24);
      data_acquisto = d0.toISOString().slice(0,10);
      scadenza_garanzia = scad.toISOString().slice(0,10);
      const diff = Math.ceil((scad - new Date()) / (1000*60*60*24));
      residuo_giorni = diff;
    }

    // prendo “note” dall’ultimo evento di permuta_ritiro se presente
    let note = null;
    if (carrello) {
      const evSnap = await carrRef.collection('eventi').orderBy('createdAt','desc').limit(1).get();
      if (!evSnap.empty) {
        const ev = evSnap.docs[0].data();
        note = ev && ev.payload && ev.payload.note || null;
      }
    }

    // deduco un “modello” preferendo la registrazione più recente che ce l’ha
    let modello = null;
    for (const r of regs) { if (r.modello) modello = r.modello; }
    if (!modello && carrello && carrello.modello) modello = carrello.modello;

    return res.json({
      seriale,
      modello,
      data_acquisto,
      scadenza_garanzia,
      residuo_giorni,
      note,
      carrello,
      registrazioni_count: regs.length
    });
  } catch (e) {
    console.error('lookup error:', e);
    return res.status(500).json({ error: 'lookup_error' });
  }
});

app.post('/permute/ritiro', adminAuth, async (req, res) => {
  try {
    const { seriale, modello, dataRientro, note } = req.body || {};
    if (!seriale || !modello) return res.status(400).json({ error: 'seriale e modello obbligatori' });

    const carrRef = db.collection('carrelli').doc(String(seriale).trim());
    await db.runTransaction(async trx => {
      const carrSnap = await trx.get(carrRef);
      if (!carrSnap.exists) {
        trx.set(carrRef, {
          seriale: String(seriale).trim(),
          modello: String(modello).trim(),
          stato: 'permuta_ritirato',
          possesso_corrente: { tipo: 'rivenditore' },
          createdAt: ts(),
          updatedAt: ts()
        });
      } else {
        trx.update(carrRef, {
          modello: String(modello).trim(),
          stato: 'permuta_ritirato',
          possesso_corrente: { tipo: 'rivenditore' },
          updatedAt: ts()
        });
      }
      // se c'era una registrazione “attiva”, la chiudo per permuta
      const regQ = await trx.get(db.collection('registrazioni').where('serial','==', String(seriale).trim()).limit(1));
      if (!regQ.empty) {
        trx.update(regQ.docs[0].ref, { stato: 'chiusa_per_permuta', updatedAt: ts() });
      }
      // evento
      trx.set(carrRef.collection('eventi').doc(), {
        tipo: 'permuta_ritiro',
        payload: {
          dataRientro: (typeof dataRientro==='string' && dataRientro.trim()) ? dataRientro.trim() : null,
          note: (typeof note==='string' && note.trim()) ? note.trim() : null
        },
        createdAt: ts(),
        by: 'backend'
      });
    });

    return res.json({ ok: true });
  } catch (e) {
    console.error('Errore /permute/ritiro:', e);
    return res.status(500).json({ error: 'permuta_error' });
  }
});

app.post('/usato/vendita', adminAuth, async (req, res) => {
  try {
    const { seriale, modello, cliente, vendita = {}, gr = {} } = req.body || {};
    if (!seriale) return res.status(400).json({ error: 'seriale obbligatorio' });
    if (!cliente || !cliente.nome || !cliente.email) {
      return res.status(400).json({ error: 'cliente.nome e cliente.email obbligatori' });
    }
    const mesi = Number(gr.mesi || 0);
    if (!Number.isFinite(mesi) || mesi < 0) {
      return res.status(400).json({ error: 'gr.mesi non valido' });
    }
    const parseDate = (s) => {
      if (!s) return new Date();
      if (/^\d{2}\/\d{2}\/\d{4}$/.test(s)) {
        const [dd, mm, yyyy] = s.split('/');
        return new Date(`${yyyy}-${mm}-${dd}T00:00:00Z`);
      }
      return new Date(String(s));
    };
    const vendDate = parseDate(vendita.data);
    if (isNaN(vendDate.getTime())) {
      return res.status(400).json({ error: 'vendita.data non valida' });
    }
    const grFine = new Date(vendDate); grFine.setMonth(grFine.getMonth() + mesi);

    const regRef = db.collection('registrazioni').doc();
    const carrRef = db.collection('carrelli').doc(String(seriale).trim());

    await db.runTransaction(async trx => {
      const carrSnap = await trx.get(carrRef);
      if (!carrSnap.exists) {
        trx.set(carrRef, {
          seriale: String(seriale).trim(),
          modello: (typeof modello==='string' && modello.trim()) ? modello.trim() : null,
          stato: 'in_uso_cliente',
          possesso_corrente: { tipo: 'cliente', riferimento_registrazione_id: regRef.id },
          createdAt: ts(),
          updatedAt: ts()
        });
      } else {
        trx.update(carrRef, {
          modello: (typeof modello==='string' && modello.trim()) ? modello.trim() : (carrSnap.data().modello || null),
          stato: 'in_uso_cliente',
          possesso_corrente: { tipo: 'cliente', riferimento_registrazione_id: regRef.id },
          updatedAt: ts()
        });
      }
      // chiudo eventuale precedente registrazione “aperta”
      const regQ = await trx.get(db.collection('registrazioni').where('serial','==', String(seriale).trim()).limit(1));
      if (!regQ.empty) {
        trx.update(regQ.docs[0].ref, { stato: 'chiusa_per_permuta', updatedAt: ts() });
      }
      // nuova registrazione usato
      trx.set(regRef, {
        tipo_registrazione: 'usato',
        serial: String(seriale).trim(),
        modello: (typeof modello==='string' && modello.trim()) ? modello.trim() : null,
        cliente: {
          nome: String(cliente.nome).trim(),
          email: String(cliente.email).trim(),
          telefono: (typeof cliente.telefono==='string' && cliente.telefono.trim()) ? cliente.telefono.trim() : null
        },
        vendita: {
          data: vendDate.toISOString(),
          sorgente: 'rivenditore',
          ordineShopify: vendita.ordineShopify ? String(vendita.ordineShopify).trim() : null
        },
        gr: {
          mesi,
          inizio: vendDate.toISOString(),
          fine: grFine.toISOString(),
          condizioni: (typeof gr.condizioni==='string' && gr.condizioni.trim()) ? gr.condizioni.trim() : null
        },
        stato: 'attiva',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      });
      // evento
      trx.set(carrRef.collection('eventi').doc(), {
        tipo: 'vendita_usato',
        payload: {
          regId: regRef.id,
          modello: (typeof modello==='string' && modello.trim()) ? modello.trim() : null,
          cliente: {
            nome: String(cliente.nome).trim(),
            email: String(cliente.email).trim(),
            telefono: (typeof cliente.telefono==='string' && cliente.telefono.trim()) ? cliente.telefono.trim() : null
          },
          gr: {
            mesi,
            fine: grFine.toISOString(),
            condizioni: (typeof gr.condizioni==='string' && gr.condizioni.trim()) ? gr.condizioni.trim() : null
          }
        },
        createdAt: ts(),
        by: 'backend'
      });
    });

    // email cliente (opzionale)
    try { await sendEmailRegistrazioneUsato({
      seriale: String(seriale).trim(),
      cliente: { nome: String(cliente.nome).trim(), email: String(cliente.email).trim() },
      gr: { mesi, fine: grFine.toISOString() },
      modello: (typeof modello==='string' && modello.trim()) ? modello.trim() : null
    }); } catch (e) { console.error('Email USATO fallita:', e.message); }

    return res.json({ ok: true, registrazioneId: regRef.id });
  } catch (err) {
    console.error('❌ Errore /usato/vendita:', err);
    return res.status(500).json({ error: 'usato_error' });
  }
});

// ── Email "usato" (con logo + immagine modello) — compatibile EMAIL_* e SMTP_*
const BASE_ASSETS_URL = (process.env.PUBLIC_ASSETS_URL || '').replace(/\/$/, '');
const MODEL_IMAGE_MAP = {
  'Q Follow Black': 'qfollow-black.jpg',
  'Q Follow Carbon': 'qfollow-carbon.jpg',
  'Q Range Red': 'qrange-red.jpg',
  'Q Range Blue': 'qrange-blue.jpg',
  'Q Range Black': 'qrange-black.jpg',
  'VERTX': 'vertx.jpg',
  'X10 Follow Bianco': 'x10-bianco.jpg',
  'X10 Follow Argento': 'x10-argento.jpg',
  'X9 Follow Bianco': 'x10-bianco.jpg',
  'X9 Follow Argento': 'x10-argento.jpg',
  'X9 Follow Black': 'x9-follow-black.jpg',
  'X9 Remote Bianco': 'x10-bianco.jpg',
  'X9 Remote Argento': 'x10-argento.jpg',
  'X9 Remote Black': 'x9-remote-black.jpg'
};
function getModelImageUrl(modello) {
  if (!BASE_ASSETS_URL) return null;
  if (!modello || typeof modello !== 'string') return null;
  const key = Object.keys(MODEL_IMAGE_MAP).find(k =>
    modello.toLowerCase().includes(k.toLowerCase())
  );
  return key ? `${BASE_ASSETS_URL}/email-assets/images/${MODEL_IMAGE_MAP[key]}` : null;
}

async function sendEmailRegistrazioneUsato({ seriale, cliente, gr, modello }) {
  const nodemailer = require('nodemailer');
  const SMTP_HOST = process.env.SMTP_HOST || process.env.EMAIL_HOST || 'ssl0.ovh.net';
  const SMTP_PORT = Number(process.env.SMTP_PORT || process.env.EMAIL_PORT || 465);
  const SMTP_SECURE_RAW = (process.env.SMTP_SECURE ?? process.env.EMAIL_SECURE ?? 'true') + '';
  const SMTP_SECURE = !/^false$/i.test(SMTP_SECURE_RAW);
  const SMTP_USER = process.env.SMTP_USER || process.env.EMAIL_USER;
  const SMTP_PASS = process.env.SMTP_PASS || process.env.EMAIL_PASS;
  const SMTP_FROM = process.env.SMTP_FROM || process.env.EMAIL_FROM || SMTP_USER || 'garanzia@stewartgolf.it';

  if (!SMTP_USER || !SMTP_PASS) {
    console.warn('✉️  Email USATO disattivata: mancano credenziali. Invio saltato.');
    return;
  }
  const transporter = nodemailer.createTransport({
    host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_SECURE,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });

  const scad = gr?.fine ? new Date(gr.fine) : null;
  const scadStr = (scad && !isNaN(scad.getTime())) ? scad.toLocaleDateString('it-IT') : '';
  const logoUrl = BASE_ASSETS_URL ? `${BASE_ASSETS_URL}/email-assets/images/logo-verticalgolf.jpg` : null;
  const modelUrl = getModelImageUrl(modello);
  const safe = (s) => (typeof s === 'string' ? s.replace(/[<>]/g, '') : '');

  const html = `
  <div style="background:#f6f7f9;padding:24px;">
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" align="center" width="100%" style="max-width:680px;background:#ffffff;border-radius:12px;overflow:hidden;font-family:Arial,Helvetica,sans-serif;">
      <tr>
        <td style="padding:16px 24px; background:#111; text-align:center;">
          ${logoUrl ? `<img src="${logoUrl}" alt="Stewart Golf" style="max-width:220px;height:auto;display:inline-block;">` : `<h2 style="color:#fff;margin:0;">Stewart Golf</h2>`}
        </td>
      </tr>
      <tr>
        <td style="padding:24px;">
          <h1 style="font-size:20px; margin:0 0 12px;">Conferma garanzia usato</h1>
          <p style="margin:0 0 8px;">Ciao ${safe(cliente?.nome)},</p>
          <p style="margin:0 0 12px;">abbiamo registrato la tua <b>garanzia usato</b> per il carrello <b>${safe(seriale)}</b>${modello ? `, modello <b>${safe(modello)}</b>` : ''}.</p>
          ${modelUrl ? `<img src="${modelUrl}" alt="${safe(modello || 'Carrello')}" style="width:100%;max-width:640px;height:auto;display:block;border-radius:8px;margin:12px 0;">` : ''}
          <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin:12px 0 16px;">
            <tr><td style="padding:8px 0;"><b>Garanzia Rivenditore:</b> ${Number(gr?.mesi || 0)} mesi ${scadStr ? `— scadenza ${scadStr}` : ''}</td></tr>
            <tr><td style="padding:8px 0;">Per eventuali interventi coperti da garanzia del produttore, ci occupiamo noi della pratica.</td></tr>
          </table>
          <p style="margin:16px 0 0;">Grazie,<br><b>Stewart Golf Italia</b></p>
        </td>
      </tr>
    </table>
  </div>`;
  await transporter.sendMail({ from: SMTP_FROM, to: cliente.email, subject: `Registrazione garanzia usato – ${seriale}`, html });
}

// ──────────────────────────────────────────────────────
//  5) ADMIN list & purge (rimasti come prima)
// ──────────────────────────────────────────────────────
app.get('/admin/registrazioni', adminAuth, async (_req, res) => {
  try {
    const snap = await db.collection('registrazioni').limit(500).get();
    const items = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.status(200).json({ items, count: items.length });
  } catch (err) {
    console.error('❌ Errore lista registrazioni:', err);
    res.status(500).json({ error: 'Errore del server' });
  }
});

app.post('/admin/purge-registrazioni', adminAuth, async (req, res) => {
  try {
    const { dryRun = true, idList = [], ordinePrefix, emailDomain, createdBefore } = req.body || {};
    const snap = await db.collection('registrazioni').limit(1000).get();
    const toDelete = [];
    const cutoff = createdBefore ? new Date(createdBefore) : null;
    const isValidDate = d => d instanceof Date && !isNaN(d.getTime());
    snap.forEach(doc => {
      const data = doc.data() || {};
      const id = doc.id;
      let match = false;
      if (idList?.length && idList.includes(id)) match = true;
      if (!match && ordinePrefix && typeof data.ordineShopify === 'string') {
        if (data.ordineShopify.startsWith(ordinePrefix)) match = true;
      }
      if (!match && emailDomain && typeof data.email === 'string') {
        if (data.email.toLowerCase().endsWith(`@${emailDomain.toLowerCase()}`)) match = true;
      }
      if (!match && cutoff) {
        const base = data.createdAt || data.data_acquisto;
        if (base) {
          const d = new Date(base);
          if (isValidDate(d) && d < cutoff) match = true;
        }
      }
      if (match) toDelete.push(doc.ref);
    });
    if (dryRun) return res.status(200).json({ dryRun: true, wouldDelete: toDelete.length });

    let deleted = 0;
    while (toDelete.length) {
      const chunk = toDelete.splice(0, 400);
      const batch = db.batch();
      chunk.forEach(ref => batch.delete(ref));
      await batch.commit();
      deleted += chunk.length;
    }
    return res.status(200).json({ deleted });
  } catch (err) {
    console.error('❌ Purge error:', err);
    return res.status(500).json({ error: 'Errore purge' });
  }
});

// ──────────────────────────────────────────────────────
//  Health & Version & Root
// ──────────────────────────────────────────────────────
app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/healthz', (_req, res) => res.json({ ok: true }));
app.get('/version', (_req, res) => {
  let version = 'dev';
  try { version = require('./package.json').version || version; } catch {}
  res.json({
    version,
    commit: process.env.RENDER_GIT_COMMIT || process.env.GIT_COMMIT || null,
    node: process.version,
    env: process.env.NODE_ENV || 'development'
  });
});
app.get('/', (_req, res) => res.json({ ok: true, service: 'stewart-backend' }));

// ── Avvio server
app.listen(port, () => {
  console.log(`🚀 Server attivo su porta ${port}`);
});
