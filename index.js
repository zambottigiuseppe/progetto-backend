// index.js
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const admin = require('firebase-admin');
const fs = require('fs');

const app = express();
app.use(express.json());
const ALLOWED = (process.env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: function (origin, cb) {
    if (!origin) return cb(null, true); // permette curl/postman
    return cb(null, ALLOWED.includes(origin));
  }
}));


// ---------- EMAIL (OVH) ----------
const EMAIL_HOST = process.env.EMAIL_HOST;          // es: ssl0.ovh.net
const EMAIL_PORT = Number(process.env.EMAIL_PORT || 465);
const EMAIL_SECURE = String(process.env.EMAIL_SECURE || 'true') === 'true';
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

const transporter = nodemailer.createTransport({
  host: EMAIL_HOST,
  port: EMAIL_PORT,
  secure: EMAIL_SECURE,
  auth: EMAIL_USER && EMAIL_PASS ? { user: EMAIL_USER, pass: EMAIL_PASS } : undefined,
});

// ---------- FIREBASE (PATH o JSON) ----------
const SA_PATH = process.env.FIREBASE_SERVICE_ACCOUNT_PATH; // es: ./serviceAccountKey.json
const SA_JSON = process.env.FIREBASE_SERVICE_ACCOUNT;      // (opzionale ma consigliato: JSON intero nell'env)

let creds;
try {
  if (SA_JSON) {
    creds = JSON.parse(SA_JSON);
  } else if (SA_PATH) {
    // ATTENZIONE: su Render il file deve esistere nel container (sconsigliato committarlo).
    // Se usi solo PATH, assicurati che il file esista. Altrimenti imposta FIREBASE_SERVICE_ACCOUNT.
    creds = require(SA_PATH);
  } else {
    throw new Error('Config Firebase mancante: imposta FIREBASE_SERVICE_ACCOUNT (consigliato) o FIREBASE_SERVICE_ACCOUNT_PATH con file presente.');
  }
} catch (e) {
  console.error('Errore credenziali Firebase:', e.message);
  throw e;
}

if (admin.apps.length === 0) {
  admin.initializeApp({ credential: admin.credential.cert(creds) });
}
const db = admin.firestore();

// ---------- HEALTH ----------
app.get('/health', (req, res) => {
  res.json({ ok: true });
});

// ---------- PREFILL SHOPIFY ----------
app.get('/shopify/prefill', async (req, res) => {
  try {
    const STORE = process.env.SHOPIFY_STORE_DOMAIN;       // es: mystore.myshopify.com
    const TOKEN = process.env.SHOPIFY_ADMIN_API_TOKEN;    // token Admin API
    const API_VERSION = process.env.SHOPIFY_API_VERSION || '2024-07';

    const orderParam = String(req.query.order || '').trim();
    const emailParam = String(req.query.email || '').trim().toLowerCase();
    if (!STORE || !TOKEN) return res.status(500).json({ ok: false, error: 'CONFIG_MANCANTE' });
    if (!orderParam || !emailParam) return res.status(400).json({ ok: false, error: 'PARAMETRI_MANCANTI' });

    const name = orderParam.startsWith('#') ? orderParam : `#${orderParam}`;
    const url = `https://${STORE}/admin/api/${API_VERSION}/orders.json?status=any&name=${encodeURIComponent(name)}`;

    const r = await fetch(url, {
      headers: { 'X-Shopify-Access-Token': TOKEN, 'Content-Type': 'application/json' },
    });
    if (!r.ok) return res.status(502).json({ ok: false, error: 'SHOPIFY_ERR', status: r.status, body: await r.text().catch(() => '') });

    const data = await r.json();
    const order = (data.orders && data.orders[0]) || null;
    if (!order) return res.status(404).json({ ok: false, error: 'ORDINE_NON_TROVATO' });

    const orderEmail = (order.email || '').toLowerCase();
    const customerEmail = ((order.customer && order.customer.email) || '').toLowerCase();
    if (emailParam !== orderEmail && emailParam !== customerEmail) {
      return res.status(403).json({ ok: false, error: 'EMAIL_NON_COINCIDE' });
    }

    const ship = order.shipping_address || {};
    const cust = order.customer || {};
    const line = (order.line_items && order.line_items[0]) || {};
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
      orderName: order.name,
    };

    res.json({ ok: true, prefill });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ---------- REGISTRAZIONE + EMAIL ----------
function emailHTML(d) {
  return `
  <div style="font-family:Arial,sans-serif;line-height:1.5">
    <h2>Registrazione garanzia ricevuta</h2>
    <ul>
      <li><b>Nome:</b> ${d.nome || ''} ${d.cognome || ''}</li>
      <li><b>Email:</b> ${d.email || '-'}</li>
      <li><b>Modello:</b> ${d.modello || '-'}</li>
      <li><b>Seriale:</b> ${d.seriale || '-'}</li>
    </ul>
  </div>`;
}

app.post('/registrazione', async (req, res) => {
  try {
    const p = req.body || {};
    if (!p.email || !p.modello) return res.status(400).json({ ok: false, error: 'DATI_INSUFFICIENTI' });

    const ref = await db.collection('registrazioni').add({
      ...p,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // invio email (non blocca la risposta in caso di errore)
    try {
      if (EMAIL_HOST && EMAIL_USER && EMAIL_PASS) {
        await transporter.sendMail({
          from: EMAIL_USER,
          to: p.email,
          subject: 'Conferma registrazione garanzia',
          html: emailHTML(p),
        });
      }
    } catch (e) {
      console.error('Email fallita:', e.message);
    }

    res.json({ ok: true, id: ref.id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ---------- AVVIO ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
