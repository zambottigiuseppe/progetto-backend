// index.js
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());

// CORS: consenti tutto per ora (puoi restringere a dominio Shopify dopo)
app.use(cors({ origin: true }));

// ---- Firebase Admin da ENV (NO file locale) ----
const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
if (!raw) throw new Error('Manca FIREBASE_SERVICE_ACCOUNT');
let serviceAccount;
try { serviceAccount = JSON.parse(raw); } catch (e) { console.error('FIREBASE_SERVICE_ACCOUNT non è JSON valido'); throw e; }
if (admin.apps.length === 0) admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

// ---- Nodemailer (OVH) ----
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const FROM_EMAIL = process.env.FROM_EMAIL || SMTP_USER;

const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: 465,
  secure: true,
  auth: { user: SMTP_USER, pass: SMTP_PASS },
});

// Template email super semplice (puoi abbellire dopo)
function buildEmailHTML(data) {
  const { nome, cognome, email, modello, seriale } = data;
  return `
  <div style="font-family:Arial,sans-serif;line-height:1.5">
    <h2>Registrazione garanzia ricevuta</h2>
    <p>Ciao ${nome || ''} ${cognome || ''}, abbiamo registrato la tua garanzia.</p>
    <ul>
      <li><b>Email:</b> ${email || '-'}</li>
      <li><b>Modello:</b> ${modello || '-'}</li>
      <li><b>Seriale:</b> ${seriale || '-'}</li>
    </ul>
    <p>Grazie,<br>Stewart Golf Italia</p>
  </div>`;
}

async function sendWarrantyEmail(data) {
  const html = buildEmailHTML(data);
  const mail = {
    from: FROM_EMAIL,
    to: data.email,
    subject: 'Conferma registrazione garanzia',
    html,
  };
  await transporter.sendMail(mail);
}

// ---- HEALTH ----
app.get('/health', (req, res) => {
  res.json({ ok: true, status: 'healthy', projectId: serviceAccount.project_id || null });
});

// ---- PREFILL DA SHOPIFY ----
// GET /shopify/prefill?order=1234&email=cliente@email.it
app.get('/shopify/prefill', async (req, res) => {
  try {
    const STORE = process.env.SHOPIFY_STORE_DOMAIN; // es: mystore.myshopify.com
    const TOKEN = process.env.SHOPIFY_ADMIN_API_TOKEN;
    const API_VERSION = process.env.SHOPIFY_API_VERSION || '2024-07';

    const orderParam = String(req.query.order || '').trim();
    const emailParam = String(req.query.email || '').trim().toLowerCase();
    if (!STORE || !TOKEN) return res.status(500).json({ ok: false, error: 'CONFIG_MANCANTE' });
    if (!orderParam || !emailParam) return res.status(400).json({ ok: false, error: 'PARAMETRI_MANCANTI' });

    // Shopify "name" include '#' (es. #1001). Se non presente, lo aggiungo.
    const name = orderParam.startsWith('#') ? orderParam : `#${orderParam}`;
    const url = `https://${STORE}/admin/api/${API_VERSION}/orders.json?status=any&name=${encodeURIComponent(name)}`;

    const r = await fetch(url, {
      headers: { 'X-Shopify-Access-Token': TOKEN, 'Content-Type': 'application/json' },
    });
    if (!r.ok) {
      const t = await r.text().catch(() => '');
      return res.status(502).json({ ok: false, error: 'SHOPIFY_ERR', status: r.status, body: t });
    }
    const data = await r.json();
    const order = (data.orders && data.orders[0]) || null;
    if (!order) return res.status(404).json({ ok: false, error: 'ORDINE_NON_TROVATO' });

    // Verifica email (sull’ordine o sul customer)
    const orderEmail = (order.email || '').toLowerCase();
    const customerEmail = (order.customer && order.customer.email || '').toLowerCase();
    if (emailParam !== orderEmail && emailParam !== customerEmail) {
      return res.status(403).json({ ok: false, error: 'EMAIL_NON_COINCIDE' });
    }

    // Preparo i dati per prefill
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
      orderName: order.name, // tipo #1001
    };

    return res.json({ ok: true, prefill });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// ---- REGISTRAZIONE GARANZIA ----
app.post('/registrazione', async (req, res) => {
  try {
    const payload = req.body || {};
    // validazione minima
    const obbligatori = ['email', 'modello'];
    const mancanti = obbligatori.filter(k => !payload[k]);
    if (mancanti.length) return res.status(400).json({ ok: false, error: 'DATI_INSUFFICIENTI', fields: mancanti });

    // salva su Firestore
    const ref = await db.collection('registrazioni').add({
      ...payload,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // email (non blocca la risposta se fallisce)
    try { await sendWarrantyEmail(payload); }
    catch (e) { console.error('Email fallita:', e.message); }

    return res.json({ ok: true, id: ref.id });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// ---- AVVIO ----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
