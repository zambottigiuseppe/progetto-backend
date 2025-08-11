// index.js
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const admin = require('firebase-admin');

const app = express();
app.use(express.json());

// ---------- CORS (whitelist da env) ----------
const ALLOWED = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: function (origin, cb) {
    if (!origin) return cb(null, true);            // permette curl/postman
    return cb(null, ALLOWED.includes(origin));     // solo origini whitelisted
  }
}));

// ---------- EMAIL (OVH) ----------
const EMAIL_HOST = process.env.EMAIL_HOST;          // es: ssl0.ovh.net
const EMAIL_PORT = Number(process.env.EMAIL_PORT || 465);
const EMAIL_SECURE = String(process.env.EMAIL_SECURE || 'true') === 'true';
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;
const EMAIL_FROM = process.env.EMAIL_FROM || EMAIL_USER;

const transporter = nodemailer.createTransport({
  host: EMAIL_HOST,
  port: EMAIL_PORT,
  secure: EMAIL_SECURE,
  auth: EMAIL_USER && EMAIL_PASS ? { user: EMAIL_USER, pass: EMAIL_PASS } : undefined,
});

// ---------- FIREBASE (PATH o JSON) ----------
const SA_PATH = process.env.FIREBASE_SERVICE_ACCOUNT_PATH; // es: ./serviceAccountKey.json
const SA_JSON = process.env.FIREBASE_SERVICE_ACCOUNT;      // consigliato: JSON intero nell'env
let creds;
try {
  if (SA_JSON) {
    creds = JSON.parse(SA_JSON);
  } else if (SA_PATH) {
    // ATTENZIONE: su Render il file deve esistere. Preferisci SA_JSON.
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

// ---------- PREFILL SHOPIFY (REST con fallback GraphQL) ----------
app.get('/shopify/prefill', async (req, res) => {
  try {
    const STORE = process.env.SHOPIFY_STORE_DOMAIN;       // <store>.myshopify.com
    const TOKEN = process.env.SHOPIFY_ADMIN_API_TOKEN;    // shpat_...
    const API_VERSION = process.env.SHOPIFY_API_VERSION || '2024-07';

    const orderParam = String(req.query.order || '').trim();
    const emailParam = String(req.query.email || '').trim().toLowerCase();
    if (!STORE || !TOKEN) return res.status(500).json({ ok: false, error: 'CONFIG_MANCANTE' });
    if (!orderParam || !emailParam) return res.status(400).json({ ok: false, error: 'PARAMETRI_MANCANTI' });

    const name = orderParam.startsWith('#') ? orderParam : `#${orderParam}`;

    // --- 1) REST by name ---
    const restURL = `https://${STORE}/admin/api/${API_VERSION}/orders.json?status=any&name=${encodeURIComponent(name)}`;
    let r = await fetch(restURL, {
      headers: { 'X-Shopify-Access-Token': TOKEN, 'Content-Type': 'application/json' },
    });

    let prefill = null;
    if (r.ok) {
      const data = await r.json();
      const order = (data.orders && data.orders[0]) || null;
      if (order) {
        const orderEmail = (order.email || '').toLowerCase();
        const customerEmail = ((order.customer && order.customer.email) || '').toLowerCase();
        if (emailParam === orderEmail || emailParam === customerEmail) {
          const ship = order.shipping_address || {};
          const cust = order.customer || {};
          const line = (order.line_items && order.line_items[0]) || {};
          prefill = {
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
        }
      }
    }

    // --- 2) Fallback GraphQL: query per name+email, più robusto ---
    if (!prefill) {
      const gqlQuery = `
        query($first:Int!, $query:String!) {
          orders(first: $first, query: $query, sortKey: CREATED_AT, reverse: true) {
            edges {
              node {
                id
                name
                email
                createdAt
                customer { email firstName lastName phone }
                shippingAddress {
                  firstName lastName address1 address2 city zip province country phone
                }
                lineItems(first: 1) { edges { node { title } } }
              }
            }
          }
        }`;
      const search = `name:${name} AND email:${emailParam}`;
      const g = await fetch(`https://${STORE}/admin/api/${API_VERSION}/graphql.json`, {
        method: 'POST',
        headers: { 'X-Shopify-Access-Token': TOKEN, 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: gqlQuery, variables: { first: 1, query: search } }),
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
          citta: ship.city || '',
          cap: ship.zip || '',
          provincia: ship.province || '',
          paese: ship.country || '',
          modello: edge.lineItems?.edges?.[0]?.node?.title || '',
          dataOrdine: edge.createdAt || '',
          orderId: edge.id,
          orderName: edge.name,
        };
      }
    }

    if (!prefill) return res.status(404).json({ ok: false, error: 'ORDINE_NON_TROVATO' });
    return res.json({ ok: true, prefill });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// ---------- EMAIL HTML ----------
function emailHTML(d) {
  return `
  <div style="font-family:Arial,sans-serif;line-height:1.5">
    <h2>Registrazione garanzia ricevuta</h2>
    <ul>
      <li><b>Nome:</b> ${d.nome || ''} ${d.cognome || ''}</li>
      <li><b>Email:</b> ${d.email || '-'}</li>
      <li><b>Modello:</b> ${d.modello || '-'}</li>
      <li><b>Seriale:</b> ${d.seriale || '-'}</li>
      <li><b>Ordine:</b> ${d.orderName || d.orderId || '-'}</li>
    </ul>
  </div>`;
}

// ---------- Utility dedup ----------
function normSerial(x){ return String(x||'').trim().toUpperCase().replace(/\s+/g,''); }
function safeId(x){ return String(x||'').trim().toUpperCase().replace(/[^A-Z0-9]+/g,'-'); }

// ---------- REGISTRAZIONE + DEDUP + EMAIL ----------
app.post('/registrazione', async (req, res) => {
  try {
    const p = req.body || {};
    // validazione minima
    const obbligatori = ['email', 'modello', 'seriale'];
    const mancanti = obbligatori.filter(k => !p[k]);
    if (mancanti.length) return res.status(400).json({ ok:false, error:'DATI_INSUFFICIENTI', fields:mancanti });

    const serialeNorm = normSerial(p.seriale);
    const ordineRef = p.orderName || p.orderId || 'SENZA-ORDINE';
    const regId = `${safeId(ordineRef)}__${serialeNorm}`;
    const docRef = db.collection('registrazioni').doc(regId);

    // create fallisce se esiste già (ALREADY_EXISTS = code 6)
    await docRef.create({
      ...p,
      seriale: serialeNorm,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // email (non blocca la risposta)
    try {
      if (EMAIL_HOST && EMAIL_USER && EMAIL_PASS) {
        await transporter.sendMail({
          from: EMAIL_FROM,
          to: p.email,
          subject: 'Conferma registrazione garanzia',
          html: emailHTML({ ...p, seriale: serialeNorm }),
        });
      }
    } catch (e) {
      console.error('Email fallita:', e.message);
    }

    return res.json({ ok:true, id: regId });
  } catch (err) {
    // duplicato
    if (err && (err.code === 6 || /ALREADY_EXISTS/i.test(String(err.message)))) {
      return res.status(409).json({ ok:false, error:'DUPLICATO' });
    }
    console.error(err);
    return res.status(500).json({ ok:false, error: err.message });
  }
});

// ---------- AVVIO ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
