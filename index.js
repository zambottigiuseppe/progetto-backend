// index.js
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');

const app = express();
app.use(cors());
app.use(express.json());

// ---- Firebase Admin da VARIABILE D'AMBIENTE (NO file locale) ----
const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
if (!raw) {
  throw new Error('Manca la variabile FIREBASE_SERVICE_ACCOUNT su Render.');
}

let serviceAccount;
try {
  serviceAccount = JSON.parse(raw);
} catch (e) {
  console.error('FIREBASE_SERVICE_ACCOUNT non è JSON valido:', e.message);
  throw e;
}

if (admin.apps.length === 0) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}
const db = admin.firestore();

// ---- ROUTE DI TEST ----
app.get('/health', (req, res) => {
  res.json({ ok: true, status: 'healthy', projectId: serviceAccount.project_id || null });
});

// ---- ESEMPIO: lookup ordine ----
// Cerca in Firestore collection 'ordini' il documento con id = numeroOrdine
app.get('/ordini/:numeroOrdine', async (req, res) => {
  const numero = String(req.params.numeroOrdine).trim();
  try {
    const doc = await db.collection('ordini').doc(numero).get();
    if (!doc.exists) {
      return res.status(404).json({ ok: false, error: 'ORDINE_NON_TROVATO', numeroOrdine: numero });
    }
    return res.json({ ok: true, ordine: { id: doc.id, ...doc.data() } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// ---- ESEMPIO: registrazione garanzia ----
app.post('/registrazione', async (req, res) => {
  try {
    const payload = req.body || {};
    if (!payload.email || !payload.modello) {
      return res.status(400).json({ ok: false, error: 'DATI_INSUFFICIENTI' });
    }
    const ref = await db.collection('registrazioni').add({
      ...payload,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    return res.json({ ok: true, id: ref.id });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// ---- AVVIO ----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
