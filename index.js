
// index.js - VERSIONE CORRETTA

const express = require('express');
const admin = require('firebase-admin');
const fetch = require('node-fetch');

const app = express();
app.use(express.json());

// Firebase init (mock config fallback)
const SA_JSON = process.env.FIREBASE_SERVICE_ACCOUNT || '{}';
const creds = JSON.parse(SA_JSON);
if (admin.apps.length === 0) admin.initializeApp({ credential: admin.credential.cert(creds) });

// ───────────────────────────────────────────────────────────────────────────────
// CARRELLI — filtro aggiornato
// ───────────────────────────────────────────────────────────────────────────────
const STRICT_CARRELLI = /^(true|1|yes)$/i.test(String(process.env.STRICT_CARRELLI || 'false'));
const TITLE_RE = /\b(carrello|trolley|follow|remote)\b|^(?:q|x|r)[-\s]?\w+/i;
const NEG_RE = /\b(ricambi|spare|accessor(i|y|ies)|guscio|cover|ruota|wheel|batter(y|ia)|charger|caricatore|bag|sacca)\b/i;

function isCarrelloMeta({ title, productType }) {
  const ttl = String(title || '').trim();
  const pty = String(productType || '').trim();
  if (/\bcarrello\b/i.test(ttl)) return true;
  if (NEG_RE.test(ttl) || NEG_RE.test(pty)) return false;
  const titleOk = TITLE_RE.test(ttl);
  const typeOk  = TITLE_RE.test(pty) || /\bgolf\s*trolley\b/i.test(pty);
  return titleOk || typeOk;
}

async function fetchJsonWithTimeout(url, opts = {}, ms = 12000) {
  const ac = new AbortController();
  const to = setTimeout(() => ac.abort(new Error('TIMEOUT')), ms);
  try {
    const r = await fetch(url, { ...opts, signal: ac.signal });
    const j = await r.json().catch(() => ({}));
    return { ok: r.ok, status: r.status, json: j };
  } finally { clearTimeout(to); }
}

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
            lineItems(first:50) {
              edges { node {
                title
                product { id productType vendor title }
              } }
            }
          } }
        }
      }`;

    const search = `name:${name}`;
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
    let firstTitle = '';
    let firstPid = null;

    for (const e of edges) {
      const li   = e?.node || {};
      const prod = li.product || {};
      const titleToCheck = li.title || prod.title || '';
      if (!firstTitle) {
        firstTitle = titleToCheck || '';
        firstPid   = prod.id || null;
      }
      if (isCarrelloMeta({ title: titleToCheck, productType: prod.productType })) {
        return {
          ok: true,
          product: {
            id: prod.id || null,
            title: titleToCheck,
            type: prod.productType || '',
            vendor: prod.vendor || ''
          }
        };
      }
    }

    return { ok:false, reason:'NON_CARRELLO', product: { title:firstTitle, id:firstPid } };
  } catch (e) {
    const msg = String(e && e.message || e || '');
    if (msg.includes('TIMEOUT')) return { ok:false, reason:'CHECK_TIMEOUT' };
    return { ok:false, reason:'CHECK_ERROR', error: msg };
  }
}

app.get('/health', (req, res) => res.json({ ok: true }));

const PORT = parseInt(process.env.PORT, 10);
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
