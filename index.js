// index.js — REST-only + dealer-mode (X-Admin-Key) + “solo carrelli” + email con immagine variant + blocco duplicati per ordine 16-08-25 11:14

const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const admin = require('firebase-admin');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

// ── Firebase ──────────────────────────────────────────────────────────────────
const SA_JSON = process.env.FIREBASE_SERVICE_ACCOUNT || '{}';
let creds; try { creds = JSON.parse(SA_JSON); } catch { creds = {}; }
if (admin.apps.length === 0) admin.initializeApp({ credential: admin.credential.cert(creds) });
const db = admin.firestore();

// ── Token HMAC prefill ────────────────────────────────────────────────────────
const SECRET = process.env.ADMIN_API_KEY || '';
const PREFILL_TTL_MS = Number(process.env.PREFILL_TTL_MS || 45 * 60 * 1000);

function safeEqHex(a,b){const A=Buffer.from(String(a||''),'utf8');const B=Buffer.from(String(b||''),'utf8');if(A.length!==B.length){const m=Math.max(A.length,B.length);const Ap=Buffer.alloc(m,0);A.copy(Ap);const Bp=Buffer.alloc(m,0);B.copy(Bp);return crypto.timingSafeEqual(Ap,Bp);}return crypto.timingSafeEqual(A,B);}
function createPrefillToken(orderRef,email){const t=Date.now();const e=(email||'').toLowerCase();const msg=`${orderRef}|${e}|${t}`;const sig=crypto.createHmac('sha256',SECRET).update(msg).digest('hex');return `${t}.${sig}.${encodeURIComponent(orderRef)}.${encodeURIComponent(e)}`;}
function verifyPrefillToken(token,orderRefFromBody,emailFromBody){
  if(!SECRET) return {ok:false,reason:'NO_SECRET'};
  const raw=String(token||'');const parts=raw.split('.');if(parts.length<4) return {ok:false,reason:'BAD_FORMAT'};
  const [tStr,sig,refEnc,...emailParts]=parts;const t=Number(tStr);let ref,em;
  try{ref=decodeURIComponent(refEnc||'');em=decodeURIComponent(emailParts.join('.')||'').toLowerCase();}catch{return {ok:false,reason:'DECODE_FAIL'};}
  if(!t||!sig||!ref) return {ok:false,reason:'BAD_FIELDS'};
  if(Date.now()-t>PREFILL_TTL_MS) return {ok:false,reason:'EXPIRED'};
  const msg=`${ref}|${em}|${t}`;const expect=crypto.createHmac('sha256',SECRET).update(msg).digest('hex');
  if(!safeEqHex(sig,expect)) return {ok:false,reason:'BAD_HMAC'};
  const normRefBody=String(orderRefFromBody||'').trim();const normEmailBody=String(emailFromBody||'').trim().toLowerCase();
  const emailOk=!normEmailBody||normEmailBody===em;const refOk=!normRefBody||normRefBody===ref;
  return {ok:emailOk&&refOk,reason:emailOk?(refOk?'OK':'ORDERREF_MISMATCH'):'EMAIL_MISMATCH',decoded:{t,ref,em}};
}
function pickToken(req){
  const auth=req.get('authorization')||'';const bear=auth.startsWith('Bearer ')?auth.slice(7):'';
  const xhdr=req.get('x-prefill-token')||'';const q=req.query?.token||'';const b1=req.body?.prefillToken||'';const b2=req.body?.token||'';
  const candidates=[xhdr,bear,q,b1,b2].filter(Boolean);
  const norm=candidates.map(t=>{try{return /%[0-9A-Fa-f]{2}/.test(t)?decodeURIComponent(t):t;}catch{return t;}});
  return {raw:candidates,norm,chosen:norm[0]||''};
}

// ── Dealer mode (bypass token) ────────────────────────────────────────────────
const ADMIN_KEY_HASH = (process.env.ADMIN_KEY_HASH || '').toLowerCase(); // es. SHA-256 hex
function isDealer(req){
  const key = (req.get('x-admin-key') || req.body?.adminKey || '').toLowerCase().trim();
  if(!ADMIN_KEY_HASH || !key) return false;
  try { return safeEqHex(key, ADMIN_KEY_HASH); } catch { return false; }
}

// ── SOLO CARRELLI euristiche ─────────────────────────────────────────────────
const STRICT_CARRELLI = /^(true|1|yes)$/i.test(String(process.env.STRICT_CARRELLI || 'false'));
const TITLE_RE=/(carrell|trolley|follow|remote|^x[0-9]+|^q[-\s]?\w+|^r1s?)/i;
const NEG_RE=/\b(ricambi|spare|accessor(i|y|ies)|guscio|cover|ruota|wheel|batter(y|ia)|charger|caricatore|bag|sacca)\b/i;
function isCarrelloMeta({title,productType,vendor,tags}){
  const ttl=String(title||'').trim();const pty=String(productType||'').trim();
  if(/\bcarrello\b/i.test(ttl)) return true;
  if(NEG_RE.test(ttl)||NEG_RE.test(pty)) return false;
  const titleOk=TITLE_RE.test(ttl);const typeOk=TITLE_RE.test(pty)||/\bgolf\s*trolley\b/i.test(pty);
  const vendOk=String(vendor||'').toLowerCase().includes('stewart');
  const tagOk=Array.isArray(tags)&&tags.some(t=>String(t||'').toLowerCase().match(/\b(stewart|carrello)\b/));
  return vendOk||tagOk||titleOk||typeOk;
}

// ── Shopify REST helpers ──────────────────────────────────────────────────────
function apiBase(){const STORE=process.env.SHOPIFY_STORE_DOMAIN;const TOKEN=process.env.SHOPIFY_ADMIN_API_TOKEN;const API_VERSION=process.env.SHOPIFY_API_VERSION||'2024-07';if(!STORE||!TOKEN) throw new Error('CONFIG_MANCANTE');const base=`https://${STORE}/admin/api/${API_VERSION}`;const headers={'X-Shopify-Access-Token':TOKEN,'Content-Type':'application/json'};return {base,headers};}
async function restGetOrderByName(name){const {base,headers}=apiBase();const url=`${base}/orders.json?status=any&name=${encodeURIComponent(name)}`;const r=await fetch(url,{headers});if(!r.ok) return {ok:false,status:r.status,json:{}};const json=await r.json().catch(()=>({}));return {ok:true,status:r.status,json};}
async function restGetProduct(pid){const {base,headers}=apiBase();const url=`${base}/products/${pid}.json`;const r=await fetch(url,{headers});if(!r.ok) return {ok:false,status:r.status,json:{}};const json=await r.json().catch(()=>({}));return {ok:true,status:r.status,json};}
async function restGetVariant(vid){const {base,headers}=apiBase();const url=`${base}/variants/${vid}.json`;const r=await fetch(url,{headers});if(!r.ok) return {ok:false,status:r.status,json:{}};const json=await r.json().catch(()=>({}));return {ok:true,status:r.status,json};}

async function orderHasCarrelloByRefEmail(refInput,emailLower){
  try{
    const name=String(refInput||'').startsWith('#')?refInput:`#${refInput}`;
    const or=await restGetOrderByName(name); if(!or.ok) return {ok:false,reason:'REST_FAIL',status:or.status};
    const order=or.json?.orders?.[0]; if(!order) return {ok:false,reason:'ORDINE_NON_TROVATO'};
    const orderEmail=(order.email||'').toLowerCase(); const custEmail=(order.customer?.email||'').toLowerCase();
    if(emailLower && !(emailLower===orderEmail||emailLower===custEmail)) return {ok:false,reason:'EMAIL_MISMATCH'};
    const items=order.line_items||[]; let firstTitle=''; let firstPid=null;
    for(const line of items){
      const pid=line.product_id; const vid=line.variant_id; const titleFallback=String(line.title||'');
      if(!firstTitle){firstTitle=titleFallback;firstPid=pid||null;}
      let productMeta={id:pid||null,variantId:vid||null,title:titleFallback,type:'',vendor:'',tags:[]};
      if(!pid && vid){const vr=await restGetVariant(vid);const V=vr.json?.variant||{};if(V.product_id) productMeta.id=V.product_id;}
      if(!productMeta.id){ if(isCarrelloMeta({title:titleFallback,productType:'',vendor:'',tags:[]})) return {ok:true,product:productMeta}; continue; }
      const pr=await restGetProduct(productMeta.id); const P=pr.json?.product||{};
      const titleToCheck=titleFallback||P.title||''; const ptype=P.product_type||''; const vendor=P.vendor||''; const tags=P.tags?String(P.tags).split(',').map(s=>s.trim()):[];
      if(isCarrelloMeta({title:titleToCheck,productType:ptype,vendor,tags})){
        return {ok:true,product:{id:P.id||productMeta.id,variantId:productMeta.variantId,title:titleToCheck,type:ptype,vendor,tags}};
      }
    }
    return {ok:false,reason:'NON_CARRELLO',product:{title:firstTitle,id:firstPid}};
  }catch(e){return {ok:false,reason:'CHECK_ERROR',error:String(e?.message||e)};}
}

async function resolveVariantImageUrl(productId,variantId){
  let resolvedProductId=productId||null; let variantImageId=null;
  if(!resolvedProductId && variantId){const vr=await restGetVariant(variantId); if(vr.ok){const V=vr.json?.variant||{};resolvedProductId=V.product_id||null;variantImageId=V.image_id||null;}}
  if(!resolvedProductId) return null;
  const pr=await restGetProduct(resolvedProductId); if(!pr.ok) return null;
  const P=pr.json?.product||{}; if(!P) return null;
  if(variantImageId && Array.isArray(P.images)){const im=P.images.find(im=>String(im.id)===String(variantImageId)); if(im?.src) return im.src;}
  if(variantId && Array.isArray(P.variants)){const v=P.variants.find(v=>String(v.id)===String(variantId)); if(v && v.image_id && Array.isArray(P.images)){const im=P.images.find(im=>String(im.id)===String(v.image_id)); if(im?.src) return im.src;}}
  return (P.image && P.image.src) || (Array.isArray(P.images) && P.images[0]?.src) || null;
}

// ── Mail ──────────────────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT || 465),
  secure: String(process.env.EMAIL_SECURE || 'true') === 'true',
  auth: (process.env.EMAIL_USER && process.env.EMAIL_PASS) ? { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS } : undefined,
});
const EMAIL_FROM  = process.env.EMAIL_FROM || process.env.EMAIL_USER || '';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || '';

function emailHTML(d,imgUrl){
  const safe=x=>String(x||'').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const lineImg=imgUrl?`<td style="width:260px;padding:0 0 16px 0;vertical-align:top"><img src="${safe(imgUrl)}" alt="${safe(d.modello||'Prodotto')}" width="260" style="display:block;border-radius:12px"></td>`:'';
  return `<div style="font-family:Arial,sans-serif;line-height:1.5;background:#f6f7f8;padding:24px">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:620px;margin:auto;background:#ffffff;border-radius:14px;border:1px solid #e5e7eb">
    <tr><td style="padding:22px 22px 6px 22px;"><h2 style="margin:0 0 6px 0;color:#0a7d2c;font-size:20px">Registrazione garanzia confermata</h2>
      <p style="margin:0;color:#4b5563;font-size:14px">Grazie ${safe(d.nome)} ${safe(d.cognome)}. Di seguito il riepilogo.</p></td></tr>
    <tr><td style="padding:10px 22px 4px 22px;"><table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr>${lineImg}
      <td style="padding-left:${imgUrl?'18px':'0'};vertical-align:top">
        <p style="margin:0 0 6px 0;font-size:15px;color:#111827"><strong>Modello:</strong> ${safe(d.modello)}</p>
        <p style="margin:0 0 6px 0;font-size:15px;color:#111827"><strong>Seriale:</strong> ${safe(d.seriale)}</p>
        <p style="margin:0 0 6px 0;font-size:14px;color:#374151"><strong>Ordine:</strong> ${safe(d.orderName||d.orderId||'-')}</p>
        <p style="margin:0 0 6px 0;font-size:14px;color:#374151"><strong>Email:</strong> ${safe(d.email)}</p>
      </td></tr></table></td></tr>
    <tr><td style="height:8px"></td></tr></table>
  <p style="text-align:center;margin:14px 0 0 0;color:#6b7280;font-size:12px">Vertical Golf — Conferma registrazione garanzia</p></div>`;
}

const normSerial = x => String(x||'').trim().toUpperCase().replace(/\s+/g,'');
const safeId     = x => String(x||'').trim().toUpperCase().replace(/[^A-Z0-9]+/g,'-');

function limitByIp(max,windowMs){
  const hits=new Map();
  return (req,res,next)=>{const ip=req.ip||req.headers['x-forwarded-for']||req.connection.remoteAddress||'unknown';const now=Date.now();const rec=hits.get(ip)||{count:0,reset:now+windowMs};if(now>rec.reset){rec.count=0;rec.reset=now+windowMs;}rec.count+=1;hits.set(ip,rec);if(rec.count>max) return res.status(429).json({ok:false,error:'RATE_LIMIT'});next();};
}
const regLimiter=limitByIp(Number(process.env.RATE_LIMIT_REG_MAX||5),Number(process.env.RATE_LIMIT_REG_WINDOW||10*60*1000));

// ── Routes ────────────────────────────────────────────────────────────────────
app.get('/health',(req,res)=>res.json({ok:true}));

app.get('/shopify/prefill', async (req,res)=>{
  try{
    const orderParam=String(req.query.order||'').trim();
    const emailParam=String(req.query.email||'').trim().toLowerCase();
    if(!orderParam||!emailParam) return res.status(400).json({ok:false,error:'PARAMETRI_MANCANTI'});
    const name=orderParam.startsWith('#')?orderParam:`#${orderParam}`;
    const or=await restGetOrderByName(name); if(!or.ok) return res.status(500).json({ok:false,error:'REST_FAIL'});
    const order=or.json?.orders?.[0]; if(!order) return res.status(404).json({ok:false,error:'ORDINE_NON_TROVATO'});

    const orderEmail=(order.email||'').toLowerCase(); const custEmail=(order.customer?.email||'').toLowerCase();
    if(!(emailParam===orderEmail||emailParam===custEmail)) return res.status(400).json({ok:false,error:'EMAIL_MISMATCH'});

    const ship=order.shipping_address||{}; const cust=order.customer||{}; const line=order.line_items?.[0]||{};
    const prefill={nome:ship.first_name||cust.first_name||'',cognome:ship.last_name||cust.last_name||'',email:order.email||cust.email||'',telefono:ship.phone||cust.phone||order.phone||'',
      indirizzo:[ship.address1,ship.address2].filter(Boolean).join(', '),citta:ship.city||'',cap:ship.zip||'',provincia:ship.province||'',paese:ship.country||'',
      modello:line.title||'',dataOrdine:order.created_at||'',orderId:order.id,orderName:order.name};
    const token=SECRET?createPrefillToken(prefill.orderName||prefill.orderId,prefill.email):null;

    if(STRICT_CARRELLI){
      const chk=await orderHasCarrelloByRefEmail(prefill.orderName||prefill.orderId,emailParam);
      if(!chk.ok && chk.reason==='NON_CARRELLO') return res.status(400).json({ok:false,error:'NON_CARRELLO',product:chk.product||null});
      if(!chk.ok && chk.reason!=='NON_CARRELLO') return res.status(502).json({ok:false,error:chk.reason});
    }
    return res.json({ok:true,prefill,token,ttl:PREFILL_TTL_MS});
  }catch(err){return res.status(500).json({ok:false,error:String(err?.message||err)});}
});

app.post('/registrazione', regLimiter, async (req,res)=>{
  try{
    const p=req.body||{}; if(p.hp) return res.status(400).json({ok:false,error:'BOT'});
    const dealer=isDealer(req);
    const orderRef=p.orderName||p.orderId||'';

    // Token obbligatorio SOLO se non dealer
    if(!dealer){
      const tok=pickToken(req); const token=tok.chosen||p.prefillToken||'';
      if(SECRET){
        if(!token) return res.status(400).json({ok:false,error:'PREFILL_OBBLIGATORIO'});
        const v=verifyPrefillToken(token,orderRef,p.email);
        if(!v.ok) return res.status(400).json({ok:false,error:'TOKEN_INVALIDO',reason:v.reason,decoded:v.decoded,provided:{orderRef,email:(p.email||'').toLowerCase()}});
        if(STRICT_CARRELLI){
          const ref=(v.decoded?.ref||orderRef||'').trim(); const em=(v.decoded?.em||p.email||'').toLowerCase().trim();
          const chk=await orderHasCarrelloByRefEmail(ref,em);
          if(!chk.ok) return res.status(400).json({ok:false,error:chk.reason,details:chk.product||null});
          req._cartInfo = chk.product || null;
        }
      }else{
        return res.status(500).json({ok:false,error:'CONFIG_TOKEN_MANCANTE'});
      }
    }

    // Blocco “una sola registrazione per ordine” SOLO non-dealer
    if(!dealer){
      try{
        await db.collection('registrazioni_idx').doc(`ORDER__${safeId(orderRef||'SENZA-ORDINE')}`)
          .create({orderRef,createdAt:admin.firestore.FieldValue.serverTimestamp()});
      }catch(e){
        if(e && (e.code===6 || /ALREADY_EXISTS/i.test(String(e.message)))) return res.status(409).json({ok:false,error:'DUPLICATO_ORDINE'});
        throw e;
      }
    }

    // Immagine mail (se disponibile per non-dealer; dealer spesso senza ordine)
    let mailImageUrl=null;
    if(!dealer){
      const cartInfo=req._cartInfo || null;
      if(cartInfo?.id || cartInfo?.variantId) mailImageUrl=await resolveVariantImageUrl(cartInfo.id,cartInfo.variantId);
    }

    // Dati minimi
    const obbligatori=['email','modello','seriale','telefono'];
    const mancanti=obbligatori.filter(k=>!p[k]);
    if(mancanti.length) return res.status(400).json({ok:false,error:'DATI_INSUFFICIENTI',fields:mancanti});

    const serialeNorm=String(p.seriale||'').trim().toUpperCase().replace(/\s+/g,'');
    const regId=`${safeId(orderRef|| (dealer?'RIVENDITORE':'SENZA-ORDINE'))}__${serialeNorm}`;
    const docRef=db.collection('registrazioni').doc(regId);

    await docRef.create({
      ...p,
      seriale: serialeNorm,
      imageUrl: mailImageUrl || null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      dealerMode: dealer || false
    });

    const ip=req.ip||req.headers['x-forwarded-for']||req.connection.remoteAddress||'unknown';
    await db.collection('registrazioni_log').add({
      regId, orderRef, seriale: serialeNorm, ip, ua:req.headers['user-agent']||'',
      origin:req.headers['origin']||'', when:admin.firestore.FieldValue.serverTimestamp(),
      ok:true, dealer
    });

    // Email
    try{
      if(transporter.options.host && transporter.options.auth){
        await transporter.sendMail({
          from: EMAIL_FROM,
          to: p.email,
          bcc: ADMIN_EMAIL || undefined,
          subject: 'Conferma registrazione garanzia',
          html: emailHTML({ ...p, seriale: serialeNorm, orderName: orderRef }, mailImageUrl),
        });
      }
    }catch(e){ console.error('Email fallita:', e.message); }

    return res.json({ok:true,id:regId,reset:true,dealer});
  }catch(err){
    if(err && (err.code===6 || /ALREADY_EXISTS/i.test(String(err.message)))){
      try{
        const p=req.body||{}; const orderRef=p.orderName||p.orderId||''; const serialeNorm=String(p.seriale||'').trim().toUpperCase().replace(/\s+/g,'');
        const ip=req.ip||req.headers['x-forwarded-for']||req.connection.remoteAddress||'unknown';
        await db.collection('registrazioni_log').add({regId:`${safeId(orderRef||'SENZA-ORDINE')}__${serialeNorm}`,orderRef,seriale:serialeNorm,ip,ua:req.headers['user-agent']||'',origin:req.headers['origin']||'',when:admin.firestore.FieldValue.serverTimestamp(),ok:false,error:'DUPLICATO'});
      }catch(_){}
      return res.status(409).json({ok:false,error:'DUPLICATO'});
    }
    console.error(err);
    return res.status(500).json({ok:false,error:String(err?.message||err)});
  }
});

const PORT=process.env.PORT||3000;
app.listen(PORT,()=>console.log(`✅ Server running on port ${PORT}`));
