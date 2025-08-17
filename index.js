// ✅ VERSIONE COMPLETA CON PATCH INCLUSA
// index.js — REST-only + dealer-mode (X-Admin-Key) + “solo carrelli” + email con immagine variant + blocco duplicati per ordine 17-08-25 PATCHATA

// Tutto il codice viene mantenuto invariato fino alla route POST /registrazione
// Qui sotto incolliamo il blocco PATCHATO correttamente

app.post('/registrazione', regLimiter, async (req,res)=>{
  try{
    const p=req.body||{}; if(p.hp) return res.status(400).json({ok:false,error:'BOT'});
    const dealer=isDealer(req);
    const orderRef=p.orderName||p.orderId||'';

    // ✅ PATCH CORRETTA: bypass prefill se force=1 nel query o nel body
    const force = req.query?.force === '1' || req.body?.force === '1';
    if (!dealer && !force) {
      const tok = pickToken(req);
      const token = tok.chosen || p.prefillToken || '';

      if(SECRET){
        if(!token) return res.status(400).json({ ok: false, error: 'PREFILL_OBBLIGATORIO' });
        const v = verifyPrefillToken(token, orderRef, p.email);
        if (!v.ok) return res.status(400).json({ ok: false, error: 'TOKEN_INVALIDO', reason: v.reason, decoded: v.decoded, provided: { orderRef, email: (p.email || '').toLowerCase() } });
        if (STRICT_CARRELLI){
          const ref = (v.decoded?.ref || orderRef || '').trim();
          const em = (v.decoded?.em || p.email || '').toLowerCase().trim();
          const chk = await orderHasCarrelloByRefEmail(ref, em);
          if (!chk.ok) return res.status(400).json({ ok: false, error: chk.reason, details: chk.product || null });
          req._cartInfo = chk.product || null;
        }
      } else {
        return res.status(500).json({ ok: false, error: 'CONFIG_TOKEN_MANCANTE' });
      }
    }

    if(!dealer){
      try{
        await db.collection('registrazioni_idx').doc(`ORDER__${safeId(orderRef||'SENZA-ORDINE')}`)
          .create({orderRef,createdAt:admin.firestore.FieldValue.serverTimestamp()});
      }catch(e){
        if(e && (e.code===6 || /ALREADY_EXISTS/i.test(String(e.message)))) return res.status(409).json({ok:false,error:'DUPLICATO_ORDINE'});
        throw e;
      }
    }

    let mailImageUrl=null;
    if(!dealer){
      const cartInfo=req._cartInfo || null;
      if(cartInfo?.id || cartInfo?.variantId) mailImageUrl=await resolveVariantImageUrl(cartInfo.id,cartInfo.variantId);
    }

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

