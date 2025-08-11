const emailSender = require('./emailSender');

const datiFinti = {
  nome: "Giuseppe",
  cognome: "Zambotti",
  email: "gzambotti@me.com", // Usa un tuo indirizzo reale per testare
  telefono: "3483135370",
  modello: "Q Follow carbon Follow da 307 Wh",
  serial: "Q-123456",
  luogo: "Rovato",
  data_acquisto: "2025-08-06"
};

emailSender(datiFinti)
  .then(() => {
    console.log("✅ Email di test inviata con successo.");
  })
  .catch((err) => {
    console.error("❌ Errore nell'invio email:", err);
  });
