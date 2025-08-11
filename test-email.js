const sendConfirmationEmail = require('./emailSender');

sendConfirmationEmail({
  nome: "Mario",
  cognome: "Rossi",
  email: "gzambotti@me.com", // 👈 cambialo con un'email reale tua
  modello: "Q Follow Carbon",
  serial: "Q-123456",
  luogo: "Negozio Golf Paradise",
  data_acquisto: "2025-08-01"
});
