// mailer.js
const nodemailer = require("nodemailer");

async function inviaConfermaRegistrazione({ to, modello, seriale, nome, email, telefono, data, luogo, immagine }) {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_UTENTE,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  const html = `
    <div style="font-family:Arial, sans-serif; font-size:16px; line-height:1.6;">
      <h2 style="color:#007c3d;">Registrazione Garanzia Stewart Confermata ✅</h2>
      <p><strong>Nome:</strong> ${nome}</p>
      <p><strong>Email:</strong> ${email}</p>
      <p><strong>Telefono:</strong> ${telefono}</p>
      <p><strong>Data:</strong> ${data}</p>
      <p><strong>Luogo:</strong> ${luogo}</p>
      <p><strong>Modello carrello:</strong> ${modello}</p>
      <p><strong>Serial Number:</strong> ${seriale}</p>
      ${immagine ? `<img src="${immagine}" alt="Modello acquistato" style="width:100%;max-width:400px;border-radius:12px;margin-top:20px;">` : ""}
      <hr>
      <p style="color:#555;">Grazie per aver registrato il tuo carrello Stewart Golf con VerticalGolf.</p>
    </div>
  `;

  await transporter.sendMail({
    from: `"VerticalGolf" <${process.env.EMAIL_UTENTE}>`,
    to,
    subject: "Registrazione Garanzia Confermata",
    html,
  });
}

module.exports = inviaConfermaRegistrazione;
