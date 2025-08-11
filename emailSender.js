require('dotenv').config();
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');

// modello → file immagine
const modelloToImage = {
  "X10 Argento": "x10-argento.jpg",
  "X10 Bianco": "x10-bianco.jpg",
  "Q Follow Black edition": "qfollow-black.jpg",
  "Q Follow Carbon": "qfollow-carbon.jpg",
  "Q Range Follow Red": "qrange-red.jpg",
  "Q Range Follow Blue": "qrange-blue.jpg",
  "Q Range Follow Black": "qrange-black.jpg",
  "VERTX": "vertx.jpg"
};

// Transport SMTP OVH
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: parseInt(process.env.EMAIL_PORT || '465', 10),
  secure: String(process.env.EMAIL_SECURE || 'true').toLowerCase() === 'true',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

async function sendConfirmationEmail(dati) {
  const modello = dati.modello || '';
  const imageFile = modelloToImage[modello];
  const imagePath = imageFile ? path.join(__dirname, 'email-assets', 'images', imageFile) : null;
  const hasLocal = imagePath ? fs.existsSync(imagePath) : false;
  const publicUrl = imageFile ? `${process.env.BASE_IMAGE_URL}/${imageFile}` : null;

  const imgTag = imageFile
    ? (hasLocal
        ? `<img src="cid:carrelloImage" alt="Carrello Stewart" style="max-width:100%;border-radius:8px;margin-top:20px;">`
        : `<img src="${publicUrl}" alt="Carrello Stewart" style="max-width:100%;border-radius:8px;margin-top:20px;">`)
    : '';

  const htmlContent = `
    <div style="font-family: Arial, sans-serif; color:#333; max-width:600px; margin:auto;">
      <h2 style="color:#007c4f;">🎉 Garanzia registrata con successo</h2>
      <p>Gentile <strong>${dati.nome || ''} ${dati.cognome || ''}</strong>,</p>
      <p>Grazie per aver registrato il tuo carrello <strong>${modello}</strong>. Ecco i dettagli:</p>
      <ul style="line-height:1.6;">
        <li><strong>Modello:</strong> ${modello}</li>
        <li><strong>Serial Number:</strong> ${dati.serial || '-'}</li>
        <li><strong>Luogo di acquisto:</strong> ${dati.luogo || '-'}</li>
        <li><strong>Data di acquisto:</strong> ${dati.data_acquisto || '-'}</li>
        <li><strong>Email registrata:</strong> ${dati.email}</li>
        <li><strong>Data registrazione:</strong> ${new Date().toLocaleDateString()}</li>
      </ul>
      <p>Per qualsiasi informazione scrivici a <a href="mailto:${process.env.EMAIL_USER}">${process.env.EMAIL_USER}</a>.</p>
      ${imgTag}
    </div>
  `;

  const from = process.env.FROM_EMAIL || `"Stewart Golf" <${process.env.EMAIL_USER}>`;

  const mailOptions = {
    from,
    to: dati.email,
    subject: 'Conferma registrazione garanzia Stewart Golf',
    html: htmlContent,
    attachments: hasLocal ? [{ filename: imageFile, path: imagePath, cid: 'carrelloImage' }] : []
  };

  const info = await transporter.sendMail(mailOptions);
  console.log('✅ Email inviata:', info.messageId, '(allegato locale:', hasLocal, ')');
}

module.exports = sendConfirmationEmail;
