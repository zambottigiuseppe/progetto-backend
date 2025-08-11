require('dotenv').config();
const admin = require('firebase-admin');
const fs = require('fs');

// Verifica esistenza file chiave
if (!fs.existsSync(process.env.FIREBASE_PRIVATE_KEY_PATH)) {
  console.error("❌ File serviceAccountKey.json non trovato nel percorso indicato:", process.env.FIREBASE_PRIVATE_KEY_PATH);
  process.exit(1);
}

// Carica la chiave
const serviceAccount = require(process.env.FIREBASE_PRIVATE_KEY_PATH);

// Inizializza Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// Test lettura di una collezione esistente
async function testFirebaseConnection() {
  try {
    const snapshot = await db.collection('registrazioni').limit(1).get();

    if (snapshot.empty) {
      console.log("✅ Connessione OK, ma la collezione è vuota.");
    } else {
      snapshot.forEach(doc => {
        console.log("✅ Connessione OK, primo documento:", doc.id, doc.data());
      });
    }
  } catch (err) {
    console.error("❌ Errore nella connessione a Firestore:", err.message);
  }
}

testFirebaseConnection();
