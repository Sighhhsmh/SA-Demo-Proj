const admin =  require("firebase-admin");
//const { readFileSync } = require("fs");

const serviceAccount = JSON.parse(process.env['Firebase-Service-Account']);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

module.exports = db;

