const admin =  require("firebase-admin");
const { readFileSync } = require("fs");

const serviceAccount = JSON.parse(
  readFileSync("./sso-demo-securityarchitecture-firebase-adminsdk-fbsvc-f67f14456d.json", "utf8")
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

module.exports = db;