import admin from 'firebase-admin';
import fs from 'fs';

const sa = JSON.parse(fs.readFileSync('./firebase-service-account.json', 'utf8'));
admin.initializeApp({ credential: admin.credential.cert(sa), projectId: sa.project_id });
const db = admin.firestore();

const snap = await db.collection('climate_tokens')
  .where('role', '==', 'teachers')
  .where('status', '==', 'active')
  .limit(20)
  .get();

if (snap.empty) {
  console.log('No active teacher tokens found.');
} else {
  snap.forEach(doc => {
    const d = doc.data();
    console.log(JSON.stringify({ token: d.token, school_name: d.school_name, school_id: d.school_id, district: d.district, is_test: d.is_test, created_at: d.created_at }));
  });
}
process.exit(0);
