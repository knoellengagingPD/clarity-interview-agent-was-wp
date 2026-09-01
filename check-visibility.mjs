/**
 * Why is a session not showing on the dashboard?
 *
 * /school-climate/sessions hides a document for exactly two reasons, and they
 * live in different collections from the data itself:
 *
 *   1. its token is flagged is_test in `climate_tokens`   (Hide Test Data, default ON)
 *   2. its session_id is flagged archived in `climate_session_flags`
 *
 * Neither touches `responses`. A hidden session is fully intact — which is
 * worth knowing before anyone goes looking for lost data.
 *
 * This reports every session for a district and says, per session, which of the
 * two filters is hiding it. READ ONLY.
 *
 *   node check-visibility.mjs <school_id>
 */

import 'dotenv/config';
import admin from 'firebase-admin';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const schoolId = process.argv[2];
if (!schoolId) {
  console.error('usage: node check-visibility.mjs <school_id>');
  process.exit(1);
}

function credentials() {
  const b64 = process.env.FIREBASE_SERVICE_ACCOUNT_B64;
  if (b64) return JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
  const json = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (json) return JSON.parse(json);
  const file = path.join(here, 'firebase-service-account.json');
  if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  console.error('No Firebase credentials found.');
  process.exit(1);
}

const sa = credentials();
admin.initializeApp({
  credential: admin.credential.cert(sa),
  projectId: process.env.FIREBASE_PROJECT_ID || sa.project_id,
});
const db = admin.firestore();

const responses = await db.collection('responses').where('school_id', '==', schoolId).get();
if (responses.empty) {
  console.log(`No responses at all for school_id "${schoolId}".`);
  process.exit(0);
}

const testTokens = new Set();
const tokenSnap = await db.collection('climate_tokens').where('school_id', '==', schoolId).get();
tokenSnap.docs.forEach(d => { if (d.data().is_test === true) testTokens.add(d.data().token); });

const archived = new Set();
const flagSnap = await db.collection('climate_session_flags').where('school_id', '==', schoolId).get();
flagSnap.docs.forEach(d => { if (d.data().status === 'archived') archived.add(d.data().session_id); });

const sessions = new Map();
for (const d of responses.docs) {
  const r = d.data();
  const s = sessions.get(r.session_id) || {
    id: r.session_id, section: r.section, token: r.token, answers: 0, first: r.ts,
  };
  s.answers += 1;
  if (r.ts && r.ts < s.first) s.first = r.ts;
  sessions.set(r.session_id, s);
}

console.log(`school_id: ${schoolId}`);
console.log(`${responses.size} answers across ${sessions.size} session(s)`);
console.log(`test tokens: ${testTokens.size} | archived sessions: ${archived.size}\n`);

const rows = [...sessions.values()].sort((a, b) => String(a.first).localeCompare(String(b.first)));
for (const s of rows) {
  const why = [];
  if (s.token && testTokens.has(s.token)) why.push('token is flagged is_test');
  if (archived.has(s.id)) why.push('session is ARCHIVED');
  const state = why.length ? `HIDDEN — ${why.join(' + ')}` : 'visible';
  console.log(`  ${state}`);
  console.log(`      ${s.section}  ${s.answers} answers  ${String(s.first).slice(0, 19)}`);
  console.log(`      session ${s.id}`);
  console.log(`      token   ${s.token}\n`);
}

const hidden = rows.filter(s => archived.has(s.id) || (s.token && testTokens.has(s.token)));
console.log(`${rows.length - hidden.length} visible, ${hidden.length} hidden.`);
if (hidden.length) {
  console.log('\nNothing above has been deleted. To restore an archived session:');
  console.log('  node unarchive-session.mjs <session_id>');
}
process.exit(0);
