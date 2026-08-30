/**
 * Are the composite indexes ready?
 *
 * Rather than reading a status page, this runs one query of each indexed shape.
 * Firestore answers the question directly: a query whose index is missing or
 * still building fails with FAILED_PRECONDITION and says so. A query that
 * returns — even with zero rows — is served.
 *
 * That is a better test than the console, because the console reports on the
 * index and this reports on the query. Those are the same thing right up until
 * they are not: a typo in a field name yields a perfectly Enabled index that no
 * query will ever use.
 *
 * READ ONLY.
 *
 *   node check-indexes.mjs
 */

import 'dotenv/config';
import admin from 'firebase-admin';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));

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

const checks = [
  ['responses  section + ts_at', () =>
    db.collection('responses')
      .where('section', '==', 'school_climate_teachers')
      .orderBy('ts_at', 'desc').limit(1).get()],

  ['responses  section + school_id + ts_at', () =>
    db.collection('responses')
      .where('section', '==', 'school_climate_teachers')
      .where('school_id', '==', 'august-30')
      .orderBy('ts_at', 'desc').limit(1).get()],

  ['responses  section + school_id + survey_cycle + ts_at', () =>
    db.collection('responses')
      .where('section', '==', 'school_climate_teachers')
      .where('school_id', '==', 'august-30')
      .where('survey_cycle', '==', 'Fall 2026')
      .orderBy('ts_at', 'desc').limit(1).get()],

  ['responses  session_id + section', () =>
    db.collection('responses')
      .where('session_id', '==', 'probe')
      .where('section', '==', 'school_climate_teachers').limit(1).get()],

  ['responses  section + question_id + item_version', () =>
    db.collection('responses')
      .where('section', '==', 'school_climate_teachers')
      .where('question_id', '==', 'S7')
      .where('item_version', '==', 'probe').limit(1).get()],

  ['climate_sessions  school_id + completed_at', () =>
    db.collection('climate_sessions')
      .where('school_id', '==', 'august-30')
      .orderBy('completed_at', 'desc').limit(1).get()],

  ['climate_sessions  school_id + role + completed_at', () =>
    db.collection('climate_sessions')
      .where('school_id', '==', 'august-30')
      .where('role', '==', 'teachers')
      .orderBy('completed_at', 'desc').limit(1).get()],
];

console.log(`Project: ${process.env.FIREBASE_PROJECT_ID || sa.project_id}\n`);

let ready = 0, building = 0, other = 0;

for (const [name, run] of checks) {
  try {
    const snap = await run();
    console.log(`  READY     ${name.padEnd(52)} (${snap.size} row${snap.size === 1 ? '' : 's'})`);
    ready++;
  } catch (err) {
    const msg = String(err.message || err);
    if (/currently building|being built/i.test(msg)) {
      console.log(`  BUILDING  ${name}`);
      building++;
    } else if (/index/i.test(msg) && /FAILED_PRECONDITION|requires an index/i.test(msg)) {
      console.log(`  MISSING   ${name}`);
      const link = msg.match(/https:\/\/\S+/);
      if (link) console.log(`            create: ${link[0]}`);
      building++;
    } else {
      console.log(`  ERROR     ${name}\n            ${msg.slice(0, 160)}`);
      other++;
    }
  }
}

console.log(`\n${ready} ready, ${building} not ready, ${other} other error`);
if (ready === checks.length) {
  console.log('\nAll shapes served. The query paths can move to server-side filtering.');
} else if (building > 0) {
  console.log('\nStill building — Firestore takes a few minutes. Re-run shortly.');
}
process.exit(0);
