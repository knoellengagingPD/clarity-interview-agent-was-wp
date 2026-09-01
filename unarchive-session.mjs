/**
 * Restore an archived School Climate session.
 *
 * Archiving never deleted anything: it wrote one flag document keyed by
 * session_id into `climate_session_flags`, and the dashboard skips any session
 * that has one. Unarchiving deletes that flag. The answers in `responses` are
 * untouched throughout, so this is fully reversible in both directions.
 *
 * Equivalent to PATCH /school-climate/sessions/:id {action:'unarchive'}, which
 * is what the Unarchive button in the dashboard calls. Use that button when you
 * can — it also clears the server's query cache. This script exists for when
 * the session is hard to find in the UI, and it prints the cache note itself.
 *
 *   node unarchive-session.mjs <session_id>
 *   node unarchive-session.mjs --list <school_id>
 */

import 'dotenv/config';
import admin from 'firebase-admin';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);

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

// ── List mode ───────────────────────────────────────────────────────────────
if (args[0] === '--list') {
  const schoolId = args[1];
  let q = db.collection('climate_session_flags');
  if (schoolId) q = q.where('school_id', '==', schoolId);
  const snap = await q.get();
  const arch = snap.docs.filter(d => d.data().status === 'archived');
  if (!arch.length) {
    console.log(schoolId ? `Nothing archived for "${schoolId}".` : 'Nothing archived.');
    process.exit(0);
  }
  console.log(`${arch.length} archived session(s):\n`);
  for (const d of arch) {
    const f = d.data();
    const answers = await db.collection('responses').where('session_id', '==', f.session_id).get();
    console.log(`  ${f.session_id}`);
    console.log(`      school ${f.school_id}  ·  ${answers.size} answers still in Firestore`);
    console.log(`      archived ${String(f.created_at).slice(0, 19)}\n`);
  }
  process.exit(0);
}

// ── Unarchive ───────────────────────────────────────────────────────────────
const sessionId = args[0];
if (!sessionId) {
  console.error('usage: node unarchive-session.mjs <session_id>');
  console.error('       node unarchive-session.mjs --list [school_id]');
  process.exit(1);
}

const ref = db.collection('climate_session_flags').doc(sessionId);
const doc = await ref.get();

if (!doc.exists) {
  console.log(`No flag for ${sessionId} — it is not archived, so nothing to undo.`);
  console.log('If it is still missing from the dashboard, the other filter is');
  console.log('Hide Test Data. Run: node check-visibility.mjs <school_id>');
  process.exit(0);
}

// Say what is about to change, and prove the data survived, before changing it.
const answers = await db.collection('responses').where('session_id', '==', sessionId).get();
const sections = new Set(answers.docs.map(d => d.data().section));
console.log(`session  ${sessionId}`);
console.log(`school   ${doc.data().school_id}`);
console.log(`section  ${[...sections].join(', ') || '(none)'}`);
console.log(`answers  ${answers.size} in \`responses\` — never touched by archiving\n`);

await ref.delete();
console.log('Unarchived.');
console.log('\nThe dashboard caches session queries, so hit Refresh once. If it');
console.log('still does not appear, check Hide Test Data with check-visibility.mjs.');
process.exit(0);
