/**
 * Move a completed interview from one district to another.
 *
 * A tester used an old invitation link, so a real interview landed under the
 * wrong school_id. Nothing is wrong with the answers — they are simply filed
 * in the wrong drawer, and every dashboard figure and report keys on
 * school_id.
 *
 * This rewrites that field on the session's response rows, and on its
 * climate_sessions summary if one exists. It does not touch the answers, the
 * ratings, the timestamps or the document ids — those are
 * `<session>__<question>` and stay put, so the move is idempotent and a second
 * run changes nothing.
 *
 * DRY RUN BY DEFAULT. It prints what it would change and stops. Pass --apply
 * to write. That is deliberate: this is the only script here that edits
 * interview data rather than a flag beside it.
 *
 *   node move-session.mjs <session_id> <new_school_id> [--token NEW] [--apply]
 *
 * Example:
 *   node move-session.mjs sclst-480ea9cb-... gas-sept-8a
 *   node move-session.mjs sclst-480ea9cb-... gas-sept-8a --token SCL-HTF8A3 --apply
 *
 * ON THE TOKEN
 *
 * Optional, and worth thinking about rather than always passing. The dashboard
 * hides test data by matching a row's token against tokens flagged is_test. If
 * the old token is flagged and the new one is not — or the reverse — moving the
 * school_id alone will change whether these rows appear. Pass --token to move
 * the row onto the new district's token as well, which is usually what you
 * want when the interview should look like it was taken there.
 */

import 'dotenv/config';
import admin from 'firebase-admin';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const APPLY = args.includes('--apply');
const tokenIdx = args.indexOf('--token');
const NEW_TOKEN = tokenIdx > -1 ? args[tokenIdx + 1] : null;
const positional = args.filter((a, i) =>
  !a.startsWith('--') && !(tokenIdx > -1 && i === tokenIdx + 1));
const [SESSION_ID, NEW_SCHOOL_ID] = positional;

if (!SESSION_ID || !NEW_SCHOOL_ID) {
  console.error('usage: node move-session.mjs <session_id> <new_school_id> [--token NEW] [--apply]');
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

const snap = await db.collection('responses').where('session_id', '==', SESSION_ID).get();
if (snap.empty) {
  console.log(`No responses found for session ${SESSION_ID}. Nothing to move.`);
  process.exit(0);
}

// What is it now, and what would it become?
const first = snap.docs[0].data();
const sections = new Set(snap.docs.map(d => d.data().section));
const oldSchool = first.school_id || '(none)';
const oldToken = first.token || '(none)';

console.log(`session   ${SESSION_ID}`);
console.log(`section   ${[...sections].join(', ')}`);
console.log(`answers   ${snap.size}`);
console.log('');
console.log(`school_id ${oldSchool}  ->  ${NEW_SCHOOL_ID}`);
console.log(`token     ${oldToken}  ->  ${NEW_TOKEN || '(unchanged)'}`);

// The destination's own name and district, so the moved rows match their
// new neighbours rather than carrying the old district's labels.
let newName = null, newDistrict = null;
const destTokens = await db.collection('climate_tokens')
  .where('school_id', '==', NEW_SCHOOL_ID).limit(5).get();
if (!destTokens.empty) {
  const d = destTokens.docs[0].data();
  newName = d.school_name || null;
  newDistrict = d.district || null;
  console.log(`school_name ${first.school_name || '(none)'}  ->  ${newName || '(unchanged)'}`);
}

const summary = await db.collection('climate_sessions').doc(SESSION_ID).get();
console.log(`summary   ${summary.exists ? 'climate_sessions row will move too' : 'no climate_sessions row'}`);

if (!APPLY) {
  console.log('\nDRY RUN — nothing written. Re-run with --apply to make these changes.');
  process.exit(0);
}

const patch = { school_id: NEW_SCHOOL_ID };
if (NEW_TOKEN) patch.token = NEW_TOKEN;
if (newName) patch.school_name = newName;
if (newDistrict !== null) patch.district = newDistrict;

// Batched, because 18 individual writes can half-succeed and leave an
// interview split across two districts — which is worse than the problem.
let batch = db.batch(), n = 0, written = 0;
for (const doc of snap.docs) {
  batch.update(doc.ref, patch);
  if (++n % 400 === 0) { await batch.commit(); written += n; batch = db.batch(); n = 0; }
}
if (summary.exists) batch.update(summary.ref, patch);
await batch.commit();
written += n;

console.log(`\nMoved ${written} response row(s)${summary.exists ? ' and the session summary' : ''} to ${NEW_SCHOOL_ID}.`);
console.log('The dashboard caches for 30 seconds — wait, then Refresh.');
process.exit(0);
