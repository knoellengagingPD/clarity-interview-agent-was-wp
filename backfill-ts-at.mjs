/**
 * Give every existing response document a real Firestore Timestamp.
 *
 * WHY
 *
 * `ts` has always been an ISO-8601 string. That sorts correctly and works, but
 * Firestore's date operators and BigQuery both want a Timestamp. New writes get
 * `ts_at` as of 2026-08-30; older documents do not have it.
 *
 * That gap is the whole problem. Firestore OMITS documents that lack an indexed
 * field, so the moment any query filters on ts_at, every document written before
 * today silently disappears from the results. Not an error — just quietly fewer
 * rows, which is the failure mode that has cost this project the most time.
 *
 * So: backfill first, switch queries second. After this runs, no document is
 * missing the field and ts_at can safely become the indexed date.
 *
 * Derives ts_at from the existing `ts` string — it does not invent a time.
 * A document with no usable `ts` is reported and left alone rather than being
 * given a plausible-looking wrong one.
 *
 * SAFE BY DEFAULT. Adds one field, changes nothing else, deletes nothing, and
 * is safe to run twice. Dry-run unless you pass --apply.
 *
 *   node backfill-ts-at.mjs            # report what would change
 *   node backfill-ts-at.mjs --apply    # write it
 */

import 'dotenv/config';
import admin from 'firebase-admin';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const APPLY = process.argv.includes('--apply');

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

console.log(APPLY ? 'APPLYING\n' : 'DRY RUN — nothing will be written. Use --apply to write.\n');

const snap = await db.collection('responses').get();
console.log(`${snap.size} documents in \`responses\`\n`);

let already = 0, toWrite = 0, unusable = 0;
const batchLimit = 400;
let batch = db.batch();
let inBatch = 0;
const bad = [];

for (const doc of snap.docs) {
  const d = doc.data();
  if (d.ts_at) { already++; continue; }

  const parsed = d.ts ? Date.parse(d.ts) : NaN;
  if (!Number.isFinite(parsed)) {
    unusable++;
    if (bad.length < 10) bad.push(`${doc.id}  ts=${JSON.stringify(d.ts)}`);
    continue;
  }

  toWrite++;
  if (APPLY) {
    batch.update(doc.ref, { ts_at: admin.firestore.Timestamp.fromMillis(parsed) });
    if (++inBatch >= batchLimit) {
      await batch.commit();
      process.stdout.write(`  committed ${toWrite}\r`);
      batch = db.batch();
      inBatch = 0;
    }
  }
}

if (APPLY && inBatch > 0) await batch.commit();

console.log(`already had ts_at : ${already}`);
console.log(`${APPLY ? 'written' : 'would write'}           : ${toWrite}`);
console.log(`unusable ts       : ${unusable}`);
if (bad.length) {
  console.log('\nDocuments left alone because their ts could not be parsed:');
  bad.forEach(b => console.log('  ' + b));
  console.log('  (left as-is deliberately — a guessed timestamp is worse than a missing one)');
}

if (!APPLY && toWrite > 0) console.log('\nRe-run with --apply to write these.');
if (APPLY && unusable === 0) {
  console.log('\nEvery document now has ts_at. Indexes and queries can safely move to it.');
}
process.exit(0);
