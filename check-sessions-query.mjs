/**
 * Does the new server-side date filter return exactly what the old in-memory
 * one did?
 *
 * /admin/sessions used to fetch every document and drop the out-of-range ones
 * locally. It now asks Firestore to do it. That is the same query in principle,
 * and the place it could quietly differ is the boundary: `end` is an inclusive
 * calendar day, so it has to become "< start of the following day". Off by one
 * there and a whole day of interviews vanishes from the dashboard with no error.
 *
 * So this runs both implementations over the same date windows and compares the
 * resulting document id sets. Differential, not eyeballed — the same approach
 * that proved the rating parser was equivalent to the four it replaced.
 *
 * Also confirms the ts_at backfill is complete, since a document lacking that
 * field is silently excluded from every filtered query.
 *
 * READ ONLY.
 *
 *   node check-sessions-query.mjs
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

// ── Preflight: is every document indexable? ─────────────────────────────────
const all = await db.collection('responses').get();
const missing = all.docs.filter(d => !d.data().ts_at);
console.log(`${all.size} documents in \`responses\``);
console.log(`missing ts_at: ${missing.length}${missing.length ? '  <-- these are invisible to every filtered query' : ''}\n`);

// ── OLD: fetch everything, filter in memory (exactly the previous code) ─────
function oldWay(section, start, end) {
  const startIso = start ? new Date(start).toISOString() : null;
  const endIso = end ? (() => { const d = new Date(end); d.setDate(d.getDate() + 1); return d.toISOString(); })() : null;
  return new Set(all.docs
    .filter(d => !section || d.data().section === section)
    .filter(d => {
      const doc = d.data();
      if (startIso && doc.ts && doc.ts < startIso) return false;
      if (endIso && doc.ts && doc.ts > endIso) return false;
      return true;
    })
    .map(d => d.id));
}

// ── NEW: let Firestore filter (exactly the current code) ────────────────────
async function newWay(section, start, end) {
  let q = db.collection('responses');
  if (section) q = q.where('section', '==', section);
  if (start) q = q.where('ts_at', '>=', admin.firestore.Timestamp.fromDate(new Date(start)));
  if (end) {
    const e = new Date(end);
    e.setDate(e.getDate() + 1);
    q = q.where('ts_at', '<', admin.firestore.Timestamp.fromDate(e));
  }
  // Mirrors the production query, orderBy included. Omitting it here is what
  // let a broken deploy pass verification on 2026-08-30: without an ordering,
  // Firestore wants an ASCENDING index and the deployed one is DESCENDING.
  if (start || end) q = q.orderBy('ts_at', 'desc');
  const snap = await q.get();
  return new Set(snap.docs.map(d => d.id));
}

const cases = [
  ['no filters',                    null,                       null,         null],
  ['section only',                  'school_climate_teachers',  null,         null],
  ['section + start',               'school_climate_teachers',  '2026-08-01', null],
  ['section + end',                 'school_climate_teachers',  null,         '2026-08-30'],
  ['section + both',                'school_climate_teachers',  '2026-08-01', '2026-08-30'],
  ['single day (boundary case)',    'school_climate_teachers',  '2026-08-30', '2026-08-30'],
  ['single day, earlier',           'school_climate_teachers',  '2026-08-27', '2026-08-27'],
  ['superintendent, wide window',   'superintendent_interview', '2026-01-01', '2026-12-31'],
];

let pass = 0;
for (const [name, section, start, end] of cases) {
  const before = oldWay(section, start, end);
  const after = await newWay(section, start, end);

  const onlyOld = [...before].filter(id => !after.has(id));
  const onlyNew = [...after].filter(id => !before.has(id));
  const ok = onlyOld.length === 0 && onlyNew.length === 0;
  if (ok) pass++;

  console.log(`  ${ok ? 'MATCH  ' : 'DIFFER '} ${name.padEnd(30)} ${before.size} docs`);
  if (!ok) {
    console.log(`           dropped by the new query : ${onlyOld.length}`);
    console.log(`           added by the new query   : ${onlyNew.length}`);
    if (onlyOld.length) {
      const d = all.docs.find(x => x.id === onlyOld[0]).data();
      console.log(`           example dropped: ts=${d.ts} ts_at=${d.ts_at ? d.ts_at.toDate().toISOString() : 'MISSING'}`);
    }
  }
}

console.log(`\n${pass}/${cases.length} identical`);
if (pass === cases.length && missing.length === 0) {
  console.log('Server-side filtering returns exactly what in-memory filtering did.');
}
process.exit(0);
