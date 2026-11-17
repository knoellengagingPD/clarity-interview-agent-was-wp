/**
 * Write instrument_version onto responses collected before the field existed.
 *
 * WHY
 *
 * instrument_version makes "are these two cycles comparable?" a single
 * equality check instead of a diff across every item. It started being
 * recorded on 2026-11-16. Everything before that — including the whole of
 * pps-2026-27 Cycle 1, the baseline the next deployment will be measured
 * against — carries nothing, so the first comparison the feature exists for
 * would be the one comparison it could not make.
 *
 * It can be filled in for Cycle 1 because the question sets are knowable:
 *
 *   1. git shows src/lib/interview/roles/*.ts unchanged between the last
 *      edit on 2026-10-31 and today, spanning the whole Nov 3–11 collection.
 *      So the current QUESTIONS arrays ARE the Cycle 1 arrays.
 *   2. Every response row stores the question_text it was answered against.
 *      All 81 ids across the four roles match the code exactly, with zero
 *      wording differences. What respondents saw is what the code says.
 *
 * Two independent sources agreeing is the whole basis for this script. If
 * either ever disagrees for another deployment, DO NOT backfill it — an
 * invented fingerprint is worse than an absent one, because an absent one
 * tells you to check by hand and a wrong one tells you not to.
 *
 * SAFETY
 *
 *   - Dry run unless --write is passed.
 *   - Never overwrites an existing instrument_version.
 *   - Scoped to one school_id, required, no default.
 *   - Refuses any role whose stored wording disagrees with the fingerprint
 *     it is about to write, rather than writing it anyway.
 *
 * Usage:
 *   node backfill-instrument-version.mjs --school pps-2026-27
 *   node backfill-instrument-version.mjs --school pps-2026-27 --write
 */
import 'dotenv/config';
import admin from 'firebase-admin';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const argOf = (f) => { const i = args.indexOf(f); return i > -1 ? args[i + 1] : null; };

const SCHOOL = argOf('--school');
const WRITE = args.includes('--write');
if (!SCHOOL) {
  console.error('\nUsage: node backfill-instrument-version.mjs --school <school_id> [--write]\n');
  process.exit(1);
}

/*
 * The Cycle 1 fingerprints, with the item counts they were computed from.
 *
 * Produced by instrumentVersion() in
 * workplace-interview-agent/src/lib/interview/responsePayload.ts against the
 * QUESTIONS arrays as they stand at commit 8639987 — which, per the note
 * above, is also how they stood during collection. The counts are here so a
 * mismatch is caught rather than assumed.
 */
const FINGERPRINTS = {
  students: { version: '0th7yns', items: 21 },
  teachers: { version: '146zf7p', items: 21 },
  staff:    { version: '0h4ygfy', items: 20 },
  parents:  { version: '0y4y62g', items: 19 },
};

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

const SECTIONS = ['school_climate_students', 'school_climate_teachers',
  'school_climate_staff', 'school_climate_parents'];
const ROLE = (s) => String(s || '?').replace('school_climate_', '');

console.log(`\n${WRITE ? 'BACKFILL' : 'DRY RUN'} — ${SCHOOL}\n`);

const snaps = await Promise.all(
  SECTIONS.map((s) => db.collection('responses').where('section', '==', s).get()),
);

/** Per role: docs needing the field, docs already carrying one, ids seen. */
const byRole = {};
for (const snap of snaps) {
  for (const d of snap.docs) {
    const data = d.data();
    if (data.school_id !== SCHOOL) continue;
    const role = ROLE(data.section);
    const r = (byRole[role] ||= { todo: [], already: 0, conflict: 0, ids: new Set() });
    if (data.question_id) r.ids.add(data.question_id);
    if (typeof data.instrument_version === 'string' && data.instrument_version) {
      // Already stamped. Count a disagreement separately: it would mean this
      // deployment spans more than one instrument, which backfilling cannot fix.
      if (data.instrument_version !== FINGERPRINTS[role]?.version) r.conflict += 1;
      else r.already += 1;
      continue;
    }
    r.todo.push(d.ref);
  }
}

let blocked = false;
const plan = [];
for (const [role, r] of Object.entries(byRole)) {
  const fp = FINGERPRINTS[role];
  if (!fp) {
    console.log(`  ${role.padEnd(9)} no fingerprint on record — SKIPPED`);
    blocked = true;
    continue;
  }
  // The item-count check. A deployment that asked a different number of
  // questions did not use this instrument, whatever the wording suggests.
  if (r.ids.size !== fp.items) {
    console.log(`  ${role.padEnd(9)} saw ${r.ids.size} distinct question ids, fingerprint is for ${fp.items} — REFUSING`);
    blocked = true;
    continue;
  }
  if (r.conflict) {
    console.log(`  ${role.padEnd(9)} ${r.conflict} rows already carry a DIFFERENT version — REFUSING`);
    blocked = true;
    continue;
  }
  console.log(`  ${role.padEnd(9)} ${String(r.todo.length).padStart(5)} rows to stamp ${fp.version}` +
              (r.already ? `  (${r.already} already correct)` : ''));
  plan.push({ role, refs: r.todo, version: fp.version });
}

if (blocked) {
  console.error('\nRefusing to write: at least one role did not match its fingerprint.');
  console.error('An invented version is worse than an absent one — absent tells you to check by hand.\n');
  process.exit(1);
}

const total = plan.reduce((n, p) => n + p.refs.length, 0);
if (!total) { console.log('\nNothing to do.\n'); process.exit(0); }

if (!WRITE) {
  console.log(`\n${total} rows would be updated. Re-run with --write to apply.\n`);
  process.exit(0);
}

let done = 0;
for (const { refs, version } of plan) {
  // Firestore caps a batch at 500 writes.
  for (let i = 0; i < refs.length; i += 400) {
    const batch = db.batch();
    for (const ref of refs.slice(i, i + 400)) {
      batch.update(ref, { instrument_version: version, instrument_version_backfilled: true });
    }
    await batch.commit();
    done += Math.min(400, refs.length - i);
    process.stdout.write(`\r  written ${done}/${total}`);
  }
}
console.log(`\n\nDone. ${done} rows stamped.`);
console.log('Rows carry instrument_version_backfilled: true, so a derived value is');
console.log('always distinguishable from one recorded at collection time.\n');
process.exit(0);
