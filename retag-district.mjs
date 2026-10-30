/**
 * Move every session for one district onto a new school_id.
 *
 * WHY
 *
 * Pleasanton's pilot data and its full deployment must not pool. Reports key
 * on school_id, so two phases sharing one id means the pilot's figures — taken
 * before the transcript fixes, before the id renumbering, on a handful of
 * participants — are averaged into the district's real results, and nothing
 * anywhere says so.
 *
 * WHY school_id AND NOT A TEST FLAG
 *
 * The obvious alternative is flagging the old tokens is_test and letting the
 * dashboard's Hide Test Data filter deal with it. That filter is:
 *
 *   if (shouldHideTest && doc.token && testTokenSet.has(doc.token)) return false;
 *
 * Note `doc.token &&`. A row with NO token field is never hidden, whatever is
 * flagged in climate_tokens — and much of the historical climate data predates
 * the token system entirely. So flagging would quietly do nothing for exactly
 * the oldest rows it was meant to separate, and the failure would be invisible.
 * audit-districts.mjs exists to measure that; run it first.
 *
 * Re-tagging school_id works regardless of whether a row carries a token,
 * because school_id is the field every report and dashboard figure groups on.
 *
 * WHAT IT TOUCHES
 *
 * school_id on response rows, and on each session's climate_sessions summary
 * where one exists. Nothing else. Not answers, not ratings, not timestamps, not
 * question_ids, not document ids — those are `<session>__<question>` and stay
 * put, so a second run changes nothing and the operation is idempotent.
 *
 * It also does NOT touch climate_tokens. A token records the school it was
 * minted for, and rewriting that would make the token guard refuse new writes
 * from a link already in someone's inbox. Old tokens keep pointing at the old
 * id; that is correct, because the sessions they produced have moved with them.
 *
 * DRY RUN BY DEFAULT.
 *
 *   node retag-district.mjs --list
 *   node retag-district.mjs --from pleasanton --to pps-pilot-2026
 *   node retag-district.mjs --from pleasanton --to pps-pilot-2026 --apply
 *
 * Run --list first. It prints every distinct school_id with its response count
 * and date range, because the id Pleasanton's pilot actually used is a fact in
 * the data, not something to assume from the district's name.
 */

import 'dotenv/config';
import admin from 'firebase-admin';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const has = (f) => args.includes(f);
const argOf = (f) => {
  const i = args.indexOf(f);
  return i > -1 ? args[i + 1] : null;
};

const LIST = has('--list');
const APPLY = has('--apply');
const FROM = argOf('--from');
const TO = argOf('--to');

const CLIMATE_SECTIONS = [
  'school_climate_students',
  'school_climate_teachers',
  'school_climate_staff',
  'school_climate_parents',
];

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

admin.initializeApp({ credential: admin.credential.cert(credentials()) });
const db = admin.firestore();

async function climateRows() {
  const out = [];
  for (const section of CLIMATE_SECTIONS) {
    const snap = await db.collection('responses').where('section', '==', section).get();
    for (const d of snap.docs) out.push({ _ref: d.ref, _id: d.id, ...d.data() });
  }
  return out;
}

async function main() {
  const rows = await climateRows();

  if (LIST || !FROM || !TO) {
    const by = new Map();
    for (const r of rows) {
      const id = r.school_id || '(none)';
      if (!by.has(id)) by.set(id, { n: 0, tokened: 0, sessions: new Set(), names: new Set(), ts: [] });
      const e = by.get(id);
      e.n++;
      if (r.token) e.tokened++;
      if (r.session_id) e.sessions.add(r.session_id);
      if (r.school_name) e.names.add(r.school_name);
      if (r.ts) e.ts.push(r.ts);
    }

    console.log('\nEvery school_id in the four climate sections:\n');
    console.log('  school_id                       rows  w/token  sessions  first        last');
    console.log('  ' + '-'.repeat(82));
    const sorted = [...by.entries()].sort((a, b) => b[1].n - a[1].n);
    for (const [id, e] of sorted) {
      const ts = e.ts.sort();
      console.log(
        `  ${id.padEnd(30)} ${String(e.n).padStart(5)} ${String(e.tokened).padStart(8)} `
        + `${String(e.sessions.size).padStart(9)}  ${(ts[0] || '').slice(0, 10)}   ${(ts[ts.length - 1] || '').slice(0, 10)}`,
      );
      if (e.names.size) console.log(`  ${''.padEnd(30)} names: ${[...e.names].join(', ')}`);
    }

    console.log('\n  "w/token" is the column that matters if you were considering the test-data');
    console.log('  flag instead: rows without a token can never be hidden by it.\n');
    if (!FROM || !TO) {
      console.log('  Then: node retag-district.mjs --from <old id> --to <new id>\n');
    }
    if (LIST) process.exit(0);
  }

  const affected = rows.filter((r) => r.school_id === FROM);

  if (!affected.length) {
    console.error(`\nNo climate rows have school_id "${FROM}". Run --list to see the real ids.\n`);
    process.exit(1);
  }

  const clash = rows.filter((r) => r.school_id === TO);
  const sessions = [...new Set(affected.map((r) => r.session_id).filter(Boolean))];
  const ts = affected.map((r) => r.ts).filter(Boolean).sort();

  console.log('');
  console.log('='.repeat(78));
  console.log(`  ${APPLY ? 'RE-TAGGING' : 'DRY RUN — nothing will be written'}`);
  console.log('='.repeat(78));
  console.log(`  from school_id   ${FROM}`);
  console.log(`  to   school_id   ${TO}`);
  console.log(`  response rows    ${affected.length}`);
  console.log(`  sessions         ${sessions.length}`);
  console.log(`  date range       ${(ts[0] || '').slice(0, 10)} to ${(ts[ts.length - 1] || '').slice(0, 10)}`);
  console.log('');

  if (clash.length) {
    console.log(`  NOTE: ${clash.length} rows already carry school_id "${TO}". After this they will`);
    console.log('  pool with the rows being moved. If that is not what you want, pick a');
    console.log('  different destination id and run again.');
    console.log('');
  }

  const perSection = new Map();
  for (const r of affected) perSection.set(r.section, (perSection.get(r.section) || 0) + 1);
  console.log('  by section');
  for (const [s, n] of [...perSection].sort()) console.log(`    ${s.padEnd(26)} ${n}`);
  console.log('');

  if (!APPLY) {
    console.log('  Re-run with --apply to write. Nothing has changed.');
    console.log('='.repeat(78));
    console.log('');
    process.exit(0);
  }

  // Batched, 400 at a time — Firestore's limit is 500 and a summary write may
  // ride along in the same batch.
  let written = 0;
  for (let i = 0; i < affected.length; i += 400) {
    const batch = db.batch();
    for (const r of affected.slice(i, i + 400)) {
      batch.update(r._ref, { school_id: TO });
      written++;
    }
    await batch.commit();
    console.log(`  wrote ${Math.min(i + 400, affected.length)} / ${affected.length}`);
  }

  // The per-session summary, where one exists. Keyed by session id, so a
  // missing document is normal for older runs rather than an error.
  let summaries = 0;
  for (const sid of sessions) {
    const ref = db.collection('climate_sessions').doc(sid);
    const doc = await ref.get();
    if (!doc.exists) continue;
    if (doc.data().school_id !== FROM) continue;
    await ref.update({ school_id: TO });
    summaries++;
  }

  console.log('');
  console.log(`  ${written} response rows and ${summaries} session summaries now carry "${TO}".`);
  console.log('');
  console.log('  climate_tokens was deliberately NOT touched: a token records the school it');
  console.log('  was minted for, and rewriting that would make the server-side guard refuse');
  console.log('  new writes from links already sent out.');
  console.log('');
  console.log('  Refresh the admin dashboard manually — it does not auto-refresh.');
  console.log('='.repeat(78));
  console.log('');
}

main().catch((e) => {
  console.error('\nretag-district failed:', e.message);
  process.exit(1);
});
