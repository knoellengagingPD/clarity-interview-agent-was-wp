/**
 * Did the spoken answers actually get stored?
 *
 * Gary's workplace interview on 2026-09-14 recorded 19 answers and stored an
 * empty string for every one of them. The ratings were fine — those are taps,
 * and the write fires whether the explanation is a sentence or "". Only the
 * three Dream Big items failed visibly, because they have no rating to hide
 * behind.
 *
 * Which means the capture counter we have been reading as a success metric
 * ("18 of 18 clean") counts WRITES, not CONTENT. A run with no transcripts at
 * all would still report a healthy number.
 *
 * This groups every stored response by session and reports how many carry real
 * explanation text. If push-to-talk broke transcription when it shipped, the
 * sessions split cleanly by date.
 *
 *   node audit-empty-answers.mjs              # all sections, summary per session
 *   node audit-empty-answers.mjs --section workplace_climate
 *   node audit-empty-answers.mjs --school gas-sept-8a
 *   node audit-empty-answers.mjs --samples    # print a few real answers found
 *
 * Read-only. Touches nothing.
 */

import 'dotenv/config';
import admin from 'firebase-admin';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const argOf = (flag) => {
  const i = args.indexOf(flag);
  return i > -1 ? args[i + 1] : null;
};
const ONLY_SECTION = argOf('--section');
const ONLY_SCHOOL = argOf('--school');
const SHOW_SAMPLES = args.includes('--samples');

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

// Climate and administrator answers live in `responses`. Workplace writes to
// its own collection — /workplace/log_response does
// admin.firestore().collection('workplace_climate') — so auditing only
// `responses` silently omits every workplace interview, which is how the first
// run of this script came back with no workplace rows at all.
const COLLECTIONS = ['responses', 'workplace_climate'];

const docs = [];
for (const name of COLLECTIONS) {
  let q = db.collection(name);
  if (ONLY_SECTION) q = q.where('section', '==', ONLY_SECTION);
  if (ONLY_SCHOOL) q = q.where('school_id', '==', ONLY_SCHOOL);
  try {
    const s = await q.get();
    console.log(`  ${name}: ${s.size} docs`);
    for (const d of s.docs) docs.push(d);
  } catch (e) {
    console.log(`  ${name}: unreadable (${e.message})`);
  }
}
if (!docs.length) {
  console.log('No responses matched.');
  process.exit(0);
}
const snap = { docs };

// The free-text field has had two names across products.
const textOf = (d) => (d.followup_text ?? d.text ?? '') || '';
const when = (d) =>
  d.ts_at?.toDate?.() ||
  (typeof d.ts === 'string' ? new Date(d.ts) : null) ||
  (d.ts?.toDate?.() ?? null);

const sessions = new Map();
for (const doc of snap.docs) {
  const d = doc.data();
  const id = d.session_id || '(no session)';
  if (!sessions.has(id)) {
    sessions.set(id, {
      section: d.section || '?', school: d.school_id || '?',
      rows: 0, withText: 0, chars: 0, date: null, samples: [],
    });
  }
  const s = sessions.get(id);
  const t = textOf(d).trim();
  s.rows += 1;
  if (t.length > 0) {
    s.withText += 1;
    s.chars += t.length;
    if (s.samples.length < 2) s.samples.push(`${d.question_id || '?'}: ${t.slice(0, 90)}`);
  }
  const dt = when(d);
  if (dt && (!s.date || dt < s.date)) s.date = dt;
}

const rows = [...sessions.entries()].sort((a, b) => {
  const da = a[1].date ? a[1].date.getTime() : 0;
  const db_ = b[1].date ? b[1].date.getTime() : 0;
  return da - db_;
});

console.log('');
console.log('date        section              school              rows  with-text   avg-chars  verdict');
console.log('─'.repeat(104));

let totRows = 0, totText = 0, deadSessions = 0;
for (const [id, s] of rows) {
  totRows += s.rows;
  totText += s.withText;
  const pct = s.rows ? Math.round((s.withText / s.rows) * 100) : 0;
  const avg = s.withText ? Math.round(s.chars / s.withText) : 0;
  let verdict;
  if (s.withText === 0) { verdict = '*** ALL EMPTY ***'; deadSessions += 1; }
  else if (pct < 50) verdict = `!! only ${pct}%`;
  else verdict = 'ok';
  console.log(
    `${(s.date ? s.date.toISOString().slice(0, 10) : '??????????').padEnd(11)} ` +
    `${s.section.slice(0, 20).padEnd(20)} ${s.school.slice(0, 19).padEnd(19)} ` +
    `${String(s.rows).padStart(4)}  ${String(s.withText).padStart(5)} (${String(pct).padStart(3)}%)  ` +
    `${String(avg).padStart(9)}  ${verdict}`,
  );
  if (SHOW_SAMPLES && s.samples.length) {
    for (const x of s.samples) console.log(`              · ${x}`);
  }
}

console.log('─'.repeat(104));
console.log(
  `${rows.length} session(s), ${totRows} stored answers, ` +
  `${totText} with text (${totRows ? Math.round((totText / totRows) * 100) : 0}%)`,
);
if (deadSessions) {
  console.log('');
  console.log(`${deadSessions} session(s) stored NOT ONE spoken answer.`);
  console.log('Their ratings are still valid — those are taps. Everything the');
  console.log('participant said in those interviews is gone.');
}
console.log('');
console.log('Read the date column. A clean split means push-to-talk broke it;');
console.log('scattered failures mean something environmental.');
process.exit(0);
