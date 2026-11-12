/**
 * Snapshot one school's climate data to CSV, before anyone touches it.
 *
 * WHY
 *
 * Pleasanton's 2,947 answers exist in exactly one place. The week they were
 * collected included two bulk retags moving 1,768 rows, three session moves
 * and four token rewrites — every one dry-run first, every one correct, and
 * all of them writes against live data with no snapshot behind them.
 *
 * Report generation is read-only and cannot hurt the data. The risk starts
 * afterwards, when findings turn into archiving, exclusions and cleanup. Take
 * the snapshot before that, not after.
 *
 * archive-export.mjs already exists and is deliberately left alone: it is
 * pinned to the 2026 teacher pilot and the superintendent interviews, and
 * rewriting it to be general would put a historical artefact at risk for no
 * reason. This is the one for a current deployment.
 *
 *   node export-school.mjs --school pps-2026-27
 *   node export-school.mjs --school pps-2026-27 --out ~/Desktop/pps-snapshot
 *
 * Writes three files:
 *
 *   responses.csv   one row per answer — the data itself
 *   sessions.csv    one row per respondent, with the quality flags
 *   MANIFEST.txt    counts, date range, and what was flagged
 *
 * READ ONLY. Reads two collections and writes to disk. Touches nothing in
 * Firestore.
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
if (!SCHOOL) {
  console.error('\nUsage: node export-school.mjs --school <school_id> [--out <dir>]\n');
  process.exit(1);
}
const OUT = path.resolve(argOf('--out') || path.join(here, `export-${SCHOOL}`));

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
admin.initializeApp({ credential: admin.credential.cert(sa), projectId: process.env.FIREBASE_PROJECT_ID || sa.project_id });
const db = admin.firestore();

const textOf = (d) => (d.followup_text ?? d.text ?? '') || '';
const when = (d) =>
  d.ts_at?.toDate?.() || (typeof d.ts === 'string' ? new Date(d.ts) : null) || (d.ts?.toDate?.() ?? null);
const ROLE = (s) => String(s || '?').replace('school_climate_', '');

/* Same test as watch-deployment.mjs — see the long note there. */
const FOREIGN_SCRIPT = /[Ѐ-ӿͰ-Ͽ֐-׿؀-ۿ一-鿿぀-ヿऀ-ॿ]/;
const DIACRITIC = /[À-ÿĀ-ɏ]/g;
function looksFabricated(t) {
  if (!t) return false;
  if (FOREIGN_SCRIPT.test(t)) return true;
  const h = t.match(DIACRITIC);
  return h !== null && h.length >= 3;
}

/**
 * RFC 4180. Answers contain commas, quotes and newlines — a naive join would
 * silently corrupt the thing this script exists to preserve.
 */
const csv = (v) => {
  const s = v === null || v === undefined ? '' : String(v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
const row = (cells) => cells.map(csv).join(',');

const SECTIONS = ['school_climate_students', 'school_climate_teachers',
  'school_climate_staff', 'school_climate_parents'];

console.log(`\nReading ${SCHOOL} …`);

const docs = [];
const snaps = await Promise.all(
  SECTIONS.map((s) => db.collection('responses').where('section', '==', s).get()),
);
for (const snap of snaps) {
  for (const d of snap.docs) {
    const data = d.data();
    if (data.school_id !== SCHOOL) continue;
    docs.push({ _id: d.id, ...data });
  }
}

if (!docs.length) {
  console.error(`\nNo responses found for school_id "${SCHOOL}". Nothing written.\n`);
  process.exit(1);
}

docs.sort((a, b) => String(a.session_id).localeCompare(String(b.session_id))
  || String(a.question_id).localeCompare(String(b.question_id)));

fs.mkdirSync(OUT, { recursive: true });

/* ── responses.csv ─────────────────────────────────────────────────────────── */

const responseLines = [row([
  'session_id', 'role', 'question_id', 'rating', 'domain',
  'answer_text', 'chars', 'flagged_fabricated', 'token', 'ts', 'doc_id',
])];

const sessions = new Map();

for (const d of docs) {
  const t = textOf(d);
  const fab = looksFabricated(t);
  const role = ROLE(d.section);
  const dt = when(d);

  responseLines.push(row([
    d.session_id, role, d.question_id, d.rating, d.domain,
    t, t.length, fab ? 'YES' : '', d.token, dt ? dt.toISOString() : '', d._id,
  ]));

  if (!sessions.has(d.session_id)) {
    sessions.set(d.session_id, {
      id: d.session_id, role, token: d.token || '',
      rows: 0, withText: 0, fabricated: 0, first: null, last: null,
    });
  }
  const s = sessions.get(d.session_id);
  s.rows += 1;
  if (t.trim()) s.withText += 1;
  if (fab) s.fabricated += 1;
  if (dt) {
    if (!s.first || dt < s.first) s.first = dt;
    if (!s.last || dt > s.last) s.last = dt;
  }
}

fs.writeFileSync(path.join(OUT, 'responses.csv'), responseLines.join('\n') + '\n');

/* ── sessions.csv ──────────────────────────────────────────────────────────── */

const all = [...sessions.values()];
const sessionLines = [row([
  'session_id', 'role', 'answers', 'with_text', 'text_pct',
  'fabricated', 'ratings_only', 'started', 'ended', 'minutes', 'token',
])];

for (const s of all.sort((a, b) => a.role.localeCompare(b.role) || (a.first - b.first))) {
  const mins = s.first && s.last ? Math.round((s.last - s.first) / 60000) : '';
  sessionLines.push(row([
    s.id, s.role, s.rows, s.withText,
    s.rows ? Math.round((s.withText / s.rows) * 100) : '',
    s.fabricated || '',
    // Named plainly rather than "blank run": these people completed the
    // survey and declined the optional spoken part. The ratings are valid.
    s.withText === 0 && s.rows >= 2 ? 'YES' : '',
    s.first ? s.first.toISOString() : '', s.last ? s.last.toISOString() : '', mins,
    s.token,
  ]));
}

fs.writeFileSync(path.join(OUT, 'sessions.csv'), sessionLines.join('\n') + '\n');

/* ── MANIFEST.txt ──────────────────────────────────────────────────────────── */

const byRole = {};
for (const s of all) {
  const r = (byRole[s.role] ||= { sessions: 0, answers: 0, withText: 0, fab: 0, ratingsOnly: 0 });
  r.sessions += 1; r.answers += s.rows; r.withText += s.withText; r.fab += s.fabricated;
  if (s.withText === 0 && s.rows >= 2) r.ratingsOnly += 1;
}

// Comparator required. Array.sort() with none converts to string, and a Date
// stringifies to "Mon Nov 09 2026 …" — so the default sorts alphabetically by
// weekday name. The first manifest reported a range of 09 to 11 November for
// data collected from the 3rd, because "Mon" sorts before "Tue".
const dates = all.map((s) => s.first).filter(Boolean).sort((a, b) => a - b);
const L = [];
L.push(`Clarity 360 — export of ${SCHOOL}`);
L.push(`taken ${new Date().toISOString()}`);
L.push('');
L.push(`sessions  ${all.length}`);
L.push(`answers   ${docs.length}`);
L.push(`range     ${dates[0]?.toISOString().slice(0, 10)} to ${dates[dates.length - 1]?.toISOString().slice(0, 10)}`);
L.push('');
L.push('role        sessions  answers  w/text   fabricated  ratings-only');
L.push('-'.repeat(66));
for (const [role, r] of Object.entries(byRole).sort()) {
  const pct = r.answers ? Math.round((r.withText / r.answers) * 100) : 0;
  L.push(`${role.padEnd(12)}${String(r.sessions).padStart(5)}${String(r.answers).padStart(9)}`
    + `${String(r.withText).padStart(8)} (${String(pct).padStart(3)}%)`
    + `${String(r.fab).padStart(8)}${String(r.ratingsOnly).padStart(14)}`);
}
L.push('');
L.push('READING THESE NUMBERS');
L.push('');
L.push('ratings-only — the respondent completed the survey and did not speak.');
L.push('  Their ratings are valid and belong in every average. They are not a');
L.push('  fault and were not excluded.');
L.push('');
L.push('fabricated — transcription invented an answer, usually in another');
L.push('  language, when loud background noise made the audio unparseable.');
L.push('  Those answers are not what anyone said and should not be quoted or');
L.push('  counted. The RATINGS from the same respondents are unaffected.');
L.push('');
L.push('w/text counts answers with any stored words, before either judgement.');
L.push('');
L.push('Written by export-school.mjs. Read-only; nothing in Firestore was');
L.push('modified to produce it.');

fs.writeFileSync(path.join(OUT, 'MANIFEST.txt'), L.join('\n') + '\n');

console.log('');
console.log(L.join('\n'));
console.log('');
console.log(`written to ${OUT}`);
console.log('  responses.csv   one row per answer');
console.log('  sessions.csv    one row per respondent');
console.log('  MANIFEST.txt    the summary above');
console.log('');
process.exit(0);
