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
 * Writes five files:
 *
 *   responses.csv   one row per answer — the data itself
 *   sessions.csv    one row per respondent, with the quality flags
 *   items.csv       one row per question: n, mean, min, max, sd
 *   shareable.csv   ratings only, no free text, respondents renumbered
 *   MANIFEST.TXT    counts, date range, and what was flagged
 *
 * question_text is carried on every answer row. It was omitted until
 * 2026-11-11, which made the export uninterpretable by anyone who did not
 * already have the survey in front of them: question ids are post-renumbering
 * (SC_STU_04 and the like) and NEITHER REPO CONTAINS A LOOKUP TABLE for them —
 * only a comment at server.js:6913 noting the 2026-10-27 renumbering happened.
 * The field was on the Firestore docs the whole time; the export simply did not
 * write it.
 *
 * items.csv exists because within-domain item spread is large: across all
 * twelve role-domains in pps-2026-27 the gap between a domain's easiest and
 * hardest item ran 0.39 to 0.71, median 0.61, which in every case exceeded the
 * change that role could reliably detect, and ran two to four times larger
 * than the differences between domains. Whether that is item difficulty or
 * genuine variation in what respondents think cannot be settled without an IRT
 * calibration across many schools. Either way the domain mean compresses most
 * of it away, so the item table is where the readable findings are.
 *
 * shareable.csv carries no free text, no token and no document id, and
 * renumbers respondents within role. Open answers can name a teacher or an
 * incident, and 87 students in one district is a small enough crowd that a
 * quotation plus a role can identify someone. The ratings cannot. Use this one
 * for anything leaving the district's control — an outside analyst, a
 * statistics question, a third-party tool.
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
const qtext = (d) =>
  typeof d.question_text === 'string' && d.question_text.trim() ? d.question_text.trim() : '';

/**
 * Mirrors server.js:5161. A rating of 0 is a placeholder written by the
 * open-ended half of a question pair, not an answer of zero — every
 * dream_big row and roughly half the ai_readiness rows carry one. Averaging
 * them in drags AI Readiness from about 2.6 down to about 1.3, which is how
 * an analysis of this export first read it as a near-floor score.
 */
const isRated = (d) => {
  const n = Number(d.rating);
  return d.rating !== undefined && d.rating !== null && !isNaN(n) && n !== 0;
};
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
  'session_id', 'role', 'question_id', 'question_text', 'rating', 'domain',
  'answer_text', 'chars', 'flagged_fabricated', 'token', 'ts', 'doc_id',
])];

const sessions = new Map();

for (const d of docs) {
  const t = textOf(d);
  const fab = looksFabricated(t);
  const role = ROLE(d.section);
  const dt = when(d);

  responseLines.push(row([
    d.session_id, role, d.question_id, qtext(d), d.rating, d.domain,
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

/* ── items.csv ─────────────────────────────────────────────────────────────── */

const items = new Map();
for (const d of docs) {
  if (!isRated(d)) continue;
  const key = `${ROLE(d.section)}|${d.question_id}`;
  if (!items.has(key)) {
    items.set(key, {
      role: ROLE(d.section), qid: d.question_id, domain: d.domain || '',
      text: qtext(d), vals: [],
    });
  }
  const it = items.get(key);
  it.vals.push(Number(d.rating));
  if (!it.text) it.text = qtext(d);
}

const itemLines = [row(['role', 'domain', 'question_id', 'question_text',
  'n', 'mean', 'min', 'max', 'sd'])];

// Sample sd (n-1). The population form understates spread at these sample
// sizes, and several roles here are small enough for the difference to matter.
const sd = (v) => {
  if (v.length < 2) return '';
  const m = v.reduce((a, b) => a + b, 0) / v.length;
  return Math.sqrt(v.reduce((a, x) => a + (x - m) ** 2, 0) / (v.length - 1));
};

const itemRows = [...items.values()].sort((a, b) =>
  a.role.localeCompare(b.role) || String(a.domain).localeCompare(String(b.domain))
  || String(a.qid).localeCompare(String(b.qid)));

for (const it of itemRows) {
  const m = it.vals.reduce((a, b) => a + b, 0) / it.vals.length;
  const s = sd(it.vals);
  itemLines.push(row([
    it.role, it.domain, it.qid, it.text, it.vals.length,
    m.toFixed(2), Math.min(...it.vals), Math.max(...it.vals),
    s === '' ? '' : s.toFixed(2),
  ]));
}

fs.writeFileSync(path.join(OUT, 'items.csv'), itemLines.join('\n') + '\n');

/* ── shareable.csv ─────────────────────────────────────────────────────────── */

// Respondents are renumbered within role, so per-respondent analysis still
// works (a domain mean's standard error needs the respondent as the unit)
// while the session id, which appears in Firestore and in the admin
// dashboard, does not travel.
const pseudo = new Map();
const shareLines = [row(['role', 'respondent', 'domain', 'question_id',
  'question_text', 'rating'])];

for (const d of docs) {
  if (!isRated(d)) continue;
  const role = ROLE(d.section);
  const key = `${role}|${d.session_id}`;
  if (!pseudo.has(key)) {
    const nth = [...pseudo.keys()].filter(k => k.startsWith(`${role}|`)).length + 1;
    pseudo.set(key, `${role.slice(0, 3).toUpperCase()}-${String(nth).padStart(3, '0')}`);
  }
  shareLines.push(row([
    role, pseudo.get(key), d.domain, d.question_id, qtext(d), d.rating,
  ]));
}

fs.writeFileSync(path.join(OUT, 'shareable.csv'), shareLines.join('\n') + '\n');

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
L.push('rating 0 is NOT an answer of zero. It is a placeholder written by the');
L.push('  open-ended half of a question pair. Every dream_big row carries one,');
L.push('  and so do about half the ai_readiness rows. Exclude them before');
L.push('  averaging anything — including them drags AI Readiness from roughly');
L.push('  2.6 to roughly 1.3. items.csv and shareable.csv already exclude them;');
L.push('  responses.csv keeps every row as stored.');
L.push('');
L.push('shareable.csv is the file to send outside the district: ratings only,');
L.push('  no free text, no token, no document id, respondents renumbered. Open');
L.push('  answers can name a teacher or an incident; the ratings cannot.');
L.push('');
L.push('Written by export-school.mjs. Read-only; nothing in Firestore was');
L.push('modified to produce it.');

fs.writeFileSync(path.join(OUT, 'MANIFEST.txt'), L.join('\n') + '\n');

console.log('');
console.log(L.join('\n'));
console.log('');
console.log(`written to ${OUT}`);
console.log('  responses.csv   one row per answer, with question text');
console.log('  sessions.csv    one row per respondent');
console.log('  items.csv       one row per question — n, mean, min, max, sd');
console.log('  shareable.csv   ratings only, de-identified, safe to send out');
console.log('  MANIFEST.txt    the summary above');
console.log('');
process.exit(0);
