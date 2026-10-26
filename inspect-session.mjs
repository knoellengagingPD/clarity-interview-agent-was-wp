/**
 * Look at one session answer by answer, to spot a truncated response.
 *
 * The audit script answers "did it store?" — this answers "did it store the
 * WHOLE thing?", which is a different question and the one that matters after
 * a participant reports an accidental stop.
 *
 * A truncated answer has a signature: it ends mid-sentence, with no terminal
 * punctuation, and is conspicuously shorter than its neighbours. Someone who
 * simply answered briefly still finishes their sentence. So this prints each
 * answer's length and its final few words, which is enough to tell the two
 * apart without reading anyone's raw speech.
 *
 *   node inspect-session.mjs --session wp-xxxxxxxx-...
 *   node inspect-session.mjs --date 2026-10-09 --section workplace_climate
 *   node inspect-session.mjs --session wp-... --text      # full answers
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
const argOf = (f) => { const i = args.indexOf(f); return i > -1 ? args[i + 1] : null; };
const SESSION = argOf('--session');
const DATE = argOf('--date');
const SECTION = argOf('--section');
const SHOW_TEXT = args.includes('--text');

if (!SESSION && !DATE) {
  console.error(
    'Usage:\n' +
    '  node inspect-session.mjs --session wp-xxxxxxxx-...\n' +
    '  node inspect-session.mjs --date 2026-10-09 [--section workplace_climate]\n\n' +
    'Add --text to print the full answers rather than their endings.\n',
  );
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

const textOf = (d) => (d.followup_text ?? d.text ?? '') || '';
const when = (d) =>
  d.ts_at?.toDate?.() ||
  (typeof d.ts === 'string' ? new Date(d.ts) : null) ||
  (d.ts?.toDate?.() ?? null);

const docs = [];
for (const name of ['responses', 'workplace_climate']) {
  if (SECTION && !name.includes(SECTION.replace('school_climate_', '')) && name !== 'responses') continue;
  try {
    const snap = await db.collection(name).get();
    for (const doc of snap.docs) docs.push(doc.data());
  } catch (e) {
    console.log(`  ${name}: unreadable (${e.message})`);
  }
}

// Group into sessions, then pick the one asked for.
const sessions = new Map();
for (const d of docs) {
  const id = d.session_id || '(none)';
  if (!sessions.has(id)) sessions.set(id, []);
  sessions.get(id).push(d);
}

let chosen = [];
let chosenId = SESSION;
if (SESSION) {
  chosen = sessions.get(SESSION) || [];
} else {
  // Newest session whose first answer falls on --date.
  const matches = [...sessions.entries()].filter(([, rows]) => {
    const first = rows.map(when).filter(Boolean).sort((a, b) => a - b)[0];
    return first && first.toISOString().slice(0, 10) === DATE
      && (!SECTION || rows[0].section === SECTION);
  });
  if (matches.length > 1) {
    console.log(`\n${matches.length} sessions on ${DATE}. Pick one with --session:\n`);
    for (const [id, rows] of matches) console.log(`  ${id}   ${rows.length} answers`);
    process.exit(0);
  }
  if (matches.length === 1) { [chosenId, chosen] = matches[0]; }
}

if (!chosen.length) {
  console.log('\nNo answers found for that session or date.\n');
  process.exit(0);
}

// Turn records (turn_1, turn_2 …) are the raw conversation log, not answers.
const answers = chosen
  .filter((d) => !/^turn_\d+$/.test(d.question_id || ''))
  .sort((a, b) => String(a.question_id).localeCompare(String(b.question_id), undefined, { numeric: true }));

const lens = answers.map((d) => textOf(d).trim().length).filter((n) => n > 0);
const median = lens.length ? [...lens].sort((a, b) => a - b)[Math.floor(lens.length / 2)] : 0;

console.log(`\nsession ${chosenId}`);
console.log(`${answers.length} answers · median ${median} chars\n`);
console.log('question   rating   chars   ends with');
console.log('-'.repeat(86));

for (const d of answers) {
  const t = textOf(d).trim();
  const q = String(d.question_id || '?').padEnd(8);
  const r = String(d.rating ?? d.score ?? '-').padStart(6);
  const n = String(t.length).padStart(6);

  // The tell: an answer that stops without terminal punctuation, and is well
  // below the median for this session, was probably cut off mid-sentence.
  const finished = /[.!?…"']$/.test(t);
  const short = t.length > 0 && t.length < median * 0.4;
  const flag = t.length === 0 ? '  *** EMPTY ***'
    : (!finished && short) ? '  <-- LOOK: short and unfinished'
    : !finished ? '  (no end punctuation)'
    : '';

  const tail = SHOW_TEXT ? `\n           ${t}` : `…${t.slice(-44)}`;
  console.log(`${q} ${r} ${n}   ${tail}${flag}`);
}

console.log('-'.repeat(86));
console.log('An answer cut off by a mis-tapped Stop ends mid-sentence AND is well short');
console.log('of the median. Someone who simply answered briefly still finishes a sentence.');
console.log('Transcription does not add punctuation that was not spoken, so treat a single');
console.log('missing full stop as weak evidence on its own.\n');
process.exit(0);
