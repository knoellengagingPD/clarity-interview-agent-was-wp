/**
 * Print the individual rating every workplace respondent gave to every
 * question, beside the mean the report prompt is built from.
 *
 * WHY
 *
 * On 2026-10-19 two Workplace Climate reports were generated for nowling-test
 * from identical, unchanged data. They disagreed about Q5: one said the three
 * answers were 2, 4, 4 and described an employee whose experience diverged
 * sharply from colleagues; the other said 3, 3, 4 and described broad modest
 * agreement. Both are arithmetically valid decompositions of the mean 3.33 at
 * n=3, which is the point — at least one report invented them, and the text
 * alone cannot say which.
 *
 * This is the arbiter. It reads the stored ratings directly, so whatever it
 * prints is what the prompt should contain and what a report may assert.
 *
 *   node workplace-answers.mjs nowling-test
 *   node workplace-answers.mjs nowling-test --session wp-ce205bcd-...
 *
 * Read-only. Writes nothing.
 */

import 'dotenv/config';
import admin from 'firebase-admin';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const argOf = (flag) => { const i = args.indexOf(flag); return i > -1 ? args[i + 1] : null; };
const ONLY_SESSION = argOf('--session');
const ORG = args.find(a => !a.startsWith('--') && a !== ONLY_SESSION);

if (!ORG) {
  console.error('usage: node workplace-answers.mjs <organization_id> [--session <session_id>]');
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

const snap = await db.collection('workplace_climate')
  .where('organization_id', '==', ORG).get();

if (snap.empty) {
  console.log(`No workplace_climate rows with organization_id == "${ORG}".`);
  process.exit(0);
}

// DB1-3 are open-ended and are logged with rating: 0; turn_N rows are
// transcript logs. /workplace/stats excludes both from its averages, so they
// are excluded here too or the means would not match the prompt's.
const isRated = (qid) => /^(Q\d+|AIR1)$/.test(qid);

const bySession = new Map();
const questions = new Set();
for (const d of snap.docs) {
  const x = d.data() || {};
  const sid = x.session_id || '(none)';
  if (ONLY_SESSION && sid !== ONLY_SESSION) continue;
  const qid = String(x.question_id || '');
  if (!isRated(qid)) continue;
  if (typeof x.rating !== 'number' || !Number.isFinite(x.rating)) continue;
  if (!bySession.has(sid)) bySession.set(sid, { ratings: {}, ts: null });
  const s = bySession.get(sid);
  s.ratings[qid] = x.rating;
  questions.add(qid);
  const dt = x.ts_at?.toDate?.() || (typeof x.ts === 'string' ? new Date(x.ts) : null);
  if (dt && (!s.ts || dt < s.ts)) s.ts = dt;
}

const sessions = [...bySession.entries()]
  .sort((a, b) => (a[1].ts?.getTime() || 0) - (b[1].ts?.getTime() || 0));

const qids = [...questions].sort((a, b) => {
  const n = (q) => (q.startsWith('Q') ? parseInt(q.slice(1), 10) : 999);
  return n(a) - n(b) || a.localeCompare(b);
});

console.log(`organization   ${ORG}`);
console.log(`respondents    ${sessions.length}`);
console.log('');
sessions.forEach(([sid, s], i) => {
  console.log(`  R${i + 1}  ${s.ts ? s.ts.toISOString().slice(0, 10) : '??????????'}  ${sid}`);
});
console.log('');

const header = `question  ${sessions.map((_, i) => `R${i + 1}`.padStart(3)).join(' ')}   mean   decompositions of that mean`;
console.log(header);
console.log('─'.repeat(header.length + 12));

/** How many ways n answers on a 1-4 scale could produce this sum. */
function decompositions(sum, n) {
  const out = [];
  const walk = (start, left, total, acc) => {
    if (left === 0) { if (total === 0) out.push([...acc]); return; }
    for (let v = start; v <= 4; v++) {
      if (v * left > total || v + 4 * (left - 1) < total) continue;
      acc.push(v); walk(v, left - 1, total - v, acc); acc.pop();
    }
  };
  walk(1, n, sum, []);
  return out;
}

let ambiguous = 0;
for (const qid of qids) {
  const vals = sessions.map(([, s]) => s.ratings[qid]);
  const present = vals.filter(v => typeof v === 'number');
  const mean = present.length ? present.reduce((a, b) => a + b, 0) / present.length : null;
  const cells = vals.map(v => String(v ?? '·').padStart(3)).join(' ');
  const rounded = mean == null ? '   -' : (Math.round(mean * 100) / 100).toFixed(2);

  let note = '';
  if (mean != null && present.length) {
    const opts = decompositions(present.reduce((a, b) => a + b, 0), present.length);
    const asText = opts.map(o => `{${o.join(',')}}`).join(' ');
    if (opts.length > 1) { ambiguous += 1; note = `${opts.length} possible: ${asText}  <- the mean alone cannot say which`; }
    else note = 'determined by the mean';
  }
  console.log(`${qid.padEnd(9)} ${cells}   ${rounded}   ${note}`);
}

console.log('');
console.log(`${ambiguous} of ${qids.length} question(s) cannot be recovered from the mean alone.`);
console.log('Any report asserting individual answers for those had to be sent them.');
console.log('Compare the R columns above against the brackets the report printed.');
process.exit(0);
