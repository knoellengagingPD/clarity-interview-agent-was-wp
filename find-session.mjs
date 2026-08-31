/**
 * Find recent climate survey sessions and show exactly what was captured.
 *
 * WHY THIS EXISTS
 *
 * The admin dashboard groups by the district ID. Type a district NAME into that
 * box instead and the run seems to vanish -- but nothing was lost. Responses are
 * keyed by the school_id carried on the TOKEN, and the district you type is a
 * display field written alongside them. This reads the responses directly, so it
 * finds a session no matter what was typed.
 *
 * It also answers the question the dashboard makes tedious: of the questions the
 * survey asks, which ones actually landed? Missing ids are listed by name.
 *
 *   node find-session.mjs              # last 24 hours
 *   node find-session.mjs 72           # last 72 hours
 *   node find-session.mjs 24 ZK78TD    # filter by token fragment or school_id
 */

import 'dotenv/config';
import admin from 'firebase-admin';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const HOURS = Number(process.argv[2] || 24);
const FILTER = (process.argv[3] || '').toLowerCase();

// Expected question ids per role, so "what is missing" is answerable rather than
// merely countable. Kept in step with src/lib/interview/roles/*.ts.
// Keys are the PLURAL role as it appears in section (school_climate_students),
// not the singular used for the speaker label. Getting this wrong made the first
// run report "CAPTURED 0 of 8" with every real answer listed as UNEXPECTED.
const EXPECTED = {
  students: ['S1','S2','S3','S4','S5','S6','S7','E1','E2','E3','E4','E5','E6','AIR1','EN1','DB1','DB2','DB3'],
  teachers: ['S1','S2','S3','S4','S5','S6','S7','E1','RES1','E2','E3','E4','E5','E6','AIR1','EN1','EN2','EN3','DB1','DB2','DB3'],
  staff:    ['S1','S2','S3','S4','S5','S6','E1','E2','E3','E4','E5','AIR1','EN1','EN2','DB1','DB2','DB3'],
  parents:  ['S1','S2','S3','S4','S5','S6','E1','E2','E3','E4','E5','AIR1','EN1','EN2','DB1','DB2','DB3'],
};

function credentials() {
  const b64 = process.env.FIREBASE_SERVICE_ACCOUNT_B64;
  if (b64) return JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));

  const json = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (json) return JSON.parse(json);

  const file = path.join(here, 'firebase-service-account.json');
  if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));

  console.error('No Firebase credentials found in .env or firebase-service-account.json.');
  process.exit(1);
}

const sa = credentials();
admin.initializeApp({
  credential: admin.credential.cert(sa),
  projectId: process.env.FIREBASE_PROJECT_ID || sa.project_id,
});
const db = admin.firestore();

const since = new Date(Date.now() - HOURS * 3600 * 1000).toISOString();
console.log(`Climate responses since ${since}${FILTER ? `  (filter: "${FILTER}")` : ''}\n`);

const snap = await db.collection('responses').where('ts', '>=', since).get();

// Group into sessions.
const sessions = new Map();
snap.forEach(doc => {
  const d = doc.data();
  if (!String(d.section || '').startsWith('school_climate_')) return;

  const hay = `${d.school_id || ''} ${d.token || ''} ${d.district || ''} ${d.school_name || ''}`.toLowerCase();
  if (FILTER && !hay.includes(FILTER)) return;

  const key = d.session_id || doc.id;
  if (!sessions.has(key)) {
    sessions.set(key, {
      role: (d.section || '').replace('school_climate_', ''),
      school_id: d.school_id, token: d.token,
      district: d.district, school_name: d.school_name,
      first: d.ts, last: d.ts, answers: new Map(),
    });
  }
  const s = sessions.get(key);
  if (d.ts < s.first) s.first = d.ts;
  if (d.ts > s.last) s.last = d.ts;
  s.answers.set(d.question_id, { rating: d.rating, text: d.followup_text || d.text || '' });
});

if (sessions.size === 0) {
  console.log('No matching sessions.');
  console.log('Widen the window (node find-session.mjs 72) or drop the filter.');
  process.exit(0);
}

for (const [id, s] of [...sessions].sort((a, b) => a[1].first.localeCompare(b[1].first))) {
  const expected = EXPECTED[s.role] || [];
  const captured = expected.filter(q => s.answers.has(q));
  const missing  = expected.filter(q => !s.answers.has(q));
  const extra    = [...s.answers.keys()].filter(q => !expected.includes(q));

  console.log('─'.repeat(78));
  console.log(`session   ${id}`);
  console.log(`role      ${s.role}`);
  console.log(`school_id ${s.school_id}          token ${s.token || '(none)'}`);
  if (s.district || s.school_name) console.log(`labelled  district="${s.district || ''}" school="${s.school_name || ''}"`);
  console.log(`started   ${s.first}`);
  console.log(`duration  ${Math.round((Date.parse(s.last) - Date.parse(s.first)) / 60000)} min`);
  console.log('');
  console.log(`CAPTURED  ${captured.length} of ${expected.length || s.answers.size}`);

  if (missing.length) console.log(`MISSING   ${missing.join(', ')}`);
  if (extra.length)   console.log(`UNEXPECTED ${extra.join(', ')}`);

  console.log('');
  for (const q of (expected.length ? expected : [...s.answers.keys()])) {
    const a = s.answers.get(q);
    if (!a) { console.log(`  ${q.padEnd(5)} —`); continue; }
    const rating = (a.rating === undefined || a.rating === null || a.rating === 0) ? ' ' : String(a.rating);
    const text = a.text.length > 88 ? a.text.slice(0, 88) + '…' : a.text;
    console.log(`  ${q.padEnd(5)} ${rating}  ${text}`);
  }
  console.log('');
}

console.log('─'.repeat(78));
console.log(`${sessions.size} session(s).`);
process.exit(0);
