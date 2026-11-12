/**
 * Administrator (superintendent) interviews in a recent window, one line each.
 *
 * WHY
 *
 * The dashboard's LIVE STATS panel gives a running total and a most-recent
 * date, which cannot answer "how many in the last 45 days", "which districts",
 * or "is that one real". On 2026-11-12 the panel showed 38 interviews and a
 * most-recent date of 9 November, the same day 134 of Pleasanton's 159 climate
 * sessions ran, with no completion email received for it.
 *
 * It also distinguishes a finished interview from an abandoned one, which the
 * totals cannot. A full administrator interview is 7 questions plus Dream Big;
 * a session carrying two or three answers is someone who opened the link and
 * stopped, and it counts toward the dashboard's total exactly the same.
 *
 *   node supt-recent.mjs                 # last 45 days
 *   node supt-recent.mjs --days 90
 *   node supt-recent.mjs --days 365 --all
 *
 * READ ONLY. Reads the responses collection. Touches nothing.
 */

import 'dotenv/config';
import admin from 'firebase-admin';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const argOf = (f, d) => { const i = args.indexOf(f); return i > -1 ? args[i + 1] : d; };
const DAYS = Number(argOf('--days', 45));
const SHOW_ALL = args.includes('--all'); void SHOW_ALL;

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

const when = (d) =>
  d.ts_at?.toDate?.() || (typeof d.ts === 'string' ? new Date(d.ts) : null) || (d.ts?.toDate?.() ?? null);

/* A full run is 7 rated questions plus Dream Big. Below this, somebody opened
 * the link and stopped — still a row in the dashboard's total. */
const COMPLETE_ENOUGH = 6;

const cutoff = new Date(Date.now() - DAYS * 86400000);

console.log(`\nAdministrator interviews since ${cutoff.toISOString().slice(0, 10)} (${DAYS} days)\n`);

const snap = await db.collection('responses')
  .where('section', '==', 'superintendent_interview')
  .get();

const sessions = new Map();
for (const doc of snap.docs) {
  const d = doc.data();
  const sid = d.session_id;
  if (!sid) continue;
  if (!sessions.has(sid)) {
    sessions.set(sid, {
      sid, answers: 0, turns: 0, withText: 0, first: null, last: null,
      district: d.school_id || d.district || '',
      isTest: d.is_test === true,
    });
  }
  const s = sessions.get(sid);
  /*
   * turn_* rows are conversational scaffolding; a real answer carries a
   * question id. Counted separately rather than dropped, because the
   * difference is the finding: /admin/sessions keeps both, so the dashboard
   * counts a session that stored only turns exactly like one that stored
   * answers. On 2026-11-12 the dashboard showed 38 sessions and this script,
   * which was dropping turn rows, found 8 -- the newest from 2 April.
   */
  if (/^turn_\d+$/.test(String(d.question_id || ''))) { s.turns += 1; continue; }
  s.answers += 1;
  const t = (d.followup_text ?? d.text ?? '') || '';
  if (t.trim()) s.withText += 1;
  const dt = when(d);
  if (dt) {
    if (!s.first || dt < s.first) s.first = dt;
    if (!s.last || dt > s.last) s.last = dt;
  }
  if (!s.district && (d.school_id || d.district)) s.district = d.school_id || d.district;
}

const all = [...sessions.values()].filter(s => s.first);
const recent = all.filter(s => s.first >= cutoff).sort((a, b) => b.first - a.first);

if (recent.length === 0) {
  console.log(`  none. Most recent of all ${all.length} sessions: `
    + `${all.sort((a, b) => b.first - a.first)[0]?.first.toISOString().slice(0, 10) ?? 'n/a'}\n`);
  process.exit(0);
}

console.log(`  ${'date'.padEnd(12)}${'answers'.padStart(8)}${'turns'.padStart(7)}${'w/text'.padStart(8)}  ${'district'.padEnd(22)}session`);
console.log('  ' + '-'.repeat(86));
let complete = 0, partial = 0, test = 0, turnsOnly = 0;
for (const s of recent) {
  const done = s.answers >= COMPLETE_ENOUGH;
  if (s.isTest) test += 1; else if (done) complete += 1; else partial += 1;
  if (s.answers === 0 && s.turns > 0) turnsOnly += 1;
  const mark = s.isTest ? ' TEST'
    : s.answers === 0 && s.turns > 0 ? ' TURNS ONLY — no structured answers stored'
    : done ? '' : ' partial';
  console.log(`  ${s.first.toISOString().slice(0, 10).padEnd(12)}`
    + `${String(s.answers).padStart(8)}${String(s.turns).padStart(7)}${String(s.withText).padStart(8)}  `
    + `${(s.district || '—').padEnd(22)}${s.sid}${mark}`);
}

console.log('');
console.log(`  completed (${COMPLETE_ENOUGH}+ answers)  ${complete}`);
console.log(`  partial / abandoned       ${partial}${SHOW_ALL ? '' : '   (hidden — pass --all to list)'}`);
if (test) console.log(`  flagged as test data      ${test}`);
console.log(`  total sessions in window  ${recent.length}`);
console.log(`  all time                  ${all.length}`);
console.log('');
process.exit(0);
