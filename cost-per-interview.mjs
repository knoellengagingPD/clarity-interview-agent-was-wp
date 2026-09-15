/**
 * How many interviews have we actually completed, and what does one cost?
 *
 * Both halves come from the same scan, because the cost answer is just the
 * count with a division on the end.
 *
 * WHY THIS IS THE COST. Every dollar OpenAI bills us is gpt-realtime plus
 * gpt-4o-mini-transcribe. Report generation runs on the Anthropic key, Firebase
 * bills separately, and nothing else in the stack calls OpenAI. So the billing
 * period's spend divided by the interviews inside that period IS the
 * per-interview cost — no token arithmetic, no pricing table, nothing to get
 * wrong.
 *
 *   node cost-per-interview.mjs                     # count only
 *   node cost-per-interview.mjs --spend 14.69       # count + cost per interview
 *   node cost-per-interview.mjs --spend 14.69 --since 2026-09-01
 *
 * --since defaults to the 1st of the current month, which is when the OpenAI
 * billing period opens. Read the figure off the Limits page: "Organization
 * spend limit  $14.69 / $120.00".
 *
 * A "full" interview is one that stored a spoken answer for at least 80% of its
 * role's items. That threshold is deliberate: the old capture counter counted
 * WRITES, which is why Gary's 2026-09-14 run reported nineteen healthy answers
 * while storing an empty string for every one of them.
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
const argOf = (f) => {
  const i = args.indexOf(f);
  return i > -1 ? args[i + 1] : null;
};

const SPEND = argOf('--spend') ? Number(argOf('--spend')) : null;
const now = new Date();
const SINCE = new Date(
  argOf('--since') || `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}-01T00:00:00Z`,
);

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

// Climate and administrator answers live in `responses`; workplace writes to
// its own `workplace_climate` collection. Reading only the first silently omits
// every workplace interview.
const COLLECTIONS = ['responses', 'workplace_climate'];

// A completeness threshold must NOT be a per-role item count.
//
// The first version of this script keyed such a map on 'students', 'teachers',
// 'staff' — but the stored section values are 'school_climate_students' and so
// on. Every lookup missed and fell through to the row count itself, so the
// measure became "80% of whatever was written", and a session holding ONE
// answer scored 100% and was reported as a complete interview. Six did.
//
// Worse, even a correct map would rot: the instrument changed on 2026-09-14
// (18/19/18/17), so sessions recorded before and after that date have different
// legitimate totals, and next year's revision breaks it again.
//
// Two version-independent facts separate a real interview from an abandoned
// one, and neither depends on the instrument:
const MIN_ANSWERS = 10;   // fewer than this and nobody got past the opening
const MIN_TEXT_SHARE = 0.8; // below this, transcripts were being lost

const textOf = (d) => (d.followup_text ?? d.text ?? '') || '';
const when = (d) =>
  d.ts_at?.toDate?.() ||
  (typeof d.ts === 'string' ? new Date(d.ts) : null) ||
  (d.ts?.toDate?.() ?? null);

const sessions = new Map();
for (const name of COLLECTIONS) {
  try {
    const snap = await db.collection(name).get();
    console.log(`  ${name}: ${snap.size} docs`);
    for (const doc of snap.docs) {
      const d = doc.data();
      const id = d.session_id || '(no session)';
      if (!sessions.has(id)) {
        sessions.set(id, {
          section: d.section || '?',
          school: d.school_id || '?',
          rows: 0, withText: 0, first: null, last: null,
        });
      }
      const s = sessions.get(id);
      s.rows += 1;
      if (textOf(d).trim()) s.withText += 1;
      const dt = when(d);
      if (dt) {
        if (!s.first || dt < s.first) s.first = dt;
        if (!s.last || dt > s.last) s.last = dt;
      }
    }
  } catch (e) {
    console.log(`  ${name}: unreadable (${e.message})`);
  }
}

const all = [...sessions.values()].filter((s) => s.first);
/** Someone sat down and worked through the instrument, whatever version it was. */
const isReal = (s) => s.rows >= MIN_ANSWERS;
/** A real run whose answers actually made it to disk. This is a usable interview. */
const isFull = (s) => isReal(s) && s.withText / s.rows >= MIN_TEXT_SHARE;
/** A real run that stored not one spoken word — Gary's failure mode. */
const isDead = (s) => isReal(s) && s.withText === 0;

// ── Lifetime ────────────────────────────────────────────────────────────────
console.log('\n=== ALL TIME ===\n');
const bySection = new Map();
for (const s of all) {
  if (!bySection.has(s.section)) bySection.set(s.section, { n: 0, real: 0, full: 0, dead: 0 });
  const b = bySection.get(s.section);
  b.n += 1;
  if (isReal(s)) b.real += 1;
  if (isFull(s)) b.full += 1;
  if (isDead(s)) b.dead += 1;
}
const line = (label, b) => console.log(
  `${label.slice(0, 24).padEnd(24)}  ${String(b.n).padStart(8)}  ${String(b.real).padStart(9)}  ` +
  `${String(b.full).padStart(6)}  ${String(b.dead).padStart(9)}`,
);
console.log(`(a run counts as started at ${MIN_ANSWERS}+ answers; usable at ${MIN_TEXT_SHARE * 100}%+ carrying text)\n`);
console.log('section                   sessions    started   usable   no-speech');
console.log('-'.repeat(68));
for (const [sec, b] of [...bySection].sort((a, b2) => b2[1].n - a[1].n)) line(sec, b);
console.log('-'.repeat(68));
line('TOTAL', {
  n: all.length,
  real: all.filter(isReal).length,
  full: all.filter(isFull).length,
  dead: all.filter(isDead).length,
});
console.log('\nsessions minus started = people who opened the link and left almost');
console.log('immediately. started minus usable = runs that lost their transcripts.');

// ── Billing period ──────────────────────────────────────────────────────────
const period = all.filter((s) => s.first >= SINCE);
const periodFull = period.filter(isFull);
console.log(`\n=== SINCE ${SINCE.toISOString().slice(0, 10)} (OpenAI billing period) ===\n`);
console.log(`  ${period.length} sessions started, ${periodFull.length} of them full`);

const minutes = period.reduce((t, s) => t + (s.last - s.first) / 60000, 0);
console.log(`  ${minutes.toFixed(0)} minutes of measured session time`);
console.log('  (first stored answer to last — excludes the greeting and the closing,');
console.log('   so true audio time is somewhat higher)');

// The MEAN is the wrong statistic here. A handful of two-minute aborts sitting
// beside genuine full-length runs produces an average that describes neither,
// and the district cost projection multiplies that average by 500. Print every
// session so the shape is visible.
console.log('\n  each session, shortest first:');
console.log('  date        section                  answers  w/text   minutes  full?');
for (const s of [...period].sort((a, b) => (a.last - a.first) - (b.last - b.first))) {
  const m = (s.last - s.first) / 60000;
  console.log(
    `  ${s.first.toISOString().slice(0, 10)}  ${s.section.slice(0, 24).padEnd(24)} ` +
    `${String(s.rows).padStart(5)}  ${String(s.withText).padStart(6)}  ${m.toFixed(1).padStart(8)}  ` +
    (isFull(s) ? 'full' : '--'),
  );
}
const fullMins = periodFull.map((s) => (s.last - s.first) / 60000).sort((a, b) => a - b);
if (fullMins.length) {
  const med = fullMins[Math.floor(fullMins.length / 2)];
  console.log(
    `\n  full interviews only: median ${med.toFixed(1)} min, ` +
    `range ${fullMins[0].toFixed(1)}–${fullMins[fullMins.length - 1].toFixed(1)} min`,
  );
  console.log('  ^ THIS is the number to multiply for a district, not the mean above.');
}

if (SPEND != null && period.length) {
  console.log('\n=== COST ===\n');
  const started = period.filter(isReal).length;
  // Divide by interviews DELIVERED, not by sessions opened, but keep the
  // abandoned ones in the numerator: they burned a greeting and a statement
  // read apiece, and a district will generate them too. Dividing the whole
  // spend by the usable interviews prices that waste in, which is what a budget
  // needs. The per-minute rate below understates for the same reason — the
  // greeting, the closing and every abandoned start fall outside the measured
  // window, so real audio minutes exceed the ones counted here.
  if (periodFull.length) {
    console.log(`  $${SPEND.toFixed(2)} / ${periodFull.length} usable interviews = ` +
                `$${(SPEND / periodFull.length).toFixed(2)} per interview delivered`);
    console.log(`  (${period.length - started} abandoned starts are priced in — a district will produce them too)`);
    console.log(`\n  500 participants  ->  about $${Math.round((SPEND / periodFull.length) * 500)}`);
    console.log('  Budget roughly double that, and check it against the organization');
    console.log('  spend limit and the monthly auto-reload ceiling BEFORE deploying.');
  }
  if (minutes > 0) {
    console.log(`\n  $${(SPEND / minutes).toFixed(3)} per measured minute (an upper bound; see note in source)`);
  }
} else if (SPEND == null) {
  console.log('\n  Pass --spend with the figure from the OpenAI Limits page to get cost.');
}

process.exit(0);
