/**
 * Is the deployment working RIGHT NOW?
 *
 * One command, for reading while standing in a school with a room full of
 * people, not for analysis afterwards. cost-per-interview.mjs answers "how did
 * it go"; this answers "do I stop".
 *
 *   node watch-deployment.mjs
 *   node watch-deployment.mjs --school pps-2026-27
 *   node watch-deployment.mjs --watch          # refresh every 60s until Ctrl-C
 *   node watch-deployment.mjs --watch 30
 *
 * WHY A SEPARATE LIVE MEASURE
 *
 * cost-per-interview.mjs calls a session "started" at 10+ answers and "usable"
 * at 80% carrying text. Those are the right thresholds for a finished run and
 * the WRONG ones at 9:40am, because every session in the room is in progress
 * and sitting at two or three answers. Judged by that rule a perfectly healthy
 * morning reads as zero started, zero usable, which is exactly the shape of a
 * catastrophe. Someone reading that under pressure stops a deployment that was
 * fine.
 *
 * So the live rule is different, and deliberately so: a session with at least
 * two stored answers and NOT ONE of them carrying text is already broken. You
 * do not need to wait for the tenth answer to know transcripts are being lost,
 * and waiting for it costs you eight more participants.
 *
 * WHAT IT COSTS TO RUN
 *
 * Filtered by school_id at the query, not read-everything-then-filter like the
 * older scripts. `responses` is nearly five thousand documents and a district
 * will add to it; a --watch loop that read the whole collection every minute
 * would bill a few thousand reads a minute to look at thirty. Equality on a
 * single field is indexed automatically, so this reads only the rows for the
 * school being watched.
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
const has = (f) => args.includes(f);

/*
 * Schools to watch, comma-separated.
 *
 * The default is BOTH Pleasanton buckets, because for this deployment the
 * district's answers are arriving in two places: teachers, staff and students
 * on the live tokens into pps-2026-27, and parents on a mis-sent test token
 * into zz-test-pps-devices-2026-11. Watching one of them shows you half a
 * deployment and no indication that the other half exists — which, on the
 * morning the parent email went out, would read as "parents aren't responding"
 * rather than "parents are landing somewhere else".
 *
 * Two indexed equality queries, so the cost is the rows returned, not the
 * collection scanned.
 */
const SCHOOLS = (argOf('--school') || 'pps-2026-27,zz-test-pps-devices-2026-11')
  .split(',').map((s) => s.trim()).filter(Boolean);
const SCHOOL = SCHOOLS[0];          // kept for the header when there is only one
const WATCH = has('--watch');
const EVERY = Number(argOf('--watch')) > 0 ? Number(argOf('--watch')) : 60;

/** A session is "active" if something was written this recently. */
const ACTIVE_WINDOW_MIN = 15;

/**
 * Stored answers before silence counts as a fault rather than a slow start.
 * Two, not one: a single blank can be someone who tapped a rating and had
 * nothing to add, which is legitimate. Two in a row is a pattern.
 */
const BLANK_RUN_ALARM = 2;

/**
 * Answers needed before the percentage verdict means anything.
 *
 * The STOP rule above is exempt and deliberately so: two blanks in one session
 * is a pattern whatever the totals say. This only governs the softer "x% carry
 * text" judgement, which on tiny numbers swings between 0% and 100% on a
 * single answer and would cry wolf in the first minutes of the morning.
 */
const MIN_SAMPLE = 5;

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

// Same accessors as cost-per-interview.mjs. Two names for the answer text
// because both are in the data; two for the timestamp because ts_at was
// backfilled later and older rows only carry the string.
const textOf = (d) => (d.followup_text ?? d.text ?? '') || '';
const when = (d) =>
  d.ts_at?.toDate?.() ||
  (typeof d.ts === 'string' ? new Date(d.ts) : null) ||
  (d.ts?.toDate?.() ?? null);

const ROLE = (section) => String(section || '?').replace('school_climate_', '');

/**
 * An orphan has no stored row, so there is no `section` field to read. The
 * session id prefix is the only thing left that says who it was.
 */
const ROLE_FROM_ID = (id) => {
  const s = String(id || '');
  if (s.startsWith('sclstf-')) return 'staff';
  if (s.startsWith('scltch-')) return 'teachers';
  if (s.startsWith('sclpar-')) return 'parents';
  if (s.startsWith('sclst-')) return 'students';
  if (s.startsWith('sadm-')) return 'administrator';
  return '?';
};

/* ── Orphan detection ──────────────────────────────────────────────────────── */

/**
 * Find interviews that RAN but stored nothing.
 *
 * WHY THIS EXISTS
 *
 * 2026-11-03: a complete 19-question parent interview stored not one answer.
 * The link had picked up a stray character, the token did not resolve, and
 * school_id stayed empty — so every write was rejected server-side. The
 * participant saw the closing and was told to submit. Nothing was kept.
 *
 * Nothing above can see that, because everything above counts stored rows and
 * an orphan has none. The only trace of it is in `debug_traces`, which exists
 * for an unrelated reason and happens to be the one place such a session is
 * visible. So: take the sessions that shipped trace lines, and subtract the
 * ones that stored answers. What is left ran and was thrown away.
 *
 * NOT FILTERED BY SCHOOL, deliberately. An orphan's defining property is that
 * it has no school, so filtering by one would hide exactly what we are looking
 * for.
 */
const ORPHAN_WINDOW_HOURS = 24;

/**
 * Trace lines before a session counts as a real interview rather than someone
 * opening a link and leaving.
 *
 * The preamble alone is 7 lines on Safari and 9 on Chromium, so anything at or
 * below about a dozen is a person who looked and closed the tab — ordinary
 * abandonment, not a fault, and flagging it would bury the real signal. The
 * lost parent interview was 245.
 */
const ORPHAN_MIN_LINES = 20;

async function findOrphans(storedSessionIds) {
  const cutoff = new Date(Date.now() - ORPHAN_WINDOW_HOURS * 3600_000).toISOString();
  const snap = await db.collection('debug_traces').where('created_at', '>=', cutoff).get();

  const seen = new Map();
  for (const doc of snap.docs) {
    const d = doc.data();
    const id = d.session_id;
    if (!id) continue;
    if (!seen.has(id)) seen.set(id, { id, lines: 0, first: null, last: null });
    const s = seen.get(id);
    s.lines += Array.isArray(d.lines) ? d.lines.length : 0;
    const dt = d.created_at ? new Date(d.created_at) : null;
    if (dt) {
      if (!s.first || dt < s.first) s.first = dt;
      if (!s.last || dt > s.last) s.last = dt;
    }
  }

  const orphans = [];
  for (const s of seen.values()) {
    if (storedSessionIds.has(s.id)) continue;       // stored under the watched school
    if (s.lines < ORPHAN_MIN_LINES) continue;       // opened and left; not a fault
    // It stored nothing HERE, but it may have stored under another school_id —
    // a different district running at the same time. One indexed lookup each,
    // and only for the handful that get this far.
    const row = await db.collection('responses').where('session_id', '==', s.id).limit(1).get();
    if (!row.empty) continue;
    orphans.push(s);
  }
  return orphans;
}

async function collect() {
  const sessions = new Map();
  // One indexed query per school, merged. A session cannot span two schools, so
  // there is nothing to reconcile — but each session remembers which school it
  // came from, because "which bucket did the parents land in" is the question
  // this whole mode exists to answer.
  const snaps = await Promise.all(
    SCHOOLS.map((s) => db.collection('responses').where('school_id', '==', s).get()),
  );

  for (const snap of snaps) {
  for (const doc of snap.docs) {
    const d = doc.data();
    const id = d.session_id || '(no session)';
    if (!sessions.has(id)) {
      sessions.set(id, {
        id, role: ROLE(d.section), token: d.token || null,
        school: d.school_id || '(none)',
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
  }
  return [...sessions.values()];
}

const ago = (dt) => (dt ? Math.round((Date.now() - dt.getTime()) / 60000) : null);

function render(all, orphans = []) {
  const now = new Date();
  // Only in --watch, where each refresh replaces the last and a screen full of
  // stale panels is worse than none. A one-shot run must NOT clear: it throws
  // away whatever the operator ran before it, which on 2026-11-01 was the
  // check-debug-traces output someone wanted to read.
  if (WATCH) console.clear?.();
  console.log('');
  console.log('='.repeat(72));
  console.log(`  ${SCHOOLS.join('  +  ')}          ${now.toLocaleTimeString()}`);
  console.log('='.repeat(72));

  if (all.length === 0 && orphans.length === 0) {
    console.log('');
    console.log(`  Nothing stored yet in ${SCHOOLS.length > 1 ? 'either school' : 'this school'}.`);
    console.log('');
    console.log('  Correct before anyone has started. If people are taking it right now,');
    console.log('  they are writing to a different school_id — check the link they used.');
    console.log('');
    return;
  }

  const broken = all.filter((s) => s.rows >= BLANK_RUN_ALARM && s.withText === 0);
  const active = all.filter((s) => ago(s.last) !== null && ago(s.last) <= ACTIVE_WINDOW_MIN);
  const answers = all.reduce((n, s) => n + s.rows, 0);
  const withText = all.reduce((n, s) => n + s.withText, 0);
  const share = answers ? Math.round((withText / answers) * 100) : 0;

  // The verdict goes first and on its own, because it is the only line that
  // will reliably get read.
  console.log('');
  if (orphans.length) {
    // Said every time: an orphan has no school_id, so this list cannot be
    // filtered to the school being watched and will appear under all of them.
    // Without this line it reads as "a participant from THIS school was lost".
    console.log(`  ⚠   ${orphans.length} interview(s) RAN but stored nothing — almost certainly a bad link.`);
    console.log(`      (Across all schools — an orphan has no school to file under.)`);
    for (const o of orphans.sort((a, b) => b.last - a.last)) {
      const mins = o.first && o.last ? Math.round((o.last - o.first) / 60000) : 0;
      console.log(`      ${o.id}  ${ROLE_FROM_ID(o.id)}  ${o.lines} trace lines, ${mins} min, ${ago(o.last)} min ago`);
    }
    console.log('      Their answers were rejected and are not recoverable. If the same');
    console.log('      person is reachable, send them a clean link and ask them to redo it.');
    console.log('');
  }
  if (broken.length) {
    console.log(`  ⛔  STOP — ${broken.length} session(s) stored answers with NO text.`);
    console.log('      This is the transcript failure. Participants will look fine');
    console.log('      and their answers will be empty. Do not send more people in.');
  } else if (answers === 0) {
    console.log('  …   Sessions exist but nothing is stored yet.');
  } else if (answers < MIN_SAMPLE) {
    // Too early to judge. One blank at 9:02 is someone with nothing to add,
    // and a warning here would arrive at exactly the moment it is most likely
    // to be believed and least likely to be true.
    console.log(`  …   ${answers} answer(s) so far — too few to judge. Check again shortly.`);
  } else if (share >= 90) {
    console.log(`  ✓   Healthy — ${withText} of ${answers} stored answers carry text (${share}%).`);
  } else {
    console.log(`  ⚠   ${share}% of stored answers carry text. Below 90% is worth a look`);
    console.log('      before the next group goes in.');
  }
  console.log('');

  console.log(`  sessions ${all.length}        active (last ${ACTIVE_WINDOW_MIN}m) ${active.length}`);
  const last = all.map((s) => s.last).filter(Boolean).sort((a, b) => b - a)[0];
  console.log(`  answers  ${answers}        last activity ${last ? `${ago(last)} min ago` : '—'}`);
  console.log('');

  // ── By school, when watching more than one ────────────────────────────────
  //
  // The combined totals above are what you want day to day. This line is what
  // you want when a number looks wrong, because "which bucket is this landing
  // in" is the question behind most of them.
  if (SCHOOLS.length > 1) {
    const bySchool = new Map();
    for (const s of all) {
      if (!bySchool.has(s.school)) bySchool.set(s.school, { n: 0, rows: 0 });
      const b = bySchool.get(s.school);
      b.n += 1; b.rows += s.rows;
    }
    for (const school of SCHOOLS) {
      const b = bySchool.get(school) || { n: 0, rows: 0 };
      const roles = [...new Set(all.filter((s) => s.school === school).map((s) => s.role))];
      console.log(
        `  ${school.padEnd(32)} ${String(b.rows).padStart(4)} answers`
        + `${roles.length ? `   (${roles.sort().join(', ')})` : ''}`,
      );
    }
    console.log('');
  }

  // ── By role ───────────────────────────────────────────────────────────────
  const byRole = new Map();
  for (const s of all) {
    if (!byRole.has(s.role)) byRole.set(s.role, { n: 0, rows: 0, text: 0, blank: 0 });
    const r = byRole.get(s.role);
    r.n += 1; r.rows += s.rows; r.text += s.withText;
    if (s.rows >= BLANK_RUN_ALARM && s.withText === 0) r.blank += 1;
  }
  console.log('  role        sessions   answers   w/text   blank runs');
  console.log('  ' + '-'.repeat(54));
  for (const [role, r] of [...byRole].sort((a, b) => b[1].n - a[1].n)) {
    const pct = r.rows ? `${Math.round((r.text / r.rows) * 100)}%` : '—';
    console.log(
      `  ${role.padEnd(12)}${String(r.n).padStart(6)}${String(r.rows).padStart(10)}`
      + `${String(r.text).padStart(9)} (${pct.padStart(4)})${String(r.blank || '').padStart(7)}`,
    );
  }
  console.log('');

  // ── Anything broken, named ────────────────────────────────────────────────
  if (broken.length) {
    console.log('  Sessions that stored nothing but blanks:');
    for (const s of broken.sort((a, b) => b.last - a.last)) {
      console.log(`    ${s.id}  ${s.role}  ${s.rows} answers  ${ago(s.last)} min ago`);
    }
    console.log('');
    console.log('    node verify-student-run.mjs   # for the detail on one of them');
    console.log('');
  }

  // ── In progress, so you can see the room ──────────────────────────────────
  if (active.length) {
    console.log(`  In progress (wrote something in the last ${ACTIVE_WINDOW_MIN} minutes):`);
    for (const s of active.sort((a, b) => b.last - a.last).slice(0, 12)) {
      const pct = s.rows ? Math.round((s.withText / s.rows) * 100) : 0;
      const flag = s.rows >= BLANK_RUN_ALARM && s.withText === 0 ? '  ⛔' : '';
      console.log(
        `    ${s.role.padEnd(10)} ${String(s.rows).padStart(2)} answers, `
        + `${String(pct).padStart(3)}% with text   ${ago(s.last)}m ago${flag}`,
      );
    }
    if (active.length > 12) console.log(`    …and ${active.length - 12} more`);
    console.log('');
  }

  console.log('='.repeat(72));
  if (WATCH) console.log(`  refreshing every ${EVERY}s — Ctrl-C to stop`);
  console.log('');
}

async function once() {
  try {
    const all = await collect();
    let orphans = [];
    try {
      orphans = await findOrphans(new Set(all.map((s) => s.id)));
    } catch (e) {
      // Debugging Mode may be off, or the collection may not exist. That is a
      // reason to show less, never a reason to show nothing.
      orphans = [];
    }
    render(all, orphans);
  } catch (e) {
    console.error(`\n  could not read: ${e.message}\n`);
  }
}

await once();
if (WATCH) {
  setInterval(once, EVERY * 1000);
} else {
  process.exit(0);
}
