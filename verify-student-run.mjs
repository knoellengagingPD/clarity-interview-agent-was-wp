/**
 * Did a student interview actually store correctly on the CURRENT build?
 *
 * WHY THIS EXISTS
 *
 * cost-per-interview.mjs on 2026-10-28 showed the student path has 38 started
 * runs and 5 usable ones lifetime, with every one of those 5 dated before
 * 2026-09-15. Since then the student survey has had NO full clean run — and in
 * between, two changes landed that touch exactly the path a stored answer
 * travels:
 *
 *   - the id renumbering (S1..S18 -> SC_STU_01..SC_STU_21, plus a new
 *     `construct` field on every item), and
 *   - server-side token enforcement on /log_response, which now derives
 *     school_id, school_name, district and role from the token record and
 *     rejects a climate write that carries no valid token.
 *
 * The prompt snapshots came out byte-identical and the guard was exercised for
 * 401/403/200/200. Neither of those is a student completing 21 items and every
 * answer landing intact. Pleasanton is putting a whole class on this path, so
 * "untested" is not good enough and this script is what closes the gap.
 *
 * It is read-only. It touches nothing.
 *
 *   node verify-student-run.mjs                  # newest student session
 *   node verify-student-run.mjs <session_id>      # a specific one
 *   node verify-student-run.mjs --list            # recent student sessions
 *   node verify-student-run.mjs --show            # also print every answer
 *
 * WHAT "PASS" MEANS HERE
 *
 * Not "the write returned 200". Every check below is a thing that can fail
 * SILENTLY — a missing item is simply absent from every report, a stale
 * question_text puts a participant's answer under a question they were never
 * asked, and a body-supplied school_id attributes a class to the wrong school.
 * None of those raise an error anywhere. That is the failure mode this script
 * exists to make loud, and it is the same shape as Finding 10: the instruction
 * said the answers were in brackets, the brackets were not sent, and nothing
 * failed.
 *
 * ON THE EXPECTED TABLE BELOW
 *
 * It is a snapshot, generated from workplace-interview-agent's
 * src/lib/interview/roles/students.ts on 2026-10-28, and it is deliberately a
 * snapshot rather than an import: this repo is the backend and cannot reach the
 * frontend's TypeScript, and regex-parsing that file silently misses items.
 *
 * So if this script reports a WORDING or CONSTRUCT mismatch, there are two
 * possible causes and they need opposite responses:
 *
 *   1. the deployed frontend is STALE — the real failure, fix the deploy; or
 *   2. an item was deliberately reworded since the snapshot — then refresh the
 *      table by running, from ~/workplace-interview-agent:
 *
 *      node --experimental-strip-types -e "import('./src/lib/interview/roles/students.ts').then(m=>console.log(m.QUESTIONS.map(q=>'  '+JSON.stringify(q.id)+': { type: '+JSON.stringify(q.type)+', construct: '+JSON.stringify(q.construct)+', text: '+JSON.stringify(q.text)+(q.scaleOptions?', scaleOptions: '+JSON.stringify(q.scaleOptions):'')+' },').join('\n')))"
 *
 * Mismatches are never "probably fine". Decide which of the two it is.
 */

import 'dotenv/config';
import admin from 'firebase-admin';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const flag = (f) => args.includes(f);
const SHOW = flag('--show');
const LIST = flag('--list');
const SESSION_ARG = args.find((a) => !a.startsWith('--')) || null;

const SECTION = 'school_climate_students';
const EXPECTED_ROLE = 'student';

/* ── The items as the current build asks them ─────────────────────────────── */

const DEFAULT_SCALE = ['Strongly Disagree', 'Disagree', 'Agree', 'Strongly Agree'];

const EXPECTED = {
  "SC_STU_01": { type: "rated", construct: "SAFE_SELF", text: "I feel safe at this school." },
  "SC_STU_02": { type: "rated", construct: "EMERGENCY", text: "This school is prepared to handle an emergency." },
  "SC_STU_03": { type: "rated", construct: "RESP_ADULT", text: "Teachers and staff treat students with respect." },
  "SC_STU_04": { type: "rated", construct: "RESP_PEER", text: "Students treat each other with respect." },
  "SC_STU_05": { type: "rated", construct: "EQUITY", text: "Students from different backgrounds are respected at this school." },
  "SC_STU_06": { type: "rated", construct: "BULLY_PREV", text: "Bullying, in person or online, is rare at this school." },
  "SC_STU_07": { type: "rated", construct: "BULLY_RESP", text: "If I report bullying, in person or online, an adult will do something about it." },
  "SC_STU_08": { type: "rated", construct: "DISCIPLINE", text: "Students at this school are disciplined fairly, no matter who they are." },
  "SC_STU_09": { type: "rated", construct: "CONCERN_HEARD", text: "When someone raises a concern here, it is taken seriously." },
  "SC_STU_10": { type: "rated", construct: "BELONG", text: "I feel like I belong at this school." },
  "SC_STU_11": { type: "rated", construct: "ADULT_CARES", text: "When I am upset, adults at this school show they care." },
  "SC_STU_12": { type: "rated", construct: "MENTAL_HEALTH", text: "If I needed help with how I was feeling, I could get it at this school." },
  "SC_STU_13": { type: "rated", construct: "VOICE", text: "My input is valued when decisions are made." },
  "SC_STU_14": { type: "rated", construct: "FEEDBACK", text: "My teachers give me feedback that helps me get better." },
  "SC_STU_15": { type: "rated", construct: "EXPECTATIONS", text: "Adults at this school expect every student to do well." },
  "SC_STU_16": { type: "rated", construct: "RESOURCES", text: "This school has the resources and materials I need to learn." },
  "SC_STU_17": { type: "rated", construct: "AI_READY", text: "How well does your school help you understand how to use AI tools, like ChatGPT, the right way for schoolwork?", scaleOptions: ["Not at all", "A little", "Somewhat", "A lot"] },
  "SC_STU_18": { type: "rated", construct: "OVERALL", text: "Overall, this is a good school." },
  "SC_STU_19": { type: "open", construct: "DB_CHANGE", text: "If you could change one or two things to make school better for everyone, what would they be?" },
  "SC_STU_20": { type: "open", construct: "DB_KEEP", text: "What is one thing about your school that you really love and never want to change?" },
  "SC_STU_21": { type: "open", construct: "DB_AI", text: "Where do you think AI could help you with schoolwork or learning — and where does it worry you or cause problems?" },
};

const RATED_IDS = Object.keys(EXPECTED).filter((id) => EXPECTED[id].type === 'rated');
const OPEN_IDS = Object.keys(EXPECTED).filter((id) => EXPECTED[id].type === 'open');

/**
 * Same djb2 as src/lib/interview/responsePayload.ts.
 *
 * Duplicated rather than imported because that file is TypeScript in the other
 * repo. If the two ever disagree this script reports every row as a mismatch,
 * which is a loud failure rather than a quiet one — the right direction to fail.
 */
function itemVersion(text) {
  let h = 5381;
  for (let i = 0; i < text.length; i++) {
    h = ((h << 5) + h + text.charCodeAt(i)) >>> 0;
  }
  return h.toString(36).padStart(7, '0').slice(0, 8);
}

/* ── Firestore ────────────────────────────────────────────────────────────── */

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

/* ── Check bookkeeping ────────────────────────────────────────────────────── */

const results = [];
function check(name, ok, detail, { fatal = true } = {}) {
  results.push({ name, ok, detail, fatal });
}

const bullet = (lines, max = 8) => {
  const shown = lines.slice(0, max).map((l) => `      - ${l}`);
  if (lines.length > max) shown.push(`      - ... and ${lines.length - max} more`);
  return shown.join('\n');
};

/* ── Main ─────────────────────────────────────────────────────────────────── */

async function main() {
  /*
   * Every student row, sorted in memory.
   *
   * Deliberately not .orderBy('ts') with the equality filter: that needs a
   * composite index, and a missing index would fail this script for a reason
   * that has nothing to do with what it is checking. The whole responses
   * collection is a few thousand documents, so the filter alone is cheap.
   */
  const snap = await db.collection('responses').where('section', '==', SECTION).get();
  const rows = snap.docs.map((d) => ({ _id: d.id, ...d.data() }));

  if (!rows.length) {
    console.log(`\nNo ${SECTION} rows exist at all. Nothing to verify.\n`);
    process.exit(1);
  }

  const bySession = new Map();
  for (const r of rows) {
    const sid = r.session_id || 'unknown';
    if (!bySession.has(sid)) bySession.set(sid, []);
    bySession.get(sid).push(r);
  }

  const sessions = [...bySession.entries()]
    .map(([sid, rs]) => {
      const ts = rs.map((r) => r.ts).filter(Boolean).sort();
      return { sid, rows: rs, first: ts[0], last: ts[ts.length - 1] };
    })
    .sort((a, b) => String(b.last).localeCompare(String(a.last)));

  if (LIST) {
    console.log(`\nRecent ${SECTION} sessions, newest first:\n`);
    console.log('  session_id                              rows  answers  first seen');
    console.log('  ' + '-'.repeat(76));
    for (const s of sessions.slice(0, 20)) {
      const withText = s.rows.filter((r) => (r.followup_text || '').trim()).length;
      console.log(
        `  ${s.sid.padEnd(38)}  ${String(s.rows.length).padStart(4)}  ${String(withText).padStart(7)}  ${(s.first || '').slice(0, 19)}`,
      );
    }
    console.log('');
    process.exit(0);
  }

  const target = SESSION_ARG
    ? sessions.find((s) => s.sid === SESSION_ARG)
    : sessions[0];

  if (!target) {
    console.error(`\nNo ${SECTION} session with id ${SESSION_ARG}. Try --list.\n`);
    process.exit(1);
  }

  const { sid, rows: r, first, last } = target;
  const minutes = first && last ? (new Date(last) - new Date(first)) / 60000 : 0;

  console.log('');
  console.log('='.repeat(78));
  console.log(`  STUDENT RUN VERIFICATION — ${sid}`);
  console.log('='.repeat(78));
  console.log(`  rows stored      ${r.length}`);
  console.log(`  first answer     ${first || '(none)'}`);
  console.log(`  last answer      ${last || '(none)'}`);
  console.log(`  elapsed          ${minutes.toFixed(1)} min`);
  console.log('');

  const byId = new Map();
  for (const row of r) {
    const qid = row.question_id || '(missing)';
    if (!byId.has(qid)) byId.set(qid, []);
    byId.get(qid).push(row);
  }

  /* 1. Scaffolding rows must never persist. */
  const turns = [...byId.keys()].filter((q) => /^turn_/.test(q));
  check(
    'NO_TRANSCRIPT_SCAFFOLDING',
    turns.length === 0,
    turns.length
      ? `${turns.length} turn_* rows stored; /log_response should discard these for climate sections`
      : 'no turn_* rows, as expected',
  );

  /* 2. Ids belong to the current scheme. A legacy id means a stale frontend. */
  const unknown = [...byId.keys()].filter((q) => !/^turn_/.test(q) && !EXPECTED[q]);
  check(
    'IDS_CURRENT_SCHEME',
    unknown.length === 0,
    unknown.length
      ? `ids stored that the current build does not ask — a STALE DEPLOYED FRONTEND is the likely cause:\n${bullet(unknown)}`
      : `all ids match SC_STU_*`,
  );

  /* 3. Completeness. A missing item is silently absent from every report. */
  const missing = Object.keys(EXPECTED).filter((id) => !byId.has(id));
  const dupes = [...byId.entries()].filter(([q, v]) => EXPECTED[q] && v.length > 1).map(([q, v]) => `${q} stored ${v.length} times`);
  check(
    'ALL_21_ITEMS_PRESENT',
    missing.length === 0,
    missing.length ? `not stored:\n${bullet(missing, 21)}` : 'all 18 rated + 3 Dream Big present',
  );
  check(
    'NO_DUPLICATE_ITEMS',
    dupes.length === 0,
    dupes.length ? bullet(dupes) : 'each item stored exactly once',
  );

  /* 4-6. Per-row field verification. */
  const wrongText = [];
  const wrongVersion = [];
  const wrongConstruct = [];
  const emptyText = [];
  const badRating = [];
  const badScale = [];
  const missingAnalysis = [];
  const inputMethods = new Map();

  for (const [qid, exp] of Object.entries(EXPECTED)) {
    const row = (byId.get(qid) || [])[0];
    if (!row) continue;

    if (row.question_text !== exp.text) {
      wrongText.push(`${qid}\n          stored:   ${JSON.stringify(row.question_text ?? null)}\n          expected: ${JSON.stringify(exp.text)}`);
    }
    const wantVersion = itemVersion(exp.text);
    if (row.item_version !== wantVersion) {
      wrongVersion.push(`${qid}: stored ${row.item_version ?? '(none)'}, expected ${wantVersion}`);
    }
    if (row.construct !== exp.construct) {
      wrongConstruct.push(`${qid}: stored ${row.construct ?? '(none)'}, expected ${exp.construct}`);
    }
    if (!(row.followup_text || '').trim()) {
      emptyText.push(`${qid} (${exp.type})`);
    }

    if (exp.type === 'rated') {
      if (!Number.isInteger(row.rating) || row.rating < 1 || row.rating > 4) {
        badRating.push(`${qid}: rating ${JSON.stringify(row.rating)} is not 1-4`);
      }
      const wantScale = exp.scaleOptions ?? DEFAULT_SCALE;
      if (row.scale_max !== wantScale.length) {
        badScale.push(`${qid}: scale_max ${JSON.stringify(row.scale_max)}, expected ${wantScale.length}`);
      }
      if (JSON.stringify(row.scale_labels) !== JSON.stringify(wantScale)) {
        badScale.push(`${qid}: scale_labels ${JSON.stringify(row.scale_labels)}, expected ${JSON.stringify(wantScale)}`);
      }
      if (row.question_type !== 'rated') missingAnalysis.push(`${qid}: question_type ${JSON.stringify(row.question_type)}`);
    } else {
      if (row.rating !== 0 && row.rating !== undefined && row.rating !== null) {
        badRating.push(`${qid}: open item carries rating ${JSON.stringify(row.rating)}, expected 0`);
      }
      if (row.question_type !== 'open') missingAnalysis.push(`${qid}: question_type ${JSON.stringify(row.question_type)}`);
    }

    if (!row.survey_cycle) missingAnalysis.push(`${qid}: survey_cycle missing`);
    if (!row.ts_at) missingAnalysis.push(`${qid}: ts_at missing`);
    if (!row.input_method) missingAnalysis.push(`${qid}: input_method missing`);
    else inputMethods.set(row.input_method, (inputMethods.get(row.input_method) || 0) + 1);
  }

  check(
    'WORDING_MATCHES_BUILD',
    wrongText.length === 0,
    wrongText.length
      ? `question_text differs from the item the current build asks. Either the deployed\n      frontend is stale, or an item was reworded since this script's snapshot —\n      see the header. A mismatch means a report prints a question nobody was asked:\n${bullet(wrongText, 6)}`
      : 'every stored question_text matches the deployed wording',
  );
  check(
    'ITEM_VERSION_CORRECT',
    wrongVersion.length === 0,
    wrongVersion.length ? bullet(wrongVersion) : 'every item_version is the hash of its stored wording',
  );
  check(
    'CONSTRUCT_PRESENT',
    wrongConstruct.length === 0,
    wrongConstruct.length
      ? `construct is the field added with the renumber; cross-role analysis joins on it:\n${bullet(wrongConstruct)}`
      : 'every item carries its expected construct',
  );
  check(
    'ANSWER_TEXT_CAPTURED',
    emptyText.length === 0,
    emptyText.length
      ? `stored with an EMPTY followup_text — this is the exact failure that made 33 of 38\n      earlier student runs unusable, and it is invisible in the dashboard's counts:\n${bullet(emptyText, 21)}`
      : 'all 21 answers carry spoken text',
  );
  check('RATINGS_VALID', badRating.length === 0, badRating.length ? bullet(badRating) : 'ratings in range, open items at 0');
  check('SCALE_RECORDED', badScale.length === 0, badScale.length ? bullet(badScale) : 'scale labels and max stored per item');
  check(
    'ANALYSIS_FIELDS',
    missingAnalysis.length === 0,
    missingAnalysis.length ? bullet(missingAnalysis) : 'question_type, input_method, survey_cycle and ts_at on every row',
    { fatal: false },
  );

  /* 7. The token guard: school attribution must come from the token record. */
  const tokens = [...new Set(r.map((x) => x.token).filter(Boolean))];
  let tokenRecord = null;

  if (tokens.length !== 1) {
    check(
      'TOKEN_STORED',
      false,
      tokens.length === 0
        ? 'no token on any row. Under the 2026-10-27 guard these writes should have been\n      refused with 401 — if they landed, the deployed backend predates the guard.'
        : `${tokens.length} different tokens in one session: ${tokens.join(', ')}`,
    );
  } else {
    check('TOKEN_STORED', true, `single token on every row: ${tokens[0]}`);
    const tsnap = await db.collection('climate_tokens').where('token', '==', tokens[0]).limit(1).get();
    tokenRecord = tsnap.empty ? null : tsnap.docs[0].data();

    check('TOKEN_RESOLVES', Boolean(tokenRecord), tokenRecord ? 'token exists in climate_tokens' : 'token is not in climate_tokens — the guard should have refused these writes with 403');

    if (tokenRecord) {
      check('TOKEN_ACTIVE', tokenRecord.status === 'active', `status = ${JSON.stringify(tokenRecord.status)}`, { fatal: false });
      check('TOKEN_ROLE_MATCHES', tokenRecord.role === EXPECTED_ROLE, `token role = ${JSON.stringify(tokenRecord.role)}, section = ${SECTION}`);

      /*
       * The point of the whole guard. school_id must equal the TOKEN's school,
       * not whatever the browser put in the body. Before 2026-10-27 a valid
       * token for one school could store answers against another, and the
       * 2026-10-08 orphan write is what that looked like in the data.
       */
      const mismatched = [];
      for (const row of r) {
        if (row.school_id !== tokenRecord.school_id) {
          mismatched.push(`${row.question_id}: school_id ${JSON.stringify(row.school_id)} != token's ${JSON.stringify(tokenRecord.school_id)}`);
        }
        if (row.role !== EXPECTED_ROLE) {
          mismatched.push(`${row.question_id}: role ${JSON.stringify(row.role)} != ${EXPECTED_ROLE}`);
        }
      }
      check(
        'SCHOOL_DERIVED_FROM_TOKEN',
        mismatched.length === 0,
        mismatched.length ? bullet(mismatched) : `every row attributed to ${tokenRecord.school_id} (${tokenRecord.school_name || 'no name'})`,
      );

      const noName = r.filter((row) => !row.school_name).length;
      check(
        'SCHOOL_NAME_STORED',
        noName === 0 || !tokenRecord.school_name,
        noName ? `${noName} rows missing school_name though the token carries ${JSON.stringify(tokenRecord.school_name)}` : 'school_name present',
        { fatal: false },
      );
    }
  }

  /* ── Report ─────────────────────────────────────────────────────────────── */

  console.log('  CHECKS');
  console.log('  ' + '-'.repeat(76));
  for (const { name, ok, detail, fatal } of results) {
    const mark = ok ? 'PASS' : fatal ? 'FAIL' : 'WARN';
    console.log(`  [${mark}] ${name}`);
    if (!ok || SHOW) console.log(`      ${ok ? detail : detail}`);
  }
  console.log('');

  if (inputMethods.size) {
    console.log('  HOW THE ANSWERS ARRIVED');
    for (const [m, n] of inputMethods) console.log(`    ${m.padEnd(8)} ${n}`);
    console.log('    (ratings are clicked by design; followups are voice)');
    console.log('');
  }

  if (SHOW) {
    console.log('  WHAT WAS STORED');
    console.log('  ' + '-'.repeat(76));
    for (const [qid, exp] of Object.entries(EXPECTED)) {
      const row = (byId.get(qid) || [])[0];
      if (!row) { console.log(`  ${qid}  (MISSING)`); continue; }
      const score = exp.type === 'rated' ? `[${row.rating}]` : '[open]';
      console.log(`  ${qid} ${score} ${exp.text}`);
      console.log(`      ${JSON.stringify((row.followup_text || '').slice(0, 220))}`);
    }
    console.log('');
  }

  const failed = results.filter((x) => !x.ok && x.fatal);
  const warned = results.filter((x) => !x.ok && !x.fatal);

  console.log('='.repeat(78));
  if (failed.length === 0) {
    console.log('  GO — this run stored correctly on the current build.');
    console.log(`  ${results.filter((x) => x.ok).length} checks passed${warned.length ? `, ${warned.length} warning(s) above` : ''}.`);
    console.log('');
    console.log('  One clean run proves the path works. It does not prove it works for');
    console.log('  thirty at once — /session is capped at 120/min per IP and a school');
    console.log('  shares one address, so stagger classes rather than starting together.');
  } else {
    console.log(`  NO-GO — ${failed.length} check(s) failed.`);
    console.log('');
    console.log('  Every failure above is a SILENT one: nothing in the dashboard, the');
    console.log('  report, or the participant\'s experience would have revealed it. Do');
    console.log('  not deploy a district onto this until each is understood.');
  }
  console.log('='.repeat(78));
  console.log('');

  process.exit(failed.length ? 1 : 0);
}

main().catch((e) => {
  console.error('\nverify-student-run failed:', e.message);
  process.exit(1);
});
