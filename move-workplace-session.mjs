/**
 * Move a completed WORKPLACE interview from one organization to another.
 *
 * WHY A SECOND SCRIPT
 *
 * move-session.mjs already does this for school climate, and it cannot be
 * pointed at a workplace interview: it queries `responses` and writes
 * `school_id`, while workplace writes to `workplace_climate` and keys on
 * `organization_id`. Run it on a workplace session and it reports
 * "Nothing to move" — no harm done, and nothing moved either.
 *
 * That split is finding 9 in the status report. This script is the workplace
 * half of it rather than a fix for it.
 *
 * THREE SPELLINGS OF ONE FIELD
 *
 * server.js warns about this at /workplace/organization-ids, and it matters
 * here: the response rows store `organization_id`, the token documents store
 * `organizationId`, and the display name is `organization_name` or
 * `organizationName` depending on where you look. The dashboard's session list
 * queries `workplace_climate.organization_id == orgId` exactly, then looks up
 * test tokens by `workplace_tokens.organizationId == orgId`. So the rows need
 * the snake_case field and the token lookup uses the camelCase one. Both are
 * read below; only the rows are written.
 *
 * WHAT THE DASHBOARD ACTUALLY NEEDS
 *
 * GET /workplace/sessions builds its list from the response rows, so the
 * columns come from the rows and not from the organization:
 *
 *   organization_id   the query — without this the session is invisible
 *   organization      the "Organization" column, free text
 *   department        the "Department" column, free text
 *   token             governs Hide Test Data (see below)
 *   19 answers        what makes it say "complete"
 *
 * ON THE TOKEN — read this before passing --token
 *
 * Hide Test Data is ON by default. It hides a row when that row's `token` is
 * one of the destination organization's tokens flagged `is_test: true`. The
 * consequences are not symmetric:
 *
 *   - Row has no token, or a token that isn't flagged test: the interview
 *     SHOWS even with Hide Test Data on.
 *   - Row carries a test-flagged token of the destination: the interview
 *     HIDES by default, and only appears once Hide Test Data is turned off.
 *
 * So if the destination is a test organization and you want the interview to
 * behave like test data, pass --token with one of its test tokens. If you want
 * it visible in the default view, leave the token alone.
 *
 * WHAT THIS DOES NOT TOUCH
 *
 *   - The answers, ratings, timestamps and document ids. Ids are
 *     `<session>__<question>`, so a second run changes nothing.
 *   - Supabase. /workplace/session-complete also writes the session to
 *     `workplace_sessions` there with its own organization_id, and this script
 *     does not reach it. After moving, Firestore and Supabase disagree about
 *     which organization owns the interview.
 *   - workplace_session_flags. An archive flag carries its own
 *     organization_id, and the dashboard queries flags by organization. If
 *     this session was archived under the old organization, the flag stops
 *     matching after the move and the session comes back unarchived. --apply
 *     reports it when it sees one.
 *
 * DRY RUN BY DEFAULT. It prints what it would change and stops.
 *
 *   node move-workplace-session.mjs --list
 *   node move-workplace-session.mjs <session_id> <new_organization_id>
 *   node move-workplace-session.mjs <session_id> nowling-test --token WRK-XXXXXX --apply
 *
 * Read-only until --apply is passed.
 */

import 'dotenv/config';
import admin from 'firebase-admin';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const APPLY = args.includes('--apply');
const LIST = args.includes('--list');
const tokenIdx = args.indexOf('--token');
const NEW_TOKEN = tokenIdx > -1 ? args[tokenIdx + 1] : null;
const orgNameIdx = args.indexOf('--organization');
const NEW_ORG_LABEL = orgNameIdx > -1 ? args[orgNameIdx + 1] : null;
const positional = args.filter((a, i) =>
  !a.startsWith('--')
  && !(tokenIdx > -1 && i === tokenIdx + 1)
  && !(orgNameIdx > -1 && i === orgNameIdx + 1));
const [SESSION_ID, NEW_ORG_ID] = positional;

if (!LIST && (!SESSION_ID || !NEW_ORG_ID)) {
  console.error('usage: node move-workplace-session.mjs --list');
  console.error('       node move-workplace-session.mjs <session_id> <new_organization_id> [--token WRK-X] [--organization "Label"] [--apply]');
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

const when = (d) =>
  d.ts_at?.toDate?.() ||
  (typeof d.ts === 'string' ? new Date(d.ts) : null) ||
  (d.ts?.toDate?.() ?? null);

/** Every workplace organization known to the token collection, both spellings. */
async function organizations() {
  const snap = await db.collection('workplace_tokens').get();
  const byId = new Map();
  for (const d of snap.docs) {
    const x = d.data() || {};
    const id = String(x.organizationId || x.organization_id || '').trim();
    if (!id) continue;
    if (!byId.has(id)) byId.set(id, { name: '', tokens: [] });
    const entry = byId.get(id);
    const name = String(x.organizationName || x.organization_name || '').trim();
    if (name && !entry.name) entry.name = name;
    entry.tokens.push({ token: x.token || d.id, is_test: x.is_test === true });
  }
  return byId;
}

// ── --list: what is there, so the right session and destination get picked ───

if (LIST) {
  const snap = await db.collection('workplace_climate').get();
  const sessions = new Map();
  for (const doc of snap.docs) {
    const x = doc.data() || {};
    const id = x.session_id || '(no session_id)';
    if (!sessions.has(id)) {
      sessions.set(id, {
        org: x.organization_id ?? '(field absent)',
        label: x.organization || '',
        dept: x.department || '',
        token: x.token || '(none)',
        rows: 0, withText: 0, date: null,
      });
    }
    const s = sessions.get(id);
    s.rows += 1;
    if ((x.followup_text ?? x.text ?? '').trim()) s.withText += 1;
    const dt = when(x);
    if (dt && (!s.date || dt < s.date)) s.date = dt;
  }

  const rows = [...sessions.entries()].sort(
    (a, b) => (a[1].date?.getTime() || 0) - (b[1].date?.getTime() || 0));

  console.log(`workplace_climate — ${rows.length} session(s), ${snap.size} answer rows\n`);
  console.log('date        rows text  organization_id       token         session_id');
  console.log('─'.repeat(118));
  for (const [id, s] of rows) {
    console.log(
      `${(s.date ? s.date.toISOString().slice(0, 10) : '??????????')}  ` +
      `${String(s.rows).padStart(4)} ${String(s.withText).padStart(4)}  ` +
      `${String(s.org).slice(0, 21).padEnd(21)} ${String(s.token).slice(0, 13).padEnd(13)} ${id}`);
  }

  const orgs = await organizations();
  console.log(`\nworkplace_tokens — ${orgs.size} organization(s)\n`);
  for (const [id, o] of [...orgs].sort((a, b) => a[0].localeCompare(b[0]))) {
    const test = o.tokens.filter(t => t.is_test).map(t => t.token);
    const live = o.tokens.filter(t => !t.is_test).map(t => t.token);
    console.log(`  ${id}${o.name ? `  "${o.name}"` : ''}`);
    if (live.length) console.log(`      live: ${live.join(', ')}`);
    if (test.length) console.log(`      test: ${test.join(', ')}`);
  }
  console.log('\nPick the session_id to move and the organization_id to move it to.');
  process.exit(0);
}

// ── the move ─────────────────────────────────────────────────────────────────

const snap = await db.collection('workplace_climate')
  .where('session_id', '==', SESSION_ID).get();

if (snap.empty) {
  console.log(`No workplace_climate rows for session ${SESSION_ID}.`);
  console.log('Run with --list to see the sessions that do exist.');
  console.log('A school-climate or administrator session lives in `responses` — use move-session.mjs for those.');
  process.exit(0);
}

const first = snap.docs[0].data();
const sections = new Set(snap.docs.map(d => d.data().section));
const tokens = new Set(snap.docs.map(d => d.data().token || '(none)'));
const withText = snap.docs.filter(d => (d.data().followup_text ?? '').trim()).length;

console.log(`session        ${SESSION_ID}`);
console.log(`section        ${[...sections].join(', ')}`);
console.log(`answers        ${snap.size} rows, ${withText} carrying text`);
console.log(`complete        ${snap.size >= 19 ? 'yes — 19 or more answers' : `NO — ${snap.size} of 19, the dashboard will show this as abandoned`}`);
console.log('');
console.log(`organization_id ${first.organization_id ?? '(field absent)'}  ->  ${NEW_ORG_ID}`);
console.log(`organization    ${first.organization || '(none)'}  ->  ${NEW_ORG_LABEL || '(unchanged)'}`);
console.log(`department      ${first.department || '(none)'}  ->  (unchanged)`);
console.log(`token           ${[...tokens].join(', ')}  ->  ${NEW_TOKEN || '(unchanged)'}`);

// Does the destination exist, and what would the token choice mean there?
const orgs = await organizations();
const dest = orgs.get(NEW_ORG_ID);
console.log('');
if (!dest) {
  console.log(`WARNING  "${NEW_ORG_ID}" has no token in workplace_tokens.`);
  console.log('         The move still works — the dashboard queries the response rows, not the');
  console.log('         token collection — but the organization will not appear in the picker,');
  console.log('         so you would have to reach it by its id.');
} else {
  const testTokens = new Set(dest.tokens.filter(t => t.is_test).map(t => t.token));
  console.log(`destination    ${NEW_ORG_ID}${dest.name ? ` "${dest.name}"` : ''}, ${dest.tokens.length} token(s), ${testTokens.size} flagged test`);
  const effective = NEW_TOKEN || first.token || '';
  if (effective && testTokens.has(effective)) {
    console.log(`visibility     token ${effective} is flagged is_test — this interview will be HIDDEN`);
    console.log('               while Hide Test Data is on (it is on by default).');
  } else {
    console.log(`visibility     token ${effective || '(none)'} is not a test token of this organization —`);
    console.log('               the interview will SHOW even with Hide Test Data on.');
  }
}

// An archive flag carries its own organization_id and would stop matching.
const flag = await db.collection('workplace_session_flags').doc(SESSION_ID).get();
if (flag.exists) {
  const f = flag.data() || {};
  console.log('');
  console.log(`flag           workplace_session_flags: status=${f.status}, organization_id=${f.organization_id}`);
  console.log('               The dashboard queries flags by organization, so this flag will be');
  console.log('               rewritten to the new organization_id too, keeping the archive state.');
}

console.log('');
console.log('NOTE           Supabase is not touched. /workplace/session-complete wrote this');
console.log('               session to `workplace_sessions` there with the old organization_id,');
console.log('               and it will still say the old one after this move.');

if (!APPLY) {
  console.log('\nDRY RUN — nothing written. Re-run with --apply to make these changes.');
  process.exit(0);
}

const patch = { organization_id: NEW_ORG_ID };
if (NEW_TOKEN) patch.token = NEW_TOKEN;
if (NEW_ORG_LABEL) patch.organization = NEW_ORG_LABEL;

// Batched, because partial success would split one interview across two
// organizations — worse than the problem being fixed.
let batch = db.batch(), n = 0, written = 0;
for (const doc of snap.docs) {
  batch.update(doc.ref, patch);
  if (++n % 400 === 0) { await batch.commit(); written += n; batch = db.batch(); n = 0; }
}
if (flag.exists) batch.update(flag.ref, { organization_id: NEW_ORG_ID });
await batch.commit();
written += n;

console.log(`\nMoved ${written} answer row(s)${flag.exists ? ' and the archive flag' : ''} to ${NEW_ORG_ID}.`);
console.log('The dashboard caches for 30 seconds — wait, then Refresh.');
process.exit(0);
