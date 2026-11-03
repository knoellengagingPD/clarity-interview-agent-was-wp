/**
 * Point a survey token at a different school.
 *
 * WHY THIS EXISTS
 *
 * 2026-11-03. Pleasanton's parent invitation went out carrying SCL-DL3SW4 —
 * a device-test token — instead of SCL-SXR3ZY. The link is valid and the
 * interview works; the answers simply file under the test school, where no
 * report will find them, and where the dashboard hides them because the token
 * is flagged is_test.
 *
 * The email cannot be unsent. So instead of correcting every parent, correct
 * the token: make the link that is already in their inboxes the right link.
 *
 * WHAT IT WRITES, AND WHAT IT DELIBERATELY DOES NOT
 *
 * school_id, school_name, district, is_test. Nothing else — not `role`, not
 * `token`, not `status`, not `created_at`.
 *
 * `role` especially. The server-side guard in lib/climateTokenGuard.js rejects
 * a write whose token role does not match the section being written to, and it
 * is the only thing standing between a forwarded link and mislabelled data.
 * Changing school is invisible to that guard; changing role would break it.
 *
 * school_name matters more than it looks: it is interpolated into Clarity's
 * instructions — "You are interviewing a parent or guardian of a student at
 * ${schoolName}" — so a token left pointing at a test school is one question
 * away from saying so out loud.
 *
 * WHAT IT CANNOT FIX
 *
 * Rows already written. school_id is stamped onto each response at write time,
 * which is why retag-district.mjs exists. Run this while the old bucket is
 * empty, or retag what is in it afterwards.
 *
 * DRY RUN BY DEFAULT.
 *
 *   node repoint-token.mjs SCL-DL3SW4
 *   node repoint-token.mjs SCL-DL3SW4 --like SCL-SXR3ZY
 *   node repoint-token.mjs SCL-DL3SW4 --like SCL-SXR3ZY --apply
 *
 * --like copies school_id, school_name and district from a token already
 * pointing where you want this one to point, rather than retyping three
 * strings. Copying a known-good document is harder to get wrong than
 * describing one.
 */

import 'dotenv/config';
import admin from 'firebase-admin';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const APPLY = args.includes('--apply');
const argOf = (f) => { const i = args.indexOf(f); return i > -1 ? args[i + 1] : null; };

const TOKEN = args.find((a) => a.startsWith('SCL-'));
const LIKE = argOf('--like');

if (!TOKEN) {
  console.error('\nUsage: node repoint-token.mjs SCL-XXXXXX --like SCL-YYYYYY [--apply]\n');
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
admin.initializeApp({ credential: admin.credential.cert(sa), projectId: process.env.FIREBASE_PROJECT_ID || sa.project_id });
const db = admin.firestore();

/** Tokens are stored with an auto id and the token string in a field. */
async function findToken(t) {
  const q = await db.collection('climate_tokens').where('token', '==', t).get();
  if (q.empty) return null;
  if (q.size > 1) {
    console.error(`\n${t} matches ${q.size} documents. Refusing to guess which one.\n`);
    process.exit(1);
  }
  return q.docs[0];
}

const doc = await findToken(TOKEN);
if (!doc) { console.error(`\n${TOKEN} not found in climate_tokens.\n`); process.exit(1); }
const cur = doc.data();

let target;
if (LIKE) {
  const ref = await findToken(LIKE);
  if (!ref) { console.error(`\n${LIKE} not found — nothing to copy from.\n`); process.exit(1); }
  const r = ref.data();
  // A reference token must already be where we want to go, and must not itself
  // be flagged test — copying is_test from a test token would be silent and
  // would defeat the point of the exercise.
  target = { school_id: r.school_id, school_name: r.school_name, district: r.district, is_test: false };
  if (r.is_test === true) {
    console.error(`\n${LIKE} is itself flagged is_test. That is not a template worth copying.\n`);
    process.exit(1);
  }
  if (r.role !== cur.role) {
    console.error(`\nRole mismatch: ${TOKEN} is "${cur.role}", ${LIKE} is "${r.role}".`);
    console.error('Copy from a token for the same role, or the comparison means nothing.\n');
    process.exit(1);
  }
} else {
  target = {
    school_id: argOf('--school-id') ?? cur.school_id,
    school_name: argOf('--school-name') ?? cur.school_name,
    district: argOf('--district') ?? cur.district,
    is_test: false,
  };
}

const FIELDS = ['school_id', 'school_name', 'district', 'is_test'];

console.log('');
console.log('='.repeat(74));
console.log(`  ${APPLY ? 'REPOINTING' : 'DRY RUN — nothing will be written'}`);
console.log('='.repeat(74));
console.log(`  token       ${TOKEN}`);
console.log(`  document    ${doc.id}`);
console.log(`  role        ${cur.role}   (NOT changed — the write guard depends on it)`);
console.log('');
let changes = 0;
for (const f of FIELDS) {
  const from = cur[f];
  const to = target[f];
  const same = String(from) === String(to);
  if (!same) changes++;
  console.log(`  ${f.padEnd(12)} ${String(from).padEnd(30)} ${same ? '=' : '->'}  ${to}`);
}
console.log('');

if (!changes) {
  console.log('  Nothing to change. This token already points there.');
  console.log('='.repeat(74) + '\n');
  process.exit(0);
}

console.log('  Rows already written keep the school_id they were stamped with.');
console.log('  Check the old bucket is empty, or retag it afterwards:');
console.log(`    node watch-deployment.mjs --school ${cur.school_id}`);
console.log('');

if (!APPLY) {
  console.log('  Re-run with --apply to write. Nothing has changed.');
  console.log('='.repeat(74) + '\n');
  process.exit(0);
}

// The restore point, printed before the write rather than after, so it exists
// even if the write is what goes wrong.
console.log('  BEFORE (restore point):');
console.log('  ' + JSON.stringify(cur));
console.log('');

await doc.ref.update(target);

const after = (await doc.ref.get()).data();
console.log('  AFTER:');
console.log('  ' + JSON.stringify(after));
console.log('');
console.log('  Verify the token still resolves before trusting it:');
console.log(`    curl -s -H "x-clarity-key: \\$K" \\`);
console.log(`      https://clarity-interview-agent-was-wp.vercel.app/school-climate/token/${TOKEN}`);
console.log('');
console.log('='.repeat(74) + '\n');
process.exit(0);
