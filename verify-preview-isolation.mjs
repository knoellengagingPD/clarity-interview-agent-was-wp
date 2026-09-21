/**
 * Did the preview interview land ONLY in dev?
 *
 * This is the Phase 4 proof. Setting Preview-scoped environment variables in a
 * dashboard looks like it worked whether or not it did — the deployment builds
 * either way, the interview runs either way, and the answers go somewhere. The
 * only way to know which database received them is to look in both.
 *
 * Run one full interview on a preview deployment, note the session id from the
 * trace header, then:
 *
 *   node verify-preview-isolation.mjs --session wp-xxxxxxxx-....
 *
 * PASS means the session exists in dev and does NOT exist in production.
 * Anything else is a failure, including "exists in neither" — that means the
 * write path is broken, not that isolation is working.
 *
 * Credentials. Production comes from the variables already in .env:
 *
 *   FIREBASE_SERVICE_ACCOUNT_B64   (or FIREBASE_CLIENT_EMAIL + FIREBASE_PRIVATE_KEY)
 *
 * Dev comes from the same names with a DEV_ prefix, which you add to .env
 * locally — NOT to Vercel:
 *
 *   DEV_FIREBASE_SERVICE_ACCOUNT_B64
 *
 * Read-only. Touches nothing in either project.
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

if (!SESSION) {
  console.error(
    'Usage: node verify-preview-isolation.mjs --session <session_id>\n\n' +
    'The session id is in the first lines of the downloaded interview trace.\n',
  );
  process.exit(1);
}

/** Load one project's credentials, optionally from DEV_-prefixed variables. */
function credentials(prefix = '') {
  const b64 = process.env[`${prefix}FIREBASE_SERVICE_ACCOUNT_B64`];
  if (b64) return JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));

  const json = process.env[`${prefix}FIREBASE_SERVICE_ACCOUNT_JSON`];
  if (json) return JSON.parse(json);

  const email = process.env[`${prefix}FIREBASE_CLIENT_EMAIL`];
  const key = process.env[`${prefix}FIREBASE_PRIVATE_KEY`];
  const projectId = process.env[`${prefix}FIREBASE_PROJECT_ID`];
  if (email && key && projectId) {
    return {
      type: 'service_account',
      project_id: projectId,
      client_email: email,
      private_key: key.replace(/\\n/g, '\n').trim(),
    };
  }

  // Only production has a file on disk; dev is expected to come from env.
  if (!prefix) {
    const file = path.join(here, 'firebase-service-account.json');
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  }
  return null;
}

const prodSa = credentials('');
const devSa = credentials('DEV_');

if (!prodSa) { console.error('No production Firebase credentials found.'); process.exit(1); }
if (!devSa) {
  console.error(
    'No dev Firebase credentials found.\n\n' +
    'Add DEV_FIREBASE_SERVICE_ACCOUNT_B64 to your local .env — the base64 of the\n' +
    'clarity-360-dev service account JSON. Do not add it to Vercel.\n',
  );
  process.exit(1);
}

if (prodSa.project_id === devSa.project_id) {
  console.error(
    `Both credential sets point at "${prodSa.project_id}".\n` +
    'That is the failure this script exists to catch — there is nothing to compare.\n',
  );
  process.exit(1);
}

const prod = admin.initializeApp({ credential: admin.credential.cert(prodSa), projectId: prodSa.project_id }, 'prod');
const dev = admin.initializeApp({ credential: admin.credential.cert(devSa), projectId: devSa.project_id }, 'dev');

const COLLECTIONS = ['responses', 'workplace_climate'];

/** How many rows of this session exist in one project, across both collections. */
async function countIn(app) {
  const db = admin.firestore(app);
  let total = 0;
  const per = {};
  for (const name of COLLECTIONS) {
    try {
      const snap = await db.collection(name).where('session_id', '==', SESSION).get();
      per[name] = snap.size;
      total += snap.size;
    } catch (e) {
      per[name] = `unreadable (${e.message})`;
    }
  }
  return { total, per };
}

console.log(`\nLooking for session ${SESSION}\n`);
console.log(`  production project: ${prodSa.project_id}`);
console.log(`  dev project:        ${devSa.project_id}\n`);

const inProd = await countIn(prod);
const inDev = await countIn(dev);

const row = (label, r) => {
  console.log(`  ${label.padEnd(22)} ${String(r.total).padStart(4)} rows` +
    `   (${COLLECTIONS.map((c) => `${c}: ${r.per[c]}`).join(', ')})`);
};
row(prodSa.project_id, inProd);
row(devSa.project_id, inDev);

console.log('');
if (inDev.total > 0 && inProd.total === 0) {
  console.log('  PASS — the preview wrote to dev only. Production never saw this session.');
} else if (inProd.total > 0 && inDev.total > 0) {
  console.log('  FAIL — the session is in BOTH projects. Preview is not fully isolated.');
} else if (inProd.total > 0) {
  console.log('  FAIL — the session went to PRODUCTION. Preview env vars are not taking effect.');
} else {
  console.log('  INCONCLUSIVE — the session is in neither project.');
  console.log('  That is a broken write path, not proof of isolation. Check the');
  console.log('  session id, and confirm the interview actually stored answers.');
}

console.log('\n  Also confirm by hand: no email arrived for this run.');
console.log('  RESEND_API_KEY should be a dev key or unset on Preview.\n');
process.exit(0);
