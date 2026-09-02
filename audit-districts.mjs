/**
 * What is actually in `responses`, and what would Hide Test Data hide?
 *
 * Before flagging old districts as test data it is worth knowing whether
 * flagging will work, because the dashboard's filter is:
 *
 *   if (shouldHideTest && doc.token && testTokenSet.has(doc.token)) return false;
 *
 * Note `doc.token &&`. A response with NO token field is never hidden, no
 * matter what is flagged in `climate_tokens`. Much of the historical data
 * predates the token system, so "flag the token" may quietly do nothing for
 * exactly the districts it was meant to clean up — and the failure is silent,
 * which is the kind this project keeps getting caught by.
 *
 * So this reports, per district: how many responses exist, how many carry a
 * token, how many of those tokens are already flagged is_test, and therefore
 * how many rows would STILL appear on the dashboard after flagging everything.
 *
 * READ ONLY. It changes nothing; it tells you what changing something would do.
 *
 *   node audit-districts.mjs
 *   node audit-districts.mjs --sessions        also break down by session
 */

import 'dotenv/config';
import admin from 'firebase-admin';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const showSessions = process.argv.includes('--sessions');

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

console.log('Reading responses, climate_tokens and climate_session_flags…\n');

const [responses, tokens, flags] = await Promise.all([
  db.collection('responses').get(),
  db.collection('climate_tokens').get(),
  db.collection('climate_session_flags').get(),
]);

const testTokens = new Set();
const knownTokens = new Set();
tokens.docs.forEach(d => {
  const t = d.data();
  if (t.token) knownTokens.add(t.token);
  if (t.is_test === true && t.token) testTokens.add(t.token);
});

const archivedSessions = new Set(
  flags.docs.filter(d => d.data().status === 'archived').map(d => d.data().session_id),
);

/** district -> stats */
const districts = new Map();

for (const doc of responses.docs) {
  const r = doc.data();
  const key = r.school_id || '(no school_id)';
  let d = districts.get(key);
  if (!d) {
    d = {
      total: 0, withToken: 0, flaggedTest: 0, unknownToken: 0,
      sections: new Map(), sessions: new Map(), first: null, last: null,
    };
    districts.set(key, d);
  }
  d.total += 1;
  if (r.token) {
    d.withToken += 1;
    if (testTokens.has(r.token)) d.flaggedTest += 1;
    else if (!knownTokens.has(r.token)) d.unknownToken += 1;
  }
  d.sections.set(r.section || '(none)', (d.sections.get(r.section || '(none)') || 0) + 1);
  if (r.session_id) d.sessions.set(r.session_id, (d.sessions.get(r.session_id) || 0) + 1);
  const ts = r.ts || null;
  if (ts) {
    if (!d.first || ts < d.first) d.first = ts;
    if (!d.last || ts > d.last) d.last = ts;
  }
}

const rows = [...districts.entries()].sort((a, b) => String(a[1].first).localeCompare(String(b[1].first)));

console.log(`${responses.size} responses across ${districts.size} district(s)`);
console.log(`${tokens.size} tokens, ${testTokens.size} already flagged is_test`);
console.log(`${archivedSessions.size} archived session(s)\n`);
console.log('='.repeat(78));

let stubbornTotal = 0;

for (const [school, d] of rows) {
  // Rows that would survive flagging every token in this district, because
  // they carry no token for the filter to match on.
  const noToken = d.total - d.withToken;
  stubbornTotal += noToken;

  console.log(`\n${school}`);
  console.log(`  ${d.total} responses · ${d.sessions.size} sessions · ${String(d.first).slice(0, 10)} → ${String(d.last).slice(0, 10)}`);
  console.log(`  roles: ${[...d.sections.entries()].map(([s, n]) => `${s.replace('school_climate_', '')}=${n}`).join(' ')}`);
  console.log(`  tokens: ${d.withToken} carry one, ${noToken} do NOT` +
    (d.flaggedTest ? `, ${d.flaggedTest} already flagged is_test` : '') +
    (d.unknownToken ? `, ${d.unknownToken} reference a token not in climate_tokens` : ''));

  if (noToken > 0) {
    console.log(`  >> Hide Test Data CANNOT hide ${noToken} of these ${d.total} rows.`);
  } else if (d.flaggedTest === d.total) {
    console.log('  >> already fully hidden by Hide Test Data.');
  } else {
    console.log('  >> flagging this district\'s tokens would hide all of it.');
  }

  if (showSessions) {
    const ss = [...d.sessions.entries()].sort((a, b) => b[1] - a[1]);
    for (const [sid, n] of ss) {
      console.log(`      ${archivedSessions.has(sid) ? 'ARCHIVED' : '        '} ${sid}  ${n} answers`);
    }
  }
}

console.log('\n' + '='.repeat(78));
console.log(`\n${stubbornTotal} response(s) across all districts carry no token.`);
if (stubbornTotal > 0) {
  console.log('Those cannot be hidden by flagging tokens — the dashboard filter');
  console.log('requires doc.token to be present before it will consult the flag.');
  console.log('Hiding them needs either an is_test field on the responses plus a');
  console.log('filter change, or archiving those sessions one by one.');
} else {
  console.log('Every response carries a token, so flagging tokens is sufficient.');
}
console.log('\nNothing was modified.');
process.exit(0);
