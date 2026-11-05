/**
 * Check every survey link in an email before it goes out.
 *
 * WHY THIS EXISTS
 *
 * Two of Pleasanton's four invitations went out carrying device-test tokens.
 * The parent email on 2 November and the staff email on 5 November both
 * pointed at zz-test-pps-devices-2026-11, so real answers filed where no
 * report would find them. Both were caught by accident — the first because
 * someone happened to read the Google Doc, the second because staff responses
 * appeared in the wrong bucket while being watched.
 *
 * Neither mistake was in the start-up packet. The packet had the right tokens
 * both times. They happened in the copy from packet to email, which is the one
 * step nothing checked.
 *
 * So this checks the thing that actually gets sent. Paste the email, it finds
 * every link and resolves it.
 *
 * SCL-DL3SW4 and SCL-SXR3ZY are both valid parent tokens for Pleasanton and
 * differ in nothing a human eye can use. That is the root cause, and until
 * test tokens carry a visibly different prefix, a checking step is the defence.
 *
 *   node verify-links.mjs https://schoolclimate.clarity360hq.com/...?token=SCL-XXXXXX
 *   pbpaste | node verify-links.mjs           # paste the whole email
 *   node verify-links.mjs < invitation.txt
 *
 * Needs no credentials: the token endpoint is unauthenticated. Read-only;
 * it resolves tokens and writes nothing.
 */

import 'dotenv/config';

const BACKEND = process.env.NEXT_PUBLIC_BACKEND_URL
  || 'https://clarity-interview-agent-was-wp.vercel.app';

/** Any Clarity survey URL, however it is wrapped or punctuated in an email. */
const LINK_RE = /https?:\/\/[^\s<>"')\]]*clarity360hq\.com[^\s<>"')\]]*/gi;

/**
 * Pull the token out of a URL.
 *
 * Decoded first, because the failure that cost a 19-question interview was a
 * token arriving as "SCL-DL3SW4%20l" — a space and a stray character picked up
 * when the URL was selected on a phone. A checker that silently tidied that
 * away would pass a link the app then rejects, which is worse than not
 * checking.
 */
function tokenOf(url) {
  try {
    const u = new URL(url);
    const raw = u.searchParams.get('token');
    return raw === null ? null : raw;
  } catch {
    return null;
  }
}

function roleFromPath(url) {
  const m = /\/school-climate\/(students|teachers|staff|parents)\b/i.exec(url);
  return m ? m[1].toLowerCase() : /\/interview\b/.test(url) ? 'administrator' : null;
}

async function readStdin() {
  if (process.stdin.isTTY) return '';
  let s = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) s += chunk;
  return s;
}

const fromArgs = process.argv.slice(2).join('\n');
const text = `${fromArgs}\n${await readStdin()}`;
const urls = [...new Set(text.match(LINK_RE) || [])];

if (!urls.length) {
  console.error('\nNo clarity360hq.com links found.');
  console.error('Pass URLs as arguments, or pipe the email text in:\n');
  console.error('  pbpaste | node verify-links.mjs\n');
  process.exit(1);
}

console.log('');
console.log('='.repeat(94));
console.log(`  ${urls.length} link(s) found — resolving against ${BACKEND}`);
console.log('='.repeat(94));
console.log('');

let problems = 0;

for (const url of urls) {
  const pathRole = roleFromPath(url);
  const token = tokenOf(url);

  // A video or marketing link in the same email is not a fault.
  if (!token) {
    if (pathRole) {
      console.log(`  ✗  ${url}`);
      console.log('     NO TOKEN in this link — it cannot work.\n');
      problems++;
    }
    continue;
  }

  if (token !== token.trim() || /\s/.test(token)) {
    console.log(`  ✗  token "${token}"`);
    console.log('     Contains whitespace. This will NOT resolve, and the participant');
    console.log('     will complete a whole interview that stores nothing.\n');
    problems++;
    continue;
  }

  let d;
  try {
    const res = await fetch(`${BACKEND}/school-climate/token/${encodeURIComponent(token)}`);
    if (!res.ok) {
      console.log(`  ✗  ${token}   HTTP ${res.status} — token not found.\n`);
      problems++;
      continue;
    }
    d = await res.json();
  } catch (e) {
    console.log(`  ?  ${token}   could not reach the backend: ${e.message}\n`);
    problems++;
    continue;
  }

  const school = d.school_id || '(none)';
  // The naming convention is the signal: zz- prefixes everything that is not a
  // live district. is_test is not returned by this endpoint, so the school id
  // is what there is to go on — which is also what a report groups by, so it
  // is the thing that actually matters.
  const isTestBucket = /^zz-/i.test(school);
  const roleMismatch = pathRole && d.role && pathRole !== d.role;

  const mark = isTestBucket || roleMismatch ? '✗' : '✓';
  if (mark === '✗') problems++;

  console.log(`  ${mark}  ${token.padEnd(12)} ${String(d.role).padEnd(14)} ${school}`);
  if (isTestBucket) {
    console.log('     ^^ TEST BUCKET — do not send. Real answers filed here are');
    console.log('        invisible to every report until someone moves them.');
  }
  if (roleMismatch) {
    console.log(`     ^^ ROLE MISMATCH — the link path says "${pathRole}", the token says "${d.role}".`);
    console.log('        The server will reject every write from this link.');
  }
  console.log(`     ${url}`);
  console.log('');
}

console.log('='.repeat(94));
if (problems) {
  console.log(`  ${problems} problem(s). DO NOT SEND until these are fixed.`);
} else {
  console.log('  All links resolve to a live school with a matching role. Safe to send.');
}
console.log('='.repeat(94));
console.log('');
process.exit(problems ? 1 : 0);
