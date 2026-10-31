/**
 * What is in debug_traces? And optionally, remove a test session from it.
 *
 * Debugging Mode returns 204 whether or not the Firestore write landed, on
 * purpose: the browser must never branch on whether debug succeeded. That
 * makes the HTTP code useless as proof, so this is the only way to confirm a
 * batch actually arrived.
 *
 * READ ONLY unless you pass --delete, which takes a session id and removes
 * only that session's documents.
 *
 *   node check-debug-traces.mjs
 *   node check-debug-traces.mjs t1
 *   node check-debug-traces.mjs --delete t1
 */

import 'dotenv/config';
import admin from 'firebase-admin';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const DELETE = args.includes('--delete');
const SESSION = args.find((a) => !a.startsWith('--')) || null;

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

async function main() {
  console.log(`\nProject: ${process.env.FIREBASE_PROJECT_ID || '(from service account)'}`);

  const col = db.collection('debug_traces');
  const snap = SESSION
    ? await col.where('session_id', '==', SESSION).get()
    : await col.get();

  if (snap.empty) {
    console.log(SESSION
      ? `\nNothing in debug_traces for session "${SESSION}".\n`
      : '\ndebug_traces is empty.\n');
    return;
  }

  if (DELETE) {
    if (!SESSION) {
      console.error('\n--delete needs a session id. Refusing to delete everything.\n');
      process.exit(1);
    }
    let n = 0;
    for (const doc of snap.docs) { await doc.ref.delete(); n++; }
    console.log(`\nDeleted ${n} document(s) for session "${SESSION}".\n`);
    return;
  }

  // Group by session so a real interview reads as one block, not 200 rows.
  const bySession = new Map();
  for (const doc of snap.docs) {
    const d = doc.data();
    const key = d.session_id || '(none)';
    if (!bySession.has(key)) bySession.set(key, []);
    bySession.get(key).push({ id: doc.id, ...d });
  }

  console.log(`\n${snap.size} document(s) across ${bySession.size} session(s):\n`);

  for (const [sessionId, docs] of bySession) {
    docs.sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
    const lineCount = docs.reduce((t, d) => t + (Array.isArray(d.lines) ? d.lines.length : 0), 0);
    const seqs = docs.map((d) => d.seq).filter((s) => Number.isFinite(s));
    const gaps = [];
    for (let i = 1; i < seqs.length; i++) {
      if (seqs[i] !== seqs[i - 1] + 1) gaps.push(`${seqs[i - 1]} -> ${seqs[i]}`);
    }

    console.log(`  ${sessionId}`);
    console.log(`    documents : ${docs.length}`);
    console.log(`    lines     : ${lineCount}`);
    console.log(`    sources   : ${[...new Set(docs.map((d) => d.source))].join(', ')}`);
    console.log(`    first     : ${docs[0].created_at}`);
    console.log(`    last      : ${docs[docs.length - 1].created_at}`);
    console.log(`    seq gaps  : ${gaps.length ? gaps.join(', ') : 'none'}`);

    // Any double quote left in a shipped line means the browser's stripper
    // missed something. This is the check that protects the consent promise.
    const quoted = [];
    for (const d of docs) {
      for (const line of (d.lines || [])) {
        if (typeof line === 'string' && line.includes('"')) quoted.push(line.slice(0, 80));
      }
    }
    if (quoted.length) {
      console.log(`    WARNING   : ${quoted.length} line(s) still contain a double quote:`);
      for (const q of quoted.slice(0, 5)) console.log(`                ${q}`);
    } else {
      console.log(`    quotes    : none (no text slipped through)`);
    }

    if (SESSION) {
      console.log('\n    lines:');
      for (const d of docs) {
        for (const line of (d.lines || [])) console.log(`      ${line}`);
      }
    }
    console.log('');
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
