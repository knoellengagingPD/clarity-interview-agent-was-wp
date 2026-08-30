/**
 * Archive the interview data worth keeping, as CSV.
 *
 * Chris, 2026-08-30: "The only data we need from all previously kept interviews
 * is pleasanton teacher data and potentially the superintendent interview data."
 *
 * Writes to ./archive/ :
 *
 *   pleasanton-teacher-responses.csv     the rated answers and explanations
 *   pleasanton-teacher-transcript.csv    the turn_N rows — see note below
 *   superintendent-interviews.csv        every administrator interview
 *   MANIFEST.txt                         counts, dates, and what was skipped
 *
 * ON THE TRANSCRIPT FILE
 *
 * Pleasanton predates the change that stops turn_N scaffolding being persisted,
 * so its documents include the raw conversation. That is the only surviving
 * record of what was actually said in those interviews, and it is separated
 * rather than dropped: it is not survey data and must never be averaged with
 * the real answers, but deleting it would destroy something unrecoverable.
 *
 * READ ONLY. This script does not modify or delete anything.
 *
 *   node archive-export.mjs
 */

import 'dotenv/config';
import admin from 'firebase-admin';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(here, 'archive');

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

/** RFC 4180 escaping, plus a UTF-8 BOM so Excel reads accents correctly. */
const esc = v => {
  if (v === null || v === undefined) return '';
  const s = typeof v === 'object' ? JSON.stringify(v) : String(v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

function writeCsv(name, rows, columns) {
  fs.mkdirSync(OUT, { recursive: true });
  const lines = [columns.join(',')];
  for (const r of rows) lines.push(columns.map(c => esc(r[c])).join(','));
  fs.writeFileSync(path.join(OUT, name), '﻿' + lines.join('\n'));
  console.log(`  ${name.padEnd(38)} ${rows.length} rows`);
}

const COLUMNS = [
  'document_id', 'session_id', 'section', 'question_id', 'question_type',
  'question_text', 'item_version', 'role', 'school_id', 'school_name',
  'district', 'domain', 'rating', 'scale_max', 'scale_labels', 'input_method',
  'followup_text', 'text', 'token', 'response_mode', 'survey_cycle', 'ts',
];

console.log('Reading responses...\n');
const snap = await db.collection('responses').get();
const all = snap.docs.map(d => ({ document_id: d.id, ...d.data() }));
console.log(`  ${all.length} documents total\n`);

// ── Pleasanton teachers ──────────────────────────────────────────────────────
// Matched on a school_id prefix rather than an exact string: the value has been
// written slightly differently over time and an exact match would silently
// archive nothing while reporting success.
const pleasanton = all.filter(r =>
  String(r.school_id || '').toLowerCase().startsWith('pleasanton') &&
  String(r.section || '') === 'school_climate_teachers');

const isTurn = r => String(r.question_id || '').startsWith('turn_');
const answers = pleasanton.filter(r => !isTurn(r));
const turns = pleasanton.filter(isTurn);

console.log('Writing archive/\n');
writeCsv('pleasanton-teacher-responses.csv', answers, COLUMNS);
writeCsv('pleasanton-teacher-transcript.csv', turns,
  ['document_id', 'session_id', 'question_id', 'followup_text', 'ts']);

// ── Superintendent interviews ────────────────────────────────────────────────
const supers = all.filter(r => String(r.section || '') === 'superintendent_interview');
writeCsv('superintendent-interviews.csv', supers, COLUMNS);

// ── Manifest ─────────────────────────────────────────────────────────────────
const dates = rows => {
  const ts = rows.map(r => r.ts).filter(Boolean).sort();
  return ts.length ? `${ts[0].slice(0, 10)} to ${ts[ts.length - 1].slice(0, 10)}` : '—';
};
const sessions = rows => new Set(rows.map(r => r.session_id)).size;

const otherSections = {};
for (const r of all) {
  const s = r.section || '(none)';
  if (s === 'superintendent_interview') continue;
  if (pleasanton.includes(r)) continue;
  otherSections[s] = (otherSections[s] || 0) + 1;
}

const manifest = [
  `Clarity 360 archive — generated ${new Date().toISOString()}`,
  `Firestore project: ${process.env.FIREBASE_PROJECT_ID || sa.project_id}`,
  '',
  `Total documents in \`responses\`: ${all.length}`,
  '',
  'ARCHIVED',
  `  Pleasanton teacher answers    ${answers.length} rows, ${sessions(answers)} sessions, ${dates(answers)}`,
  `  Pleasanton teacher transcript ${turns.length} rows  (turn_N scaffolding — NOT survey data)`,
  `  Superintendent interviews     ${supers.length} rows, ${sessions(supers)} sessions, ${dates(supers)}`,
  '',
  'NOT ARCHIVED (test districts and other sections)',
  ...Object.entries(otherSections).sort((a, b) => b[1] - a[1])
    .map(([s, n]) => `  ${s.padEnd(30)} ${n}`),
  '',
  'NOTE: nothing was modified or deleted. This export is read-only.',
].join('\n');

fs.writeFileSync(path.join(OUT, 'MANIFEST.txt'), manifest);
console.log('\n' + manifest);
process.exit(0);
