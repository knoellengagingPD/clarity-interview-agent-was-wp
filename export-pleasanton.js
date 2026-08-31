/**
 * export-pleasanton.js
 *
 * One-time export script — NOT committed or deployed.
 *
 * Queries all responses for school_id == "pleasanton-public-schools"
 * and writes them to pleasanton-responses.csv in this directory.
 *
 * Run with:  node export-pleasanton.js
 */

import 'dotenv/config';
import admin from 'firebase-admin';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Mirror server.js loadServiceAccount for the primary (FIREBASE_*) db ──────
function loadServiceAccount(prefix = '') {
  const clientEmailKey  = prefix ? `${prefix}_CLIENT_EMAIL`         : 'FIREBASE_CLIENT_EMAIL';
  const privateKeyKey   = prefix ? `${prefix}_PRIVATE_KEY`          : 'FIREBASE_PRIVATE_KEY';
  const privateKeyIdKey = prefix ? `${prefix}_PRIVATE_KEY_ID`       : 'FIREBASE_PRIVATE_KEY_ID';
  const projectIdKey    = prefix ? `${prefix}_PROJECT_ID`           : 'FIREBASE_PROJECT_ID';
  const b64Key          = prefix ? `${prefix}_SERVICE_ACCOUNT_B64`  : 'FIREBASE_SERVICE_ACCOUNT_B64';
  const jsonKey         = prefix ? `${prefix}_SERVICE_ACCOUNT_JSON` : 'FIREBASE_SERVICE_ACCOUNT_JSON';

  const projectId = process.env[projectIdKey];

  if (process.env[clientEmailKey] && process.env[privateKeyKey]) {
    const rawKey = process.env[privateKeyKey].replace(/\\n/g, '\n').trim();
    const cleanProjectId = projectId?.trim();
    return {
      sa: {
        type: 'service_account',
        project_id: cleanProjectId,
        private_key_id: process.env[privateKeyIdKey] || '',
        private_key: rawKey.endsWith('\n') ? rawKey : rawKey + '\n',
        client_email: process.env[clientEmailKey].trim(),
        token_uri: 'https://oauth2.googleapis.com/token',
      },
      projectId: cleanProjectId,
    };
  }

  if (process.env[b64Key]) {
    const decoded = Buffer.from(process.env[b64Key], 'base64').toString('utf8');
    return { sa: JSON.parse(decoded), projectId };
  }

  if (process.env[jsonKey]) {
    const sa = JSON.parse(process.env[jsonKey].trim());
    if (sa.private_key) sa.private_key = sa.private_key.replace(/\\n/g, '\n');
    return { sa, projectId: sa.project_id || projectId };
  }

  // fallback: local service account file
  const localFile = prefix
    ? path.join(process.cwd(), `firebase-service-account-${prefix.toLowerCase()}.json`)
    : path.join(process.cwd(), 'firebase-service-account.json');
  if (fs.existsSync(localFile)) {
    const sa = JSON.parse(fs.readFileSync(localFile, 'utf8'));
    return { sa, projectId: sa.project_id || projectId };
  }

  return null;
}

// ── CSV helpers ───────────────────────────────────────────────────────────────
const CSV_COLUMNS = [
  'document_id',
  'session_id',
  'question_id',
  'role',
  'section',
  'rating',
  'followup_text',
  'domain',
  'token',
  'ts',
];

/**
 * Escapes a single CSV field value.
 * Wraps in double-quotes if the value contains a comma, newline, or double-quote.
 * Internal double-quotes are escaped by doubling them.
 */
function csvField(value) {
  const str = value === undefined || value === null ? '' : String(value);
  if (str.includes('"') || str.includes(',') || str.includes('\n') || str.includes('\r')) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

function csvRow(values) {
  return values.map(csvField).join(',');
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  // Init Firebase
  const result = loadServiceAccount('FIREBASE');
  if (!result || !result.sa) {
    console.error('ERROR: Could not load Clarity 360 Firebase credentials from environment.');
    process.exit(1);
  }

  admin.initializeApp({
    credential: admin.credential.cert(result.sa),
    projectId: result.projectId,
  });

  const db = admin.firestore();
  console.log(`Connected to Firebase project: ${result.projectId}`);

  // Query — all responses for Pleasanton (no rating filter)
  const SCHOOL_ID = 'pleasanton-public-schools';
  console.log(`Querying responses where school_id == "${SCHOOL_ID}" …`);

  const snap = await db.collection('responses')
    .where('school_id', '==', SCHOOL_ID)
    .get();

  console.log(`Fetched ${snap.size} document(s).`);

  // Build CSV
  const lines = [csvRow(CSV_COLUMNS)]; // header row

  snap.docs.forEach(doc => {
    const d = doc.data();

    // Resolve timestamp: Firestore Timestamp → ISO string, or raw string passthrough
    let ts = '';
    if (d.ts) {
      ts = typeof d.ts.toDate === 'function' ? d.ts.toDate().toISOString() : String(d.ts);
    } else if (d.timestamp) {
      ts = typeof d.timestamp.toDate === 'function' ? d.timestamp.toDate().toISOString() : String(d.timestamp);
    } else if (d.created_at) {
      ts = typeof d.created_at.toDate === 'function' ? d.created_at.toDate().toISOString() : String(d.created_at);
    }

    lines.push(csvRow([
      doc.id,
      d.session_id   ?? '',
      d.question_id  ?? '',
      d.role         ?? '',
      d.section      ?? '',
      d.rating       ?? '',
      d.followup_text ?? '',
      d.domain       ?? '',
      d.token        ?? '',
      ts,
    ]));
  });

  // Write file
  const outPath = path.join(__dirname, 'pleasanton-responses.csv');
  fs.writeFileSync(outPath, lines.join('\n'), 'utf8');

  console.log(`✓ Exported ${snap.size} documents to ${outPath}`);
}

main().catch(err => {
  console.error('Export failed:', err);
  process.exit(1);
});
