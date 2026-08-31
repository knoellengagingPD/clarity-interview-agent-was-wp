/**
 * test-turn-fix.mjs
 *
 * Simulates a School Climate teacher session's traffic pattern against the
 * LIVE deployed backend (clarity-interview-agent-was-wp.vercel.app), then
 * reads Firestore directly to confirm:
 *   1. turn_* records are never persisted
 *   2. chunked open-ended followup_text gets consolidated into ONE doc
 *   3. rated responses still write immediately, with correct role/rating
 *
 * All data is flagged is_test: true on the token so it's excluded from the
 * admin dashboard and real pilot data by default.
 */
import 'dotenv/config';
import admin from 'firebase-admin';

const BACKEND_URL = 'https://clarity-interview-agent-was-wp.vercel.app';
const CLARITY_KEY = process.env.CLARITY_ACCESS_KEY;
const ADMIN_PASSWORD = process.argv[2];

if (!ADMIN_PASSWORD) {
  console.error('Usage: node test-turn-fix.mjs <ADMIN_PASSWORD>');
  process.exit(1);
}

async function main() {
  // 1. Admin login
  const loginRes = await fetch(`${BACKEND_URL}/admin/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: ADMIN_PASSWORD }),
  });
  if (!loginRes.ok) {
    console.error('Admin login failed:', loginRes.status, await loginRes.text());
    process.exit(1);
  }
  const { token: adminToken } = await loginRes.json();
  console.log('✓ Admin login OK');

  // 2. Create a test token
  const schoolId = `turn-fix-test-${Date.now()}`;
  const tokenRes = await fetch(`${BACKEND_URL}/school-climate/tokens`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({
      school_name: 'Turn Fix Test School',
      school_id: schoolId,
      district: 'Test District',
      role: 'teachers',
      is_test: true,
    }),
  });
  if (!tokenRes.ok) {
    console.error('Token creation failed:', tokenRes.status, await tokenRes.text());
    process.exit(1);
  }
  const tokenDoc = await tokenRes.json();
  console.log('✓ Test token created:', tokenDoc.token, '(is_test:', tokenDoc.is_test, ')');

  const sessionId = `scltch-testfix-${Date.now()}`;

  async function logResponse(body) {
    const res = await fetch(`${BACKEND_URL}/log_response`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-clarity-key': CLARITY_KEY },
      body: JSON.stringify({
        session_id: sessionId,
        section: 'school_climate_teachers',
        school_id: schoolId,
        token: tokenDoc.token,
        role: 'teacher',
        ...body,
      }),
    });
    const json = await res.json().catch(() => ({}));
    return { status: res.status, json };
  }

  // 3. Simulate the exact traffic pattern a real session sends:
  //    - AI greeting turn (should be skipped)
  const r1 = await logResponse({ question_id: 'turn_1', followup_text: '[clarity] Hi! Ready to begin?' });
  console.log('turn_1 (AI greeting) ->', r1.status, r1.json);

  //    - Participant STT chunks arriving for question S1 (open-ended, rating 0)
  const chunks = ['I feel', 'I feel very safe', 'I feel very safe at this school because'];
  for (const c of chunks) {
    const r = await logResponse({ question_id: 'S1', rating: 0, followup_text: c });
    console.log(`S1 chunk "${c.slice(0, 20)}..." ->`, r.status, r.json);
    await new Promise((r) => setTimeout(r, 300));
  }

  //    - More AI turn scaffolding interleaved (should also be skipped)
  const r2 = await logResponse({ question_id: 'turn_5', followup_text: '[clarity] Got it, thank you.' });
  console.log('turn_5 (AI) ->', r2.status, r2.json);

  //    - Final rated answer for S1
  const r3 = await logResponse({ question_id: 'S1', rating: 4, followup_text: 'I feel very safe at this school because it is a small community and everybody is close.' });
  console.log('S1 final rating ->', r3.status, r3.json);

  // 4. Wait for the 4s followup buffer flush + margin
  console.log('Waiting 6s for buffer flush...');
  await new Promise((r) => setTimeout(r, 6000));

  // 5. Read Firestore directly
  const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
  admin.initializeApp({ credential: admin.credential.cert(sa), projectId: process.env.FIREBASE_PROJECT_ID });
  const db = admin.firestore();

  const snap = await db.collection('responses').where('session_id', '==', sessionId).get();
  console.log(`\n=== Firestore result: ${snap.size} document(s) for session ${sessionId} ===`);
  snap.docs.forEach((doc) => {
    const d = doc.data();
    console.log(`  [${doc.id}] question_id=${d.question_id} role=${d.role} rating=${d.rating} followup_text=${JSON.stringify(d.followup_text)}`);
  });

  const turnDocs = snap.docs.filter((d) => d.data().question_id?.startsWith('turn_'));
  console.log(`\nturn_* docs persisted: ${turnDocs.length} (expected: 0)`);
  console.log(`Total docs for S1: ${snap.docs.filter((d) => d.data().question_id === 'S1').length} (expected: 1, consolidated)`);

  // 6. Cleanup — delete the test docs and token so nothing lingers
  const batch = db.batch();
  snap.docs.forEach((d) => batch.delete(d.ref));
  await batch.commit();
  await db.collection('climate_tokens').doc(tokenDoc.id).delete();
  console.log('\n✓ Cleaned up test documents and token.');
}

main().catch((e) => {
  console.error('Test failed:', e);
  process.exit(1);
});
