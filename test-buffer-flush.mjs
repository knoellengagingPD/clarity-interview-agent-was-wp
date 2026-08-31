/**
 * test-buffer-flush.mjs
 *
 * Sends ONE real Dream-Big-style call (question_id "DB1", rating 0 — exactly
 * how the students/staff/parents client code logs the open-ended question)
 * against the LIVE backend, then polls Firestore for up to 60s to see
 * whether the 4s in-memory buffer flush ever actually persists the document.
 *
 * Outcomes:
 *   - Doc appears within ~4-8s  -> buffer works fine, prior test was a fluke
 *   - Doc appears late (>10s)   -> buffer only fires when Vercel happens to
 *                                   reuse/thaw the same container later
 *   - Doc never appears in 60s -> confirms silent data loss in production
 */
import 'dotenv/config';
import admin from 'firebase-admin';

const BACKEND_URL = 'https://clarity-interview-agent-was-wp.vercel.app';
const CLARITY_KEY = process.env.CLARITY_ACCESS_KEY;
const ADMIN_PASSWORD = process.argv[2];

if (!ADMIN_PASSWORD) {
  console.error('Usage: node test-buffer-flush.mjs <ADMIN_PASSWORD>');
  process.exit(1);
}

async function main() {
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

  const schoolId = `buffer-fix-test-${Date.now()}`;
  const tokenRes = await fetch(`${BACKEND_URL}/school-climate/tokens`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({
      school_name: 'Buffer Flush Test School',
      school_id: schoolId,
      district: 'Test District',
      role: 'students',
      is_test: true,
    }),
  });
  if (!tokenRes.ok) {
    console.error('Token creation failed:', tokenRes.status, await tokenRes.text());
    process.exit(1);
  }
  const tokenDoc = await tokenRes.json();
  console.log('✓ Test token created:', tokenDoc.token);

  const sessionId = `sclstu-bufftest-${Date.now()}`;

  // This mirrors logClimateResponse() exactly as called for the Dream Big
  // question in students/page.tsx line 378: score=0, real question_id.
  const sentAt = Date.now();
  const res = await fetch(`${BACKEND_URL}/log_response`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-clarity-key': CLARITY_KEY },
    body: JSON.stringify({
      session_id: sessionId,
      section: 'school_climate_students',
      question_id: 'DB1',
      role: 'student',
      school_id: schoolId,
      rating: 0,
      followup_text: 'If I could change one thing, I would want more time for group projects.',
      token: tokenDoc.token,
    }),
  });
  const json = await res.json().catch(() => ({}));
  console.log('DB1 call ->', res.status, json, `(sent at t=0s)`);

  const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
  admin.initializeApp({ credential: admin.credential.cert(sa), projectId: process.env.FIREBASE_PROJECT_ID });
  const db = admin.firestore();

  console.log('\nPolling Firestore every 3s for up to 60s...');
  let found = false;
  for (let elapsed = 0; elapsed <= 60; elapsed += 3) {
    await new Promise((r) => setTimeout(r, 3000));
    const snap = await db.collection('responses').where('session_id', '==', sessionId).get();
    const secsSinceSend = ((Date.now() - sentAt) / 1000).toFixed(1);
    if (!snap.empty) {
      console.log(`\n✓ Document appeared at t=${secsSinceSend}s`);
      snap.docs.forEach((doc) => {
        const d = doc.data();
        console.log(`  [${doc.id}] question_id=${d.question_id} role=${d.role} rating=${d.rating} followup_text=${JSON.stringify(d.followup_text)}`);
      });
      found = true;
      // cleanup
      const batch = db.batch();
      snap.docs.forEach((d) => batch.delete(d.ref));
      await batch.commit();
      break;
    } else {
      console.log(`  t=${secsSinceSend}s: not yet persisted`);
    }
  }

  if (!found) {
    console.log('\n✗ Document NEVER appeared within 60s. The Dream Big / open-ended answer was silently lost.');
  }

  await db.collection('climate_tokens').doc(tokenDoc.id).delete();
  console.log('✓ Cleaned up test token.');
  process.exit(found ? 0 : 2);
}

main().catch((e) => {
  console.error('Test failed:', e);
  process.exit(1);
});
