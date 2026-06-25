// Supabase REST API client — raw fetch only, no SDK
// Avoids UND_ERR_SOCKET errors in Vercel serverless functions

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

export async function supabaseUpsert(table, rows, onConflict) {
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    throw new Error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
  }

  const url = `${SUPABASE_URL}/rest/v1/${table}?on_conflict=${onConflict}`;

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'apikey': SUPABASE_KEY,
      'Authorization': `Bearer ${SUPABASE_KEY}`,
      'Prefer': 'resolution=ignore-duplicates,return=minimal'
    },
    body: JSON.stringify(Array.isArray(rows) ? rows : [rows])
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Supabase ${table} upsert failed: ${res.status} ${errText}`);
  }

  return true;
}
