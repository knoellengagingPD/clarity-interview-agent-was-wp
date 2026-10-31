/**
 * Debugging Mode: the server gate, and the only writer.
 *
 * WHY THIS EXISTS
 *
 * The browser keeps a turn-by-turn trace in memory and offers a Download
 * button at the end of an interview. That trace dies with the tab. If a
 * participant hits a fault and closes the window, the one artefact that would
 * explain it is gone, and the server side of the same session — route timings,
 * token verdicts, Claude usage, write durations — was never captured at all.
 *
 * Debugging Mode sends a copy of the browser's trace lines to the server and
 * adds the server's own. It is off by default and does nothing when off.
 *
 * WHAT IT NEVER HOLDS
 *
 * No participant text, raw or scrubbed. The browser strips every double-quoted
 * span before a line is batched, and the server records a pointer to the
 * `responses` document plus status fields (text_present, text_chars,
 * stored_chars, scrub_changed, write_status). The words live in `responses`,
 * where scrubPII has already run on them, and nowhere else.
 *
 * TWO RULES THAT ARE EASY TO BREAK
 *
 * 1. Nothing here may call log.* — not info, not warn, not error. When the
 *    switch is on, log.* forwards every line to writeDebugTrace(). A log call
 *    inside the writer is therefore infinite recursion. The one catch block
 *    below uses console.error directly, deliberately.
 *
 * 2. There is no read function, and there never should be. The survey writes
 *    logs and never reads them. Only an export script, run by an operator
 *    outside the app, reads `debug_traces`.
 *
 * TESTABILITY NOTE
 *
 * isDebugOn() is pure and can be tested by setting the environment variable.
 * writeDebugTrace() takes the Firestore handle it writes through, so a test
 * can pass a fake. The spec names this function writeDebugTrace(doc); the db
 * parameter is added ahead of it rather than reaching for a module-level
 * singleton, so the writer has no hidden dependency.
 */

/** The switch. On only when the value is exactly 'on'. */
const SWITCH = 'CLARITY_DEBUG_TRACE';

/** Collection. Never read by the survey. */
const COLLECTION = 'debug_traces';

/** Caps, so debug writes can never starve survey writes. */
const MAX_DOCS_PER_SESSION = 200;
const MAX_WRITES_PER_DAY = 100_000;

/**
 * Per-session document counts, and the daily write counter.
 *
 * Both are per-instance. This backend runs as multi-instance Vercel
 * serverless, so the caps are approximate: each instance counts only its own
 * writes. That is accepted. The caps exist to stop a runaway, not to enforce
 * an exact budget, and making them exact would cost a Firestore read on every
 * write — which is the thing they are protecting.
 */
const sessionDocCounts = new Map();
let dayKey = null;
let writesToday = 0;

/** UTC day, so the counter resets at a predictable moment. */
function currentDayKey() {
  return new Date().toISOString().slice(0, 10);
}

/**
 * The gate. The ONLY code that reads the switch.
 *
 * Every logging action — every write, send, sample, timer and listener —
 * calls this first and returns at once when it is false. A call site that
 * skips it is a defect.
 */
export function isDebugOn() {
  return process.env[SWITCH] === 'on';
}

/**
 * Write one batch. Returns true if a document was written.
 *
 * Never throws. Never retries. A debug failure must not delay a survey write
 * or surface to a participant, so every failure path returns false quietly.
 *
 * @param {FirebaseFirestore.Firestore} db
 * @param {object} doc
 * @param {string} doc.session_id
 * @param {number} doc.seq           monotonic per session, so gaps are visible
 * @param {'client'|'server'} doc.source
 * @param {Array} doc.lines
 */
export async function writeDebugTrace(db, doc) {
  // Gate first, always.
  if (!isDebugOn()) return false;

  try {
    if (!db) return false;
    if (!doc || typeof doc !== 'object') return false;

    const sessionId = typeof doc.session_id === 'string' ? doc.session_id.trim() : '';
    if (!sessionId) return false;

    const lines = Array.isArray(doc.lines) ? doc.lines : null;
    if (!lines || lines.length === 0) return false;

    // Daily cap. Reset on the first write of a new UTC day.
    const today = currentDayKey();
    if (dayKey !== today) {
      dayKey = today;
      writesToday = 0;
      sessionDocCounts.clear();
    }
    if (writesToday >= MAX_WRITES_PER_DAY) return false;

    // Per-session cap.
    const used = sessionDocCounts.get(sessionId) || 0;
    if (used >= MAX_DOCS_PER_SESSION) return false;

    // Automatic id, never sequential: sequential ids create write hotspots.
    await db.collection(COLLECTION).add({
      session_id: sessionId,
      seq: Number.isFinite(doc.seq) ? doc.seq : null,
      source: doc.source === 'client' || doc.source === 'server' ? doc.source : null,
      created_at: new Date().toISOString(),
      lines,
    });

    sessionDocCounts.set(sessionId, used + 1);
    writesToday += 1;
    return true;
  } catch (err) {
    // console, never log.* — log.* forwards here when the switch is on.
    console.error(JSON.stringify({
      level: 'error',
      msg: 'debug trace write failed',
      error: err && err.message ? err.message : String(err),
      ts: new Date().toISOString(),
    }));
    return false;
  }
}

/** Exposed for the acceptance checks only. Reads no Firestore data. */
export function debugTraceCounters() {
  return { dayKey, writesToday, sessions: sessionDocCounts.size };
}
