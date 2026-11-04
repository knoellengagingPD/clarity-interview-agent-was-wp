# Debugging Mode: findings for Dallin

Running list from building against `clarity360-requirements-debug-mode.md` (v2).
Newest section last. Each item says what was found, where, and what it asks of you.

---

## Decisions Chris made that change the spec

**Step 0 is dropped. Better Stack stays as it is for now.**
No token removal, no `shipLog` deletion, nothing sent or stopped. The spec treats
step 0 as a prerequisite; it has not been done and is not scheduled. Everything
below was built on top of the code as it stands, with Better Stack still shipping.

---

## Better Stack, for whenever it is picked up again

**There is a second leak site, not just the failure path.**
You flagged `server.js:3890`, which ships a participant email on a failed FMP
reminder. The line immediately after it does the same on success:

```js
log.info('FMP reminder sent', { email, checkinNum, code: returnCode, emailId: emailData.id })
```

That sends the participant's email address *and* their FMP return code, which is
what they use to resume their sessions. It fires on every successful reminder,
not only on errors.

**The five uptime monitors survive token removal.**
They are external HTTP checks configured in the Better Stack dashboard and do not
use `BETTER_STACK_TOKEN`. Removing the variable stops log ingestion only. What is
lost is searchable server log history, not monitoring.

**The footprint is two lines.**
`server.js:26` reads the token, `server.js:29` posts to the endpoint, both inside
`shipLog`. Nothing else in the backend references Better Stack, nothing in `lib/`,
nothing in the frontend, no script or config. The 198 `log.*` call sites all funnel
through that one function, so there is a single point to cut. `shipLog` is never
awaited and swallows its own errors, so removal cannot affect request handling.

---

## Step 1: fast-forward dev to main

**dev was 5 commits behind, not 4.**
The extra one is `bbf988b Add retag-district.mjs`, which landed after v2 was
written. Your count was correct at the time. Confirmed `493af5d` is the token
enforcement commit (adds `lib/climateTokenGuard.js`, its tests, and the
`/log_response` changes).

Fast-forward was clean: dev had no commits main lacked.

---

## Step 2: server gate, writer, route, /session flag

Built on `feature/debug-trace-server`, commit `0490893`.

### Two acceptance checks in the spec cannot pass as written

**"An oversized body is rejected" returns 500, not 413.**
The global error handler at `server.js:7250` ignores `err.status` and flattens
everything:

```js
app.use((err, req, res, _next) => {
  log.error('Unhandled error', { error: err.message, stack: err.stack });
  res.status(500).json({ error: 'Internal server error' });
});
```

Express throws `PayloadTooLargeError` with `status: 413`; the handler discards it.
This is pre-existing and affects every route, `/log_response` included. The
rejection itself works correctly: the body never parses, the route never runs,
nothing is written. Only the status code is wrong.

Suggested: update the check to expect 500, and fix the handler in its own commit
after 10 November, since it changes the response of every route in the file.

**"/session returns a byte-identical response" cannot be tested.**
`client_secret.value` is minted fresh by OpenAI on every call, so two consecutive
responses differ with no code change at all. The check has to be structural.
What was used instead, and passes:

| Server state | `sorted(keys)` |
|---|---|
| before the change | `client_secret, model, url` |
| switch on | `client_secret, debug, model, url` |
| switch off, after the change | `client_secret, model, url` |

The `debug` key is appended rather than inserted, so key order is also unchanged
when the switch is off.

### Small corrections

**`/session` is a GET.** The spec names the route without a method. It is
`app.get('/session', ...)` at `server.js:819`.

**No separate body cap was added.** v1 specified 256 KB. `express.json` is already
capped at 50 KB (`server.js:714`) and v2 batches at 40 KB, so an oversized body is
rejected before the route runs. A second limit would be a third number to keep in
sync with the other two.

### Decisions that are yours to overrule

**Signature is `writeDebugTrace(db, doc)`, not `writeDebugTrace(doc)`.**
The Firestore handle is passed in rather than reached for at module scope, so a
test can supply a fake, the same reason `climateTokenGuard.js` is pure. One-line
change if you would rather match the spec exactly.

**Rate limit is 300/min on bucket `debug-trace`.** Reasoned, not measured: thirty
students batching every 30s is roughly sixty a minute from one school IP, with
headroom for the `pagehide` beacons that arrive together at the end of a session.
Its own bucket so debug can never consume the budget `/log_response` depends on.

**Caps are per-instance and therefore approximate.** 200 documents per session and
100,000 writes per day, both held in memory. Vercel runs multiple instances, each
counting only its own. Making them exact would need a Firestore read on every
write, which is the cost the caps exist to avoid. Reasoning is written into the
file so it is not mistaken later for an oversight.

### One thing that is load-bearing and easy to break

**`writeDebugTrace` must never call `log.*`.** Once `log.info`, `log.warn` and
`log.error` forward to `writeDebugTrace`, a `log.*` call inside the writer is
infinite recursion, and it would only appear under load. The single catch block
uses `console.error` directly. This is deliberate and should stay that way.

---

## Design concern for steps 3 and 4

**The quote-stripping rule is syntactic, not semantic, and already has one hole.**

Replacing every double-quoted span protects the consent promise only because the
codebase happens to quote all participant speech. One line does not:

```js
trace('  held', `heard ${heard} for ${q.id} — waiting for a tap, kept as fallback`)
```

`heard` is parsed from what the participant said and carries no quotes, so it
ships. The content is a single rating word, so this is not a problem today. The
problem is structural: the next trace line anyone adds that interpolates text
without quotes leaks silently, and no acceptance check would catch it unless the
test interview happened to say that exact phrase.

Suggested hardening, cheapest first:

1. After stripping, have the shipper drop or truncate any line that still contains
   a double quote.
2. Cap every detail field at a fixed length before batching.
3. Allowlist which fields may ship, rather than blocklisting what may not.

---

## Tooling added

**`check-debug-traces.mjs`** (read-only unless `--delete <session_id>`).

The route returns 204 whether or not the Firestore write landed, by design, so the
HTTP code proves nothing. This is the only way to confirm a batch arrived.

```
node check-debug-traces.mjs                 # everything, grouped by session
node check-debug-traces.mjs <session_id>    # one session, with its lines
node check-debug-traces.mjs --delete <id>   # refuses without an id
```

Per session it reports document count, line count, sources, first and last
timestamps, `seq` gaps, and **whether any shipped line still contains a double
quote**. That last one is the check that protects the consent promise once the
browser shipper exists.

---

## Operational note for your step 7

Turning the switch on in Production and running "one test interview" writes real
rows to a real `school_id`. Use a token minted under `zz-test-pps-devices-2026-11`,
not a Pleasanton one. Pleasanton's live deployment is `pps-2026-27`, and its
teacher group is small enough that a few test rows would move the averages.

---

## Steps 3 and 4 are built, merged, and ON in production

Written 2026-11-01, the night before Pleasanton opens. Chris needed Debugging
Mode live for the deployment rather than after it, so this did not wait for
review. Everything below is on `main` in both repos and deployed.

| | |
|---|---|
| Backend | `30a7c74` — gate, writer, `/debug/trace`, `/session` flag |
| Frontend | `9b385bc` — gate, redactor, shipper, collectors |
| Switch | `CLARITY_DEBUG_TRACE=on`, Production, set via CLI |
| Window | Pleasanton `pps-2026-27`, 2–10 November |

**To turn it off:** set the variable to anything but `on` and redeploy the
backend. `/session` stops emitting `debug`, the browser gate stays false, every
collector becomes an early return, and `/debug/trace` answers 404. About three
minutes end to end. No frontend change is needed to kill it.

### Step 3 — the shipper

`workplace-interview-agent/src/lib/interview/debugShipper.ts`.

Batches redacted lines and POSTs `{ session_id, seq, source: 'client', lines }`.
Two rules it is built around, both worth preserving if you refactor it:

**It never throws.** Every exported function is wrapped, every await caught. A
diagnostic that can interrupt an interview is worse than no diagnostic. There is
a test that asserts a rejecting `fetch` does not reject into the caller.

**Redaction happens on the way in, not on the way out.** `shipTraceLine` redacts
before the line enters the buffer, so raw speech never sits in memory waiting to
be sent and no future call site can forget.

`fetch(keepalive)` rather than `navigator.sendBeacon` for the final flush:
sendBeacon cannot set headers, and `/debug/trace` sits behind `requireAccessKey`,
so every beacon would 401. The last batch of a session is the one most likely to
explain why it ended.

A 404 stops the session — the switch is off server-side and there is nothing to
retry. Three consecutive failures also stop it, rather than retrying on a
participant's connection during an interview that still has to work.

Preamble blocks: `BUILD` (commit, ref, env) and `DEVICE` (ua, cores, memory,
effective connection, mediaDevices and RTCPeerConnection presence, viewport,
secure context). **Device labels are never read.** `enumerateDevices()` returns
strings like "Chris's AirPods"; whether a device exists and permission was
granted is the useful part and is available without the label.

Known gap: `BUILD` currently reports `commit unknown`. Next only inlines
`NEXT_PUBLIC_`-prefixed variables into the browser bundle and Vercel's git
variables are not prefixed. Fixed by adding `NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA`
to the frontend project. Cosmetic, left alone before the deployment.

### Step 4 — the collectors

All five interview pages. `/session` now returns `debug`, which remains the only
thing that can open the browser gate. `setDebugEnabled` and `startDebugShipper`
run at the call site before any trace line exists, so the preamble is first and
nothing earlier is dropped. `trace()` offers every line to the shipper from its
single existing call site — which is what makes a `trace()` added next month
collected by default rather than forgotten.

### Your three hardening suggestions

From the "Design concern for steps 3 and 4" section above:

1. **Drop any line that still contains a quote** — done, in `redactBatch`.
2. **Cap every detail field** — done, but only for an allowlist of kinds known to
   carry speech (`PARTICIPANT`, `CLARITY`, `TAIL`, `skipped`, `held`, `parsed`,
   `RESCUED`), and only when the quote rule did **not** fire. Capping an already
   redacted line truncates the diagnostic words that are the reason for keeping
   it: `too short to be an elaboration ([text: 2 chars]) — likely noise` is longer
   than the cap and contains no speech at all.
3. **Allowlist which fields may ship** — not done. Instead, audited.

**The audit, because the `held` hole you identified deserved a measurement
rather than a guess.** Every `trace()` call across all five pages, every template
interpolation not wrapped in quote characters: **31 of them, and not one carries
free text.** They are question ids, numeric scores, durations, counts, booleans,
and one `String(err)` from the audio API. `held → heard` is the only
participant-derived value and it is a single parsed rating word inside the cap.

So the structural risk you named is real and remains real — the allowlist is
hand-maintained and the next unquoted line leaks silently — but there is nothing
leaking today. Worth re-running that audit whenever trace lines are added.

### Two deviations from the spec, both deliberate

**The switch is now case-insensitive.** The spec's `=== 'on'` meant `ON`, `On`
and ` on ` all left Debugging Mode off — silently, because off is also the normal
state. It would have been discovered by looking for traces that were never
captured, after the interviews they existed to explain. Still only the word
"on", trimmed and lowercased; `true`, `1` and `yes` remain off so a stray config
value cannot enable it by accident. `announceDebugState()` now logs the resolved
state once at import, via `console.*` for the recursion reason, so the Vercel log
distinguishes "off" from "misconfigured".

**Flush interval is 30s, not 10s.** Measured rather than assumed — see below.

### Verification, on real runs

Both sessions are `zz-test-pps-devices-2026-11`, per the operational note above.
No Pleasanton rows were touched.

| | `sclst-0f924668` | `sclst-f0666492` |
|---|---|---|
| Flush interval | 10s | 30s |
| Duration | 120s | 83s |
| Documents | 11 | 4 |
| Lines | 47 | 35 |
| Lines per document | 4.3 | 8.75 |
| seq gaps | none | none |
| Quotes surviving | none | none |

**Redaction confirmed against real transcription, not fixtures.** The local
download of the first session has 47 content lines and three `PARTICIPANT` lines
carrying full sentences. The server copy has 47 lines and zero quotes. Nothing
was lost and nothing leaked.

**`pagehide` works.** The first session was ended by closing the tab mid-interview
and the final partial batch still arrived — line counts match exactly.

**Why the interval changed.** At 10s the timer fired on nearly every burst of
trace lines and `BATCH_SIZE` almost never fired at all. Extrapolated, a
15.6-minute interview is ~120 documents and a 33-minute one reaches
`MAX_DOCS_PER_SESSION`, at which point the shipper goes quiet silently and the
*end* of the longest sessions is what gets lost — the worst part to lose, since a
participant who runs long is both the likeliest to and the most worth having a
trace for. At 30s the same interview is ~40 documents, and 200 participants cost
Firestore roughly a thousand writes instead of three thousand. Nothing reads this
collection live, so the delay costs nobody anything.

### Tooling added since

**`watch-deployment.mjs`** (read-only). One command answering "is it working
right now", for reading in a school rather than afterwards.

```
node watch-deployment.mjs                    # one shot
node watch-deployment.mjs --watch 60         # refresh until Ctrl-C
node watch-deployment.mjs --school <id>
```

The live rule deliberately differs from `cost-per-interview.mjs`, and the reason
may interest you: that script calls a session started at 10+ answers and usable
at 80% text, which is correct for a finished run and wrong at 9:40am when every
session in the room sits at two or three answers. Judged by that rule a healthy
morning reads as zero started, zero usable — the exact shape of a catastrophe.
So the live rule is: **two or more stored answers and not one carrying text means
already broken.** The softer percentage verdict is withheld below five answers so
a single blank cannot raise an alarm in the first minutes of the day.

Queries are filtered by `school_id` at the query rather than read-everything-
then-filter like the older scripts — `responses` is ~4,750 documents and a
`--watch` loop reading all of it every minute would bill thousands of reads to
look at thirty.

### Open for you

- `NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA` so `BUILD` reports a real commit.
- The server-side collectors. Everything shipped so far is `source: 'client'`;
  nothing writes `source: 'server'` yet, so route timings, token verdicts, Claude
  usage and write durations are still uncaptured. That was the original
  justification for the feature and it is the remaining half.
- Better Stack, untouched. Both leak sites are still live — the one you flagged
  and the FMP reminder success path documented above.
- Whether the per-instance caps should ever become exact. They are approximate on
  multi-instance serverless by design; worth revisiting only if a district is
  large enough for the daily cap to bind, which Pleasanton is not.

---

## Day two of Pleasanton: what Debugging Mode caught

Written 2026-11-03, with the window open. Four findings, one of them a defect
that silently destroys completed interviews and is worth your attention before
anything else on this list.

### 1. A full interview can run on a token that does not resolve, and store nothing

**Reproduced on desktop Chrome. Not browser-specific, not a race — deterministic.**

A parent link picked up a stray character in transit (`?token=SCL-DL3SW4%20l`).
What happened next:

1. The page looks the token up. The backend returns **404**, correctly.
2. The page handles that correctly too — dispatches `SET_ERROR` and renders
   "⚠️ Interview Link Issue — Token not found".
3. **Two modals render on top of that error screen**: the tips modal, then
   "What to Expect" with the "I'm Ready — Begin Interview" button.
4. The participant clicks through both, never sees the error, and begins.
5. `schoolIdRef` is never assigned, so every write carries an empty
   `school_id` and the server-side guard rejects all of them.
6. Clarity delivers the closing and tells them to submit.

**No participant has hit this.** It was found in Chris's own test on the night
of the 2nd — a complete 19-question parent run on an iPhone, eleven minutes,
`captured 19 of 19, missing (none)` in the downloaded trace, and not one row
stored. The real parent interview that arrived the next morning stored
correctly.

That matters for how you prioritise it, so: the severity is what it *would*
cost, not what it has. A participant hitting this gives up fifteen minutes,
sees the closing, is told to submit, and has no way to know. You would not find
out from them, and until the orphan detector below existed you would not have
found out at all.

The validation was never broken. The pre-interview modals were added later and
do not check whether the page is in an error state.

**Suggested fix, smallest first:** do not render the modals when
`screen === 'error'`. The error screen already exists and is already correct —
it just needs to be the thing on top. That is a render condition, not new
logic. Belt and braces would be refusing to write a response with an empty
`school_id`, so a session that cannot be attributed fails loudly in the first
thirty seconds rather than silently at minute eleven.

**To reproduce:** open any climate page with a deliberately damaged token, e.g.
`/school-climate/parents?token=SCL-ANYTHING%20x`, and click through both
modals. `get_page_text` shows the error screen rendering underneath.

### 2. The token lookup endpoint is unauthenticated

`GET /school-climate/token/:token` returns `role`, `school_name`, `school_id`
and `district` with no access key. Found by accident — a `curl` ran with an
unset `$K` and still returned data.

Low severity: the token is itself the secret, and anyone holding one could read
the school off the page anyway. Worth a decision rather than leaving it
undecided, since it is the one endpoint that maps a token to a district.

### 3. Debugging Mode was the only witness to the lost interview

Worth knowing because it is an argument for the feature rather than a defect.

Everything that monitors this deployment counts stored rows. An interview that
stores nothing is invisible to all of it — it leaves no response, no
`climate_sessions` summary, nothing. The *only* record that the lost parent
interview ever happened is 22 documents in `debug_traces`.

That turned into a detector. `watch-deployment.mjs` now takes the sessions that
shipped trace lines, subtracts those that stored answers, and reports what is
left:

```
⚠  1 interview(s) RAN but stored nothing — almost certainly a bad link.
   sclpar-6c6df907  parents  245 trace lines, 11 min, 59 min ago
```

Sessions under 20 trace lines are ignored — the preamble alone is 7 or 9, so
anything near that is someone opening a link and leaving.

### 4. The DEVICE preamble fingerprints the rendering engine, by accident

`deviceMemory` and `navigator.connection` are Chromium-only. Safari omits both,
so the preamble is **7 lines on WebKit and 9 on Chromium**. That turned out to
be the fastest way to tell an iPhone session from a laptop one without reading
any content, and it identified which of two abandoned sessions came from a
Chromebook.

Unintended, but worth not breaking.

### Still open from the earlier list

- **The first trace line of every session never ships.** `trace('READY', …)`
  fires when the tips modal is dismissed; `startDebugShipper()` runs inside
  `startRealtimeSession()`, which is later. So `READY` is written to the local
  buffer before the shipper exists and is dropped from the shipped copy. My
  commit message claimed otherwise and was wrong — the Chromebook trace proves
  it. Fix is to replay whatever is already in `traceRef` immediately after the
  shipper starts.
- **`BUILD commit unknown`** — needs `NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA` on the
  frontend project.
- **The server-side collectors.** Everything shipping is still `source:
  'client'`. Route timings, token verdicts, Claude usage and write durations —
  the original justification for the feature — remain uncaptured.
- **One API race at the end of a long interview**, recovered cleanly:
  `Conversation already has an active response in progress: resp_…`. Seen once,
  at the closing, after the final open question. Harmless so far.

### Tooling added today

**`repoint-token.mjs`** — points a survey token at a different school, so a link
already sitting in people's inboxes becomes the right link rather than needing
a correction email. Writes `school_id`, `school_name`, `district` and
`is_test`; deliberately never `role`, since the write guard depends on it.
`--like <token>` copies from a known-good token and refuses if that token is
flagged test or carries a different role. Dry run by default, and it prints the
before state as a restore point ahead of the write rather than after it.

Note for whenever you touch token handling: `school_name` is interpolated into
Clarity's instructions — *"You are interviewing a parent or guardian of a
student at ${schoolName}"* — so a token pointing at a test school is one
participant question away from saying so out loud.
