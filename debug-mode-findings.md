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
