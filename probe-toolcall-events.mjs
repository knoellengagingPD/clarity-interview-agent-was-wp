/**
 * Does ONE function call produce more than one event we act on?
 *
 * This exists because I claimed it does, twice misdiagnosed the symptom it
 * causes, and Chris quite reasonably asked whether I was sure. Rather than
 * argue from the docs, ask the API.
 *
 * It opens a text-only Realtime session with the same record_answer tool the
 * teacher survey uses, gives it one unambiguous answer, and prints every event
 * that carries a completed function call along with that call's id.
 *
 * Reads: how many events would parseToolCall accept, and how many DISTINCT
 * calls do they actually represent? If the counts differ, the page was acting
 * more than once per answer and the deduplication fix is correct.
 *
 * No dependencies — Node 22's built-in WebSocket, authenticated by subprotocol
 * the way a browser does. Costs a fraction of a cent. Run from this folder:
 *
 *   node probe-toolcall-events.mjs
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));

/**
 * Collect candidate keys and try them in turn.
 *
 * The committed .env holds a key that no longer works — production reads its
 * key from Vercel, so the local file drifted without anything noticing. Rather
 * than guess which file is current, try each and report the SOURCE that worked.
 * Keys themselves are never printed.
 */
function candidateKeys() {
  const found = [];
  const add = (source, value) => {
    const v = (value || '').trim().replace(/^["']|["']$/g, '');
    if (v.startsWith('sk-') && !found.some(f => f.key === v)) found.push({ source, key: v });
  };

  add('OPENAI_API_KEY environment variable', process.env.OPENAI_API_KEY);

  for (const file of ['.env', '.env.local', '.env.production', '.env.save', '.env.backup']) {
    const p = path.join(here, file);
    if (!fs.existsSync(p)) continue;
    const line = fs.readFileSync(p, 'utf8').split('\n').find(l => l.startsWith('OPENAI_API_KEY'));
    if (line) add(file, line.split('=').slice(1).join('='));
  }
  return found;
}

const KEYS = candidateKeys();
if (KEYS.length === 0) {
  console.error('No OPENAI_API_KEY found. Pull the live one first:  vercel env pull .env.local');
  process.exit(1);
}
console.log(`Found ${KEYS.length} candidate key(s): ${KEYS.map(k => k.source).join(', ')}\n`);

const TOOL = {
  type: 'function',
  name: 'record_answer',
  description: "Record the participant's answer to one interview question.",
  parameters: {
    type: 'object',
    properties: {
      question_id: { type: 'string', enum: ['S1', 'S2'] },
      rating: { type: 'integer', minimum: 1, maximum: 4 },
      follow_up: { type: 'string' },
    },
    required: ['question_id'],
  },
};

function report(carryingACall, sequence) {
  const distinct = new Set(carryingACall.map(c => c.callId));

  console.log('\n=== EVENTS parseToolCall WOULD ACCEPT ===');
  if (carryingACall.length === 0) {
    console.log('  (none — the model replied in text instead of calling the tool)');
  }
  carryingACall.forEach(c => console.log(`  ${c.event.padEnd(44)} call_id=${c.callId}`));

  console.log(`\n  events the page would have acted on     : ${carryingACall.length}`);
  console.log(`  function calls those actually represent : ${distinct.size}`);

  if (carryingACall.length > distinct.size) {
    const n = carryingACall.length;
    console.log(`\n  >>> CONFIRMED: ${n} events, ${distinct.size} real call.`);
    console.log(`  >>> Undeduplicated, one answer sent ${n} function_call_outputs and`);
    console.log(`  >>> ${n} response.create events — so Clarity produced ${n} responses`);
    console.log(`  >>> back to back and moved through ${n} questions.`);
  } else if (carryingACall.length === 1) {
    console.log('\n  >>> NOT CONFIRMED: one event per call. My diagnosis is wrong.');
    console.log('  >>> Deduplication is still harmless, but the skip has another cause.');
  }

  console.log('\n=== FULL EVENT SEQUENCE ===');
  sequence.forEach(t => console.log(`  ${t}`));
}

function probe(index) {
  if (index >= KEYS.length) {
    console.error('\nEvery candidate key was rejected. Pull the live one:');
    console.error('  cd ~/engaging-interviewer-voice && vercel env pull .env.local');
    process.exit(1);
  }
  const { source, key } = KEYS[index];
  console.log(`Trying key from ${source}...`);

  // GA, not beta. The 'openai-beta.realtime-v1' subprotocol now hard-fails with
  // beta_api_shape_disabled — the same GA/beta split that silently broke event
  // handling on three survey pages in August.
  const ws = new WebSocket('wss://api.openai.com/v1/realtime?model=gpt-realtime', [
    'realtime',
    `openai-insecure-api-key.${key}`,
  ]);

  const carryingACall = [];
  const sequence = [];
  let done = false;

  const timer = setTimeout(() => {
    if (done) return;
    console.error('Timed out after 45s with no response.done.');
    process.exit(1);
  }, 45000);

  ws.addEventListener('open', () => {
    ws.send(JSON.stringify({
      type: 'session.update',
      session: {
        // GA session shape, matching what the teacher page actually sends.
        type: 'realtime',
        output_modalities: ['text'],
        instructions:
          'You are conducting a school climate survey. When the participant answers ' +
          'a statement, call record_answer BEFORE saying anything else.',
        tools: [TOOL],
        tool_choice: 'auto',
      },
    }));

    ws.send(JSON.stringify({
      type: 'conversation.item.create',
      item: {
        type: 'message',
        role: 'user',
        content: [{
          type: 'input_text',
          text: 'For statement S1, "I feel safe at this school" — I say 4, strongly agree. ' +
                'The staff are attentive and I have never felt unsafe here.',
        }],
      },
    }));

    ws.send(JSON.stringify({ type: 'response.create' }));
  });

  ws.addEventListener('message', ev => {
    const e = JSON.parse(ev.data);
    sequence.push(e.type);

    if (e.type === 'error') {
      done = true;
      clearTimeout(timer);
      try { ws.close(); } catch {}
      if (e.error?.code === 'invalid_api_key') {
        console.log(`  rejected (${source}) — trying the next candidate\n`);
        probe(index + 1);
      } else {
        console.error('API ERROR:', JSON.stringify(e.error, null, 2));
        process.exit(1);
      }
      return;
    }

    // Exactly the three shapes parseToolCall accepts.
    let callId = null;
    if (e.type === 'response.function_call_arguments.done') {
      callId = e.call_id;
    } else if (e.type === 'response.output_item.done' && e.item?.type === 'function_call') {
      callId = e.item.call_id;
    } else if (e.type === 'response.done') {
      const fc = (e.response?.output ?? []).find(o => o?.type === 'function_call');
      if (fc) callId = fc.call_id;
    }
    if (callId) carryingACall.push({ event: e.type, callId });

    if (e.type === 'response.done') {
      done = true;
      clearTimeout(timer);
      console.log(`  connected with the key from ${source}`);
      report(carryingACall, sequence);
      try { ws.close(); } catch {}
    }
  });

  ws.addEventListener('error', () => {
    if (done) return;
    console.error('WebSocket error — check network access.');
    process.exit(1);
  });
}

probe(0);
