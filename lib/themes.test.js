/**
 * The theme layer's rules. The counts these produce go into district reports,
 * so every way a model reply can be wrong is pinned here.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  SPINE_V1, SPINE_IDS, TAXONOMY_VERSION, directionOf, corpusOf, looksFabricated, labelId,
  volunteeredPrompt, pointsPrompt, parseModelJson, validateVolunteered, validatePoints, tally, isReviewed,
} from './themes.js';

test('spine v1 has the fifteen themes the handoff lists', () => {
  assert.equal(SPINE_V1.length, 15);
  assert.equal(SPINE_IDS.size, 15);
  assert.equal(TAXONOMY_VERSION, 'spine-v1');
});

test('the change and keep questions are told apart for every role', () => {
  assert.equal(directionOf('students', 'SC_STU_19'), 'change');
  assert.equal(directionOf('students', 'SC_STU_20'), 'keep');
  assert.equal(directionOf('parents', 'SC_PAR_17'), 'change');
  assert.equal(directionOf('staff', 'SC_STF_19'), 'keep');
  assert.equal(directionOf('students', 'SC_STU_21'), null); // AI, not Dream Big
});

test('each response lands in exactly one corpus', () => {
  assert.equal(corpusOf({ question_id: 'SC_STU_19', domain: 'dream_big', rating: 0, followup_text: 'better food' }, 'students'), 'volunteered');
  assert.equal(corpusOf({ question_id: 'SC_STU_21', domain: 'ai_readiness', rating: 0, followup_text: 'it helps' }, 'students'), 'ai_open');
  assert.equal(corpusOf({ question_id: 'SC_STU_02', domain: 'safety', rating: 3, followup_text: 'drills' }, 'students'), 'elaborated');
  // no words, a skip, a placeholder rating, a conversational turn: not an answer
  assert.equal(corpusOf({ question_id: 'SC_STU_02', rating: 3, followup_text: '' }, 'students'), null);
  assert.equal(corpusOf({ question_id: 'SC_STU_02', rating: 3, followup_text: '[skipped]' }, 'students'), null);
  assert.equal(corpusOf({ question_id: 'SC_STU_02', rating: 0, followup_text: 'words' }, 'students'), null);
  assert.equal(corpusOf({ question_id: 'turn_4', rating: 3, followup_text: 'words' }, 'students'), null);
});

test('a Dream Big answer stored under `text` is still read', () => {
  assert.equal(corpusOf({ question_id: 'SC_TCH_20', domain: 'dream_big', text: 'the community' }, 'teachers'), 'volunteered');
});

test('fabricated transcriptions are recognised, ordinary accents are not', () => {
  assert.ok(looksFabricated('Спокойной ночи.'));
  assert.ok(looksFabricated('Emanações são as justificações na galinha.'));
  assert.ok(!looksFabricated('Our café has a good jalapeño dip.'));
});

test('a label id is per school, per taxonomy version, per response', () => {
  assert.equal(labelId('pps-2026-27', 'sclstu-1__SC_STU_19'), 'pps-2026-27__spine-v1__sclstu-1__SC_STU_19');
});

test('prompts carry every answer under its key, and the AI prompt carries ratings only when rated', () => {
  const v = volunteeredPrompt({ questionText: 'What would you change?', direction: 'change', extensions: [], items: [{ key: 'a1', text: 'more study halls' }] });
  assert.match(v, /\[a1\] more study halls/);
  assert.match(v, /CHANGED/);
  const p = pointsPrompt({ questionText: 'This school is prepared to handle an emergency.', corpus: 'elaborated', extensions: [], items: [{ key: 'b1', rating: 4, text: 'we do drills' }] });
  assert.match(p, /\[b1\] \(rated 4\) we do drills/);
  const ai = pointsPrompt({ questionText: 'Where could AI help?', corpus: 'ai_open', extensions: [], items: [{ key: 'c1', rating: 0, text: 'homework' }] });
  assert.match(ai, /\[c1\] homework/);
  assert.doesNotMatch(ai, /\(rated/);
});

test('model JSON is read through a code fence and rejected when broken', () => {
  assert.deepEqual(parseModelJson('```json\n{"labels":[]}\n```').value, { labels: [] });
  assert.equal(parseModelJson('Here you go: {"labels": [').ok, false);
  assert.equal(parseModelJson('no json at all').ok, false);
});

test('volunteered: unknown themes are dropped, never guessed, and reported', () => {
  const r = validateVolunteered({
    new_themes: [{ id: 'community size', label: 'Community & school size', description: 'small school' }],
    labels: [
      { key: 'a', codable: true, themes: ['food', 'x_community_size'], led: 'x_community_size' },
      { key: 'b', codable: true, themes: ['cafeteria'], led: 'cafeteria' },
      { key: 'c', codable: false, themes: ['food'], led: 'food' },
    ],
  }, ['a', 'b', 'c', 'd']);
  assert.deepEqual(r.added.map(t => t.id), ['x_community_size']);
  assert.deepEqual(r.labels.get('a'), { codable: true, themes: ['food', 'x_community_size'], led: 'x_community_size' });
  // nothing valid left: uncodable rather than an invented theme
  assert.deepEqual(r.labels.get('b'), { codable: false, themes: [], led: null });
  assert.deepEqual(r.labels.get('c'), { codable: false, themes: [], led: null });
  assert.deepEqual(r.missing, ['d']);
  assert.ok(r.problems.some(p => /cafeteria/.test(p)));
});

test('volunteered: led must be one of the answer\'s own themes', () => {
  const r = validateVolunteered({ labels: [{ key: 'a', themes: ['food', 'time'], led: 'bullying' }] }, ['a']);
  assert.equal(r.labels.get('a').led, 'food');
});

test('volunteered: an extension that already exists is reused, not added twice', () => {
  const r = validateVolunteered(
    { new_themes: [{ id: 'x_community_size', label: 'Community' }], labels: [{ key: 'a', themes: ['x_community_size'] }] },
    ['a'], [{ id: 'x_community_size', label: 'Community & school size' }],
  );
  assert.deepEqual(r.added, []);
  assert.deepEqual(r.labels.get('a').themes, ['x_community_size']);
});

test('points: only defined points survive, and duplicate keys are ignored', () => {
  const r = validatePoints({
    points: [{ id: 'p1', label: 'fire and tornado drills' }, { id: 'p2', label: 'construction' }],
    labels: [
      { key: 'a', codable: true, theme: 'safety', points: ['p1', 'p9'] },
      { key: 'a', codable: true, theme: 'safety', points: ['p2'] },
      { key: 'b', codable: true, theme: 'nonsense', points: ['p2'] },
    ],
  }, ['a', 'b']);
  assert.deepEqual(r.labels.get('a'), { codable: true, points: ['p1'], theme: 'safety' });
  assert.deepEqual(r.labels.get('b'), { codable: true, points: ['p2'], theme: null });
  assert.ok(r.problems.some(p => /duplicate/.test(p)));
});

const L = (o) => ({ codable: true, excluded: null, review: { status: 'accepted' }, ...o });

test('tally: people, not mentions; volunteered ranked by people then by who led with it', () => {
  const labels = [
    L({ corpus: 'volunteered', direction: 'change', session_id: 's1', role: 'students', themes: ['food', 'time'], led: 'food' }),
    L({ corpus: 'volunteered', direction: 'change', session_id: 's2', role: 'students', themes: ['time'], led: 'time' }),
    L({ corpus: 'volunteered', direction: 'change', session_id: 's3', role: 'parents', themes: ['curriculum', 'time'], led: 'curriculum' }),
    L({ corpus: 'volunteered', direction: 'change', session_id: 's4', role: 'teachers', codable: false, themes: [], led: null }),
    L({ corpus: 'volunteered', direction: 'keep', session_id: 's1', role: 'students', themes: ['belonging'], led: 'belonging' }),
  ];
  const t = tally(labels);
  const change = t.volunteered.change;
  assert.equal(change.answers, 4);
  assert.equal(change.coded_people, 3);
  assert.equal(change.not_codable, 1);
  assert.deepEqual(change.themes.map(x => [x.id, x.people, x.led]), [['time', 3, 1], ['curriculum', 1, 1], ['food', 1, 1]]);
  assert.deepEqual(change.themes[0].roles, { students: 2, parents: 1 });
  assert.deepEqual(t.volunteered.keep.themes.map(x => x.id), ['belonging']);
});

test('tally: follow-up points are counted per question, split by the rating given', () => {
  const defs = { p1: 'fire and tornado drills' };
  const labels = [
    L({ corpus: 'elaborated', role: 'students', question_id: 'SC_STU_02', rating: 4, points: ['p1'], point_defs: defs }),
    L({ corpus: 'elaborated', role: 'students', question_id: 'SC_STU_02', rating: 3, points: ['p1'], point_defs: defs }),
    L({ corpus: 'elaborated', role: 'students', question_id: 'SC_STU_02', rating: 2, points: ['p1'], point_defs: defs }),
    L({ corpus: 'elaborated', role: 'students', question_id: 'SC_STU_02', rating: 3, points: [], codable: false }),
  ];
  const q = tally(labels).by_question['students|SC_STU_02'];
  assert.equal(q.answers, 4);
  assert.equal(q.coded, 3);
  assert.deepEqual(q.points, [{ id: 'p1', label: 'fire and tornado drills', n: 3, agreed: 2, disagreed: 1 }]);
});

test('tally: review progress counts every label; only accepted or edited count as reviewed', () => {
  const t = tally([
    L({ corpus: 'volunteered', direction: 'keep', session_id: 'a', role: 'students', themes: ['food'], led: 'food' }),
    L({ corpus: 'volunteered', direction: 'keep', session_id: 'b', role: 'students', themes: ['food'], led: 'food', review: { status: 'unreviewed' } }),
    L({ corpus: 'volunteered', direction: 'keep', session_id: 'c', role: 'students', themes: ['food'], led: 'food', review: { status: 'edited' } }),
  ]);
  assert.deepEqual(t.progress, { total: 3, reviewed: 2, unreviewed: 1 });
  assert.ok(!isReviewed({ review: { status: 'unreviewed' } }));
});

test('tally: excluded (fabricated) answers are never counted toward a theme', () => {
  const t = tally([
    L({ corpus: 'volunteered', direction: 'change', session_id: 'a', role: 'students', themes: ['food'], led: 'food', excluded: 'fabricated' }),
  ]);
  assert.equal(t.volunteered.change.coded_people, 0);
  assert.deepEqual(t.volunteered.change.themes, []);
});

test('points: a second pass reuses the first pass\'s point ids, and the prompt lists them', () => {
  const existing = [{ id: 'p1', label: 'fire and tornado drills' }];
  const prompt = pointsPrompt({ questionText: 'Prepared for an emergency.', corpus: 'elaborated', extensions: [], items: [{ key: 'z', rating: 3, text: 'drills' }], existingPoints: existing });
  assert.match(prompt, /- p1: fire and tornado drills/);
  const r = validatePoints({ points: [{ id: 'p2', label: 'construction' }], labels: [{ key: 'z', theme: 'safety', points: ['p1', 'p2'] }] }, ['z'], [], existing);
  assert.deepEqual(r.labels.get('z').points, ['p1', 'p2']);
  assert.deepEqual(r.points, [{ id: 'p2', label: 'construction' }]); // only the new one is returned as new
});
