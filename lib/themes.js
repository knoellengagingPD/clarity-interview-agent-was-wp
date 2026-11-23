/**
 * The theme layer: label every open answer, count the labels in code, and
 * give the report a theme order it cannot get wrong.
 *
 * WHY
 *
 * The cross-role report ranks themes by how many people raised them, and the
 * model was doing that counting itself across ~250 answers. It cannot. On
 * 2026-11-21 it opened "what respondents want changed" with discipline and
 * bullying -- raised unprompted by 5 and 3 people -- and left out course
 * offerings, which 21 people raised across all four groups. The 2026-11-18
 * hand tally (export-pps-2026-27/theme-tally-2026-11-18.md) is the proof of
 * concept for this file; its counts survived, its per-response labels did
 * not, so nothing it said could be audited. Here every label is stored with
 * the answer it describes, reviewed by a person, and counted by code.
 *
 * DECISIONS THIS FOLLOWS (CLARITY360-HANDOFF.md section 2)
 *
 *   - Fixed spine + district extensions. Compare on the spine; report with
 *     the extensions. Extensions are created freely during labelling.
 *   - The raw response is stored alongside every label, and the taxonomy is
 *     versioned exactly as the instrument is.
 *   - Volunteered (Dream Big) and elaborated (rated follow-ups) are counted
 *     separately and never pooled. Theme order comes from volunteered only.
 *   - Review before use: a count reaches a report only when every label behind
 *     it has been looked at by a person (decided 2026-11-23).
 *
 * Follow-ups get a spine theme AND a point grouped per question -- "drills"
 * under emergency preparedness -- because a pattern inside a high-agreement
 * item (33 students who agreed, explaining their answer by the drills) is
 * invisible at theme level and invisible to any sample.
 */

export const TAXONOMY_VERSION = 'spine-v1';

/**
 * Draft spine v1, from the Pleasanton hand-label pass. Validate against
 * district 2 before freezing. Written to work in both directions -- what
 * people want kept and what they want changed.
 */
export const SPINE_V1 = [
  { id: 'teaching', label: 'Teaching & instruction', description: 'quality of teaching, teacher conduct and care in class, feedback, expectations' },
  { id: 'curriculum', label: 'Curriculum & pathways', description: 'courses, rigour, college classes, work study, electives' },
  { id: 'time', label: 'Time, schedule & workload', description: 'daily schedule, passing periods, study halls, homework load' },
  { id: 'food', label: 'Food service', description: 'lunch quality, quantity, cost' },
  { id: 'facilities', label: 'Facilities & space', description: 'buildings, construction, classrooms, grounds, parking' },
  { id: 'technology', label: 'Technology & devices', description: 'computers, Chromebooks, wifi, software' },
  { id: 'activities', label: 'Activities & athletics', description: 'sports, clubs, FFA, band, extracurriculars' },
  { id: 'belonging', label: 'Belonging, inclusion & peer culture', description: 'friendships, kindness, inclusion, how students treat each other' },
  { id: 'discipline', label: 'Discipline & fairness', description: 'consequences, consistency, favouritism' },
  { id: 'bullying', label: 'Bullying', description: 'bullying in person or online and how it is handled' },
  { id: 'safety', label: 'Safety & security', description: 'physical safety, drills, emergency preparedness, supervision' },
  { id: 'staffing', label: 'Staffing & individual support', description: 'class size, special education, intervention, tutoring' },
  { id: 'working_conditions', label: 'Staff working conditions', description: 'prep time, professional development, budgets, autonomy' },
  { id: 'leadership', label: 'Leadership & administration', description: 'principal, superintendent, administrators, how decisions are made' },
  { id: 'communication', label: 'Communication & voice', description: 'school-to-home communication, communication among staff, student input' },
];

export const SPINE_IDS = new Set(SPINE_V1.map(t => t.id));

/**
 * The open questions, by role. In every role the first asks what to change,
 * the second what to keep, the third about AI (CLIMATE_OPEN_IDS in the
 * dashboard's questionMaps.ts).
 */
export const OPEN_QUESTIONS = {
  students: { change: 'SC_STU_19', keep: 'SC_STU_20', ai: 'SC_STU_21' },
  teachers: { change: 'SC_TCH_19', keep: 'SC_TCH_20', ai: 'SC_TCH_21' },
  staff:    { change: 'SC_STF_18', keep: 'SC_STF_19', ai: 'SC_STF_20' },
  parents:  { change: 'SC_PAR_17', keep: 'SC_PAR_18', ai: 'SC_PAR_19' },
};

/** 'change' | 'keep' for a Dream Big question, else null. */
export function directionOf(role, questionId) {
  const q = OPEN_QUESTIONS[role];
  if (!q) return null;
  if (q.change === questionId) return 'change';
  if (q.keep === questionId) return 'keep';
  return null;
}

/* Same test as export-school.mjs and the dashboard's quoteRefs.ts. */
const FOREIGN_SCRIPT = /[Ѐ-ӿͰ-Ͽ֐-׿؀-ۿ一-鿿぀-ヿऀ-ॿ]/;
const DIACRITIC = /[À-ÿĀ-ɏ]/g;
export function looksFabricated(t) {
  if (!t) return false;
  if (FOREIGN_SCRIPT.test(t)) return true;
  const h = t.match(DIACRITIC);
  return h !== null && h.length >= 3;
}

/** The text of a response document, in export-school.mjs's field order. */
export const textOf = (doc) => String(doc.followup_text ?? doc.text ?? '').trim();

/**
 * Which corpus a response document belongs to, or null if it is not an
 * answer anyone gave in words.
 *
 *   volunteered -- a Dream Big answer (change or keep)
 *   ai_open     -- an answer to the open AI question
 *   elaborated  -- the follow-up to a rated item
 */
export function corpusOf(doc, role) {
  const qid = doc.question_id ? String(doc.question_id) : '';
  if (!qid || /^turn_\d+$/.test(qid)) return null;
  const text = textOf(doc);
  if (!text || text === '[skipped]') return null;
  if (directionOf(role, qid)) return 'volunteered';
  if (OPEN_QUESTIONS[role]?.ai === qid) return 'ai_open';
  const r = Number(doc.rating);
  if (r >= 1 && r <= 4) return 'elaborated';
  return null;
}

export const labelId = (schoolId, responseId) => `${schoolId}__${TAXONOMY_VERSION}__${responseId}`;

/* ── prompts ─────────────────────────────────────────────────────────────── */

const spineList = (extensions = []) => [
  ...SPINE_V1.map(t => `- ${t.id}: ${t.label} (${t.description})`),
  ...extensions.map(t => `- ${t.id}: ${t.label} (${t.description || 'district extension'})`),
].join('\n');

/**
 * Prompt for one Dream Big question. Multi-label; `led` is the theme the
 * respondent raised first, the intensity signal the hand tally found was
 * enough on its own.
 */
export function volunteeredPrompt({ questionText, direction, extensions, items }) {
  return `You are labelling open answers from a school climate survey. Each answer below responds to this question:

"${questionText}"

These answers say what the respondent wants ${direction === 'keep' ? 'KEPT -- what the school does well and should never change' : 'CHANGED -- what would make the school better'}.

THEMES (use these ids):
${spineList(extensions)}

For every answer:
- themes: every theme the answer raises, as ids. An answer can raise several.
- led: the id of the theme the respondent raised FIRST. It must be one of its themes.
- codable: false when the answer is garbled transcription, names nothing ("nothing", "I don't know"), or cannot be read as an answer. Then themes is [] and led is null.

Only when no theme above fits a point the answer makes, add a new theme to "new_themes" with an id beginning "x_" (lowercase, underscores), a short label, and a one-line description, and use it. Do not add a theme that is a narrower version of one above: food is "food", not "x_lunch_portions". Reuse a new theme you have already added rather than adding a near-duplicate.

Label what the answer says, not what you infer. Do not count, summarise or comment.

Return JSON only, no prose, no code fence:
{"new_themes":[{"id":"x_...","label":"...","description":"..."}],"labels":[{"key":"<key>","codable":true,"themes":["..."],"led":"..."}]}

Every key below must appear exactly once in "labels".

ANSWERS:
${items.map(it => `[${it.key}] ${it.text}`).join('\n')}`;
}

/**
 * Prompt for one rated item's follow-ups, or one role's open AI answers.
 * The points are defined for this question and nowhere else, which is what
 * makes them consistent: the model sees every answer to the question at once.
 */
export function pointsPrompt({ questionText, corpus, extensions, items, existingPoints = [] }) {
  const rated = corpus === 'elaborated';
  const reuse = existingPoints.length
    ? `\n\nSome answers to this question were labelled earlier with these points. Use them wherever they fit, keeping their ids exactly, and add a new point only for something none of them covers:\n${existingPoints.map(p => `- ${p.id}: ${p.label}`).join('\n')}`
    : '';
  return `You are labelling answers from a school climate survey. Each answer below responds to this ${rated ? 'rated statement, and is the respondent explaining the rating they gave (1 = strongly disagree, 4 = strongly agree)' : 'open question'}:

"${questionText}"

First, define the POINTS: the specific things respondents raise in these answers, in a few words each ("fire and tornado drills", "construction makes exits unclear", "teachers know students by name"). Between 2 and 10 points, each raised by at least two answers. A point is concrete and specific to this question; it is not a sentiment ("positive", "agrees") and not a restatement of the question.${reuse}

Then, for every answer:
- points: the ids of every point it raises. [] if it raises none.
- theme: the one theme id below that the answer is most about, or null.
- codable: false when the answer is garbled transcription or says nothing beyond a rating ("yes", "I agree", "it's fine"). Then points is [] and theme is null.

THEMES:
${spineList(extensions)}

Label what the answer says, not what you infer. Do not count, summarise or comment.

Return JSON only, no prose, no code fence:
{"points":[{"id":"p1","label":"..."}],"labels":[{"key":"<key>","codable":true,"theme":"...","points":["p1"]}]}

Every key below must appear exactly once in "labels".

ANSWERS:
${items.map(it => `[${it.key}]${rated ? ` (rated ${it.rating})` : ''} ${it.text}`).join('\n')}`;
}

/* ── reading the model's answer ──────────────────────────────────────────── */

/** The JSON object in a model reply, tolerating a code fence around it. */
export function parseModelJson(text) {
  if (typeof text !== 'string') return { ok: false, error: 'no text' };
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end <= start) return { ok: false, error: 'no JSON object in reply' };
  try {
    return { ok: true, value: JSON.parse(text.slice(start, end + 1)) };
  } catch (e) {
    return { ok: false, error: `unparseable JSON: ${e.message}` };
  }
}

const slug = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 40);

/**
 * Check a volunteered reply against the keys that were sent. Every key must
 * come back once; theme ids must be spine, an existing extension, or one the
 * reply adds. Anything else is dropped and reported -- never guessed.
 */
export function validateVolunteered(value, keys, existingExtensions = []) {
  const problems = [];
  const added = [];
  const known = new Set([...SPINE_IDS, ...existingExtensions.map(t => t.id)]);
  for (const t of (value && Array.isArray(value.new_themes) ? value.new_themes : [])) {
    let id = slug(t && t.id);
    if (!id.startsWith('x_')) id = `x_${id}`;
    if (id === 'x_' || !t.label) { problems.push('a new theme without an id or label was ignored'); continue; }
    if (known.has(id)) continue;
    known.add(id);
    added.push({ id, label: String(t.label).slice(0, 60), description: String(t.description || '').slice(0, 160) });
  }
  const byKey = new Map();
  for (const l of (value && Array.isArray(value.labels) ? value.labels : [])) {
    if (!l || !keys.includes(l.key)) { problems.push(`label for an unknown key ${l && l.key} ignored`); continue; }
    if (byKey.has(l.key)) { problems.push(`duplicate label for ${l.key} ignored`); continue; }
    const codable = l.codable !== false;
    let themes = codable ? [...new Set((Array.isArray(l.themes) ? l.themes : []).map(String))] : [];
    const unknown = themes.filter(t => !known.has(t));
    if (unknown.length) problems.push(`${l.key}: unknown theme ${unknown.join(', ')} dropped`);
    themes = themes.filter(t => known.has(t));
    let led = codable && themes.includes(l.led) ? l.led : (themes[0] ?? null);
    byKey.set(l.key, { codable: codable && themes.length > 0, themes, led });
  }
  const missing = keys.filter(k => !byKey.has(k));
  if (missing.length) problems.push(`no label returned for ${missing.length} answer(s)`);
  return { labels: byKey, added, missing, problems };
}

/** Same for a points reply. Point ids are re-keyed per question. */
export function validatePoints(value, keys, existingExtensions = [], existingPoints = []) {
  const problems = [];
  const known = new Set([...SPINE_IDS, ...existingExtensions.map(t => t.id)]);
  const points = [];
  const pointIds = new Set(existingPoints.map(p => p.id));
  for (const p of (value && Array.isArray(value.points) ? value.points : []).slice(0, 12)) {
    const id = slug(p && p.id);
    if (!id || !p.label || pointIds.has(id)) continue;
    pointIds.add(id);
    points.push({ id, label: String(p.label).slice(0, 80) });
  }
  const byKey = new Map();
  for (const l of (value && Array.isArray(value.labels) ? value.labels : [])) {
    if (!l || !keys.includes(l.key)) { problems.push(`label for an unknown key ${l && l.key} ignored`); continue; }
    if (byKey.has(l.key)) { problems.push(`duplicate label for ${l.key} ignored`); continue; }
    const codable = l.codable !== false;
    const ps = codable ? [...new Set((Array.isArray(l.points) ? l.points : []).map(slug))].filter(id => pointIds.has(id)) : [];
    let theme = codable && l.theme != null ? String(l.theme) : null;
    if (theme && !known.has(theme)) { problems.push(`${l.key}: unknown theme ${theme} dropped`); theme = null; }
    byKey.set(l.key, { codable, points: ps, theme });
  }
  const missing = keys.filter(k => !byKey.has(k));
  if (missing.length) problems.push(`no label returned for ${missing.length} answer(s)`);
  return { labels: byKey, points, missing, problems };
}

/* ── counting ────────────────────────────────────────────────────────────── */

export const isReviewed = (l) => l && l.review && (l.review.status === 'accepted' || l.review.status === 'edited');

/**
 * Count the labels. Pure: takes label records, returns counts.
 *
 * People, not mentions: a respondent who answered the change question once is
 * one person however many themes the answer touched. Fabricated and uncodable
 * answers are reported as excluded, never counted toward a theme.
 */
export function tally(labels, extensions = []) {
  const themeLabel = new Map([...SPINE_V1, ...extensions].map(t => [t.id, t.label]));
  const out = {
    taxonomy_version: TAXONOMY_VERSION,
    progress: { total: 0, reviewed: 0, unreviewed: 0 },
    volunteered: {},
    by_question: {},
  };
  for (const l of labels) {
    out.progress.total++;
    if (isReviewed(l)) out.progress.reviewed++; else out.progress.unreviewed++;
  }

  for (const direction of ['change', 'keep']) {
    const rows = labels.filter(l => l.corpus === 'volunteered' && l.direction === direction);
    const coded = rows.filter(l => l.codable && !l.excluded);
    const people = new Set(coded.map(l => l.session_id));
    const themes = new Map();
    for (const l of coded) {
      for (const t of l.themes || []) {
        const e = themes.get(t) || { id: t, label: themeLabel.get(t) || t, people: new Set(), led: new Set(), roles: {} };
        e.people.add(l.session_id);
        if (l.led === t) e.led.add(l.session_id);
        e.roles[l.role] = (e.roles[l.role] || new Set()).add(l.session_id);
        themes.set(t, e);
      }
    }
    out.volunteered[direction] = {
      answers: rows.length,
      coded_people: people.size,
      not_codable: rows.filter(l => !l.codable || l.excluded).length,
      themes: [...themes.values()]
        .map(e => ({
          id: e.id, label: e.label, spine: SPINE_IDS.has(e.id),
          people: e.people.size, led: e.led.size,
          roles: Object.fromEntries(Object.entries(e.roles).map(([r, s]) => [r, s.size])),
        }))
        .sort((a, b) => b.people - a.people || b.led - a.led || a.label.localeCompare(b.label)),
    };
  }

  for (const l of labels) {
    if (l.corpus !== 'elaborated' && l.corpus !== 'ai_open') continue;
    const k = `${l.role}|${l.question_id}`;
    const q = out.by_question[k] || {
      role: l.role, question_id: l.question_id, question_text: l.question_text || '', corpus: l.corpus,
      answers: 0, coded: 0, points: {}, point_labels: l.point_defs || {},
    };
    q.answers++;
    if (l.codable && !l.excluded) {
      q.coded++;
      for (const p of l.points || []) {
        const e = q.points[p] || { id: p, label: (l.point_defs && l.point_defs[p]) || p, n: 0, agreed: 0, disagreed: 0 };
        e.n++;
        if (l.corpus === 'elaborated') { if (Number(l.rating) >= 3) e.agreed++; else e.disagreed++; }
        q.points[p] = e;
      }
    }
    out.by_question[k] = q;
  }
  for (const q of Object.values(out.by_question)) {
    q.points = Object.values(q.points).sort((a, b) => b.n - a.n || a.label.localeCompare(b.label));
    delete q.point_labels;
  }
  return out;
}

/* ── extensions: safe to update concurrently, recoverable, mergeable ─────── */

/**
 * Union by id, existing first. On 2026-11-23 two questions labelled at the
 * same moment each wrote "the list I read, plus mine", and the second write
 * erased the first's new theme ("x_phones" survived in its labels and nowhere
 * else). The server now applies this inside a transaction.
 */
export function mergeExtensions(existing = [], added = []) {
  const seen = new Set(existing.map(t => t.id));
  return [...existing, ...added.filter(t => !seen.has(t.id) && seen.add(t.id))];
}

/** "x_phones" -> "Phones", for a theme whose stored label was lost. */
export const humanizeThemeId = (id) => {
  const words = String(id).replace(/^x_/, '').split('_').filter(Boolean);
  return words.length ? words.map((w, i) => (i === 0 ? w[0].toUpperCase() + w.slice(1) : w)).join(' ') : String(id);
};

/**
 * The stored extensions plus any theme a label uses that neither the spine
 * nor the stored list knows -- so a lost extension is shown, counted and
 * mergeable instead of appearing as a bare id.
 */
export function withOrphans(extensions = [], labels = []) {
  const known = new Set([...SPINE_IDS, ...extensions.map(t => t.id)]);
  const orphans = [];
  for (const l of labels) {
    for (const id of [...(l.themes || []), l.led, l.theme]) {
      if (!id || known.has(id)) continue;
      known.add(id);
      orphans.push({ id, label: humanizeThemeId(id), description: 'recovered: its stored label was lost' });
    }
  }
  return [...extensions, ...orphans];
}

/**
 * One label with theme `from` replaced by `to`. Returns null when the label
 * does not use `from`. Review status is left alone: merging is a decision
 * about the taxonomy, not a review of this answer.
 */
export function applyThemeMerge(label, from, to) {
  const uses = (label.themes || []).includes(from) || label.led === from || label.theme === from;
  if (!uses) return null;
  const themes = [...new Set((label.themes || []).map(t => (t === from ? to : t)))];
  return {
    themes,
    led: label.led === from ? to : (label.led ?? null),
    theme: label.theme === from ? to : (label.theme ?? null),
    merged: [...(label.merged || []), { from, to }],
  };
}
