/**
 * The rules that stop an unauthenticated climate write.
 *
 * The regression these exist for: /log_response accepted school-climate
 * answers with no token, and took school_id from the request body, so a valid
 * token for one school could write answers attributed to another and no token
 * at all still wrote.
 *
 * The non-climate cases matter as much as the climate ones. /log_response also
 * carries superintendent_interview and find_my_purpose, neither of which has a
 * token — if this guard ever stops skipping those, the administrator interview
 * and FMP break on deploy.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateClimateWrite, isClimateSection, CLIMATE_SECTIONS, ROLE_SECTION } from './climateTokenGuard.js';

const active = (over = {}) => ({
  token: 'SCL-ABC123',
  status: 'active',
  role: 'student',
  school_id: 'pleasanton-public-schools',
  school_name: 'Pleasanton Public Schools',
  district: 'Pleasanton',
  ...over,
});

const climate = (over = {}) =>
  evaluateClimateWrite({ section: 'school_climate_students', token: 'SCL-ABC123', ...over });

// ── the sections this guard must not touch ───────────────────────────────────

test('non-climate sections are skipped, so the administrator interview still writes', () => {
  for (const section of ['superintendent_interview', 'find_my_purpose', 'find_my_purpose_s2',
                         'edscls_safety', 'dream_big']) {
    const r = evaluateClimateWrite({ section, token: undefined, record: null });
    assert.equal(r.action, 'skip', `${section} must be skipped, not gated`);
  }
});

test('a missing or malformed section is skipped rather than rejected', () => {
  // /log_response validates the section itself; this guard should not become a
  // second, differently-worded validator of the same field.
  for (const section of [undefined, null, '', 42, 'nonsense']) {
    assert.equal(evaluateClimateWrite({ section, token: 'X', record: null }).action, 'skip');
  }
});

test('all four climate sections are governed', () => {
  assert.equal(CLIMATE_SECTIONS.size, 4);
  for (const section of CLIMATE_SECTIONS) assert.ok(isClimateSection(section));
  // Every role the token generator accepts maps to a governed section.
  for (const section of Object.values(ROLE_SECTION)) assert.ok(CLIMATE_SECTIONS.has(section));
});

// ── no token ─────────────────────────────────────────────────────────────────

test('a climate write with no token is refused', () => {
  for (const token of [undefined, null, '', '   ']) {
    const r = climate({ token, record: active() });
    assert.equal(r.action, 'reject');
    assert.equal(r.status, 401);
  }
});

// ── bad token ────────────────────────────────────────────────────────────────

test('an unknown token is refused', () => {
  const r = climate({ record: null });
  assert.equal(r.action, 'reject');
  assert.equal(r.status, 403);
  assert.match(r.error, /not found/i);
});

test('a token that is not active is refused', () => {
  for (const status of ['expired', 'revoked', 'inactive', undefined]) {
    const r = climate({ record: active({ status }) });
    assert.equal(r.action, 'reject', `status=${status} must be refused`);
    assert.equal(r.status, 403);
  }
});

test('a token for another role cannot write this survey', () => {
  const r = climate({ record: active({ role: 'teacher' }) });
  assert.equal(r.action, 'reject');
  assert.equal(r.status, 403);
  assert.match(r.error, /different survey/i);
});

test('every role is held to its own section', () => {
  for (const [role, section] of Object.entries(ROLE_SECTION)) {
    assert.equal(
      evaluateClimateWrite({ section, token: 'SCL-ABC123', record: active({ role }) }).action,
      'allow', `${role} must be able to write ${section}`);
    for (const other of Object.values(ROLE_SECTION)) {
      if (other === section) continue;
      assert.equal(
        evaluateClimateWrite({ section: other, token: 'SCL-ABC123', record: active({ role }) }).action,
        'reject', `${role} must not be able to write ${other}`);
    }
  }
});

test('a token with no role is accepted, so older links keep working', () => {
  const r = climate({ record: active({ role: undefined }) });
  assert.equal(r.action, 'allow');
});

test('a token with no school is refused rather than stored as unknown', () => {
  for (const school_id of [undefined, '', '   ']) {
    const r = climate({ record: active({ school_id }) });
    assert.equal(r.action, 'reject');
    assert.equal(r.status, 403);
  }
});

// ── the school comes from the token, never the body ──────────────────────────

test('the school is taken from the token record', () => {
  const r = climate({ record: active() });
  assert.equal(r.action, 'allow');
  assert.deepEqual(r.school, {
    school_id: 'pleasanton-public-schools',
    school_name: 'Pleasanton Public Schools',
    district: 'Pleasanton',
    role: 'student',
  });
});

test('a valid token cannot write answers attributed to another school', () => {
  // This is the case token validation alone does not cover: the caller supplies
  // school_id in the body, so the guard has to return the authoritative value
  // and the handler has to use it.
  const r = evaluateClimateWrite({
    section: 'school_climate_students',
    token: 'SCL-ABC123',
    record: active({ school_id: 'school-a' }),
  });
  assert.equal(r.school.school_id, 'school-a');
  assert.notEqual(r.school.school_id, 'school-b');
});

test('token whitespace does not defeat the presence check', () => {
  assert.equal(climate({ token: '  SCL-ABC123  ', record: active() }).action, 'allow');
});

test('absent optional fields come back undefined, not empty strings', () => {
  const r = climate({ record: active({ school_name: undefined, district: undefined }) });
  assert.equal(r.school.school_name, undefined);
  assert.equal(r.school.district, undefined);
});
