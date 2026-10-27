/**
 * Server-side enforcement of the school-climate survey token.
 *
 * WHY THIS EXISTS
 *
 * Until now the token was checked only in the browser. The client called
 * GET /school-climate/token/:token, and if that succeeded it rendered the
 * interview. /log_response — the route every climate answer is written through
 * — was guarded by rateLimit and requireAccessKey and nothing else.
 *
 * requireAccessKey checks CLARITY_ACCESS_KEY, which ships to every browser as
 * NEXT_PUBLIC_CLARITY_KEY and is therefore public. So the write path was
 * effectively unauthenticated: anyone reading the page source could post
 * responses, as any role, in any section, attributed to any school_id — the
 * handler took school_id straight from the request body.
 *
 * That is also the explanation for the orphan write seen on 2026-10-08, with a
 * blank token and blank organisation in the trace and answers stored anyway.
 * There was no bypass to find. There was no server-side check to bypass.
 *
 * The token was already on the wire and already stored (the handler does
 * `if (req.body.token) doc.token = ...`); it was simply never validated. So
 * enforcement needs no client change and no coordinated deploy.
 *
 * WHAT IT ENFORCES
 *
 *   1. A climate write must carry a token.
 *   2. The token must exist and be active.
 *   3. The token's role must match the section being written.
 *   4. school_id, school_name and district come from the TOKEN RECORD, never
 *      from the body. Without this, token validation alone still lets a valid
 *      token for one school write answers attributed to another.
 *
 * WHAT IT DELIBERATELY DOES NOT TOUCH
 *
 * /log_response also carries superintendent_interview, find_my_purpose and
 * find_my_purpose_s2, none of which use SCL- tokens. Blanket enforcement would
 * break the administrator interview and FMP on deploy. isClimateSection() is
 * the whole scope of this guard, and 'skip' is the answer for everything else.
 */

/** The sections this guard governs. Everything else is none of its business. */
export const CLIMATE_SECTIONS = new Set([
  'school_climate_students',
  'school_climate_teachers',
  'school_climate_staff',
  'school_climate_parents',
]);

/**
 * A token is minted for one role. Writing student answers on a teacher's token
 * is not a thing a real interview does, and allowing it would let one leaked
 * link pollute every role in a school.
 */
export const ROLE_SECTION = {
  student: 'school_climate_students',
  teacher: 'school_climate_teachers',
  staff:   'school_climate_staff',
  parent:  'school_climate_parents',
};

export function isClimateSection(section) {
  return typeof section === 'string' && CLIMATE_SECTIONS.has(section);
}

/**
 * Decide what to do with one climate write.
 *
 * Pure on purpose: the Firestore read lives in server.js, the rules live here,
 * and the rules are what the tests cover.
 *
 * @param {object}  args
 * @param {string}  args.section  the section from the request body
 * @param {string}  args.token    the token from the request body, if any
 * @param {object?} args.record   the climate_tokens document data, or null if
 *                                no such token exists
 * @returns {{action: 'skip'|'allow'|'reject', status?: number, error?: string,
 *            school?: {school_id: string, school_name?: string, district?: string, role?: string}}}
 */
export function evaluateClimateWrite({ section, token, record }) {
  if (!isClimateSection(section)) return { action: 'skip' };

  const t = typeof token === 'string' ? token.trim() : '';
  if (!t) {
    return {
      action: 'reject',
      status: 401,
      error: 'A survey token is required. Please use the link provided by your school coordinator.',
    };
  }

  if (!record) {
    return { action: 'reject', status: 403, error: 'Token not found.' };
  }

  // Mirrors GET /school-climate/token/:token, which 404s on anything but active.
  if (record.status !== 'active') {
    return { action: 'reject', status: 403, error: 'Token has expired or been deactivated.' };
  }

  // A token minted before role was recorded has no role to check against;
  // accept it rather than locking out historical links.
  if (record.role) {
    const expected = ROLE_SECTION[record.role];
    if (expected && expected !== section) {
      return {
        action: 'reject',
        status: 403,
        error: 'This token is for a different survey.',
      };
    }
  }

  const schoolId = typeof record.school_id === 'string' ? record.school_id.trim() : '';
  if (!schoolId) {
    // Every token the generator writes carries one, so this means a hand-edited
    // or partially written record. Refusing is better than storing 'unknown'
    // and discovering it in a report.
    return { action: 'reject', status: 403, error: 'Token is not attached to a school.' };
  }

  return {
    action: 'allow',
    school: {
      school_id: schoolId,
      school_name: typeof record.school_name === 'string' ? record.school_name.trim() : undefined,
      district: typeof record.district === 'string' ? record.district.trim() : undefined,
      role: record.role || undefined,
    },
  };
}
