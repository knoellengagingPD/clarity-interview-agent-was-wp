import { supabaseUpsert } from './supabase.js';

export async function writeSessionToSupabase(sessionData) {
  const {
    sessionId,
    deploymentId,
    schoolId,
    role,
    responseMode,
    token,
    isTest,
    startedAt,
    completedAt,
    ratedResponses,
    dreamBigResponses
  } = sessionData;

  try {
    // Validate required fields
    if (!sessionId || !deploymentId || !schoolId || !role) {
      console.error('[Supabase] Missing required fields — skipping write', { sessionId, deploymentId, schoolId, role });
      return { success: false, reason: 'missing_required_fields' };
    }

    // Validate role
    const validRoles = ['student', 'teacher', 'staff', 'parent', 'administrator'];
    if (!validRoles.includes(role)) {
      console.error('[Supabase] Invalid role — skipping write', { role });
      return { success: false, reason: 'invalid_role' };
    }

    // Filter rated responses — only accept ratings 1-4
    const validRated = (ratedResponses || []).filter(r =>
      r.questionId &&
      r.domain &&
      typeof r.rating === 'number' &&
      r.rating >= 1 &&
      r.rating <= 4
    );

    // Filter dream big responses — must have response or followup text
    const validDreamBig = (dreamBigResponses || []).filter(r =>
      r.questionId &&
      (r.responseText || r.followupText)
    );

    // 1. Write session row
    await supabaseUpsert('sessions', {
      id: sessionId,
      deployment_id: deploymentId,
      school_id: schoolId,
      role,
      response_mode: responseMode || 'voice',
      token: token || null,
      status: 'completed',
      rated_question_count: validRated.length,
      dream_big_question_count: validDreamBig.length,
      started_at: startedAt || null,
      completed_at: completedAt || new Date().toISOString(),
      is_test: isTest || false
    }, 'id');

    // 2. Write rated responses
    if (validRated.length > 0) {
      const ratedRows = validRated.map(r => ({
        session_id: sessionId,
        deployment_id: deploymentId,
        question_id: r.questionId,
        role,
        domain: r.domain,
        rating: r.rating,
        followup_text: r.followupText || null,
        response_mode: responseMode || 'voice'
      }));

      await supabaseUpsert('rated_responses', ratedRows, 'session_id,question_id');
    }

    // 3. Write dream big responses
    if (validDreamBig.length > 0) {
      const dreamBigRows = validDreamBig.map(r => ({
        session_id: sessionId,
        deployment_id: deploymentId,
        question_id: r.questionId,
        role,
        prompt_text: r.promptText || '',
        response_text: r.responseText || null,
        followup_text: r.followupText || null,
        word_count: r.responseText ? r.responseText.split(' ').filter(Boolean).length : 0,
        response_mode: responseMode || 'voice'
      }));

      await supabaseUpsert('dream_big_responses', dreamBigRows, 'session_id,question_id');
    }

    console.log('[Supabase] Session written successfully', {
      sessionId,
      ratedCount: validRated.length,
      dreamBigCount: validDreamBig.length
    });

    return { success: true };

  } catch (err) {
    console.error('[Supabase] Unexpected error in writeSessionToSupabase:', err.message || err);
    return { success: false, reason: 'unexpected_error', error: err.message };
  }
}

// Workplace writes to its own tables (workplace_sessions / workplace_rated_responses /
// workplace_dream_big_responses) rather than the school-climate tables above. The
// school-climate `role` column already uses 'staff' for K-12 non-instructional staff,
// and Workplace also logs its single participant role as 'staff' — reusing the shared
// tables would make Workplace and School Climate rows indistinguishable from each
// other in the same role bucket. Isolated tables sidestep that collision and match
// this codebase's existing convention of isolated Firestore collections for Workplace.
export async function writeWorkplaceSessionToSupabase(sessionData) {
  const {
    sessionId,
    deploymentId,
    organizationId,
    role,
    responseMode,
    token,
    isTest,
    startedAt,
    completedAt,
    ratedResponses,
    dreamBigResponses
  } = sessionData;

  try {
    if (!sessionId || !deploymentId || !organizationId || !role) {
      console.error('[Supabase] Workplace: missing required fields — skipping write', { sessionId, deploymentId, organizationId, role });
      return { success: false, reason: 'missing_required_fields' };
    }

    if (role !== 'staff') {
      console.error('[Supabase] Workplace: invalid role — skipping write', { role });
      return { success: false, reason: 'invalid_role' };
    }

    // Workplace ratings are all 1-4 (Q10's health item was collapsed to 4 points
    // for this reason), so the same 1-4 bound used for school-climate applies.
    const validRated = (ratedResponses || []).filter(r =>
      r.questionId &&
      r.domain &&
      typeof r.rating === 'number' &&
      r.rating >= 1 &&
      r.rating <= 4
    );

    const validDreamBig = (dreamBigResponses || []).filter(r =>
      r.questionId &&
      (r.responseText || r.followupText)
    );

    await supabaseUpsert('workplace_sessions', {
      id: sessionId,
      deployment_id: deploymentId,
      organization_id: organizationId,
      role,
      response_mode: responseMode || 'voice',
      token: token || null,
      status: 'completed',
      rated_question_count: validRated.length,
      dream_big_question_count: validDreamBig.length,
      started_at: startedAt || null,
      completed_at: completedAt || new Date().toISOString(),
      is_test: isTest || false
    }, 'id');

    if (validRated.length > 0) {
      const ratedRows = validRated.map(r => ({
        session_id: sessionId,
        deployment_id: deploymentId,
        question_id: r.questionId,
        role,
        domain: r.domain,
        rating: r.rating,
        followup_text: r.followupText || null,
        response_mode: responseMode || 'voice'
      }));

      await supabaseUpsert('workplace_rated_responses', ratedRows, 'session_id,question_id');
    }

    if (validDreamBig.length > 0) {
      const dreamBigRows = validDreamBig.map(r => ({
        session_id: sessionId,
        deployment_id: deploymentId,
        question_id: r.questionId,
        role,
        prompt_text: r.promptText || '',
        response_text: r.responseText || null,
        followup_text: r.followupText || null,
        word_count: r.responseText ? r.responseText.split(' ').filter(Boolean).length : 0,
        response_mode: responseMode || 'voice'
      }));

      await supabaseUpsert('workplace_dream_big_responses', dreamBigRows, 'session_id,question_id');
    }

    console.log('[Supabase] Workplace session written successfully', {
      sessionId,
      ratedCount: validRated.length,
      dreamBigCount: validDreamBig.length
    });

    return { success: true };

  } catch (err) {
    console.error('[Supabase] Unexpected error in writeWorkplaceSessionToSupabase:', err.message || err);
    return { success: false, reason: 'unexpected_error', error: err.message };
  }
}
