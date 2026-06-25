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
