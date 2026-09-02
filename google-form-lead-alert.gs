/**
 * Clarity 360 — email alert for Google Form lead submissions.
 *
 * NOT part of the backend deploy. This is Google Apps Script, and it lives
 * inside the Google Form itself. Kept in the repo so the funnel is documented
 * in the same place as the code that feeds it.
 *
 * The built-in Forms notification ("Get email notifications for new responses")
 * tells you a response arrived and nothing else, so every lead costs a trip to
 * the form before you know whether it is a 40,000-student district or a
 * curious teacher. This sends the answers, so the alert IS the triage.
 *
 * ── SETUP ─────────────────────────────────────────────────────────────────
 *
 *  1. Open the form: https://forms.gle/H8R8SxS4WsZ4Vzgw6
 *  2. Three-dot menu (top right, next to Send) -> Apps Script
 *  3. Delete the placeholder myFunction(), paste this whole file, Save
 *  4. In the left sidebar click Triggers (the alarm clock icon)
 *  5. Add Trigger:
 *        Function to run          onFormSubmit
 *        Event source             From form
 *        Event type               On form submit
 *  6. Save. Google asks you to authorise it — that is the script asking for
 *     permission to read responses and send mail as you. Review and Allow.
 *  7. Submit a test response to the form and confirm the email arrives.
 *
 * Step 7 is not optional. An alert you have not seen fire is not an alert,
 * it is an assumption — and a silent one, since a lead that never arrives
 * looks exactly like no lead at all.
 */

/** Where alerts go. */
const ALERT_TO = 'knoell@engagingpd.com';

/** Fields to surface in the subject line, in order of preference. */
const SUBJECT_FIELDS = ['Name of School District', 'Name / Role', 'Email'];

function onFormSubmit(e) {
  try {
    const responses = e.response.getItemResponses();

    // title -> answer, so the subject line can look fields up by name and the
    // body can still print everything in the order the form asks it.
    const byTitle = {};
    const ordered = [];
    responses.forEach(function (item) {
      const title = item.getItem().getTitle();
      let answer = item.getResponse();
      if (Array.isArray(answer)) answer = answer.join(', ');
      byTitle[title] = answer;
      ordered.push({ title: title, answer: answer });
    });

    // A subject worth reading on a phone: district first, then who sent it.
    let label = '';
    for (var i = 0; i < SUBJECT_FIELDS.length; i++) {
      if (byTitle[SUBJECT_FIELDS[i]]) { label = byTitle[SUBJECT_FIELDS[i]]; break; }
    }
    const subject = 'Clarity 360 lead' + (label ? ' — ' + label : '');

    var body = 'A new response came in from the Clarity School Climate form.\n\n';
    ordered.forEach(function (f) {
      body += f.title + '\n' + (f.answer || '(blank)') + '\n\n';
    });
    body += '---\n';
    body += 'Submitted ' + new Date().toLocaleString() + '\n';
    body += 'Edit responses: ' + FormApp.getActiveForm().getEditUrl() + '\n';

    // Reply-To set to the lead's own address, so replying from your phone
    // goes to them rather than back to you.
    const options = { name: 'Clarity 360' };
    if (byTitle['Email']) options.replyTo = byTitle['Email'];

    MailApp.sendEmail(ALERT_TO, subject, body, options);
  } catch (err) {
    // Never let a formatting mistake swallow a lead. If anything above fails,
    // send the raw response rather than nothing at all.
    MailApp.sendEmail(
      ALERT_TO,
      'Clarity 360 lead — alert script errored',
      'The lead WAS recorded in the form; only this email failed.\n\n'
        + 'Error: ' + err + '\n\n'
        + 'Open the form to read it: https://forms.gle/H8R8SxS4WsZ4Vzgw6\n'
    );
  }
}
