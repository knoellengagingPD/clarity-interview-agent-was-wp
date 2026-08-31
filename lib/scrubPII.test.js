/**
 * Tests for PII scrubbing.
 *
 * Two failure modes matter here and they pull in opposite directions:
 *
 *   - a name reaching Firestore breaks a confidentiality promise
 *   - over-scrubbing destroys the qualitative data districts pay for
 *
 * So the "must NOT scrub" cases below are as important as the "must scrub"
 * ones. Several are taken verbatim from real 2026-08-27 exports.
 */

import test from 'node:test';
import assert from 'node:assert';
import { scrubPII, containsPII } from './scrubPII.js';

const scrubs = (input, expected, note) =>
  assert.strictEqual(scrubPII(input), expected, note || input);

const unchanged = (input) =>
  assert.strictEqual(scrubPII(input), input, `must not alter: ${input}`);

test('real examples from the 2026-08-27 exports', () => {
  scrubs(
    'Mr. Judd said our principal has worked very hard to craft rules and expectations that are clear.',
    '[Name Removed] said our principal has worked very hard to craft rules and expectations that are clear.',
  );
  scrubs(
    'Well, I could go to Mr. Johnson, I could go to Sue, or my partner teacher.',
    'Well, I could go to [Name Removed], I could go to [Name Removed], or my partner teacher.',
  );
  scrubs(
    'Mr. Johnson is very accommodating. When I go to him he listens.',
    '[Name Removed] is very accommodating. When I go to him he listens.',
  );
});

test('titles, with and without a period, one or two name words', () => {
  scrubs('Mrs. Smith is wonderful.', '[Name Removed] is wonderful.');
  scrubs('Mr Anderson never follows up.', '[Name Removed] never follows up.');
  scrubs('Dr. Maria Gonzalez runs the program.', '[Name Removed] runs the program.');
  scrubs('Principal Whitaker made the call.', '[Name Removed] made the call.');
  scrubs('Coach Roberts yells a lot.', '[Name Removed] yells a lot.');
  scrubs('Superintendent Lee visited once.', '[Name Removed] visited once.');
});

test('possessives stay readable', () => {
  scrubs("Mr. Johnson's class is the best part of my day.",
         "[Name Removed]'s class is the best part of my day.");
});

test('bare names in person-referring context', () => {
  scrubs('I talked to Karen about it.', 'I talked to [Name Removed] about it.');
  scrubs('I asked Dave and nothing happened.', 'I asked [Name Removed] and nothing happened.');
  scrubs('we went to Sue first.', 'we went to [Name Removed] first.');
  scrubs('but Marcus said it would be handled.', 'but [Name Removed] said it would be handled.');
});

test('emails and phone numbers', () => {
  scrubs('Email me at jane.doe@school.org anytime.', 'Email me at [email] anytime.');
  scrubs('Call 555-123-4567 to reach the office.', 'Call [phone] to reach the office.');
  scrubs('My number is (555) 987-6543.', 'My number is [phone].');
});

// ── The other half: data that must survive intact ──────────────────────────

test('school vocabulary is not mistaken for a person', () => {
  unchanged('I go to English class right after lunch.');
  unchanged('I talked to Student Services about the schedule.');
  unchanged('We went to Central High for the game.');
  unchanged('I asked Special Education for help.');
  unchanged('I could talk to Administration but it never helps.');
});

test('days and months survive', () => {
  unchanged('We went to Monday meetings for years.');
  unchanged('I talked to September about... no, that is nonsense, but May is busy.');
});

test('ordinary complaints and praise are untouched', () => {
  unchanged('We just do not have common times to be able to plan together.');
  unchanged('The air conditioning in our modular units needs replacing.');
  unchanged('I think it is our sense of community that makes this place work.');
  unchanged('There could be name-calling at times, and different groups do not get along.');
  unchanged('We get lots of emails that include good information.');
});

test('a sentence-initial capitalised word is not assumed to be a name', () => {
  unchanged('Teachers are supportive here.');
  unchanged('Students treat each other well for the most part.');
});

test('does not mangle text with no PII at all', () => {
  const plain = 'I feel safe and supported, and the rules are applied fairly to everyone.';
  unchanged(plain);
  assert.strictEqual(containsPII(plain), false);
});

test('containsPII flags text that would change', () => {
  assert.strictEqual(containsPII('Mr. Johnson helped me.'), true);
  assert.strictEqual(containsPII('Nobody helped me.'), false);
});

test('handles empty, missing and non-string input safely', () => {
  assert.strictEqual(scrubPII(''), '');
  assert.strictEqual(scrubPII(null), null);
  assert.strictEqual(scrubPII(undefined), undefined);
  assert.strictEqual(scrubPII(42), 42);
});

test('multiple names in one response are all removed', () => {
  scrubs(
    'I talked to Karen, then I asked Dave, and Mr. Peterson followed up.',
    'I talked to [Name Removed], then I asked [Name Removed], and [Name Removed] followed up.',
  );
});

/**
 * Tier 3 — names the participant speaks TO.
 *
 * People take these interviews in staff rooms and at kitchen tables, and they
 * break off to talk to whoever is in the room. In the gas-aug-31d staff
 * interview that produced "All right, Adam, just shh." — stored as that
 * person's explanation of their AI-readiness rating, name and all, on a survey
 * that promises anonymity out loud.
 *
 * Tier 2 was structurally unable to catch it: a vocative has no lead verb in
 * front and no trailing verb behind, and those are precisely what its two
 * patterns key on. The comma fence is the signal instead.
 */
test('vocatives — a name being addressed, not described', () => {
  scrubs('All right, Adam, just shh.', 'All right, [Name Removed], just shh.');
  scrubs('I told him, Sarah, that it was fine.', 'I told him, [Name Removed], that it was fine.');
  scrubs('Well, Mike. That is the issue.', 'Well, [Name Removed]. That is the issue.');
  scrubs('Hang on, Priya — sorry.', 'Hang on, [Name Removed] — sorry.');
});

test('vocative rule does not eat list items or real answers', () => {
  // Days, subjects and school vocabulary are fenced by commas the same way.
  unchanged('We meet on Monday, Friday, and sometimes Wednesday.');
  unchanged('I teach English, Spanish, and History.');
  unchanged('It is blocked, so it is not available.');
  // Verbatims from the gas-aug-31d traces — these must survive intact.
  unchanged('I love the school spirit that showed at the sporting events.');
  unchanged('We have a few, but they are far away from many of the classes.');
  unchanged('If funding were not a barrier, I feel like a STEM program would be good.');
  unchanged('I feel like actions are met with appropriate consequences, and, you know, parents are notified.');
});

/**
 * A known and deliberate gap, recorded so nobody assumes otherwise.
 *
 * A capitalised word opening a sentence is usually just a sentence beginning,
 * so every tier declines to treat it as a name. "Adam is the one who helped."
 * therefore survives. Closing this would mean scrubbing the first word of most
 * sentences, which destroys far more data than it protects.
 */
test('sentence-initial names are a documented gap, not a regression', () => {
  unchanged('Adam is the one who helped.');
});
