/**
 * Strip personal identifiers from participant speech before it is stored.
 *
 * WHY
 *
 * These surveys promise confidentiality — the tips modal says "Your responses
 * are fully anonymous — speak freely" — and participants take that at their
 * word, then name people. Real examples from the 2026-08-27 exports:
 *
 *   "Mr. Judd said our principal has worked very hard..."
 *   "I could go to Mr. Johnson, I could go to Sue..."
 *
 * Until now that text reached Firestore verbatim, and from there the CSV export
 * and the admin dashboard. The report generator reworded identifying quotes,
 * but that is downstream: it never protected what was stored or exported.
 *
 * This runs at the single write path every survey passes through, so nothing
 * can bypass it, and it is irreversible by design — the identifier never lands.
 *
 * DESIGN BIAS
 *
 * Over-scrubbing destroys the qualitative data that makes this product worth
 * buying. Under-scrubbing breaks a promise to participants. The rules below are
 * therefore ordered by confidence, and each replaces rather than deletes so the
 * sentence still reads: "Mr. Johnson is accommodating" becomes "[Name Removed] is
 * accommodating", which keeps the meaning an analyst needs.
 *
 * KNOWN LIMITATION
 *
 * A bare first name with no title and no person-referring context — "Sue was
 * great" at the start of a sentence — is not reliably distinguishable from an
 * ordinary capitalised word. Tier 2 catches the common conversational shapes;
 * it will not catch everything. Instructing the model to omit names when it
 * reports an answer is the natural complement to this, not a replacement for it.
 */

/**
 * One capitalised name word. Deliberately does NOT consume a trailing
 * possessive: "Johnson's" matches only "Johnson", leaving "'s" so the sentence
 * still reads "[Name Removed]'s class". An apostrophe followed by an UPPERCASE
 * letter is treated as part of the name, so O'Brien survives intact.
 */
const NAME_WORD = "[A-Z][a-zA-Z-]*(?:['\u2019][A-Z][a-zA-Z-]*)*";

/** Capitalised words that follow person-context but are not people. */
const NOT_NAMES = new Set([
  // school / district vocabulary
  'school', 'schools', 'district', 'office', 'administration', 'admin',
  'principal', 'superintendent', 'teacher', 'teachers', 'staff', 'student',
  'students', 'parent', 'parents', 'class', 'classes', 'classroom', 'library',
  'gym', 'cafeteria', 'nurse', 'counselor', 'counsellor', 'security', 'board',
  'committee', 'department', 'services', 'support', 'special', 'education',
  'title', 'central', 'high', 'middle', 'elementary', 'junior', 'senior',
  // subjects
  'english', 'math', 'mathematics', 'science', 'history', 'spanish', 'french',
  'german', 'latin', 'art', 'music', 'band', 'choir', 'drama', 'theater',
  'theatre', 'pe', 'health', 'reading', 'writing', 'biology', 'chemistry',
  'physics', 'geography', 'government', 'economics', 'algebra', 'geometry',
  // days, months
  'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
  'january', 'february', 'march', 'april', 'may', 'june', 'july', 'august',
  'september', 'october', 'november', 'december',
  // common sentence-starters and misc
  'i', 'the', 'they', 'we', 'it', 'this', 'that', 'there', 'these', 'those',
  'my', 'our', 'their', 'his', 'her', 'a', 'an', 'and', 'but', 'so', 'if',
  'god', 'covid', 'iep', 'ieps', 'ai', 'chatgpt', 'google', 'zoom',
  // devices, platforms and programmes heard constantly in these interviews
  'chromebook', 'chromebooks', 'ipad', 'ipads', 'powerschool', 'canvas',
  'ffa', 'fbla', 'quiz', 'bowl', 'homecoming', 'jv', 'ap', 'esports',
]);

/*
 * Given names that are essentially never anything else.
 *
 * WHY A LIST AT ALL
 *
 * The KNOWN LIMITATION above was real and measurable: across pps-2026-27's
 * 2,661 written answers, nine probable personal names survived every tier --
 * Mitch, Alex, Brody, Olson, Carney, Dugan, Roth, Sterling, Cousins. Each one
 * is a name reaching a district report on a survey that promised anonymity
 * out loud. Nine is not many; one is too many.
 *
 * WHY THIS LIST AND NOT A BIGGER ONE
 *
 * The same scan surfaced Remind and Rooms -- two apps this district actually
 * uses -- alongside Bulldog, Chrome, Gemini, Dota and Amherst. A general
 * first-name dictionary would redact a school's own software and mascot, and
 * this scrubbing is irreversible: the word never lands, so a wrong call
 * cannot be undone later. That is how "Better Chromebooks" became "Better
 * [Name Removed]" permanently.
 *
 * So this list deliberately excludes every name that doubles as an ordinary
 * word (Mark, Grace, Will, May, Art, Hope, Faith, Summer, Chase, Rose, Bill,
 * Jack, Joy, Rich, Sunny), a place (Austin, Madison, Jordan, Savannah,
 * Phoenix, Brooklyn, Sydney, Dakota, Sierra, Houston, Paris), or a brand. It
 * catches the unambiguous cases and leaves the rest to the report-time name
 * check, which flags without destroying.
 */
const GIVEN_NAMES = new Set([
  'aaron', 'adam', 'alex', 'alexis', 'alicia', 'allison', 'amanda', 'amber',
  'andrea', 'andrew', 'angela', 'anita', 'anthony', 'ashley', 'barbara',
  'becky', 'benjamin', 'bethany', 'bradley', 'brandon', 'brenda', 'brett',
  'brian', 'brittany', 'brody', 'bryan', 'caleb', 'cameron', 'carla',
  'carlos', 'carol', 'carrie', 'cheryl', 'chris', 'christina', 'christopher',
  'cindy', 'claire', 'cody', 'colin', 'connor', 'corey', 'courtney', 'craig',
  'cynthia', 'dana', 'daniel', 'danielle', 'darren', 'dave', 'david',
  'deborah', 'debra', 'denise', 'dennis', 'derek', 'diana', 'donna',
  'doug', 'douglas', 'dylan', 'edward', 'elena', 'elizabeth', 'emily',
  'emma', 'eric', 'erica', 'erin', 'ethan', 'evan', 'frank', 'gabriel',
  'gary', 'gavin', 'gerald', 'gloria', 'gregory', 'hannah', 'heather',
  'heidi', 'hector', 'holly', 'ian', 'isaac', 'jacob', 'james', 'jamie',
  'jared', 'jason', 'jeff', 'jeffrey', 'jenna', 'jennifer', 'jeremy',
  'jessica', 'joan', 'joel', 'john', 'jonathan', 'joseph', 'joshua',
  'juan', 'judith', 'julia', 'julie', 'justin', 'kaitlyn', 'karen',
  'katherine', 'kathy', 'katie', 'kayla', 'keith', 'kelly', 'kendra',
  'kenneth', 'kevin', 'kimberly', 'kristen', 'kyle', 'larry', 'laura',
  'lauren', 'leah', 'leslie', 'linda', 'lindsey', 'lisa', 'logan', 'lucas',
  'luis', 'lydia', 'marcus', 'maria', 'marie', 'marisa', 'martha', 'marty',
  'mason', 'matthew', 'megan', 'melissa', 'meredith', 'michael', 'michelle',
  'miguel', 'mitch', 'mitchell', 'molly', 'monica', 'nancy', 'natalie',
  'nathan', 'nicholas', 'nicole', 'noah', 'olivia', 'pamela', 'patricia',
  'patrick', 'paula', 'peggy', 'peter', 'philip', 'priya', 'rachel',
  'rebecca', 'renee', 'rhonda', 'ricardo', 'richard', 'robert', 'roger',
  'ronald', 'ryan', 'samantha', 'samuel', 'sandra', 'sara', 'sarah',
  'scott', 'sean', 'shannon', 'sharon', 'shawn', 'sheila', 'sophia',
  'stacey', 'stephanie', 'stephen', 'steve', 'steven', 'susan', 'tamara',
  'tanya', 'teresa', 'terrance', 'thomas', 'tiffany', 'timothy', 'tina',
  'todd', 'tracy', 'travis', 'trevor', 'tyler', 'vanessa', 'veronica',
  'vincent', 'wendy', 'wesley', 'william', 'zachary',
]);

/** Titles that all but guarantee the next capitalised word is a person. */
const TITLES =
  'Mr|Mrs|Ms|Miss|Mx|Dr|Prof|Professor|Principal|Superintendent|Coach|Officer|Nurse|Sergeant|Sgt|Captain|Rev|Reverend|Father|Sister|Deacon|Chief|Dean|Director';

/**
 * Verbs and prepositions that, in these interviews, are nearly always followed
 * by a person when the next word is capitalised: "go to Sue", "ask Karen",
 * "Dave said".
 */
const PERSON_LEAD =
  'go to|going to|went to|talk to|talked to|speak to|spoke to|spoken to|reach out to|turn to|turned to|ask|asked|tell|told|email|emailed|call|called|see|saw|with|from';

/*
 * "and" was in PERSON_LEAD and caught every capitalised word following it.
 * "like FFA and Quiz Bowl and band" became "like FFA and [Name Removed] Bowl
 * and band" in pps-2026-27, which is destructive and permanent: the word is
 * gone from Firestore. It now fires only where the thing before the "and" is
 * already a redacted name, which is the case it was there for — "Mr. Johnson
 * and Karen".
 */
const AND_AFTER_NAME = /(\[Name Removed\]\s+and\s+)([A-Z][a-zA-Z-]*)/g;

const PERSON_TRAIL = 'said|says|told|thinks|thought|feels|felt|is|was|has|had|does|did|will|would|can|could';

/**
 * Remove personal identifiers from a free-text response.
 * Returns the text unchanged if it contains none.
 */
export function scrubPII(input) {
  if (typeof input !== 'string' || !input) return input;
  let out = input;

  // ── Tier 1: unambiguous ────────────────────────────────────────────────────

  // Email addresses.
  out = out.replace(/\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g, '[email]');

  // Phone numbers: 555-123-4567, (555) 123-4567, 555.123.4567, +1 555 123 4567.
  out = out.replace(/(?:\+?\d{1,2}[\s.-])?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g, '[phone]');

  // Title + name, with or without the period, optionally two name words.
  // Handles the possessive naturally: "Mr. Johnson's" -> "[Name Removed]'s".
  out = out.replace(
    new RegExp(`\\b(?:${TITLES})\\.?\\s+${NAME_WORD}(?:\\s+${NAME_WORD})?`, 'g'),
    '[Name Removed]',
  );

  // ── Tier 2: capitalised word in person-referring context ───────────────────

  const isName = word => word && !NOT_NAMES.has(word.toLowerCase());

  // "go to Sue", "asked Karen", "with Dave"
  out = out.replace(
    new RegExp(`\\b(${PERSON_LEAD})\\s+(${NAME_WORD})\\b`, 'g'),
    (match, lead, word) => (isName(word) ? `${lead} [Name Removed]` : match),
  );

  // "Mr. Johnson and Karen" — only once the first name has already gone.
  out = out.replace(AND_AFTER_NAME, (match, lead, word) =>
    (isName(word) ? `${lead}[Name Removed]` : match));

  // "Sue said", "Karen thinks" — but not at the very start of the text, where a
  // capitalised word is usually just a sentence beginning.
  out = out.replace(
    new RegExp(`(?<=[a-z,;:]\\s)(${NAME_WORD})\\s+(${PERSON_TRAIL})\\b`, 'g'),
    (match, word, trail) => (isName(word) ? `[Name Removed] ${trail}` : match),
  );

  // ── Tier 3: direct address ────────────────────────────────────────────────
  //
  // A name the participant SPEAKS TO rather than about. Interviews are taken in
  // staff rooms and at kitchen tables, and people interrupt themselves to talk
  // to whoever is in the room:
  //
  //   "All right, Adam, just shh."
  //
  // That is a real line from the gas-aug-31d staff interview, and it was stored
  // as that person's explanation of their AI-readiness rating — with the name
  // intact, on a survey that promises anonymity out loud. Tier 2 could not see
  // it: a vocative has no lead verb before it and no trailing verb after it,
  // which is exactly what both Tier 2 patterns require.
  //
  // The comma pair is the signal. A capitalised word fenced by punctuation on
  // both sides is being addressed, not described. NOT_NAMES carries the false
  // positives that matter — ", Friday," and ", English," are set off the same
  // way — and the word must not open the sentence, where capitalisation means
  // nothing.
  out = out.replace(
    // Dashes count as a fence too — "Hang on, Priya — sorry" is the same
    // interruption with different punctuation. End-of-string is deliberately
    // NOT a fence: "the program is called Odyssey" would lose a program name.
    /*
     * The left fence must be punctuation, not merely a lowercase letter.
     * With [a-z] allowed, any capitalised word before a full stop matched:
     * "Better Chromebooks." became "Better [Name Removed]." in pps-2026-27,
     * and the original word cannot be recovered. A vocative always has a
     * comma, semicolon or colon in front of it — "All right, Adam," — which
     * is what the note above describes and what this now requires.
     */
    new RegExp(`(?<=[,;:]\\s)(${NAME_WORD})(?=\\s*[,.!?;:\\u2014\\u2013-])`, 'g'),
    (match, word) => (isName(word) ? '[Name Removed]' : match),
  );

  // ── Tier 4: an unambiguous given name, in any position ────────────────────
  //
  // The tiers above all require context — a title, a lead verb, a trailing
  // verb, a punctuation fence. A bare name in ordinary prose has none of
  // those, and that is how "We really appreciate Mitch" survived every one of
  // them. Where the word itself can only be a person, no context is needed.
  //
  // Possessives survive deliberately: "Karen's class" becomes
  // "[Name Removed]'s class", because NAME_WORD does not consume the "'s".
  out = out.replace(
    new RegExp(`\\b(${NAME_WORD})\\b`, 'g'),
    (match, word) => (GIVEN_NAMES.has(word.toLowerCase()) ? '[Name Removed]' : match),
  );

  // Collapse runs produced by consecutive names: "[Name Removed] and [Name Removed]" is fine,
  // but "[Name Removed] [Name Removed]" from a first+last pair reads badly.
  out = out.replace(/\[Name Removed\](\s+\[Name Removed\])+/g, '[Name Removed]');

  return out;
}

/** True if scrubbing would change the text — useful for logging/metrics. */
export function containsPII(input) {
  return typeof input === 'string' && scrubPII(input) !== input;
}
