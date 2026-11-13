#!/usr/bin/env python3
"""Check every quotation in a generated report against the export.

WHY

Report structure, figures, section order, redaction scope and the options
section were all made reliable by instruction. Quote attribution was not.
Across five generations on 2026-11-12 the model copied quoted text perfectly
and misassigned the speaker's role about one time in nine:

    "I really like the community that we have"        parent  -> student
    "integrating into the high school side"           parent  -> teacher
    "students need some real-world experience"        parent  -> staff
    "additional offerings in math and science"        teacher -> parent

Three of the four were given to parents. The error is invisible to any reader
without the export open, and it lands on the one claim the report is built
around — that students see this school differently from the adults in it.

So the quotes get checked by machine until they are selected by machine.

    pbpaste > /tmp/report.md && python3 -I verify-quotes.py /tmp/report.md
    python3 -I verify-quotes.py report.md --export export-pps-2026-27

Every passage in double quotes longer than MIN_LEN is looked up in the export.
For each, the role the report attributes it to is compared with the role that
actually gave it. Attribution is read from the nearest preceding mention of a
role, which is how these reports introduce quotes ("One teacher wrote,").

Read-only. Reads two files and prints.
"""
import csv
import re
import sys
from pathlib import Path

args = sys.argv[1:]
if not args:
    sys.exit(__doc__)
REPORT = Path(args[0])
EXPORT = Path(args[args.index('--export') + 1]) if '--export' in args else Path('export-pps-2026-27')
CSV = EXPORT / 'responses.csv'
MIN_LEN = 25

if not REPORT.exists():
    sys.exit(f'No such report: {REPORT}')
if not CSV.exists():
    sys.exit(f'No responses.csv under {EXPORT}. Run export-school.mjs first.')

TYPO = {'\u2018': "'", '\u2019': "'", '\u02bc': "'", '\u201c': '"', '\u201d': '"',
        '\u201e': '"', '\u2013': '-', '\u2014': '-', '\u2026': '...'}


def norm(t):
    """Firestore holds 3,594 straight apostrophes across pps-2026-27 and no
    curly ones; the model writes curly. Without this, every quote containing an
    apostrophe reads as never said by anybody."""
    for a, b in TYPO.items():
        t = t.replace(a, b)
    return re.sub(r'\s+', ' ', t.lower()).strip()


def contained(answer, quote):
    """A report trims the middle of a long quote with an ellipsis, so a
    quotation can be several fragments of one answer. Each must appear, in
    order, in the same response."""
    parts = [x.strip() for x in re.split(r'\s*\.\.\.\s*', quote) if len(x.strip()) >= 12]
    if not parts:
        return False
    at = 0
    for part in parts:
        i = answer.find(part, at)
        if i == -1:
            return False
        at = i + len(part)
    return True

answers = []
items = set()
with open(CSV) as fh:
    for r in csv.DictReader(fh):
        if r['answer_text'].strip():
            answers.append((r['role'], norm(r['answer_text'])))
        # The survey items. Ranked lists quote the question verbatim, and those
        # appear in no answer -- fifteen of them were reported as words nobody
        # said, swamping the one real alteration.
        if r.get('question_text', '').strip():
            items.add(norm(r['question_text']))

text = REPORT.read_text()

# "One teacher wrote", "A parent stated", "Teachers echoed", "Students valued".
ROLE_WORD = re.compile(r'\b(student|students|teacher|teachers|staff|parent|parents)\b', re.I)
PLURAL = {'student': 'students', 'students': 'students', 'teacher': 'teachers',
          'teachers': 'teachers', 'staff': 'staff', 'parent': 'parents', 'parents': 'parents'}

# Curly and straight quotes both; reports use either depending on where they
# have been pasted through.
QUOTE = re.compile(r'[“"]([^”"]{%d,})[”"]' % MIN_LEN)

ok = bad = unfound = 0
problems = []
for m in QUOTE.finditer(text):
    frag = norm(m.group(1))
    if any(q == frag or q in frag or frag in q for q in items):
        continue
    # Partial match: reports often trim a quote with an ellipsis.
    hits = {role for role, ans in answers if contained(ans, frag) or (len(frag) > 60 and frag[:60] in ans)}
    if not hits:
        unfound += 1
        problems.append(('NOT FOUND', '', m.group(1)[:78]))
        continue
    before = text[:m.start()]
    labels = ROLE_WORD.findall(before[-220:])
    claimed = PLURAL[labels[-1].lower()] if labels else None
    if claimed is None:
        problems.append(('NO ATTRIBUTION', '/'.join(sorted(hits)), m.group(1)[:78]))
        continue
    if claimed in hits:
        ok += 1
    else:
        bad += 1
        problems.append((f'SAYS {claimed}', 'IS ' + '/'.join(sorted(hits)), m.group(1)[:78]))

print(f'\n{REPORT.name} vs {CSV}\n')
for kind, actual, frag in problems:
    print(f'  {kind:16} {actual:14} "{frag}…"')
if not problems:
    print('  no problems found')
print()
print(f'  verbatim and correctly attributed  {ok}')
print(f'  MISATTRIBUTED                      {bad}')
print(f'  not found in the export            {unfound}   (paraphrased, trimmed oddly, or invented)')
print()
if bad or unfound:
    print('  A quote the export does not contain is the more serious of the two:')
    print('  it means the text was altered, not just the label.')
    print()
sys.exit(1 if (bad or unfound) else 0)
