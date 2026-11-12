#!/usr/bin/env python3
"""Cross-role differences on questions asked VERBATIM to more than one role.

WHY SAME-ITEM, AND NOT DOMAIN MEANS

The first version of this compared domain means between roles and found
students 0.36 below teachers on safety. That comparison is confounded, and the
methodology document's own limitation 3 says so: the four roles answer parallel
but DIFFERENT question sets, so a domain mean reflects which items are in the
bucket as much as what anyone thinks. Students' safety domain carries "Bullying
is rare at this school" (2.77) and "Students treat each other with respect"
(2.74) -- peer-conduct questions teachers were never asked. Teachers' carries
"Students treat teachers with respect" (3.22), a different construct. Much of
that 0.36 was item composition.

Fourteen question texts in pps-2026-27 are put to more than one role word for
word. Those comparisons need no caveat at all, and they are what this script
tests.

METHOD, none of it assuming normality:

  permutation   20,000 label shuffles per pair, two-sided on the difference of
                means. Right for means of ordinal answers at n=10.
  Holm + BH     across every comparison at once. Holm controls the familywise
                error rate, BH the false discovery rate; both are printed
                because they answer different questions.
  bootstrap     20,000 resamples, percentile interval on each difference.

Pure standard library: this has to run on a laptop with no numpy, and on an
analyst's machine that has nothing installed. Expect roughly a minute.

  python3 -I verify-crossrole.py export-pps-2026-27/responses.csv

Read-only.
"""
import csv
import random
import sys
from collections import defaultdict
from itertools import combinations
from statistics import mean

SRC = sys.argv[1] if len(sys.argv) > 1 else 'export-pps-2026-27/responses.csv'
B = 20000
MIN_N = 5
random.seed(20261112)


def rated(row):
    """Rating 0 is the placeholder written by the open-ended half of a question
    pair, not an answer of zero. Mirrors server.js:5161."""
    try:
        v = float(row['rating'])
    except (TypeError, ValueError):
        return None
    return v if v != 0 else None


byq = defaultdict(lambda: defaultdict(list))
with open(SRC) as fh:
    reader = csv.DictReader(fh)
    if 'question_text' not in (reader.fieldnames or []):
        sys.exit('This export has no question_text column. Re-run '
                 'export-school.mjs, which has written it since 2026-11-11.')
    for row in reader:
        v = rated(row)
        text = (row.get('question_text') or '').strip()
        if v is None or not text:
            continue
        byq[text][row['role']].append(v)

shared = {t: d for t, d in byq.items() if len(d) > 1}
if not shared:
    sys.exit('No question text is shared between roles in this file.')


def perm_p(a, b):
    obs = abs(mean(a) - mean(b))
    pool = a + b
    n = len(a)
    total = sum(pool)
    hits = 0
    for _ in range(B):
        random.shuffle(pool)
        sa = sum(pool[:n])
        # mean(a') - mean(b') from one running sum rather than two slices.
        if abs(sa / n - (total - sa) / (len(pool) - n)) >= obs - 1e-12:
            hits += 1
    # +1 on both: a p of exactly 0 evidences p < 1/(B+1), not p = 0.
    return (hits + 1) / (B + 1)


def boot_ci(a, b):
    diffs = []
    for _ in range(B):
        da = mean(random.choices(a, k=len(a)))
        db = mean(random.choices(b, k=len(b)))
        diffs.append(da - db)
    diffs.sort()
    return diffs[int(0.025 * B)], diffs[int(0.975 * B)]


def favpct(v):
    return 100 * sum(1 for x in v if x >= 3) / len(v)


tests = []
for text, roles in shared.items():
    for r1, r2 in combinations(sorted(roles), 2):
        a, b = roles[r1], roles[r2]
        if len(a) < MIN_N or len(b) < MIN_N:
            continue
        tests.append({
            'text': text, 'r1': r1, 'r2': r2,
            'd': mean(a) - mean(b), 'p': perm_p(a[:], b[:]), 'ci': boot_ci(a, b),
            'n1': len(a), 'n2': len(b), 'f1': favpct(a), 'f2': favpct(b),
        })

m = len(tests)
order = sorted(range(m), key=lambda i: tests[i]['p'])

holm = set()
for k, i in enumerate(order):
    if tests[i]['p'] <= 0.05 / (m - k):
        holm.add(i)
    else:
        break

bh, cut = set(), 0
for k, i in enumerate(order, start=1):
    if tests[i]['p'] <= k / m * 0.05:
        cut = k
for k, i in enumerate(order, start=1):
    if k <= cut:
        bh.add(i)

print(f'\n{len(shared)} question texts asked verbatim to more than one role')
print(f'{m} comparisons, {B:,} permutations each, respondent-level\n')

for i in order:
    t = tests[i]
    mark = '***  HOLM' if i in holm else ('*    BH' if i in bh else '')
    print(f"  p={t['p']:<8.4f} {t['d']:+.2f}  [{t['ci'][0]:+.2f}, {t['ci'][1]:+.2f}]  "
          f"{t['r1']} {t['f1']:.0f}% (n={t['n1']})  vs  {t['r2']} {t['f2']:.0f}% (n={t['n2']})  {mark}")
    print(f'      "{t["text"][:92]}"')

print(f'\nsurvive Holm (familywise 0.05): {len(holm)} of {m}')
for i in order:
    if i in holm:
        t = tests[i]
        print(f"   {t['r1']} vs {t['r2']}  {t['d']:+.2f}  p={t['p']:.4f}  \"{t['text'][:70]}\"")
print(f'survive Benjamini-Hochberg (FDR 0.05): {len(bh)} of {m}')
for i in order:
    if i in bh and i not in holm:
        t = tests[i]
        print(f"   (BH only) {t['r1']} vs {t['r2']}  {t['d']:+.2f}  p={t['p']:.4f}  \"{t['text'][:60]}\"")
print()
