#!/usr/bin/env python3
"""Verify the cross-role claims in cycle1-methodology.md section 2.1.

Section 2.1 is the report's lead finding and the only new quantitative work in
that document. It was computed with Welch standard errors and a +/-1.96 cutoff,
eighteen pairwise comparisons, and NO multiplicity correction -- the document
says the marginal results would not survive one without demonstrating it.

This settles it three ways, none of which assume normality:

  permutation test   20,000 label shuffles per pair. Assumption-free, and the
                     right tool for means of ordinal items at n=10.
  Holm + BH          applied across all eighteen p-values at 0.05. Holm
                     controls the familywise error rate, BH the false
                     discovery rate; reporting both because they answer
                     different questions and a reader may want either.
  bootstrap          20,000 resamples, percentile CI on each difference, plus
                     the probability that a randomly chosen member of one role
                     scores above one from the other (a rank effect size that
                     survives ordinal data).

Unit of analysis is the RESPONDENT: each person contributes one mean per
domain. Treating individual ratings as independent would understate every
standard error, since one student supplies seven safety answers.

  python3 -I verify-crossrole.mjs.py export-pps-2026-27/shareable.csv

Read-only. Touches nothing.
"""
import csv
import sys
from collections import defaultdict
from itertools import combinations

import numpy as np

SRC = sys.argv[1] if len(sys.argv) > 1 else 'export-pps-2026-27/shareable.csv'
DOMAINS = ('safety', 'engagement', 'environment')
ROLES = ('students', 'teachers', 'parents', 'staff')
B = 20000
rng = np.random.default_rng(20261111)

# shareable.csv is already ratings-only with rating 0 excluded; the id column
# is the within-role pseudonym, which is all the respondent grouping needs.
raw = defaultdict(lambda: defaultdict(list))
with open(SRC) as fh:
    for r in csv.DictReader(fh):
        if r['domain'] not in DOMAINS:
            continue
        raw[(r['role'], r['domain'])][r['respondent']].append(float(r['rating']))

means = {k: np.array([np.mean(v) for v in d.values()]) for k, d in raw.items()}


def perm_p(a, b):
    """Two-sided permutation test on the difference of means."""
    obs = abs(a.mean() - b.mean())
    pool = np.concatenate([a, b])
    n = len(a)
    idx = np.argsort(rng.random((B, len(pool))), axis=1)
    shuffled = pool[idx]
    diffs = np.abs(shuffled[:, :n].mean(1) - shuffled[:, n:].mean(1))
    # +1 in both terms: a permutation p of exactly 0 is not evidence of an
    # infinitely small p, only of one smaller than 1/(B+1).
    return (np.sum(diffs >= obs - 1e-12) + 1) / (B + 1)


def boot_ci(a, b):
    da = rng.choice(a, (B, len(a)), replace=True).mean(1)
    db = rng.choice(b, (B, len(b)), replace=True).mean(1)
    d = da - db
    return np.percentile(d, 2.5), np.percentile(d, 97.5)


def superiority(a, b):
    """P(random a > random b) + half the ties. 0.5 means no separation."""
    gt = (a[:, None] > b[None, :]).sum()
    eq = (a[:, None] == b[None, :]).sum()
    return (gt + 0.5 * eq) / (len(a) * len(b))


tests = []
for dom in DOMAINS:
    for r1, r2 in combinations(ROLES, 2):
        k1, k2 = (r1, dom), (r2, dom)
        if k1 not in means or k2 not in means:
            continue
        a, b = means[k1], means[k2]
        se = np.sqrt(a.var(ddof=1) / len(a) + b.var(ddof=1) / len(b))
        tests.append({
            'dom': dom, 'r1': r1, 'r2': r2, 'n1': len(a), 'n2': len(b),
            'diff': a.mean() - b.mean(), 't': (a.mean() - b.mean()) / se,
            'p': perm_p(a, b), 'ci': boot_ci(a, b), 'ps': superiority(a, b),
        })

p = np.array([t['p'] for t in tests])
m = len(p)
order = np.argsort(p)

# Holm: step-down, compare the k-th smallest p against alpha/(m-k).
holm = np.zeros(m, dtype=bool)
for k, i in enumerate(order):
    if p[i] <= 0.05 / (m - k):
        holm[i] = True
    else:
        break

# Benjamini-Hochberg: largest k with p_(k) <= k/m * alpha, accept all below it.
bh = np.zeros(m, dtype=bool)
cut = -1
for k, i in enumerate(order, start=1):
    if p[i] <= k / m * 0.05:
        cut = k
for k, i in enumerate(order, start=1):
    if k <= cut:
        bh[i] = True

print(f'\n{m} pairwise comparisons, respondent-level, {B:,} permutations each')
print(f'unit = respondent; n per role-domain: '
      + ', '.join(f'{r}={len(means[(r, "safety")])}' for r in ROLES if (r, 'safety') in means))
print()
hdr = f"{'comparison':34}{'diff':>7}{'t':>6}{'perm p':>9}{'Holm':>6}{'BH':>5}   {'bootstrap 95% CI':>20}  P(sup)"
print(hdr)
print('-' * len(hdr))
for i in np.argsort([t['p'] for t in tests]):
    t = tests[i]
    lab = f"{t['dom'][:11]}: {t['r1'][:8]} v {t['r2'][:8]}"
    star = '***' if holm[i] else ('*' if bh[i] else '')
    print(f"{lab:34}{t['diff']:>+7.2f}{t['t']:>+6.1f}{t['p']:>9.4f}"
          f"{'YES' if holm[i] else '-':>6}{'YES' if bh[i] else '-':>5}"
          f"   [{t['ci'][0]:>+6.2f}, {t['ci'][1]:>+6.2f}]{t['ps']:>8.2f} {star}")

print()
print(f"survive Holm (familywise 0.05): {holm.sum()} of {m}")
for i in np.where(holm)[0]:
    t = tests[i]
    print(f"   {t['dom']}: {t['r1']} vs {t['r2']}  {t['diff']:+.2f}  p={t['p']:.4f}")
print(f"survive Benjamini-Hochberg (FDR 0.05): {bh.sum()} of {m}")
for i in np.where(bh & ~holm)[0]:
    t = tests[i]
    print(f"   (BH only) {t['dom']}: {t['r1']} vs {t['r2']}  {t['diff']:+.2f}  p={t['p']:.4f}")

print()
print('claimed in cycle1-methodology.md section 2.1 at +/-1.96 uncorrected:')
for t in tests:
    if abs(t['t']) >= 1.96:
        i = tests.index(t)
        verdict = 'holds under Holm' if holm[i] else ('BH only' if bh[i] else 'DOES NOT SURVIVE')
        print(f"   {t['dom']:12} {t['r1']:9} vs {t['r2']:9} t={t['t']:+.1f}  -> {verdict}")
print()
