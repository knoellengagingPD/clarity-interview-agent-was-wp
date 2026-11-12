# Cycle 1 — findings structure and methodology note

School Climate Survey, Pleasanton Public Schools, `pps-2026-27`
Fieldwork 3–11 November 2026. Written 11 November 2026.

Scope of this document: how to structure the first-cycle report, and what the
report may and may not claim. It is the analysis plan, not the report. Every
number below is computed from `export-pps-2026-27/` and is reproducible from
`shareable.csv` and `items.csv`.

---

## 1. What cycle 1 is for

The product's value is the comparison between cycles. That makes cycle 1 a
**baseline and a resource-allocation map**, not a verdict. The report should say
so in its first paragraph, because almost every interpretive error available
here comes from reading a single cycle as a judgement.

Two consequences follow, and they constrain everything else:

**The instrument freezes now.** Items, scale, domain membership and scoring
must not change between cycles. EDSCLS broke every trend line its users had
when it moved to benchmarked scale scores in VM 3.0, and had to publish a
notice that legacy scores were not comparable. Any rescoring done after
Pleasanton cycle 1 costs the comparison the product is sold on. The band
labels were reworded on 2026-11-10 (`dcbe4bf`, `9591411` — legends only, no
thresholds moved); that is the last change before cycle 2.

**Cycle 1 should publish the thresholds cycle 2 will be judged against.**
Stating the minimum detectable change per group *before* the second wave is
run is a credibility asset, not a disclosure risk: it means the district cannot
be told after the fact that a favourable move was meaningful and an
unfavourable one was noise. Section 5 has the numbers.

---

## 2. Findings, in order of evidential strength

Order the report this way. The ordering is not editorial preference — it tracks
how well each claim survives the caveats in section 4.

### 2.1 The adult–student gap (lead with this)

Respondent-level domain means, 95% CI:

| domain | students (n=87) | teachers (n=32) | parents (n=29) | staff (n=11) |
|---|---|---|---|---|
| safety | **3.05** [2.96, 3.14] | 3.41 [3.26, 3.55] | 3.17 [2.96, 3.38] | 3.15 [2.94, 3.36] |
| engagement | **3.00** [2.90, 3.11] | 3.06 [2.88, 3.25] | 3.29 [3.09, 3.48] | 3.08 [2.66, 3.49] |
| environment | **2.90** [2.79, 3.02] | 3.18 [3.05, 3.32] | 3.09 [2.84, 3.34] | 3.27 [2.98, 3.56] |

Eighteen pairwise comparisons were available. All were tested by permutation
(20,000 label shuffles, no normality assumed), with bootstrap confidence
intervals and both Holm and Benjamini–Hochberg corrections — `verify-crossrole.py`.
An earlier draft of this section reported five results at an uncorrected
±1.96 cutoff. **One survives.**

| comparison | difference | perm p | bootstrap 95% CI | status |
|---|---|---|---|---|
| safety, students vs teachers | **−0.36** | **0.0001** | [−0.52, −0.18] | **holds under Holm** |
| environment, students vs teachers | −0.28 | 0.0065 | [−0.45, −0.11] | suggestive — see below |
| engagement, students vs parents | −0.28 | 0.0128 | [−0.49, −0.06] | not after correction |
| environment, students vs staff | −0.36 | 0.0419 | [−0.66, −0.08] | not after correction |
| safety, teachers vs staff | +0.26 | 0.0758 | [+0.02, +0.51] | **withdrawn** |

The last row is the clearest lesson. It showed t = +2.0 on a Welch standard
error and looked significant; its permutation p is 0.076, and bootstrap and
permutation disagree about whether its interval clears zero. At n=11 the normal
approximation is not trustworthy, and the earlier draft reported it on that
basis. It should not appear in the report.

The second row deserves care rather than dismissal. Its p of 0.0065 misses the
Benjamini–Hochberg boundary for the second-ranked test (0.0056) by a hair. The
evidence is not weak; the penalty for having run eighteen tests is heavy. Had
the adult–student contrast been specified in advance — three tests, not
eighteen — Holm would admit both safety and environment at 0.0167. That is an
argument for pre-specifying the contrast before cycle 2, not for promoting it
now.

So the single confirmed finding is **students rate safety 0.36 below teachers**,
p = 0.0001, surviving familywise correction across all eighteen tests. As an
effect size: a randomly chosen student scores above a randomly chosen teacher
on safety only **25%** of the time.

One pattern worth stating without a p-value attached. Students are numerically
the lowest-scoring group in every one of the nine comparisons they appear in,
across all three domains. Individually most of those are indistinguishable from
noise; the consistency of direction is weak corroboration of the confirmed
result, and should be described as that and nothing more.

This is still the lead, because it is the only finding in the deployment that
survives a familywise correction and it is immediately actionable: teachers in
this building perceive safety considerably more favourably than their students
do. It needs no external norms and no banding scheme to state. But it is one
domain and one pair of groups — not the broad adult–student gap the earlier
draft described, and the report should claim exactly as much as the table
above.

Note what it does **not** say. Teachers are not wrong and students are not
right. The two groups answered different items, so the gap is a difference in
reported perception between groups, not a measured discrepancy on identical
questions. Section 4 states this limit for the district.

### 2.2 Item-level patterns within each role

This is where the actionable detail lives, and it is larger than anything at
the domain level. Within each role-domain, the gap between the
highest- and lowest-rated item runs **0.39 to 0.71, median 0.61** — and exceeds
that group's minimum detectable change in **all twelve** role-domains, by
factors of 1.7× to 6.9×.

Verified rather than assumed, because two artefacts could have produced it:

- *Unequal respondent sets.* Restricting to the 82 students who answered all
  seven safety items leaves the spread at 0.62. Paired within those same
  students, top item minus bottom item is 0.62, SE 0.090, **t = 6.9**.
- *Survey position / fatigue.* Mean rating regressed on question number gives
  slopes of −0.008 (students), −0.007 (parents), −0.022 (teachers) and
  **+0.006 (staff)**. Too small to matter and inconsistent in sign.

Report these as **observed rank order and dispersion**. Do not describe them as
item difficulty, and do not assert that respondents experience the
lowest-ranked item worse than the highest — see 4.2. The usable form is "of the
seven safety statements, students were least likely to agree with X," together
with the item's percent agreeing and its SD.

Flag high-dispersion items separately from low-mean items. They are different
problems: a low mean with a tight SD is a shared view, a middling mean with a
wide SD is a split constituency. `SC_STF_08` (mean 3.30, SD 1.06) and
`SC_PAR_07` (mean 3.25, SD 0.99) are the latter and would be invisible in any
mean-based summary.

### 2.3 Percent agreeing, alongside every mean

On a forced-choice 1–4 scale with no neutral option, the meaningful boundary is
between Disagree (2) and Agree (3). "71% of teachers agreed or strongly agreed"
needs no banding scheme, no threshold anyone has to defend, and is what a board
understands without a scoring key. Mean and percent agreeing correlate at
r = 0.877 across the 69 items — high, but **not interchangeable**: 18 items
clear 85% agreement while their mean sits below 3.25. Report both; do not
derive one from the other.

This also matches how EDSCLS defines its own performance levels — by which
response category a respondent most likely chose, not by a quality judgement.

### 2.4 AI Readiness, presented separately

Parents 2.33, teachers 2.56, students 2.62, staff 2.80. Below every climate
domain, for every role, without exception.

Keep it visually and narratively separate from the three EDSCLS-aligned
domains. It is an addition to the instrument, EDSCLS does not define it, and it
should be framed as a **readiness and policy gap rather than a climate
deficit**. Folding 2.33 into a climate narrative tells the district something
false about its culture. `SC_PAR_15` is 43% agreement with n falling from 29 to
21 by that point in the parent survey, which is as much an exposure problem as
an opinion.

### 2.5 Completion patterns

Not a footnote — an instrument finding, and it was missed in the first pass
over this data.

| role | first item | last item | loss |
|---|---|---|---|
| students | 87 | 78 | 10% |
| teachers | 32 | 27 | 16% |
| parents | 29 | 21 | **28%** |
| staff | 11 | 10 | 9% |

Parents lose four respondents by item 3 and eight by item 15. The practical
consequence is that later items rest on a smaller, self-selected set, so item
comparisons between early and late positions carry a caveat the within-domain
comparisons in 2.2 do not — those were verified on complete cases.

The design implication for cycle 2 is to shorten the parent instrument or move
the highest-value items earlier. That is a change to *administration*, not to
items or scoring, so it does not break comparability. Dropping or reordering
items would.

### 2.6 Data quality, stated plainly

- **6 respondents rated every question and spoke on none.** Their ratings are
  valid and are included in every average. This is a legitimate way to take the
  survey, not a fault.
- **15 answers across 8 sessions contain fabricated transcription** —
  non-English or incoherent text produced when background noise made the audio
  unparseable. Those answers are excluded from quotation and from counts of who
  addressed a question. **The ratings from those same respondents are
  unaffected and retained.**
- Where quotations appear in the report, they are drawn from the subset of
  respondents who chose to elaborate. Ratings are reported for everyone.

---

## 3. What not to lead with

**The four-band scheme.** Thresholds are ≥3.5 Strength, 3.0–3.49, 2.5–2.99,
≤2.49. They were chosen rather than derived from any norm group, and on the
three substantive domains **nothing in this deployment reached 3.5** — all
twelve role-domain scores fall between 2.90 and 3.41. Two scores do clear it,
both on the single-item `overall` measure (staff 3.80, teachers 3.67), and both
in the smallest samples.

A banding scheme whose top category is awarded only by a one-item summary
measure is not discriminating usefully. Use the bands as orientation inside the
report — which answer the average respondent gave — and never as the headline.
Do not change the thresholds before cycle 2 (section 1).

**Ranking domains against each other within a role.** Domain means differ by
only 0.15–0.34 within a role, while item spread inside a single domain is
0.61. Saying "engagement is this school's weakest domain" rests on a smaller
difference than the variation it averages over. Cross-*role* comparison on the
same domain is a different matter and is sound — that is 2.1.

---

## 4. Methodology note — district-facing

Lift this into the report largely as written.

> **How to read these numbers.** Every statement in this report rests on a
> 1–4 agreement scale: 1 Strongly Disagree, 2 Disagree, 3 Agree, 4 Strongly
> Agree. There is no neutral option, so a score of 3.0 means the typical
> respondent agreed. Scores are reported for all respondents who rated a
> question; where a quotation appears, it comes from the subset who chose to
> speak.
>
> **This is a baseline.** It describes how four groups in this district
> perceived their school in November 2026. It is the measurement against which
> a second cycle later this year will be compared, and it is most useful read
> that way.
>
> **What these results support.** Differences between respondent groups on the
> same domain, where this report flags them as beyond chance. The rank order of
> statements within a group — which statements a group was most and least
> likely to agree with. The proportion of each group agreeing with each
> statement. The spread of opinion within a group.
>
> **What these results do not support.**
>
> 1. *That any score is high or low compared with other schools.* No comparison
>    group exists for this instrument. The thresholds used for orientation in
>    this report were chosen by Engaging Education Solutions and are not
>    norm-referenced. What counts as an acceptable score for this district is
>    the district's judgement, not a finding of this survey.
> 2. *That a lower-rated statement describes a worse condition than a
>    higher-rated one.* Statements differ in how readily anyone agrees with
>    them, independent of conditions. Separating that from genuine differences
>    in experience requires calibration across many schools, which does not yet
>    exist. Rank order within a group is reported as an observation and a
>    starting point for inquiry, not as a severity ranking.
> 3. *That one group's score is numerically equivalent to another's.* The four
>    groups answered parallel but different sets of statements. Differences
>    between groups are differences in reported perception, not measured
>    discrepancies on identical questions.
> 4. *Anything causal.* These are perceptions at one point in time, with no
>    linked outcome data and no comparison condition.
> 5. *Generalisation beyond the people who responded.* [Insert the response
>    rate per group once denominators are in — "87 of N students responded,
>    X%".] Where the rate is high, the results describe most of that group.
>    Where it is low, the respondents chose to take part and may differ from
>    those who did not, in ways this survey cannot measure.
> 6. *Statistical findings for non-instructional staff.* Eleven staff
>    responded. Staff results appear as counts of respondents, are descriptive
>    only, and should not drive priorities on their own.
> 7. *That the absence of a top-band score indicates a problem.* On this kind
>    of scale, top-band scores are uncommon in any institution.

---

## 5. Thresholds for cycle 2 — publish these now

Minimum detectable change in a domain mean, treating the respondent as the unit
of analysis rather than the individual rating:

| role | respondents | MDC |
|---|---|---|
| students | 82–87 | **0.09–0.12** |
| teachers | 31–32 | 0.14–0.19 |
| parents | 25–29 | 0.20–0.25 |
| staff | 10–11 | **0.21–0.42** |

Reading: a 0.10 move in a student domain mean next cycle is real. The same move
in a parent mean is not.

**These are upper bounds, and the denominators will lower them — possibly a
lot.** The figures above treat each group as a sample from an effectively
infinite population. Where respondents are a large share of the group that
could have answered, a finite-population correction applies:
SE × √((N−n)/(N−1)). Denominators are being obtained for cycle 1, so the table
should be recomputed before publication rather than issued as it stands. What
is at stake:

| role | n | if N = | response rate | MDC becomes |
|---|---|---|---|---|
| students | 87 | 95 | 92% | **0.03** |
| | | 150 | 58% | 0.06 |
| | | 500 | 17% | 0.08 |
| teachers | 32 | 35 | 91% | **0.05** |
| | | 60 | 53% | 0.10 |
| | | 200 | 16% | 0.14 |
| parents | 29 | 40 | 72% | **0.12** |
| | | 150 | 19% | 0.20 |
| staff | 11 | 15 | 73% | **0.11** |
| | | 25 | 44% | 0.16 |
| | | 80 | 14% | 0.20 |

The staff row is the consequential one. If Pleasanton employs around fifteen
non-instructional staff and eleven answered, the detectable change halves to
roughly 0.11 and **staff become usable for trend** rather than directional
only — the opposite of the conclusion the uncorrected figure supports. If the
pool is forty or more, 11 respondents stay exploratory and participation is the
only fix. Do not finalise limitation 6 in the district note until the
denominator is known.

A high response rate helps twice over: it tightens the interval, and it narrows
the room for self-selection bias, which is the limitation the correction does
not address.

Two caveats the denominators do not remove. These estimates assume respondents
are independent and the sampling roughly normal, which is approximate for
ordinal data and unreliable at n=10 regardless of the correction. And they
assume independent samples across cycles: matched respondents would detect
considerably smaller changes.

**On matched respondents.** Linking individuals across cycles would improve
precision materially. It also conflicts with what participants were told — the
token system is deliberately not person-linked, and respondents were assured
that no one can attribute an answer to them. That is a consent question for the
district to decide before cycle 2 fieldwork, not a technical change to make
quietly.

---

## 6. Before cycle 2

**Freeze:** items, wording, domain membership, the 1–4 scale, score thresholds.

**Get now, for cycle 1 itself** — these are obtainable retroactively and the
report should not publish without them, because they change section 5's numbers
and remove a limitation from the district note:

- Students enrolled in the surveyed population. State which grades, since the
  denominator must match who was invited rather than total district enrolment.
- Certificated teaching staff.
- Non-instructional staff. The consequential one: at a pool of ~15 the staff
  findings become usable, at 40+ they stay exploratory.
- Parent denominator, with the unit stated explicitly. 29 parent respondents
  against households is a different rate than against individual parents or
  guardians, and the two are not interchangeable. Pick one, record which.

Then recompute the section 5 table, fill limitation 5 in the district note, and
settle the staff guidance.

**Capture for cycle 2:** the same denominators again, since enrolment moves.
Nothing else about scoring — additions are safe, changes are not.

**Pre-specify the comparisons for cycle 2.** Testing all eighteen role pairs
cost four of five apparent findings to the multiplicity correction, including
one (students vs teachers on environment, p = 0.0065) that misses the boundary
by 0.0009. Naming the contrasts of interest in advance — the student-versus-
teacher comparison on each of the three domains is the obvious candidate, three
tests rather than eighteen — recovers that power honestly. Write them into this
document before the second wave is collected, not after seeing it.

**Fix, none of which affects comparability:**

- Staff participation. n=11 makes the role uninterpretable at any precision.
- Parent instrument length, or item order within it — 28% attrition.
- `question_text` in the export. Added to `export-school.mjs` 2026-11-11; the
  export needs re-running. Question ids are post-renumbering (`SC_STU_04` and
  the like) and **neither repository contains a lookup table** — only a comment
  at `server.js:6913`. Until the re-run, the item-level findings in 2.2 cannot
  be read by anyone without the live survey in front of them.
- The modal-over-error-screen bug, the mic-nudge `everHeardSpeech` case, and
  `SCLTEST-` prefixing for test tokens. All documented, none affecting data.

---

## 7. Provenance

Section 2.1 was computed for this document and then revised: its first draft
reported five cross-role differences at an uncorrected ±1.96 cutoff, and
permutation testing with Holm and Benjamini–Hochberg correction left one
standing. One of the five did not hold even uncorrected once normality was
dropped. `verify-crossrole.py` reproduces the whole table. The r = 0.877 figure
was computed for this document. The item
spread, its two artefact checks, the MDC estimates and the completion curves
were computed 10–11 November 2026 and are reproducible from the export.

Three independent analyses were run against the cycle 1 data — this one and two
external models — and converged on the same structure: lead with items and
cross-group contrast in cycle 1, lead with change in cycle 2, report
distributions rather than bare means, treat staff as descriptive, make no
item-difficulty claim. The convergence is from different starting framings and
is the main reason for confidence in the ordering in section 2.

Two findings came from outside this analysis: the completion curves in 2.5 and
the finite-population point in section 5. Two external suggestions were
rejected: banding derived from the observed distribution, which re-cuts itself
every cycle and would destroy cross-cycle comparability, and pooling staff with
teachers, who answered different items.

The claim that the 3.5 threshold requires zero ratings below 3 is false and
should not appear anywhere: `SC_STF_14` has a mean of exactly 3.50 with an SD
of 0.71.
