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

**The comparison to run is same-item, not same-domain.** An earlier draft of
this section compared domain means between roles and reported students 0.36
below teachers on safety. That comparison is confounded, and limitation 3 of
this document's own district note says why: the roles answer parallel but
different question sets, so a domain mean reflects which items are in the
bucket as much as what anyone thinks. Students' safety domain carries "Bullying,
in person or online, is rare at this school" (2.77) and "Students treat each
other with respect" (2.74) — peer-conduct questions teachers were never asked.
Teachers' carries "Students treat teachers with respect" (3.22), a different
construct. Much of that 0.36 was item composition.

The 2026-11-12 export, the first to carry question text, shows that **fourteen
questions are put to more than one role word for word.** Those comparisons need
no caveat. Fifty-two of them are available; all were tested by permutation
(20,000 shuffles, no normality assumed) with bootstrap intervals and both Holm
and Benjamini–Hochberg corrections — `verify-crossrole.py`.

**One survives, under both corrections:**

> **"Teachers and staff treat students with respect."**
> students **3.01, 81% agreed** (n=85) · teachers **3.56, 100% agreed** (n=32)
> difference −0.55, p = 0.0001, bootstrap 95% CI [−0.78, −0.33]

Every teacher who answered agreed. One student in five did not. Same question,
same words, no item-composition caveat and no norm group required — this is the
most defensible finding in the deployment, and it is both larger and cleaner
than the domain-level gap it replaces.

**The pattern is itself a finding, and it can be tested rather than asserted.**
Students score below teachers on **9 of 9** shared items and below staff on
**10 of 11**. Sign tests on the item-level differences give p = 0.0039 and
p = 0.0117. Teachers against staff is 5 of 11, p = 1.00 — the adult groups do
not differ from each other systematically. So the result is not "the groups
disagree"; it is that **students see this school less positively than the
adults in it do**, holding across two independent adult comparators.

Treat this as an omnibus result, not licence to assert individual items. The
items are not independent — the same 87 students answer all of them — so the
sign test slightly overstates its own confidence, and none of the individual
comparisons below the first survives correction across fifty-two tests. The
next four by p-value are coherent with the confirmed one and are reportable as
pattern, not as separate claims: adults expect every student to do well (81% vs
96%), overall a good school (92% vs 100%), **disciplined fairly, no matter who
they are (55% vs 81%)**, and feeling safe (94% vs 97%).

**Word this carefully, because the obvious phrasing is wrong.** The finding is
not that students feel disrespected — four in five said they are treated with
respect, 94% said they feel safe, and 92% said this is a good school. It is
that the adults are close to unanimous and the students are not. In a district
with a supportive community and a renovation under way, a report that leads
with the gap and omits the 81% will misrepresent the school to its own board.
Both numbers belong in the same sentence, every time.

This is the lead. It needs no norms, no banding scheme and no multiplicity
apology, and it points at something a school can actually work on.

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

**It is the lowest-favorability item for three of the four roles** — parents
43%, teachers 52%, students 54%. That makes it the one place in this
deployment where the adults are *not* more positive than the students, and it
is the clearest evidence that this is a district-wide readiness question rather
than anything about climate or about how any group experiences the school.

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

### 2.7 Fieldwork conditions — record these before anything else

**The building was under active renovation throughout the survey window**
(3–11 November 2026). This is the most important piece of context attached to
the data and it must be stated in the cycle 1 report, not recalled in cycle 2.

The renovation is one of the things stakeholders value about this district. The
survey caught it at its most disruptive point. A report that presents
facilities as a weakness, without saying the facilities are mid-rebuild, tells
the board something false.

Three consequences, each carried into the section it affects:

1. **It does NOT explain the environment scores — this was checked and the
   reading was wrong.** The environment domain here is the EDSCLS
   *institutional* one (discipline, substance use, emergency readiness) and
   contains no question about the physical building. Its lowest item asks
   whether students are disciplined fairly. See 8.2.
2. **It does not explain the confirmed cross-role finding either**, which is
   about whether adults treat students with respect, on a question put to both
   roles verbatim.
3. **It is a plausible explanation for the fabricated transcriptions, and the
   timestamps neither confirm nor refute it.** Fifteen answers across eight
   sessions were garbled by background noise loud enough to make the audio
   unparseable; the working theory during fieldwork was a vacuum cleaner.
   Construction noise fits a nine-day window better than cleaning does, so the
   session times were checked. All eight fall between 10am and 2pm — but so
   does the bulk of all activity (128 of 153 timestamped sessions, and 134 of
   159 on 9 November alone). The fabrication rate is 6.3% inside that window
   and 0% across the 25 sessions outside it, where the base rate predicts about
   1.6. Zero is unremarkable at that count (p ≈ 0.19). **The test does not
   distinguish the theories**, and the deployment is too concentrated in one
   morning for any timing analysis to. Record it as an open question, not a
   finding, and schedule cycle 2 across more days — which would answer it as a
   side effect.

Record the construction timeline now: start date, expected completion, and
which parts of the building were out of use during the survey window. Cycle 2's
interpretation depends on knowing whether it ran before or after completion,
and nobody will reconstruct this accurately in six months.

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

**Ceiling effects, which matter here more than they would elsewhere.** This
district scores well: 58 of 69 items sit at or above 75% favorable, and
teachers are at 96% on safety. An item at 90%+ favorable has almost nowhere to
move upward, so cycle 2 cannot show improvement there no matter what the
district does. Two consequences for how the second cycle is read:

- Expect movement, if any, in the lower-scoring items. Watch
  `SC_STU_08` (55% favorable), `SC_STF_13` (40%) and student environment
  generally. Treat stability at the top as the success condition it is, not as
  a failure to improve.
- **Construction does not create a protected prediction here.** An earlier
  draft said environment would rise in cycle 2 for reasons unrelated to
  anything the district did. That rested on reading environment as the physical
  building, which it is not (2.7, 8.2). No domain in this instrument is
  mechanically tied to the renovation finishing, so cycle 2 movement is not
  pre-discounted. The construction still belongs in the cycle 1 report as a
  condition of fieldwork; it is not an explanation for any score.
- Do not report a district-wide average of movement across all items. In a
  high-scoring district that average is held near zero by the ceiling and will
  understate real change in the places change was actually attempted.

This is the one respect in which doing well makes the product harder, and it
should be said to the district in cycle 1 rather than explained away in
cycle 2.

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

**Also record now, while it is knowable:** the construction start date, expected
completion, and which parts of the building were out of use during the 3–11
November window. Whether cycle 2 runs before or after completion determines how
its environment and safety results can be read, and this will not be
reconstructable later.

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

## 7. Band schemes tested against this data, and rejected

Recorded because the question returns every time someone proposes a threshold.
All figures are from the 69 rated items in `pps-2026-27`.

**The current four-band scheme** (≥3.5 Strength / 3.0–3.49 / 2.5–2.99 / ≤2.49).
Nothing reached the top band on a substantive domain — all twelve role-domain
scores fall between 2.90 and 3.41. The two scores that clear 3.5 are both the
single-item `overall` measure, in the two smallest samples. **Top band awarded:
0 of 12.**

**FEVS-style favorability bands**, synthesised from federal and district
practice (Strength ≥75% favorable, Watch 60–74%, Challenge ≥40% unfavorable,
Urgent ≥20% Strongly Disagree). Applied here:

| | result |
|---|---|
| Strength | **58 of 69 items (84%)** |
| Watch | 7 |
| Challenge | 5 — of which **3 are AI Readiness** |
| Urgent | **0** — highest Strongly-Disagree rate on any item is 16% |

By role: teachers 89% of items a strength, parents 88%, staff 88%,
students 72%.

**An important caution about reading that as miscalibration.** Pleasanton is a
small district with a recent building renovation, growing enrolment and a
supportive community — genuinely positive attributes its stakeholders
recognise. High favorability may be a correct measurement of a well-regarded
district rather than evidence that the thresholds are wrong. With one district
these two readings are observationally identical and cannot be separated. An
earlier draft of this section treated 84% strengths as proof the scheme had
failed; that inference was unsound.

The recommendation survives on a different footing. Because the two readings
cannot be distinguished, **a report asserting "this is a Strength" is making a
claim the data cannot support either way**, while a report stating "80% of
students agreed" is accurate under both. The case against banding is not that
the scores are too high. It is that the verdict is unsupportable and the number
is not.

Two of the scheme's four item rules are also the same rule: with no neutral
option,
unfavorable = 100 − favorable, so "≥40% unfavorable" is "≤60% favorable." That
independence holds on FEVS's 5-point scale, which has a neutral band between
the two, and cannot hold here. Watch and Challenge also collide at exactly 60%.

Strip the three AI Readiness items, which belong in their own section, and the
scheme identifies two climate challenges in the whole district: `SC_STU_08`
(55% unfavorable) and `SC_STF_13` (60% unfavorable on n=10 — six people, at the
privacy floor).

**EDSCLS performance levels** (Least Favorable <300, Favorable 300–400, Most
Favorable >400). Not adoptable: the cut points are Rasch-calibrated on roughly
100 schools and adjust for item difficulty, which raw means do not. Translated
onto a 1–4 mean the three levels are <3.0, 3.0–4.0 and 4.0, which puts ten of
twelve role-domain scores in a single band. EDSCLS is a sound **citation** for
anchoring bands to response categories rather than to quality judgements. It is
not a scoring system that can be borrowed without the calibration.

**Bands derived from the observed distribution** (lower/mid/upper third of
range). Rejected on principle: the cuts move every cycle and every school, so a
district could improve on every item and read the same label. For a product
whose purpose is cross-cycle comparison this is actively harmful.

**Percentile or norm-referenced bands** — Panorama's 20-point national buckets,
YouthTruth's percentile ranks, Gallup's quintiles, 5Essentials' labels. All
require a norm database. They are the right destination and are unavailable
until Clarity has enough districts to build one.

The common failure is the same in every case: a cut point calibrated against
some other population's distribution, imported whole. FEVS's 65% comes from the
federal workforce; EDSCLS's 300 from a hundred volunteer schools. Dropped onto
this district they either award everything or nothing. **A borrowed threshold
is worse than an invented one, because its provenance makes it harder to
question later.**

---

## 8. The reporting frame for cycle 1

This is the decision that lets the report be written. It removes banding as the
organising device and replaces it with four lenses, none of which needs a norm
group.

**It changes presentation, not scoring.** The freeze in section 1 covers items,
wording, domain membership, the scale, and any threshold used in a computation.
It does not cover what the report says about the numbers. Nothing below alters
a stored value or a computed average, so cross-cycle comparability is intact.

### 9.1 Percent favorable, as a number, with no verdict attached

The headline metric for every item and domain: the share answering Agree or
Strongly Agree. It needs no threshold anyone has to defend, it is what a board
understands without a scoring key, and it is the one choice on which EDSCLS,
Panorama, FEVS and three independent analyses of this data all agree.

Report the mean beside it, never instead of it. They correlate at r = 0.877
across these 69 items and are not interchangeable: 18 items clear 85%
favorable while their mean sits below 3.25.

Available in the frontend today — all three climate generators already hold
`rd.sessions[].ratings` (`admin/page.tsx` 908, 1276, 1432), so this requires no
backend change and no `server.js` deploy.

### 9.2 Within-group rank order

Which statements each group was most and least likely to agree with. Reported
as **observed rank order and dispersion**, never as a severity ranking — see
limitation 2 in the district note. This is where the actionable detail is: item
spread within a domain runs a median 0.61, against 0.15–0.34 between domains.

Report high-dispersion items separately from low-scoring ones. A low score with
a tight spread is a shared view; a middling score with a wide spread is a split
constituency, and the two need different responses. `SC_STF_08` (SD 1.06) and
`SC_PAR_07` (SD 0.99) are invisible in any mean-based summary.

Known district context belongs here as a source of hypotheses to check, and as
a condition stated plainly where it is known — but never as an explanation the
report asserts for a specific score. The building was under active construction
during fieldwork (2.7), and student environment is this district's
lowest-scoring domain (2.90, 74% favorable), holding `SC_STU_08`, the lowest
item in the deployment (2.54, 55% favorable, 16% Strongly Disagree — also the
highest intensity recorded anywhere in it).

**The export settled this on 2026-11-12, and the construction reading was
wrong.** `SC_STU_08` is *"Students at this school are disciplined fairly, no
matter who they are."* It has nothing to do with facilities. The inference that
led there — environment is lowest, the building is mid-renovation, therefore
students are reacting to the building — was an artifact of reading the domain
label rather than the items. In this instrument "environment" is the EDSCLS
*institutional* sense and carries discipline, substance use and emergency
readiness. No item in it asks about the physical building at all.

Keep the general rule that produced the error as a warning: **context suggests
hypotheses, item text settles them, and the order matters.** Three separate
readings of this deployment — a renovation effect, a facilities complaint, a
diffuse-frustration effect — were all built on a domain name.

What is actually there is a theme, and a sharper one. Students' five
lowest-scoring items are: disciplined fairly (2.54, 55% agreed, 16% strongly
disagreed), AI guidance (2.62 — the policy gap, 2.4), **my input is valued when
decisions are made** (2.66, 65%), students treat each other with respect (2.74,
68%), and bullying is rare (2.77, 64%). Their three highest are *I feel safe at
this school* (3.38, 94%), *this school is prepared to handle an emergency*
(3.37, 95%) and *overall, this is a good school* (3.29, 92%).

That reads as two clusters — institutional fairness and voice, and peer
conduct — inside a school its students plainly think well of. It is reportable
as rank order and theme without a single threshold, and the 16% strongly
disagreeing that discipline is applied fairly is the most pointed number in the
deployment.

### 9.3 Cross-group gaps — surfaced by rule, asserted by test

Use a 15-point favorability gap to **surface** candidates. Assert only what a
test supports. On this data the rule flags safety students-vs-teachers (16
points) and environment students-vs-staff (16 points); the first survives
familywise correction at p = 0.0001 and the second does not survive at all
(p = 0.042). The rule cannot tell them apart. That is the test's job, and
Hanover's convention — test at 95%, mark significant differences with an
asterisk — is the right presentation.

### 9.4 Intensity, where it is non-trivial

Percent choosing Strongly Disagree, reported as a number for items where it is
material, with no threshold. The Urgent rule at 20% never fires here (the
maximum is 16%), but the underlying point stands: intensity is information that
percent favorable discards, and the top of that distribution —
`SC_STU_08` 16%, `SC_PAR_15` 14%, `SC_PAR_10` 13% — is worth naming.

### 9.5 What the report asserts

Everything above is reported as an observation with its number attached. The
report **asserts** only:

1. The one cross-role difference that survives correction (2.1).
2. Descriptive facts: counts, percentages, rank orders, response rates.
3. The limits in section 4.

It asserts no verdict on whether a score is good, no ranking of domains within
a role, no severity ordering of items, and no comparison to other schools.
Where the district wants a judgement about acceptability, that judgement is
theirs and the report says so.

---

## 9. Provenance

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
