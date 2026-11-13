#!/usr/bin/env python3
"""Agreement rings for the climate reports.

A green band whose length is the percentage who agreed, ending in an
arrowhead. The band stops where the arrowhead begins, so nothing shows past
the point: the head is the terminus, not a marker sitting on top of a longer
band. The remainder of the circle stays white and unlabelled, because the
report does not characterise disagreement — it reports the proportion who
agreed and leaves the rest to the reader.

    python3 -I make-rings.py            # the standard set for pps-2026-27
    python3 -I make-rings.py --pct 72 --label "72% Agree" --out one.svg

Writes SVG, which Google Docs accepts by drag-and-drop and which stays sharp
at any size. Nothing here reads the export; the figures are passed in, so a
ring can never disagree with the number beside it in the text.
"""
import argparse
import math
import os

GREEN = '#2E7D32'
BAND = 84          # thickness of the ring
R_OUT = 176        # outer radius
SIZE = 400
CX = CY = SIZE / 2
R_MID = R_OUT - BAND / 2
R_IN = R_OUT - BAND

# How much of the arc the arrowhead occupies, in degrees. The band is drawn
# short by exactly this much so the two meet without overlapping.
HEAD_DEG = 15.0


def pt(deg, r):
    """Polar to cartesian, 0 degrees at twelve o'clock, clockwise."""
    a = math.radians(deg - 90)
    return CX + r * math.cos(a), CY + r * math.sin(a)


def ring(pct: float, label: str) -> str:
    pct = max(0.0, min(100.0, float(pct)))
    total = pct * 3.6

    # A full circle has no end to point at, and two arcs that meet are drawn
    # as one closed ring instead.
    if total >= 359.5:
        body = (
            f'<circle cx="{CX}" cy="{CY}" r="{R_MID}" fill="none" '
            f'stroke="{GREEN}" stroke-width="{BAND}"/>'
        )
    else:
        arc = max(0.0, total - HEAD_DEG)
        x0, y0 = pt(0, R_MID)
        x1, y1 = pt(arc, R_MID)
        large = 1 if arc > 180 else 0
        body = (
            f'<path d="M {x0:.2f} {y0:.2f} A {R_MID} {R_MID} 0 {large} 1 '
            f'{x1:.2f} {y1:.2f}" fill="none" stroke="{GREEN}" '
            f'stroke-width="{BAND}" stroke-linecap="butt"/>'
        )
        # The head: a triangle spanning the full band width at the arc's end,
        # with its apex on the mid-radius a little further round.
        # The base overhangs the band on both sides, which is what makes it
        # read as an arrowhead rather than a spike.
        bx1, by1 = pt(arc, R_OUT + 17)
        bx2, by2 = pt(arc, R_IN - 17)
        tipx, tipy = pt(total, R_MID)
        body += (
            f'<polygon points="{bx1:.2f},{by1:.2f} {bx2:.2f},{by2:.2f} '
            f'{tipx:.2f},{tipy:.2f}" fill="{GREEN}"/>'
        )

    # Label sits in the band at the bottom, white on green, as in the sample.
    lx, ly = pt(180, R_MID)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {SIZE} {SIZE}" width="{SIZE}" height="{SIZE}" role="img" aria-label="{label}">
  <rect width="{SIZE}" height="{SIZE}" fill="#FFFFFF"/>
  {body}
  <text x="{lx:.0f}" y="{ly:.0f}" fill="#FFFFFF" font-family="Arial, Helvetica, sans-serif"
        font-size="30" font-weight="700" text-anchor="middle" dominant-baseline="central">{label}</text>
</svg>
'''


# The figures the report states. Kept here rather than computed, so a ring and
# the sentence beside it cannot drift apart.
STANDARD = [
    ('overall-students', 92, '92% Agree'),
    ('overall-teachers', 100, '100% Agree'),
    ('overall-staff', 100, '100% Agree'),
    ('overall-parents', 90, '90% Agree'),
    ('safety-students', 80, '80% Agree'),
    ('safety-teachers', 96, '96% Agree'),
    ('safety-staff', 88, '88% Agree'),
    ('safety-parents', 85, '85% Agree'),
    ('engagement-students', 79, '79% Agree'),
    ('engagement-teachers', 82, '82% Agree'),
    ('engagement-staff', 80, '80% Agree'),
    ('engagement-parents', 91, '91% Agree'),
    ('environment-students', 74, '74% Agree'),
    ('environment-teachers', 87, '87% Agree'),
    ('environment-staff', 90, '90% Agree'),
    ('environment-parents', 84, '84% Agree'),
    ('ai-students', 54, '54% Agree'),
    ('ai-teachers', 52, '52% Agree'),
    ('ai-staff', 70, '70% Agree'),
    ('ai-parents', 43, '43% Agree'),
    ('discipline-students', 55, '55% Agree'),
    ('discipline-teachers', 81, '81% Agree'),
    ('discipline-staff', 90, '90% Agree'),
    ('discipline-parents', 76, '76% Agree'),
    ('staff-communication', 60, '60% Agree'),
    ('input-valued-students', 65, '65% Agree'),
]

ap = argparse.ArgumentParser()
ap.add_argument('--pct', type=float)
ap.add_argument('--label')
ap.add_argument('--out', default='rings')
a = ap.parse_args()

if a.pct is not None:
    out = a.out if a.out.endswith('.svg') else a.out + '.svg'
    open(out, 'w').write(ring(a.pct, a.label or f'{a.pct:g}% Agree'))
    print(f'wrote {out}')
else:
    os.makedirs(a.out, exist_ok=True)
    for name, pct, label in STANDARD:
        p = os.path.join(a.out, f'{name}.svg')
        open(p, 'w').write(ring(pct, label))
    print(f'wrote {len(STANDARD)} rings to {a.out}/')
