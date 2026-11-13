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
CAPTION = 58        # strip under the ring for the title
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


def ring(pct: float, label: str, title: str = '') -> str:
    pct = max(0.0, min(100.0, float(pct)))
    total = pct * 3.6

    # At 100% the ring still ends in an arrowhead rather than closing into a
    # plain circle: the arrow is what says "this is a proportion that ran all
    # the way round", and a bare ring at 100% looks like a different chart
    # from the one beside it at 96%. The head overlaps the start, which is
    # what a complete loop should look like.
    if total >= 359.5:
        total = 360.0
    if False:
        pass
    else:
        # The band's right-hand end sits at twelve o'clock and it sweeps
        # clockwise from there, which is the shape of the original.
        start = 0.0
        # A degree of overlap into the head: butted exactly, the arc's flat
        # end and the triangle's base leave a hairline seam when rendered.
        arc_end = min(total - HEAD_DEG + 1.0, 359.0)
        x0, y0 = pt(start, R_MID)
        x1, y1 = pt(arc_end, R_MID)
        arc = arc_end - start
        large = 1 if arc > 180 else 0
        body = (
            f'<path d="M {x0:.2f} {y0:.2f} A {R_MID} {R_MID} 0 {large} 1 '
            f'{x1:.2f} {y1:.2f}" fill="none" stroke="{GREEN}" '
            f'stroke-width="{BAND}" stroke-linecap="butt"/>'
        )
        # The head: a triangle spanning the full band width at the arc's end,
        # its base overhanging on both sides so it reads as an arrowhead
        # rather than a spike, with the apex on the mid-radius further round.
        bx1, by1 = pt(arc_end, R_OUT + 17)
        bx2, by2 = pt(arc_end, R_IN - 17)
        tipx, tipy = pt(total, R_MID)
        body += (
            f'<polygon points="{bx1:.2f},{by1:.2f} {bx2:.2f},{by2:.2f} '
            f'{tipx:.2f},{tipy:.2f}" fill="{GREEN}"/>'
        )

    # The label follows the band as a curve, sitting at six o'clock where
    # there is band under it and as near to six as the band allows where
    # there is not.
    #
    # Set straight it runs off the green at both ends and into the hole: the
    # band is 84 units thick and curved, the text a 150-unit horizontal
    # chord. And with the band starting at twelve it only reaches the bottom
    # above 50%, so for 43%, which stops at 155 degrees, a bottom label would
    # sit on white. The full "43% Agree" needs about 96 degrees of arc, more
    # than a short band has spare, so there the figure goes alone and the
    # text stays horizontal rather than running down the side.
    #
    # Anticlockwise, or the text comes out mirrored along the bottom.
    # The band carries the figure alone.
    #
    # "96% Agree" fits a long band and "43% Agree with Statement" fits no band
    # at all, so putting the meaning here makes the wording depend on the
    # number, which is how a chart ends up saying different things about the
    # same question. The caption below says what agreeing meant, and has room
    # to say it accurately -- including for the AI-readiness items, which are
    # not an agree scale at all but "Not at all prepared" to "Very prepared".
    label = label.split('%')[0] + '%'
    span = 22.0
    # Clear of the arrowhead: the head takes the last HEAD_DEG of the arc,
    # and at 54% a label placed two degrees short of the end ran into it.
    centre = min(180.0, max(span + 2.0, total - HEAD_DEG - span - 8.0))
    ax, ay = pt(centre + span, R_MID)
    bx, by = pt(centre - span, R_MID)
    sweep = 0
    # The title sits under the ring in small dark text, so a reader coming to
    # the figure cold knows which group and which question it is.
    # Two lines, because one ran past the tile: "Teachers - Safety . agreed
    # or strongly agreed" is about 450 units at 20pt against a 400-unit tile.
    # Who and what on the first line, what the figure means on the second.
    main, _, meaning = title.partition(' \u00b7 ')
    cap = ''
    if title:
        cap = (f'<text x="{CX}" y="{SIZE + 22}" fill="#1F2937" '
               f'font-family="Arial, Helvetica, sans-serif" font-size="20" '
               f'text-anchor="middle">{main}</text>')
        if meaning:
            cap += (f'<text x="{CX}" y="{SIZE + 45}" fill="#6B7280" '
                    f'font-family="Arial, Helvetica, sans-serif" font-size="16" '
                    f'text-anchor="middle">{meaning}</text>')
    h = SIZE + (CAPTION if title else 0)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {SIZE} {h}" width="{SIZE}" height="{h}" role="img" aria-label="{title or label}">
  <rect width="{SIZE}" height="{h}" fill="#FFFFFF"/>
  {cap}
  {body}
  <defs><path id="lbl" d="M {ax:.2f} {ay:.2f} A {R_MID} {R_MID} 0 0 {sweep} {bx:.2f} {by:.2f}"/></defs>
  <text fill="#FFFFFF" font-family="Arial, Helvetica, sans-serif" font-size="30" font-weight="700">
    <textPath href="#lbl" startOffset="50%" text-anchor="middle" dominant-baseline="central">{label}</textPath>
  </text>
</svg>
'''


# The figures the report states. Kept here rather than computed, so a ring and
# the sentence beside it cannot drift apart.
STANDARD = [
    ('overall-students', 92, '92% Agree', 'Students — Overall, this is a good school · agreed or strongly agreed'),
    ('overall-teachers', 100, '100% Agree', 'Teachers — Overall, this is a good school · agreed or strongly agreed'),
    ('overall-staff', 100, '100% Agree', 'Staff — Overall, this is a good school · agreed or strongly agreed'),
    ('overall-parents', 90, '90% Agree', 'Parents — Overall, this is a good school · agreed or strongly agreed'),
    ('safety-students', 80, '80% Agree', 'Students — Safety · agreed or strongly agreed'),
    ('safety-teachers', 96, '96% Agree', 'Teachers — Safety · agreed or strongly agreed'),
    ('safety-staff', 88, '88% Agree', 'Staff — Safety · agreed or strongly agreed'),
    ('safety-parents', 85, '85% Agree', 'Parents — Safety · agreed or strongly agreed'),
    ('engagement-students', 79, '79% Agree', 'Students — Engagement · agreed or strongly agreed'),
    ('engagement-teachers', 82, '82% Agree', 'Teachers — Engagement · agreed or strongly agreed'),
    ('engagement-staff', 80, '80% Agree', 'Staff — Engagement · agreed or strongly agreed'),
    ('engagement-parents', 91, '91% Agree', 'Parents — Engagement · agreed or strongly agreed'),
    ('environment-students', 74, '74% Agree', 'Students — Environment · agreed or strongly agreed'),
    ('environment-teachers', 87, '87% Agree', 'Teachers — Environment · agreed or strongly agreed'),
    ('environment-staff', 90, '90% Agree', 'Staff — Environment · agreed or strongly agreed'),
    ('environment-parents', 84, '84% Agree', 'Parents — Environment · agreed or strongly agreed'),
    ('ai-students', 54, '54% Agree', 'Students — AI readiness · felt prepared'),
    ('ai-teachers', 52, '52% Agree', 'Teachers — AI readiness · felt prepared'),
    ('ai-staff', 70, '70% Agree', 'Staff — AI readiness · felt prepared'),
    ('ai-parents', 43, '43% Agree', 'Parents — AI readiness · felt prepared'),
    ('discipline-students', 55, '55% Agree', 'Students — Disciplined fairly · agreed or strongly agreed'),
    ('discipline-teachers', 81, '81% Agree', 'Teachers — Disciplined fairly · agreed or strongly agreed'),
    ('discipline-staff', 90, '90% Agree', 'Staff — Disciplined fairly · agreed or strongly agreed'),
    ('discipline-parents', 76, '76% Agree', 'Parents — Disciplined fairly · agreed or strongly agreed'),
    ('staff-communication', 60, '60% Agree', 'Staff — Communication among staff is open and honest · agreed or strongly agreed'),
    ('input-valued-students', 65, '65% Agree', 'Students — My input is valued when decisions are made · agreed or strongly agreed'),
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
    for name, pct, label, title in STANDARD:
        p = os.path.join(a.out, f'{name}.svg')
        open(p, 'w').write(ring(pct, label, title))
    print(f'wrote {len(STANDARD)} rings to {a.out}/')
