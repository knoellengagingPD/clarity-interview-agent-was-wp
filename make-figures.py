#!/usr/bin/env python3
"""Compose the rings into one figure per place they appear in the report.

A row of rings is one picture, not four. Six figures instead of twenty-two
images keeps the document tidy, keeps the set together if anything is moved,
and means an insert cannot land three of four.

    python3 -I make-figures.py

Reads rings/*.svg, writes figures/*.svg and figures/*.png.
"""
import os, re, glob
import importlib.util

spec = importlib.util.spec_from_file_location('mr', 'make-rings.py')
# make-rings.py runs argparse at import, so read its pieces rather than import.
src = open('make-rings.py').read()
ns = {}
exec(src.split('ap = argparse.ArgumentParser()')[0], ns)
ring, STANDARD = ns['ring'], ns['STANDARD']
BY = {n: (p, l, t) for n, p, l, t in STANDARD}

W, H = 400, 454          # one ring tile, including its caption

GROUPS = {
    'fig-overall':   ['overall-students', 'overall-teachers', 'overall-staff', 'overall-parents'],
    'fig-ai':        ['ai-students', 'ai-teachers', 'ai-staff', 'ai-parents'],
    'fig-discipline':['discipline-students', 'discipline-teachers', 'discipline-staff', 'discipline-parents'],
    'fig-safety':    ['safety-students', 'safety-teachers', 'safety-staff', 'safety-parents'],
    'fig-lowest':    ['ai-parents', 'ai-teachers', 'ai-students', 'discipline-students', 'staff-communication'],
    # All four roles: the Options section ran six long paragraphs with no
    # figure at all, and student voice is the subject of the last of them.
    'fig-input':     ['input-valued-students', 'input-valued-teachers',
                      'input-valued-staff', 'input-valued-parents'],
    # Four more through the back half, each tied to a rated question rather
    # than decorating prose. Resources is four different questions, one per
    # role, so each tile names its own -- the report's limitation 3 forbids
    # treating them as one comparison.
    'fig-expect':    ['expect-students', 'expect-teachers', 'expect-staff', 'expect-parents'],
    'fig-safe':      ['safe-students', 'safe-teachers', 'safe-staff'],
    'fig-concern':   ['concern-students', 'concern-teachers', 'concern-staff'],
    'fig-resources': ['res-students', 'res-teachers', 'res-staff', 'res-parents'],
    'fig-respect':   ['respect-students', 'respect-teachers', 'respect-staff', 'respect-parents'],
    'fig-belong':    ['belong-students', 'belong-teachers', 'belong-staff'],
    # Peer conduct pairs two questions, each put to students and staff, so the
    # gap can be read on both without implying they are one measure.
    'fig-peer':      ['peer-students', 'peer-staff', 'bully-students', 'bully-staff'],
}


def inner(name):
    """One ring's markup, stripped of its own <svg> wrapper and backing rect."""
    pct, label, title = BY[name]
    s = ring(pct, label, title)
    s = re.sub(r'^.*?<rect[^>]*/>', '', s, flags=re.S)
    return s.rsplit('</svg>', 1)[0]


def tile_height(name):
    """The tile's real height, which is no longer a constant.

    H was hardcoded at 454 because every caption was one line. Once a question
    long enough to wrap arrived -- "My input is valued when decisions are made"
    -- the ring grew to 481 and the composer went on writing 454, so the grey
    "agreed or strongly agreed" line was cropped off the bottom of all four
    tiles. Nothing errored; the line was simply not in the PNG.
    """
    pct, label, title = BY[name]
    m = re.search(r'viewBox="0 0 \d+ (\d+)"', ring(pct, label, title))
    return int(m.group(1)) if m else H


os.makedirs('figures', exist_ok=True)
for fig, names in GROUPS.items():
    n = len(names)
    h = max(tile_height(nm) for nm in names)
    tiles = ''.join(
        f'<g transform="translate({i * W},0)">{inner(nm)}</g>' for i, nm in enumerate(names)
    )
    out = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n * W} {h}" '
           f'width="{n * W}" height="{h}">'
           f'<rect width="{n * W}" height="{h}" fill="#FFFFFF"/>{tiles}</svg>\n')
    open(f'figures/{fig}.svg', 'w').write(out)
print(f'wrote {len(GROUPS)} figures')
