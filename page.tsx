/**
 * Drop-in replacement for src/app/page.tsx in find-my-purpose-app.
 *
 * ⚠️ BEFORE PASTING:
 *  1. Confirm the filenames of the four sketches in public/. This file assumes:
 *       public/images/mess.png       (person reading scribbled book)
 *       public/images/hands.png      (hands with flow annotations)
 *       public/images/rails.png      (flagged road / rails)
 *       public/images/calendar.png   (calendar graphic)
 *     If any of those differ, update the src values in IMAGE_PATHS below.
 *
 *  2. Wire in your existing logic at the two places marked `// WIRE:` below.
 *     Nothing else in the rest of the repo — routing, Stripe, access-code
 *     gate, session handling — should be touched.
 */

'use client';

import React from 'react';

// ---- Palette ----------------------------------------------------------------
const C = {
  bg:        '#1e1b17',
  text:      '#e8e0d4',
  heading:   '#f0e8dc',
  muted:     '#9a8f82',
  footer:    '#6b6054',
  accent:    '#c9714a',
  surface:   '#252017',
  border:    '#3a342c',
  pillBg:    '#2e2520',
  pillBorder:'#4a3828',
};

// ---- Image paths (edit if public/ has different names) ----------------------
const IMAGE_PATHS = {
  mess:     '/images/mess.png',
  hands:    '/images/hands.png',
  rails:    '/images/rails.png',
  calendar: '/images/calendar.png',
};

// ---- Wiring points ----------------------------------------------------------
// Replace these two function bodies with the existing calls already in use
// elsewhere in the app. The visual component stays the same either way.
function startCheckout() {
  // WIRE: replace with existing Stripe checkout trigger.
  // e.g. window.location.href = '/api/checkout';
  //      or: await fetch('/api/create-checkout-session', { method: 'POST' })...
  //      or: call the same handler the old landing page's CTA used.
  console.warn('[page.tsx] startCheckout() is not wired yet.');
}

function openAccessCodeFlow() {
  // WIRE: replace with existing access-code input trigger.
  // e.g. setShowAccessCodeModal(true)
  //      or: router.push('/access-code')
  //      or: whatever the old landing page invoked.
  console.warn('[page.tsx] openAccessCodeFlow() is not wired yet.');
}

// -----------------------------------------------------------------------------

export default function Page() {
  return (
    <div style={styles.root}>
      <Nav />
      <Hero />
      <SketchStrip />
      <TensionBlock />
      <HowItWorks />
      <CheckInStrip />
      <ForYouIf />
      <TrustRow />
      <BottomCTA />
      <Footer />
    </div>
  );
}

// ============================================================================
// Nav
// ============================================================================
function Nav() {
  return (
    <nav style={styles.nav}>
      <div style={styles.navInner}>
        <div style={styles.brand}>
          Find My <span style={{ color: C.accent }}>Purpose</span>
        </div>
        <div style={styles.earlyPill}>Early access — $27</div>
      </div>
    </nav>
  );
}

// ============================================================================
// Hero
// ============================================================================
function Hero() {
  return (
    <section style={styles.hero}>
      <div style={styles.kicker}>A 60-day voice-guided experience</div>

      <h1 style={styles.h1}>
        You already know something is{' '}
        <em style={{ color: C.accent, fontStyle: 'italic' }}>missing.</em>
      </h1>

      <Orb />

      <p style={styles.heroBody}>
        Find My Purpose is a voice conversation that helps you figure out what
        actually matters to you — not what you&apos;re supposed to want. Then
        it checks in for 60 days to make sure you&apos;re moving.
      </p>

      <div style={styles.priceRow}>
        <span style={styles.priceBig}>$27</span>
        <span style={styles.priceStrike}>$47</span>
        <span style={styles.priceNote}>early access, one-time</span>
      </div>

      <button
        type="button"
        onClick={startCheckout}
        style={styles.ctaButton}
        onMouseEnter={(e) =>
          (e.currentTarget.style.background = '#b76238')
        }
        onMouseLeave={(e) => (e.currentTarget.style.background = C.accent)}
      >
        Start the conversation →
      </button>

      <p style={styles.heroSubline}>
        10 minutes. No therapist. No jargon. Just honest questions.
      </p>
    </section>
  );
}

// ---- Orb SVG ---------------------------------------------------------------
function Orb() {
  return (
    <svg
      width="120"
      height="120"
      viewBox="0 0 120 120"
      xmlns="http://www.w3.org/2000/svg"
      style={{ margin: '28px auto 24px', display: 'block' }}
      aria-hidden="true"
    >
      <defs>
        <radialGradient id="orbBase" cx="36%" cy="30%" r="70%">
          <stop offset="0%" stopColor="#5a5248" />
          <stop offset="55%" stopColor="#2e2a25" />
          <stop offset="100%" stopColor="#18150f" />
        </radialGradient>
        <radialGradient id="orbShine" cx="33%" cy="26%" r="40%">
          <stop offset="0%" stopColor="#b89a7a" stopOpacity="0.5" />
          <stop offset="100%" stopColor="#b89a7a" stopOpacity="0" />
        </radialGradient>
        <radialGradient id="orbBloom" cx="72%" cy="76%" r="48%">
          <stop offset="0%" stopColor="#c9714a" stopOpacity="0.42" />
          <stop offset="55%" stopColor="#c9714a" stopOpacity="0.12" />
          <stop offset="100%" stopColor="#c9714a" stopOpacity="0" />
        </radialGradient>
      </defs>

      <circle cx="60" cy="60" r="56" fill="url(#orbBase)" />
      <circle cx="60" cy="60" r="56" fill="url(#orbShine)" />
      <circle cx="60" cy="60" r="56" fill="url(#orbBloom)" />
      <circle cx="42" cy="38" r="10" fill="#c4a882" opacity="0.11" />
      <circle
        cx="60"
        cy="60"
        r="56"
        fill="none"
        stroke="#5a5248"
        strokeWidth="0.5"
        opacity="0.5"
      />
    </svg>
  );
}

// ============================================================================
// Sketch strip
// ============================================================================
function SketchStrip() {
  const items: Array<{ src: string; label: string }> = [
    { src: IMAGE_PATHS.mess,  label: 'where you are' },
    { src: IMAGE_PATHS.hands, label: 'the conversation' },
    { src: IMAGE_PATHS.rails, label: 'a direction' },
  ];

  return (
    <section style={styles.sketchStrip}>
      {items.map((item) => (
        <div key={item.label} style={styles.sketchTile}>
          <img
            src={item.src}
            alt={item.label}
            style={styles.sketchImg}
          />
          <span style={styles.sketchLabel}>{item.label}</span>
        </div>
      ))}
    </section>
  );
}

// ============================================================================
// Tension block
// ============================================================================
function TensionBlock() {
  return (
    <section style={styles.bodySection}>
      <div style={styles.tensionBlock}>
        <p style={styles.tensionPara}>
          Most people have no idea what they actually want. They know what
          their parents want, what LinkedIn says they should want, what looks
          responsible.
        </p>
        <p style={{ ...styles.tensionPara, marginBottom: 0 }}>
          This isn&apos;t a quiz. It&apos;s a real conversation — and it gives
          you something most self-help tools don&apos;t: a reason to keep going
          after day one.
        </p>
      </div>
    </section>
  );
}

// ============================================================================
// How it works
// ============================================================================
function HowItWorks() {
  const steps = [
    {
      title: 'Discovery conversation',
      body:
        'A voice-guided interview exploring what lights you up across family, friendships, meaningful work, and what you believe in. About 10 minutes.',
    },
    {
      title: 'Your purpose reflection',
      body:
        'You get a real voice-guided reflection — themes you didn\u2019t know were there, and one clear direction to start moving toward.',
    },
    {
      title: 'SMART goal session',
      body:
        'Turn your reflection into something concrete. One goal. Four pillars. Built around your actual life, not a template.',
    },
  ];

  return (
    <section style={styles.bodySection}>
      <h2 style={styles.h2}>How it works</h2>
      <ol style={styles.stepsList}>
        {steps.map((s, i) => (
          <li key={s.title} style={styles.stepItem}>
            <span style={styles.stepNum}>{i + 1}</span>
            <div style={styles.stepText}>
              <h3 style={styles.stepTitle}>{s.title}</h3>
              <p style={styles.stepBody}>{s.body}</p>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}

// ============================================================================
// Check-in strip
// ============================================================================
function CheckInStrip() {
  const days = ['Day 14', 'Day 30', 'Day 45', 'Day 60'];
  return (
    <section style={styles.bodySection}>
      <div style={styles.checkInCard}>
        <img
          src={IMAGE_PATHS.calendar}
          alt=""
          style={styles.checkInImg}
        />
        <div style={{ flex: 1, minWidth: 0 }}>
          <h3 style={styles.checkInHeading}>
            It doesn&apos;t stop after one conversation.
          </h3>
          <p style={styles.checkInBody}>
            Check-ins at four points over 60 days — so you actually follow
            through, not just feel good for a week.
          </p>
          <div style={styles.checkInPills}>
            {days.map((d) => (
              <span key={d} style={styles.checkInPill}>
                {d}
              </span>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

// ============================================================================
// This is for you if...
// ============================================================================
function ForYouIf() {
  const tags = [
    'You feel directionless',
    'You\u2019re in a career transition',
    'You just graduated',
    'Something feels off but you can\u2019t name it',
    'You want more than just a job',
    'You\u2019re starting over',
  ];
  return (
    <section style={styles.bodySection}>
      <h2 style={styles.h2}>This is for you if…</h2>
      <div style={styles.tagWrap}>
        {tags.map((t) => (
          <span key={t} style={styles.tag}>
            {t}
          </span>
        ))}
      </div>
    </section>
  );
}

// ============================================================================
// Trust row
// ============================================================================
function TrustRow() {
  const items = [
    'One-time payment, no subscription',
    'Works on any device',
    'Your responses stay private',
  ];
  return (
    <section style={{ ...styles.bodySection, marginTop: 48 }}>
      <div style={styles.trustRow}>
        {items.map((i) => (
          <div key={i} style={styles.trustItem}>
            <span style={styles.trustDot} />
            <span>{i}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

// ============================================================================
// Bottom CTA
// ============================================================================
function BottomCTA() {
  return (
    <section style={{ ...styles.bodySection, textAlign: 'center', marginTop: 56 }}>
      <div style={{ ...styles.priceRow, justifyContent: 'center' }}>
        <span style={styles.priceBig}>$27</span>
        <span style={styles.priceNote}>— early access pricing</span>
      </div>
      <p style={styles.bottomItalic}>
        Price increases to $47 at full launch. No refills, no upsells.
      </p>
      <button
        type="button"
        onClick={startCheckout}
        style={{ ...styles.ctaButton, margin: '20px auto 0' }}
        onMouseEnter={(e) =>
          (e.currentTarget.style.background = '#b76238')
        }
        onMouseLeave={(e) => (e.currentTarget.style.background = C.accent)}
      >
        Start the conversation →
      </button>
      <button
        type="button"
        onClick={openAccessCodeFlow}
        style={styles.accessCodeLink}
      >
        Have an access code?
      </button>
    </section>
  );
}

// ============================================================================
// Footer
// ============================================================================
function Footer() {
  return (
    <footer style={styles.footer}>
      Grounded in research on human flourishing · Engaging Education Solutions,
      LLC
    </footer>
  );
}

// ============================================================================
// Styles
// ============================================================================
const styles: Record<string, React.CSSProperties> = {
  root: {
    background: C.bg,
    color: C.text,
    minHeight: '100vh',
    fontFamily:
      '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
    WebkitFontSmoothing: 'antialiased',
    MozOsxFontSmoothing: 'grayscale',
    lineHeight: 1.6,
  },

  // Nav
  nav: {
    borderBottom: `1px solid ${C.border}`,
    background: C.bg,
    position: 'sticky',
    top: 0,
    zIndex: 10,
  },
  navInner: {
    maxWidth: 1040,
    margin: '0 auto',
    padding: '18px 24px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  brand: {
    fontSize: 18,
    fontWeight: 600,
    letterSpacing: 0.2,
    color: C.heading,
  },
  earlyPill: {
    background: C.pillBg,
    border: `1px solid ${C.pillBorder}`,
    color: C.accent,
    padding: '6px 14px',
    borderRadius: 999,
    fontSize: 13,
    fontWeight: 500,
  },

  // Hero
  hero: {
    maxWidth: 680,
    margin: '0 auto',
    padding: '72px 24px 56px',
    textAlign: 'center',
  },
  kicker: {
    color: C.accent,
    fontSize: 12,
    textTransform: 'uppercase',
    letterSpacing: 2.5,
    fontWeight: 600,
    marginBottom: 28,
  },
  h1: {
    color: C.heading,
    fontSize: 44,
    lineHeight: 1.15,
    margin: 0,
    fontWeight: 600,
    letterSpacing: -0.4,
  },
  heroBody: {
    color: C.text,
    fontSize: 18,
    lineHeight: 1.65,
    margin: '0 auto 32px',
    maxWidth: 580,
  },
  priceRow: {
    display: 'flex',
    alignItems: 'baseline',
    gap: 12,
    justifyContent: 'center',
    flexWrap: 'wrap',
    marginBottom: 20,
  },
  priceBig: {
    fontSize: 36,
    fontWeight: 600,
    color: C.heading,
  },
  priceStrike: {
    fontSize: 20,
    color: C.muted,
    textDecoration: 'line-through',
  },
  priceNote: {
    fontSize: 14,
    color: C.muted,
  },
  ctaButton: {
    display: 'block',
    width: '100%',
    maxWidth: 340,
    margin: '0 auto',
    background: C.accent,
    color: '#1e1b17',
    border: 'none',
    padding: '16px 24px',
    borderRadius: 8,
    fontSize: 16,
    fontWeight: 600,
    cursor: 'pointer',
    transition: 'background 0.15s ease',
    letterSpacing: 0.2,
  },
  heroSubline: {
    color: C.muted,
    fontSize: 14,
    marginTop: 18,
  },

  // Sketch strip
  sketchStrip: {
    display: 'grid',
    gridTemplateColumns: 'repeat(3, 1fr)',
    gap: 0,
    width: '100%',
    height: 180,
    background: C.surface,
    borderTop: `1px solid ${C.border}`,
    borderBottom: `1px solid ${C.border}`,
  },
  sketchTile: {
    position: 'relative',
    overflow: 'hidden',
  },
  sketchImg: {
    width: '100%',
    height: '100%',
    objectFit: 'cover',
    filter: 'grayscale(40%) brightness(0.7)',
    display: 'block',
  },
  sketchLabel: {
    position: 'absolute',
    left: 14,
    bottom: 12,
    background: 'rgba(20, 17, 13, 0.72)',
    color: '#f0e8dc',
    fontSize: 13,
    fontStyle: 'italic',
    fontFamily: 'Georgia, "Times New Roman", serif',
    padding: '4px 10px',
    borderRadius: 999,
    letterSpacing: 0.2,
  },

  // Generic body section
  bodySection: {
    maxWidth: 640,
    margin: '0 auto',
    padding: '40px 24px',
  },

  // Tension block
  tensionBlock: {
    borderLeft: `3px solid ${C.accent}`,
    paddingLeft: 20,
  },
  tensionPara: {
    color: C.text,
    fontSize: 17,
    lineHeight: 1.65,
    margin: '0 0 16px',
  },

  // How it works
  h2: {
    color: C.heading,
    fontSize: 26,
    fontWeight: 600,
    margin: '0 0 28px',
    letterSpacing: -0.2,
  },
  stepsList: {
    listStyle: 'none',
    padding: 0,
    margin: 0,
    display: 'flex',
    flexDirection: 'column',
    gap: 28,
  },
  stepItem: {
    display: 'flex',
    gap: 18,
    alignItems: 'flex-start',
  },
  stepNum: {
    flex: '0 0 auto',
    width: 32,
    height: 32,
    borderRadius: '50%',
    background: C.accent,
    color: '#1e1b17',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontWeight: 700,
    fontSize: 14,
    marginTop: 2,
  },
  stepText: {
    flex: 1,
    minWidth: 0,
  },
  stepTitle: {
    color: C.heading,
    fontSize: 17,
    fontWeight: 600,
    margin: '0 0 6px',
  },
  stepBody: {
    color: C.text,
    fontSize: 15.5,
    margin: 0,
    lineHeight: 1.6,
  },

  // Check-in strip
  checkInCard: {
    background: C.surface,
    border: `1px solid ${C.border}`,
    borderRadius: 10,
    padding: 20,
    display: 'flex',
    gap: 20,
    alignItems: 'center',
  },
  checkInImg: {
    width: 100,
    height: 75,
    objectFit: 'cover',
    filter: 'grayscale(40%) brightness(0.65)',
    borderRadius: 6,
    flex: '0 0 auto',
  },
  checkInHeading: {
    color: C.heading,
    fontSize: 18,
    fontWeight: 600,
    margin: '0 0 6px',
  },
  checkInBody: {
    color: C.text,
    fontSize: 15,
    margin: '0 0 12px',
    lineHeight: 1.55,
  },
  checkInPills: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: 8,
  },
  checkInPill: {
    background: C.pillBg,
    border: `1px solid ${C.pillBorder}`,
    color: C.accent,
    padding: '4px 10px',
    borderRadius: 999,
    fontSize: 12.5,
    fontWeight: 500,
  },

  // Tags
  tagWrap: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: 10,
  },
  tag: {
    background: C.surface,
    border: `1px solid ${C.pillBorder}`,
    color: C.muted,
    padding: '8px 14px',
    borderRadius: 999,
    fontSize: 14,
  },

  // Trust row
  trustRow: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: 24,
    justifyContent: 'center',
    borderTop: `1px solid ${C.border}`,
    borderBottom: `1px solid ${C.border}`,
    padding: '22px 0',
  },
  trustItem: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    color: C.muted,
    fontSize: 14,
  },
  trustDot: {
    width: 6,
    height: 6,
    borderRadius: '50%',
    background: C.accent,
    display: 'inline-block',
  },

  // Bottom CTA
  bottomItalic: {
    color: C.muted,
    fontStyle: 'italic',
    fontSize: 14,
    marginTop: 10,
  },
  accessCodeLink: {
    display: 'block',
    margin: '22px auto 0',
    background: 'none',
    border: 'none',
    color: C.accent,
    fontSize: 14,
    cursor: 'pointer',
    textDecoration: 'underline',
    textUnderlineOffset: 3,
  },

  // Footer
  footer: {
    color: C.footer,
    fontSize: 12.5,
    textAlign: 'center',
    padding: '40px 24px 56px',
    borderTop: `1px solid ${C.border}`,
    marginTop: 48,
    letterSpacing: 0.3,
  },
};
