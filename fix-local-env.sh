#!/usr/bin/env bash
#
# Make the local OpenAI key match the one production actually uses.
#
# THE PROBLEM
#
# server.js does `import 'dotenv/config'`, which reads .env and nothing else.
# The key in .env is dead. Production is fine -- it reads from Vercel -- so the
# two drifted apart with nothing to notice. On 2026-08-28 that cost a debugging
# session: a probe failed twice on authentication before it could answer the
# question it was written to answer.
#
# There are also four other .env* files on disk holding old keys, and a stale
# export in the shell environment that silently wins over all of them.
#
# WHAT THIS DOES
#
#   1. Finds stale OPENAI_API_KEY exports in your shell startup files and
#      comments them out (backing up each file first).
#   2. Repoints .env at the live production values from Vercel.
#   3. Moves the redundant .env copies into a dated quarantine folder.
#      It MOVES rather than deletes -- you may still need to revoke those keys
#      at platform.openai.com, and you cannot revoke what you cannot read.
#   4. Re-runs the probe to prove .env now authenticates.
#
# Nothing happens until you confirm, and every change is reversible.
#
#   bash fix-local-env.sh

set -uo pipefail
cd "$(dirname "$0")" || exit 1

BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
STAMP=$(date +%Y%m%d-%H%M%S)
QUARANTINE=".env-retired-$STAMP"

say()  { printf '%s\n' "$*"; }
head2() { printf '\n%s%s%s\n' "$BOLD" "$*" "$RESET"; }

# ── Survey: what is actually here? ────────────────────────────────────────────

head2 "1. Shell startup files"
SHELL_FILES=()
for f in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.zshenv" "$HOME/.bash_profile" "$HOME/.bashrc"; do
  [ -f "$f" ] || continue
  if grep -qE '^[[:space:]]*(export[[:space:]]+)?OPENAI_API_KEY=' "$f"; then
    SHELL_FILES+=("$f")
    say "   found an OPENAI_API_KEY line in ${f/#$HOME/\~}:"
    grep -nE '^[[:space:]]*(export[[:space:]]+)?OPENAI_API_KEY=' "$f" \
      | sed -E 's/=.*/=<hidden>/' | sed 's/^/     /'
  fi
done
[ ${#SHELL_FILES[@]} -eq 0 ] && say "   ${DIM}none — the stale value came from somewhere else in this shell${RESET}"

head2 "2. Vercel"
if command -v vercel >/dev/null 2>&1; then
  say "   vercel CLI present; will pull production values into .env"
  HAVE_VERCEL=1
else
  say "   ${DIM}vercel CLI not found — will copy the working key from .env.local instead${RESET}"
  HAVE_VERCEL=0
fi

head2 "3. Redundant .env copies"
STALE=()
for f in .env.save .env.backup .env.production; do
  [ -f "$f" ] && { STALE+=("$f"); say "   $f  ${DIM}(holds an old OPENAI_API_KEY)${RESET}"; }
done
[ ${#STALE[@]} -eq 0 ] && say "   ${DIM}none${RESET}"

# ── Confirm ───────────────────────────────────────────────────────────────────

head2 "Plan"
[ ${#SHELL_FILES[@]} -gt 0 ] && say "   • comment out the OPENAI_API_KEY line in ${#SHELL_FILES[@]} shell file(s), backing each up"
[ "$HAVE_VERCEL" = 1 ] && say "   • vercel env pull .env --environment=production" \
                       || say "   • copy the working OPENAI_API_KEY from .env.local into .env"
[ ${#STALE[@]} -gt 0 ] && say "   • move ${#STALE[@]} redundant file(s) into $QUARANTINE/"
say "   • re-run probe-toolcall-events.mjs to confirm .env authenticates"
say ""
printf 'Proceed? [y/N] '
read -r REPLY
case "$REPLY" in [yY]*) ;; *) say "Nothing changed."; exit 0 ;; esac

# ── Act ───────────────────────────────────────────────────────────────────────

head2 "Applying"

for f in ${SHELL_FILES+"${SHELL_FILES[@]}"}; do
  cp "$f" "$f.bak-$STAMP"
  # Comment out rather than delete: if something else depended on it, the line
  # is still there to be found.
  sed -i '' -E "s|^([[:space:]]*(export[[:space:]]+)?OPENAI_API_KEY=.*)$|# retired $STAMP (stale key, see fix-local-env.sh): \1|" "$f"
  say "   commented out in ${f/#$HOME/\~}  ${DIM}(backup: $(basename "$f").bak-$STAMP)${RESET}"
done

cp .env ".env.bak-$STAMP" 2>/dev/null && say "   backed up .env to .env.bak-$STAMP"

if [ "$HAVE_VERCEL" = 1 ]; then
  if vercel env pull .env --environment=production --yes >/dev/null 2>&1; then
    say "   pulled production values into .env"
  else
    say "   ${BOLD}vercel env pull failed${RESET} — falling back to .env.local"
    HAVE_VERCEL=0
  fi
fi

if [ "$HAVE_VERCEL" = 0 ] && [ -f .env.local ]; then
  KEYLINE=$(grep '^OPENAI_API_KEY' .env.local | head -1)
  if [ -n "$KEYLINE" ]; then
    if grep -q '^OPENAI_API_KEY' .env 2>/dev/null; then
      grep -v '^OPENAI_API_KEY' .env > .env.tmp && printf '%s\n' "$KEYLINE" >> .env.tmp && mv .env.tmp .env
    else
      printf '%s\n' "$KEYLINE" >> .env
    fi
    say "   copied the working OPENAI_API_KEY from .env.local into .env"
  fi
fi

if [ ${#STALE[@]} -gt 0 ]; then
  mkdir -p "$QUARANTINE"
  for f in "${STALE[@]}"; do mv "$f" "$QUARANTINE/"; done
  cat > "$QUARANTINE/README.txt" <<TXT
Retired $STAMP by fix-local-env.sh.

These files each held an OPENAI_API_KEY that nothing loads. They were moved
rather than deleted so you can still revoke the keys.

Check each against platform.openai.com/api-keys and revoke anything still
active, then delete this folder.
TXT
  say "   moved ${#STALE[@]} file(s) into $QUARANTINE/  ${DIM}(revoke the keys, then delete it)${RESET}"
fi

# ── Prove it ──────────────────────────────────────────────────────────────────

head2 "Verifying"
if [ -f probe-toolcall-events.mjs ]; then
  node probe-toolcall-events.mjs 2>&1 | grep -E "candidate key|Trying key|connected with|rejected|ERROR" || true
  say ""
  say "   ${DIM}Want '.env' on the 'connected with the key from' line above.${RESET}"
else
  say "   ${DIM}probe not found; skipped${RESET}"
fi

head2 "Done"
say "   Open a new terminal (or: source ~/.zshrc) so the retired export is gone."
[ ${#STALE[@]} -gt 0 ] && say "   Then revoke the old keys in $QUARANTINE/ and delete the folder."
