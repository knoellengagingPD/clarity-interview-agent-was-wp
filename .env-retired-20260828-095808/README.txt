Retired 20260828-095808 by fix-local-env.sh.

These files each held an OPENAI_API_KEY that nothing loads. They were moved
rather than deleted so you can still revoke the keys.

Check each against platform.openai.com/api-keys and revoke anything still
active, then delete this folder.
