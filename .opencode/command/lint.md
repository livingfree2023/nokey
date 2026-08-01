---
description: Syntax-check and shellcheck nokey.sh
---

Syntax-check and lint the bash code:

```bash
bash -n nokey.sh && echo "syntax OK"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -x nokey.sh tests/test_nokey.sh
else
  echo "shellcheck not installed; skipping lint"
fi
```

Fix any errors and warnings found (matching the conventions in `AGENTS.md`),
then re-run until clean.
