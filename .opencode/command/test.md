---
description: Run the nokey bash test suite
---

Run the full test suite and report results:

```bash
bash tests/test_nokey.sh
```

If it fails, diagnose the failing assertion (each failure prints
`FAIL: <reason>`), fix the root cause in `nokey.sh`, and re-run until green.
