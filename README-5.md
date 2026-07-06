# provcheck — does this PyPI package match its claimed source repo?

Real supply-chain attacks often publish a package artifact that differs
from the public repository everyone audits — the malicious code exists
only in the upload. provcheck downloads a package from PyPI and its
claimed GitHub source at the matching version tag, then diffs every
Python file between them.

```
$ python3 provcheck.py requests

package : requests 2.34.2  (35 .py files in artifact)
claimed : github.com/psf/requests
source  : tag v2.34.2  (37 .py files in repo)

results : 35 match, 0 differ, 0 artifact-only
VERDICT : CLEAN — every .py file in the artifact matches the repo.
```

Three verdicts per file: **MATCH** (byte-identical after line-ending
normalization), **DIFFERS** (content changed — review the diff), and
**ARTIFACT-ONLY** (in the package but not the repo — the classic attack
pattern; sometimes legitimately build-generated, always worth a look).
A package that declares no source repo at all is reported as
UNVERIFIABLE, which is itself useful signal about a dependency.

Honest limits: legitimate builds can transform files (version stamping,
generated code), so DIFFERS means "review", not "compromised". A clean
report is strong evidence; a dirty one is a starting point, and layout
differences (src/ prefixes) are handled automatically.

Stdlib only. `python3 test_provcheck.py` runs the offline
poisoned-package detection tests. MIT license.
