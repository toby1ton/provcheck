"""Offline tests: compare() must catch injected and modified files."""
import sys; sys.path.insert(0, ".")
from provcheck import compare, _norm

repo = {"src/pkg/__init__.py": b"VERSION = '1.0'\n",
        "src/pkg/core.py": b"def run():\n    return 42\n",
        "tests/test_core.py": b"def test(): pass\n"}

# Simulated poisoned artifact: core.py modified + a stealth file injected
pkg = {"pkg/__init__.py": b"VERSION = '1.0'\r\n",            # CRLF only: fine
       "pkg/core.py": b"def run():\n    import os; os.system('evil')\n    return 42\n",
       "pkg/_helpers.py": b"# injected, not in repo\n"}

match, differ, artifact_only = compare(pkg, repo)
assert match == ["pkg/__init__.py"], match          # layout+CRLF tolerated
assert differ == ["pkg/core.py"], differ            # tamper caught
assert artifact_only == ["pkg/_helpers.py"], artifact_only  # injection caught
assert _norm(b"a  \r\nb\n\n") == b"a\nb"
print("poisoned-package detection: ALL PASS")

# --- CI wrapper: parsing + fail-on logic (offline) ---------------------------
import provcheck_ci as ci, tempfile, os
p = tempfile.mktemp()
open(p, "w").write("Flask==3.0.0\npkg[extra]==1.2\nloose-dep\n-r o.txt\ngit+https://x\n# c\n")
parsed = list(ci.parse_requirements(p))
assert parsed == [("Flask", "3.0.0"), ("pkg", "1.2"), ("loose-dep", None)], parsed

import unittest.mock as um
with um.patch.object(ci, "check_package",
                     return_value=("REVIEW-ARTIFACT-ONLY", "1.0: injected.py")):
    import sys as _s
    _s.argv = ["ci", p, "--fail-on", "artifact-only"]
    try:
        ci.main(); raise AssertionError("should have failed")
    except SystemExit as e:
        assert e.code == 1
    _s.argv = ["ci", p, "--fail-on", "never"]
    try:
        ci.main()
    except SystemExit as e:
        assert e.code in (None, 0)
print("CI wrapper (parse + fail-on): ALL PASS")
