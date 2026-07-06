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
