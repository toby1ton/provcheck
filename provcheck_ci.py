"""provcheck_ci — scan every pinned dependency in a requirements file.

Designed for CI (GitHub Actions), usable anywhere:

    python3 provcheck_ci.py requirements.txt [--fail-on artifact-only|differs|never]

Exit codes: 0 all clean/skipped, 1 findings at or above the fail-on
level, 2 usage error. Writes a Markdown summary to $GITHUB_STEP_SUMMARY
when running inside GitHub Actions.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from provcheck import fetch_pypi_files, fetch_github_files, compare


def parse_requirements(path):
    """Yields (name, version|None). Handles pins, skips options/URLs."""
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = re.match(r"([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*==\s*([\w.\-]+)", line)
        if m:
            yield m.group(1), m.group(2)
        else:
            m = re.match(r"([A-Za-z0-9_.\-]+)", line)
            if m:
                yield m.group(1), None      # unpinned: check latest


def check_package(name, version):
    """Returns (status, detail). status: CLEAN | REVIEW-DIFFERS |
    REVIEW-ARTIFACT-ONLY | UNVERIFIABLE | ERROR."""
    try:
        ver, pkg_files, repo = fetch_pypi_files(name, version)
        if repo is None:
            return "UNVERIFIABLE", "%s: no source repo declared" % ver
        repo_files, tag = fetch_github_files(repo[0], repo[1], ver)
        match, differ, artifact_only = compare(pkg_files, repo_files)
        if artifact_only:
            return "REVIEW-ARTIFACT-ONLY", "%s: %d file(s) only in artifact: %s" % (
                ver, len(artifact_only), ", ".join(artifact_only[:5]))
        if differ:
            return "REVIEW-DIFFERS", "%s: %d file(s) differ: %s" % (
                ver, len(differ), ", ".join(differ[:5]))
        return "CLEAN", "%s: %d files match github.com/%s/%s@%s" % (
            ver, len(match), repo[0], repo[1], tag)
    except SystemExit as e:
        return "UNVERIFIABLE", str(e)
    except Exception as e:                   # network flake, odd archive, etc.
        return "ERROR", "%s: %s" % (type(e).__name__, e)


def main():
    args = sys.argv[1:]
    fail_on = "artifact-only"
    if "--fail-on" in args:
        i = args.index("--fail-on")
        fail_on = args[i + 1]
        del args[i:i + 2]
    if len(args) != 1 or fail_on not in ("artifact-only", "differs", "never"):
        print(__doc__)
        raise SystemExit(2)

    results = []
    for name, version in parse_requirements(args[0]):
        status, detail = check_package(name, version)
        results.append((status, name, detail))
        print("%-22s %-14s %s" % (status, name, detail))

    counts = {}
    for s, _, _ in results:
        counts[s] = counts.get(s, 0) + 1
    print("\nsummary:", ", ".join("%d %s" % (v, k) for k, v in sorted(counts.items())))

    # GitHub Actions job summary
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write("## provcheck: dependency source verification\n\n")
            f.write("| status | package | detail |\n|---|---|---|\n")
            for s, n, d in results:
                icon = {"CLEAN": "white_check_mark",
                        "UNVERIFIABLE": "grey_question",
                        "ERROR": "warning"}.get(s, "rotating_light")
                f.write("| :%s: %s | %s | %s |\n" % (icon, s, n, d.replace("|", "/")))

    bad = {"artifact-only": ("REVIEW-ARTIFACT-ONLY",),
           "differs": ("REVIEW-ARTIFACT-ONLY", "REVIEW-DIFFERS"),
           "never": ()}[fail_on]
    if any(s in bad for s, _, _ in results):
        print("\nFAIL: findings at or above --fail-on=%s level. Review above." % fail_on)
        raise SystemExit(1)
    print("\nPASS")


if __name__ == "__main__":
    main()
