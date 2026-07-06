"""provcheck — does this PyPI package match its claimed source repo?

Supply-chain attacks often work by publishing a package artifact that
differs from the public repository everyone audits: the malicious code
exists only in the upload. provcheck downloads a package from PyPI and
its claimed GitHub source at the matching tag, then diffs every Python
file between them.

    python3 provcheck.py requests
    python3 provcheck.py flask 3.0.0

Verdicts per file:
  MATCH      byte-identical (after line-ending normalization)
  DIFFERS    exists in both but content differs  <- read the diff
  ARTIFACT-ONLY  in the package but not the repo <- the classic red flag
  (repo-only files are normal: tests, docs, CI are often excluded)

Honest limits: legitimate build steps can transform files (version
stamping, generated _version.py), so DIFFERS needs human review, not
panic. A clean report is strong evidence; a dirty one is a starting
point. Requires network access. Zero dependencies beyond stdlib.

License: MIT.
"""

import io
import json
import re
import sys
import tarfile
import zipfile
import hashlib
import urllib.request

UA = {"User-Agent": "provcheck/1.0 (+supply-chain verification tool)"}


def _get(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def _norm(data):
    """Normalize for comparison: line endings + trailing whitespace."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data
    lines = [ln.rstrip() for ln in text.replace("\r\n", "\n").split("\n")]
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines).encode("utf-8")


def fetch_pypi_files(name, version=None):
    """Returns (version, {relpath: bytes}) for .py files in the sdist
    (preferred: closest to source) or wheel."""
    meta = json.loads(_get("https://pypi.org/pypi/%s/json" % name))
    version = version or meta["info"]["version"]
    rels = meta["releases"].get(version) or []
    url = None
    for r in rels:                      # prefer sdist
        if r["packagetype"] == "sdist":
            url = r["url"]
            break
    if url is None:
        for r in rels:
            if r["packagetype"] == "bdist_wheel":
                url = r["url"]
                break
    if url is None:
        raise SystemExit("no downloadable artifact for %s %s" % (name, version))
    blob = _get(url)
    files = {}
    if url.endswith((".tar.gz", ".tgz")):
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            for m in tf.getmembers():
                if m.isfile() and m.name.endswith(".py"):
                    # strip leading "pkg-1.2.3/" component
                    rel = m.name.split("/", 1)[1] if "/" in m.name else m.name
                    files[rel] = tf.extractfile(m).read()
    else:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for n in zf.namelist():
                if n.endswith(".py") and not n.startswith((".", "__MACOSX")):
                    files[n] = zf.read(n)
    repo = _guess_repo(meta["info"])
    return version, files, repo


def _guess_repo(info):
    urls = dict(info.get("project_urls") or {})
    cands = list(urls.values()) + [info.get("home_page") or ""]
    for u in cands:
        m = re.match(r"https?://github\.com/([\w.-]+)/([\w.-]+)", u or "")
        if m:
            return m.group(1), m.group(2).removesuffix(".git")
    return None


def fetch_github_files(owner, repo, version):
    """Try common tag spellings; returns {relpath: bytes} of .py files."""
    last_err = None
    for tag in ("v%s" % version, version, "%s-%s" % (repo, version)):
        url = "https://github.com/%s/%s/archive/refs/tags/%s.tar.gz" % (
            owner, repo, tag)
        try:
            blob = _get(url)
        except Exception as e:
            last_err = e
            continue
        files = {}
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            for m in tf.getmembers():
                if m.isfile() and m.name.endswith(".py"):
                    rel = m.name.split("/", 1)[1] if "/" in m.name else m.name
                    files[rel] = tf.extractfile(m).read()
        return files, tag
    raise SystemExit("could not fetch a matching tag from GitHub (%s)" % last_err)


def _index_by_basename_path(files):
    """Map files by their path suffixes so layout differences
    (src/ prefix, package dir) don't defeat matching."""
    idx = {}
    for path, data in files.items():
        parts = path.split("/")
        for i in range(len(parts)):
            idx.setdefault("/".join(parts[i:]), []).append((path, data))
    return idx


def compare(pkg_files, repo_files):
    repo_idx = _index_by_basename_path(repo_files)
    match, differ, artifact_only = [], [], []
    for path, data in sorted(pkg_files.items()):
        # find best repo counterpart by longest matching path suffix
        parts = path.split("/")
        found = None
        for i in range(len(parts)):
            suffix = "/".join(parts[i:])
            hits = repo_idx.get(suffix)
            if hits:
                found = hits[0][1]
                break
        if found is None:
            artifact_only.append(path)
        elif _norm(found) == _norm(data):
            match.append(path)
        else:
            differ.append(path)
    return match, differ, artifact_only


def main():
    if len(sys.argv) < 2:
        print("usage: python3 provcheck.py <package> [version]")
        raise SystemExit(2)
    name = sys.argv[1]
    want = sys.argv[2] if len(sys.argv) > 2 else None

    version, pkg_files, repo = fetch_pypi_files(name, want)
    print("package : %s %s  (%d .py files in artifact)"
          % (name, version, len(pkg_files)))
    if repo is None:
        print("VERDICT : UNVERIFIABLE — package declares no GitHub source URL.")
        print("          That is itself worth knowing for a dependency.")
        raise SystemExit(1)
    print("claimed : github.com/%s/%s" % repo)

    repo_files, tag = fetch_github_files(repo[0], repo[1], version)
    print("source  : tag %s  (%d .py files in repo)" % (tag, len(repo_files)))

    match, differ, artifact_only = compare(pkg_files, repo_files)
    print("\nresults : %d match, %d differ, %d artifact-only"
          % (len(match), len(differ), len(artifact_only)))
    for p in differ:
        print("  DIFFERS       %s" % p)
    for p in artifact_only:
        print("  ARTIFACT-ONLY %s" % p)

    if not differ and not artifact_only:
        print("\nVERDICT : CLEAN — every .py file in the artifact matches the repo.")
    elif artifact_only:
        print("\nVERDICT : REVIEW — files exist in the published package that are"
              "\n          not in the public repo. Often build-generated"
              "\n          (e.g. _version.py), but this is the pattern real"
              "\n          supply-chain attacks use. Inspect them.")
    else:
        print("\nVERDICT : REVIEW — content differences found. Check whether the"
              "\n          build legitimately transforms these files.")


if __name__ == "__main__":
    main()
