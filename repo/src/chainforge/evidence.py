"""Classify what actually backs each chain link, as structure rather than prose.

SPECIFICATION R3 says a chain is only as strong as its weakest link and that this must be
VISIBLE. Until now it was visible only to a human: the evidence kind had to be recovered by
regex over free text in `patch_hunk_ref`, which left 752 links unclassifiable and 620 with
nothing to read at all. A consumer selecting training records - "every link at least
execution-witnessed" - could not express that query.

The ordering is the one R3 fixes, strongest first. It is deliberately ordinal and NOT a
weighted score: each kind is a distinct verifiable claim, and collapsing them into one number
would hide exactly the weak link R3 exists to surface.
"""

from __future__ import annotations

import re
from enum import StrEnum

# Prose written by earlier pipeline stages, kept as a fallback for links whose evidence
# predates the structured fields.
_ATTESTED = re.compile(
    r"attested by the patch|adds an? (integer-overflow )?guard|origin block|patch co-signal",
    re.I,
)
_UNATTESTED = re.compile(r"NOT attested", re.I)
_INFERRED = re.compile(
    r"crash-class-implied|from the NVD CWE assignment|modelling approximation|no guard signal",
    re.I,
)


class EvidenceKind(StrEnum):
    """What a single link is backed by. Ordered strongest to weakest (see ORDER)."""

    CAUSALLY_PROVEN = "causally-proven"  # guard ablation: only this hunk, crash stops
    EXECUTION = "execution"  # a sanitizer report attributes the link to a site
    ATTESTED = "attested"  # the fix demonstrably adds the missing guard
    DATAFLOW = "dataflow"  # a static path supports the ordering, nothing ran
    INFERRED = "inferred"  # crash class or CWE assignment, nothing observed
    NONE = "none"  # no evidence recorded at all


ORDER = [
    EvidenceKind.CAUSALLY_PROVEN,
    EvidenceKind.EXECUTION,
    EvidenceKind.ATTESTED,
    EvidenceKind.DATAFLOW,
    EvidenceKind.INFERRED,
    EvidenceKind.NONE,
]
_RANK = {k: i for i, k in enumerate(ORDER)}


# A unified-diff hunk header. Patch evidence must contain at least one: a bare reference -
# an https URL, a `git://` remote, a `fix:<sha>` string - names where a fix lives without
# carrying the guard it added, so it cannot support the counterfactual GOLD asserts. Checking
# only for an "http" prefix let 176 GOLD records through on `git://` and `fix:` strings.
_HUNK_HDR = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@", re.M)


def patch_is_content(patch_diff: str | None) -> bool:
    """True if this is an actual patch rather than a pointer to one."""
    return bool(_HUNK_HDR.search(patch_diff or ""))


# Paths whose changes cannot be the guard for a memory-safety sink, however real the diff is:
# tests, docs, examples, and the fuzz harness in any of its layouts. One rule, shared with the
# ablation's hunk splitter, because the two disagreeing is how three oniguruma proofs on
# `harnesses/base.c` passed both: the splitter knew `harness/`, the checker knew neither.
_NON_GUARD_PATH = re.compile(
    r"(^|/)(\w+[_-])?(test|tests|testing|fuzz|fuzzing|fuzzer|fuzzers|fuzztest|harness|harnesses"
    r"|corpus|oss-fuzz|docs?|Documentation|examples?)/"
    r"|(^|/)[^/]*fuzz[^/]*\.(c|cc|cpp|cxx|h|hpp)$",
    re.I,
)


def is_non_guard_path(path: str) -> bool:
    """True if a change to this file cannot be the guard a source link is credited with."""
    return bool(_NON_GUARD_PATH.search(path or ""))


_SOURCE_EXT = re.compile(r"\.(c|cc|cpp|cxx|h|hpp|inc|S)$", re.I)
_FILE_HDR = re.compile(r"^diff --git a/\S+ b/(\S+)", re.M)
_COMMIT_HDR = re.compile(r"^From ([0-9a-f]{40})", re.M)


def guard_evidence_defect(patch_diff: str | None, fixed_sha: str = "") -> str | None:
    """Why this diff cannot back a guard claim, or None if it can.

    `patch_is_content` asks only whether the field holds a patch rather than a pointer to one.
    That is necessary and not sufficient: a diff can be real, well-formed, and still be unable
    to support the counterfactual GOLD asserts - curl's resolved fix for a use-after-free
    touches only `Makefile.am`, skia's touches only its fuzz harness. Checking content alone
    moved the original defect down one level rather than closing it.
    """
    d = patch_diff or ""
    if not patch_is_content(d):
        return "not a patch"
    if len(d) > 1000 and not d.endswith("\n"):
        return "truncated mid-line"
    m = _COMMIT_HDR.search(d)
    if fixed_sha and m and m.group(1) != fixed_sha:
        return f"sha mismatch (diff is {m.group(1)[:12]}, record names {fixed_sha[:12]})"
    files = _FILE_HDR.findall(d)
    if not files:
        return "no file headers"
    if not any(_SOURCE_EXT.search(f) and not is_non_guard_path(f) for f in files):
        return "touches no non-test source file"
    return None


def causal_proof_defect(evidence: dict | None) -> str | None:
    """Why this link's guard-ablation proof does not establish a SOURCE guard, or None.

    The ablation shows that applying one hunk alone silences the sanitizer. That is a causal
    claim about the hunk, not about the library: when the hunk lives in the fuzz harness, what
    it demonstrates is that the harness stopped feeding the triggering input - lwan's guard is
    `size = min(sizeof(copy) - 1, size)` in `template_fuzzer.cc`. The crash stops and nothing
    is fixed, so the record cannot claim a causally-proven source.
    """
    cp = (evidence or {}).get("causal_proof") or {}
    if not cp:
        return None
    if is_non_guard_path(cp.get("file") or ""):
        return "guard hunk is in a fuzz harness or test file"
    return None


# PR-4: what a proven guard checks decides the source CWE. Matched on the hunk's ADDED lines with
# comments stripped (a "// avoid overflow" comment is not an overflow check), tried in precedence
# order; the first class that matches decides, and an inadmissible one credits nothing. Patterns
# favour precision: an unmatched guard is "undetermined" and credits no CWE, the safe failure.
_COMMENT = re.compile(r"//.*$|/\*.*?\*/", re.M)
_FREEISH = re.compile(r"\b(?:\w*free|delete|release|destroy|close)\w*\s*\(|\bdelete\b", re.I)
_GUARD_CLASSES = [
    (
        190,
        re.compile(
            r"\b(?:SIZE|INT|UINT|LONG|ULONG|SSIZE|INT\d+|UINT\d+|U?INT_LEAST\d+)_MAX\b"
            r"|__builtin_\w+_overflow|\bcheck_\w+_overflow\b|\bnumeric_limits\b"
        ),
    ),
    (476, re.compile(r"(?:==|!=)\s*(?:NULL|nullptr)\b|\b(?:NULL|nullptr)\s*(?:==|!=)")),
    (
        416,
        re.compile(
            r"\b(?:\w+_)?(?:incref|decref|unref|kref_get|kref_put|refcount_\w+|get_ref|put_ref)\s*\("
            r"|\b\w+->ref(?:count|cnt)\b",
            re.I,
        ),
    ),
    (456, re.compile(r"\bmemset\s*\(|=\s*\{\s*0?\s*\}|\bcalloc\s*\(")),
    (129, re.compile(r"\b\w*(?:idx|index)\w*\s*(?:>=|>)|(?:<|<=)\s*\w*(?:idx|index)\w*\b", re.I)),
    # PR-4's last row: "any other rejection or clamp of input (bounds, length, early
    # return/error)" - a test in an if, a relational comparison anywhere (a loop bound, a check
    # macro, a continued condition), a clamp, or a bare error exit. `->`, shifts and C++ template
    # brackets are not comparisons.
    (
        20,
        re.compile(
            r"\bif\s*\(.*(?:!=|==).*\)"
            r"|(?<![-<>])(?<!_cast)(?:<=|>=|<(?![<=])|(?<!-)>(?![>=]))(?![<>])"
            r"|\bMIN\s*\(|\bstd::min\b|\bassert\w*\s*\(|\b\w*(?:Verify|Check|Ensure|Require)\w*\s*\("
            r"|^\s*(?:return\b[^;]*|goto\s+\w+|continue|break)\s*;",
            re.I | re.M,
        ),
    ),
]


# C++ template argument lists (`static_cast<uint32_t>`, `std::vector<int>`) are not comparisons.
_TEMPLATE = re.compile(
    r"\b(?:\w+_cast|std::\w+|vector|array|map|set|unique_ptr|shared_ptr|numeric_limits)"
    r"\s*<[^<>;()]*>"
)


def _added(hunk: str) -> str:
    added = "\n".join(
        ln[1:] for ln in hunk.splitlines() if ln.startswith("+") and not ln.startswith("+++")
    )
    return _TEMPLATE.sub("T", _COMMENT.sub("", added))


def guard_classes(hunk: str) -> list[int]:
    """Every PR-4 class a guard hunk matches, in precedence order."""
    added = _added(hunk)
    out = [cwe for cwe, rx in _GUARD_CLASSES if rx.search(added)]
    # Lifetime fix by clearing a pointer: only when the hunk also frees/releases something.
    if 416 not in out and re.search(r"=\s*(?:NULL|nullptr)\s*;", added) and _FREEISH.search(hunk):
        out.insert(min(2, len(out)), 416)
    return out


def source_for_guard(hunk: str, sink: int, admissible) -> int | None:
    """PR-4 source CWE for this sink, or None (a proven site, no CWE credited).

    The FIRST matching class decides; if it is not admissible with the sink, nothing is credited
    rather than falling through to a weaker class. An index check means CWE-129 only toward a
    CWE-119 sink; toward any other sink it is input validation, CWE-20.
    """
    classes = guard_classes(hunk)
    if not classes:
        return None
    cwe = 20 if classes[0] == 129 and sink != 119 else classes[0]
    return cwe if admissible(cwe, sink) else None


_HUNK_POS = re.compile(r"^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@ ?(.*)$", re.M)


def guard_site(hunk: str, file: str) -> dict | None:
    """Where a proven guard is missing: the vulnerable-revision line its first added line goes
    before, and the enclosing function git names in the hunk header (if any)."""
    m = _HUNK_POS.search(hunk)
    if not m:
        return None
    line = int(m.group(1))
    for ln in hunk[m.end() :].split("\n")[1:]:  # the body, after the header line
        if ln.startswith("+"):
            break
        if ln.startswith((" ", "-")):
            line += 1
    fn = re.search(r"(\w+)\s*\(", m.group(2) or "")
    return {
        "file": file,
        "line": line,
        "function": fn.group(1) if fn else None,
        "stage": "missing guard (vulnerable revision, from the proven hunk)",
    }


def normalize_path(path: str) -> str:
    """A source path comparable across witnesses: build-tree hops resolved and the container's
    absolute `/src/<project>/` root dropped (`/src/skia/out/Fuzz/../../src/codec/X.cpp` ->
    `src/codec/X.cpp`). Relative paths are only normalised; `same_file` matches by suffix."""
    import posixpath

    p = posixpath.normpath(path or "")
    if p.startswith("/src/") and p.count("/") >= 3:
        return p.split("/", 3)[3]
    return p.lstrip("/") if p != "." else ""


def same_file(a: str, b: str) -> bool:
    """Two witnessed paths name one file if one normalised path is a suffix of the other."""
    x, y = normalize_path(a), normalize_path(b)
    if not x or not y:
        return False
    return x == y or x.endswith("/" + y) or y.endswith("/" + x)


def bare_function(name: str | None) -> str | None:
    """`SkSwizzler::swizzle(void*, int)` -> `swizzle`; `foo.part.0` -> `foo`."""
    if not name:
        return None
    n = name.split("(", 1)[0].strip().split("::")[-1].split(" ")[-1]
    return re.sub(r"\.(part|isra|constprop|cold)\.\d+$|\.cold$", "", n) or None


def locality(rec: dict) -> str | None:
    """Where the root cause sits relative to the sink, from their witnessed locations:
    "in-function", "cross-function" (same file), "same-file" (a function is unknown), or
    "cross-file"; None if either end is unlocated."""
    chain = rec.get("chain") or []
    if len(chain) < 2:
        return None
    a, b = ((c.get("evidence") or {}).get("location") or {} for c in (chain[0], chain[-1]))
    if not (a.get("file") and b.get("file")):
        return None
    if not same_file(a["file"], b["file"]):
        return "cross-file"
    fa, fb = bare_function(a.get("function")), bare_function(b.get("function"))
    if not (fa and fb):
        return "same-file"
    return "in-function" if fa == fb else "cross-function"


def chain_kind(cwes: list[int]) -> str:
    """PR-5: "multi-weakness" if the chain holds >= 2 distinct weaknesses, else
    "stage-decomposition". A `416 -> 125|787` tail is one weakness (the sink is the freed-memory
    access), so it counts once."""
    distinct = len(cwes) - (
        1 if len(cwes) >= 2 and cwes[-2] == 416 and cwes[-1] in (125, 787) else 0
    )
    return "multi-weakness" if distinct >= 2 else "stage-decomposition"


def clip_patch(patch_diff: str, limit: int) -> str:
    """Cut a diff to at most `limit` bytes, keeping only WHOLE hunks.

    A naive slice ends wherever the byte count runs out - 22 GOLD records shipped diffs cut
    mid-expression at exactly 200,000 bytes. A hunk is only known to be complete once the next
    hunk header (or the end of the diff) has been seen, so cut at a hunk boundary and keep the
    file headers with it. If not even the first hunk fits, there is no valid patch to store and
    the empty string says so, rather than a fragment that reads like one.
    """
    if len(patch_diff) <= limit:
        return patch_diff
    cut = 0
    for m in list(_HUNK_HDR.finditer(patch_diff))[1:]:
        if m.start() > limit:
            break
        cut = m.start()
    # A cut at the first hunk of a new file would keep that file's header with no hunk under
    # it; drop the orphaned header too.
    hdr = patch_diff.rfind("diff --git ", 0, cut)
    if hdr > 0 and not _HUNK_HDR.search(patch_diff, hdr, cut):
        cut = hdr
    return patch_diff[:cut]


def classify_link(evidence: dict | None) -> EvidenceKind:
    """The strongest kind this link's evidence actually supports."""
    ev = evidence or {}
    if ev.get("causal_proof"):
        return EvidenceKind.CAUSALLY_PROVEN
    # A sanitizer reference is only an EXECUTION witness of *this* link when it also says
    # where. A bare reference names a log without attributing the link to a site in it.
    if ev.get("sanitizer_report_ref") and (ev.get("location") or {}).get("file"):
        return EvidenceKind.EXECUTION
    ref = ev.get("patch_hunk_ref") or ""
    if _UNATTESTED.search(ref):
        return EvidenceKind.INFERRED
    if _ATTESTED.search(ref):
        return EvidenceKind.ATTESTED
    if ev.get("sanitizer_report_ref"):
        return EvidenceKind.EXECUTION
    if ev.get("dataflow_path"):
        return EvidenceKind.DATAFLOW
    if _INFERRED.search(ref) or ref:
        return EvidenceKind.INFERRED
    return EvidenceKind.NONE


def floor(record: dict) -> EvidenceKind:
    """The WEAKEST link in the chain - what the record as a whole can honestly claim."""
    chain = [c for c in (record.get("chain") or []) if isinstance(c, dict)]
    if not chain:
        return EvidenceKind.NONE
    return max((classify_link(c.get("evidence")) for c in chain), key=lambda k: _RANK[k])


def at_least(record: dict, kind: EvidenceKind) -> bool:
    """True if EVERY link is backed at least this strongly - the query R3 implies."""
    return _RANK[floor(record)] <= _RANK[kind]
