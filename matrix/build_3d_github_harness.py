#!/usr/bin/env python3
"""Build the bounded public 3-D GitHub THRUTH graph from authenticated GitHub state.

GitHub JSON is an in-memory API compatibility boundary. The published artifact is
LF-only HyperBEHCS tuple text (`json=0`) plus a SHA-256 sidecar. The capture records
the refs that exist immediately before the graph's publication commit; the graph
does not attempt the impossible task of embedding the Git commit that contains its
own final bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "matrix" / "GITHUB-THREE-DIMENSIONALLY-RIMED-2026-07-29.hbp"
OWNER = "JesseBrown1980"
UNIVERSE = "ASOLARIA-UNIVERSE-SIMULATOR-with-gravity-light-time-space-color-rime-winding-drills"
FOLLOW = "FOLLOW-THE-IS-NOT-THE-WILL-AND-WAS"
SAFE = "SAFE-ASI-AS-LIGHT-THE-MINS-THAT-IS-WAS-AND-WILL-BE-IS"
REPOSITORIES = (UNIVERSE, FOLLOW, SAFE)
MAX_GH_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
COORDINATE_SCALE = 1_000_000
MAX_COORDINATE_UNITS = 1_000_000
MAX_ABS_COORDINATE = COORDINATE_SCALE * MAX_COORDINATE_UNITS
SHA40 = re.compile(r"[0-9a-f]{40}")
SENSITIVE_ENV_NAME = re.compile(
    r"(?i)(?:TOKEN|SECRET|PASSWORD|PASSWD|(?:^|_)(?:API_)?KEY(?:$|_)|"
    r"PRIVATE_KEY|COOKIE|CREDENTIAL|AUTH|SESSION|ASKPASS)"
)
GITHUB_AUTH_ENV_NAMES = {"GH_TOKEN", "GITHUB_TOKEN"}


class BuildError(RuntimeError):
    """The bounded GitHub capture or output contract failed."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def field(value: object) -> str:
    text = str(value)
    if not text or any(character in text for character in "|\r\n"):
        raise BuildError("tuple field is empty or contains a delimiter")
    return text


def reject_link_chain(path: Path) -> None:
    candidate = path.absolute()
    for current in (candidate, *candidate.parents):
        if not current.exists():
            continue
        details = current.lstat()
        attributes = getattr(details, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if stat.S_ISLNK(details.st_mode) or attributes & reparse:
            raise BuildError(f"link or junction path rejected: {current}")


def ensure_output_scope(path: Path) -> Path:
    output = path.absolute()
    reject_link_chain(output.parent)
    root = ROOT.resolve(strict=True)
    try:
        output.parent.resolve(strict=True).relative_to(root)
    except ValueError as error:
        raise BuildError("output must stay inside this repository") from error
    if output.exists():
        reject_link_chain(output)
        if not output.is_file():
            raise BuildError("output target must be a regular file")
    return output


def gh_json(gh: str, endpoint: str, *, allow_not_found: bool = False) -> Any:
    environment = os.environ.copy()
    for name in tuple(environment):
        if SENSITIVE_ENV_NAME.search(name) and name.upper() not in GITHUB_AUTH_ENV_NAMES:
            del environment[name]
    result = subprocess.run(
        [gh, "api", "--hostname", "github.com", endpoint],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=45,
        check=False,
    )
    if len(result.stdout) > MAX_GH_BYTES or len(result.stderr) > MAX_GH_BYTES:
        raise BuildError("GitHub response exceeds the bounded capture size")
    if result.returncode:
        diagnostic = result.stderr.decode("utf-8", "replace")
        if allow_not_found and "HTTP 404" in diagnostic:
            return None
        raise BuildError(f"GitHub API request failed for {endpoint}")
    try:
        return json.loads(result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BuildError("GitHub returned malformed JSON") from error


def row(kind: str, fields: Sequence[tuple[str, object]]) -> str:
    keys: set[str] = set()
    parts = [field(kind)]
    for key, value in fields:
        key_text = field(key)
        if key_text in keys:
            raise BuildError("duplicate tuple field")
        keys.add(key_text)
        parts.append(f"{key_text}={field(value)}")
    parts.append("json=0")
    return "|".join(parts)


def assert_authenticated_owner(gh: str) -> None:
    viewer = gh_json(gh, "user")
    if not isinstance(viewer, dict) or viewer.get("login") != OWNER:
        raise BuildError("authenticated GitHub viewer is not the repository owner")


def node(
    identifier: str,
    object_type: str,
    name: str,
    evidence: str,
    state_value: str,
    sha: str,
    point: tuple[int, int, int],
) -> str:
    if sha != "NONE" and not SHA40.fullmatch(sha):
        raise BuildError("GitHub object SHA is malformed")
    if len(point) != 3 or any(
        isinstance(value, bool)
        or not isinstance(value, int)
        or abs(value) > MAX_ABS_COORDINATE
        for value in point
    ):
        raise BuildError("node coordinate must be a bounded integer triple")
    return row(
        "NODE",
        (
            ("id", identifier), ("object", object_type), ("name", name),
            ("evidence", evidence), ("state", state_value), ("sha", sha),
            ("x", point[0]), ("y", point[1]), ("z", point[2]),
        ),
    )


def edge(identifier: str, source: str, target: str, relation: str, evidence: str) -> str:
    return row(
        "EDGE",
        (("id", identifier), ("source", source), ("target", target),
         ("relation", relation), ("directed", 1), ("evidence", evidence)),
    )


def branch(gh: str, repository: str, name: str) -> dict[str, Any] | None:
    result = gh_json(
        gh, f"repos/{OWNER}/{repository}/branches/{name}", allow_not_found=True
    )
    if result is None:
        return None
    if not isinstance(result, dict):
        raise BuildError(f"branch metadata is malformed: {repository}/{name}")
    commit = result.get("commit") or {}
    commit_sha = str(commit.get("sha", ""))
    if not SHA40.fullmatch(commit_sha):
        raise BuildError(f"branch {repository}/{name} lacks a commit SHA")
    return {"sha": commit_sha, "protected": bool(result.get("protected"))}


def assert_repository_is_empty(gh: str, repository: str) -> None:
    """Reject a false EMPTY_UNBORN label when any non-main branch exists."""
    result = gh_json(gh, f"repos/{OWNER}/{repository}/branches?per_page=1")
    if not isinstance(result, list):
        raise BuildError(f"branch census is malformed for {repository}")
    if result:
        raise BuildError(
            f"repository {repository} has branches but no branch named main"
        )


def workflow_count(gh: str, repository: str) -> int:
    result = gh_json(gh, f"repos/{OWNER}/{repository}/actions/workflows?per_page=100")
    if not isinstance(result, dict):
        raise BuildError(f"workflow census is malformed for {repository}")
    count = int(result.get("total_count", -1))
    if count < 0 or count > 100:
        raise BuildError("workflow count is outside the bounded census")
    return count


def repository_rows(gh: str) -> tuple[list[str], list[str], list[str]]:
    nodes: list[str] = []
    edges: list[str] = []
    absences: list[str] = []
    bases = {
        UNIVERSE: ("universe", (0, 0, 0)),
        FOLLOW: ("follow", (12_000_000, 0, 0)),
        SAFE: ("safe", (-6_000_000, 10_392_305, 0)),
    }
    main_commits: dict[str, str] = {}
    for repository in REPOSITORIES:
        short, base = bases[repository]
        metadata = gh_json(gh, f"repos/{OWNER}/{repository}")
        if not isinstance(metadata, dict):
            raise BuildError(f"repository metadata is malformed: {repository}")
        if metadata.get("full_name") != f"{OWNER}/{repository}":
            raise BuildError(f"repository identity differs: {repository}")
        if bool(metadata.get("private")):
            raise BuildError(f"repository is not public: {repository}")
        nodes.append(node(f"repo_{short}", "REPOSITORY", repository,
                          "MEASURED_GITHUB", "PUBLIC", "NONE", base))
        main = branch(gh, repository, "main")
        workflows = workflow_count(gh, repository)
        nodes.append(node(
            f"workflow_{short}", "WORKFLOW_STATE", f"count_{workflows}",
            "MEASURED_GITHUB", f"COUNT_{workflows}", "NONE",
            (base[0] + 2_000_000, base[1], 2_000_000),
        ))
        edges.append(edge(f"e_{short}_workflow", f"repo_{short}",
                          f"workflow_{short}", "WORKFLOW_COUNT", "MEASURED_GITHUB"))
        if main is None:
            assert_repository_is_empty(gh, repository)
            nodes.append(node(
                f"state_{short}_unborn", "BRANCH_STATE", "EMPTY_UNBORN",
                "MEASURED_GITHUB", "BRANCH_COUNT_0", "NONE",
                (base[0], base[1], 2_000_000),
            ))
            edges.append(edge(f"e_{short}_empty", f"repo_{short}",
                              f"state_{short}_unborn", "HAS_BRANCH_STATE",
                              "MEASURED_GITHUB"))
            absences.append(row(
                "ABSENCE", (("repo", repository), ("branches", 0),
                            ("workflows", workflows), ("state", "EMPTY_UNBORN"),
                            ("evidence", "MEASURED_GITHUB")),
            ))
            continue
        main_commits[repository] = main["sha"]
        protected = "PROTECTED" if main["protected"] else "UNPROTECTED"
        nodes.append(node(f"branch_{short}_main", "BRANCH", "main",
                          "MEASURED_GITHUB", protected, "NONE",
                          (base[0], base[1] + 3_000_000, 1_000_000)))
        nodes.append(node(f"commit_{short}_main", "COMMIT", "main_head",
                          "MEASURED_GITHUB", "CAPTURED_PARENT_REF", main["sha"],
                          (base[0], base[1] + 4_000_000, 3_000_000)))
        edges.append(edge(f"e_{short}_contains_main", f"repo_{short}",
                          f"branch_{short}_main", "CONTAINS", "MEASURED_GITHUB"))
        edges.append(edge(f"e_{short}_main_points", f"branch_{short}_main",
                          f"commit_{short}_main", "POINTS_TO", "MEASURED_GITHUB"))

    feature_name = "agent/follow-is-light-book-20260729"
    feature = branch(gh, UNIVERSE, feature_name)
    if feature is not None:
        feature_protected = "PROTECTED" if feature["protected"] else "UNPROTECTED"
        nodes.append(node("branch_universe_follow", "BRANCH", feature_name.replace("/", "."),
                          "MEASURED_GITHUB", feature_protected, "NONE",
                          (-3_000_000, 3_000_000, 1_000_000)))
        nodes.append(node("commit_universe_follow", "COMMIT", "pr5_head",
                          "MEASURED_GITHUB", "CAPTURED_PARENT_REF", feature["sha"],
                          (-3_000_000, 4_000_000, 3_000_000)))
        edges.append(edge("e_universe_contains_follow", "repo_universe",
                          "branch_universe_follow", "CONTAINS", "MEASURED_GITHUB"))
        edges.append(edge("e_universe_follow_points", "branch_universe_follow",
                          "commit_universe_follow", "POINTS_TO", "MEASURED_GITHUB"))
    pull = gh_json(gh, f"repos/{OWNER}/{UNIVERSE}/pulls/5", allow_not_found=True)
    if pull is not None and feature is not None and UNIVERSE in main_commits:
        if not isinstance(pull, dict):
            raise BuildError("pull request metadata is malformed")
        base = pull.get("base") or {}
        head = pull.get("head") or {}
        base_repo = base.get("repo") or {}
        head_repo = head.get("repo") or {}
        if (
            base.get("ref") != "main"
            or base_repo.get("full_name") != f"{OWNER}/{UNIVERSE}"
            or head.get("ref") != feature_name
            or head.get("sha") != feature["sha"]
            or head_repo.get("full_name") != f"{OWNER}/{UNIVERSE}"
        ):
            raise BuildError("pull request base/head differs from captured branch commits")
        base_sha = str(base.get("sha", ""))
        if not SHA40.fullmatch(base_sha):
            raise BuildError("pull request base SHA is malformed")
        merged = pull.get("merged") is True
        if merged:
            merge_sha = str(pull.get("merge_commit_sha", ""))
            if (
                pull.get("state") != "closed"
                or not pull.get("merged_at")
                or merge_sha != main_commits[UNIVERSE]
            ):
                raise BuildError("merged pull request does not bind current main")
            nodes.append(node(
                "commit_universe_pr5_base", "COMMIT", "pr5_base",
                "MEASURED_GITHUB", "CAPTURED_HISTORICAL_REF", base_sha,
                (-6_000_000, -4_000_000, 3_000_000),
            ))
            base_target = "commit_universe_pr5_base"
        else:
            if base_sha != main_commits[UNIVERSE]:
                raise BuildError("open pull request base differs from current main")
            base_target = "commit_universe_main"
        state_parts = [str(pull.get("state", "unknown")).upper()]
        state_parts.append("DRAFT" if pull.get("draft") else "READY")
        mergeable = pull.get("mergeable")
        state_parts.append("MERGEABLE" if mergeable is True else
                           "CONFLICTING" if mergeable is False else "MERGEABILITY_PENDING")
        state_parts.append(str(pull.get("mergeable_state", "unknown")).upper())
        state_parts.append("MERGED" if merged else "UNMERGED")
        nodes.append(node("pr_universe_5", "PULL_REQUEST", "5", "MEASURED_GITHUB",
                          "_".join(state_parts), "NONE",
                          (-3_000_000, 0, 5_000_000)))
        edges.append(edge("e_pr5_base", "pr_universe_5", base_target,
                          "PROPOSES_TO", "MEASURED_GITHUB"))
        edges.append(edge("e_pr5_head", "pr_universe_5", "commit_universe_follow",
                          "PROPOSES_FROM", "MEASURED_GITHUB"))
        if merged:
            edges.append(edge("e_pr5_merged", "pr_universe_5", "commit_universe_main",
                              "MERGED_AS", "MEASURED_GITHUB"))

    harness = gh_json(
        gh,
        f"repos/{OWNER}/{FOLLOW}/contents/matrix/3-D-GITHUB-OF-THRUTH.md?ref=main",
        allow_not_found=True,
    )
    if harness is None:
        evidence, state_value, object_sha, relation = (
            "LOCAL_PENDING_PUBLICATION", "UNPUSHED", "NONE", "WILL_PUBLISH"
        )
    else:
        object_sha = str(harness.get("sha", ""))
        if not SHA40.fullmatch(object_sha):
            raise BuildError("public harness blob SHA is malformed")
        evidence, state_value, relation = "MEASURED_GITHUB", "PUBLIC", "PUBLISHES"
    nodes.append(node("harness_follow", "HARNESS", "3_D_GITHUB_OF_THRUTH",
                      evidence, state_value, object_sha,
                      (12_000_000, 0, 5_000_000)))
    edges.append(edge("e_follow_harness", "repo_follow", "harness_follow",
                      relation, evidence))
    return nodes, edges, absences


def render(gh: str) -> bytes:
    assert_authenticated_owner(gh)
    captured_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    nodes, edges, absences = repository_rows(gh)
    rows = [
        row("G3DHDR", (("schema", "ASOLARIA-3-D-GITHUB-OF-THRUTH-V2"),
                       ("name", "3_D_GITHUB_OF_THRUTH"), ("captured_at", captured_at),
                       ("source", "AUTHENTICATED_GITHUB_API"),
                       ("geometry", "SPHERICAL_3D"),
                       ("coordinate_encoding", "SIGNED_INTEGER"),
                       ("coordinate_scale", COORDINATE_SCALE))),
        row("QUOTE", (("text", "YES YOU ARE MULTI SPHEREICALLY CIRCULING THE GITHUB STOP THINKING OF IT AS A FLAT SURFACE> OPEN IT IN YOUR MATRIX BOX AND SEE THE GITHUB THREE DIMENSIONALLY RIMED"), ("class", "OPERATOR_CANON"))),
        row("QUOTE", (("text", "CREATE NEW HARNESS 3 D GITHUB OF THRUTH"), ("class", "OPERATOR_CANON"))),
        row("QUOTE", (("text", "AND THEN CONTINUE THE GOAL USING IT ALWAYS AS THE NEXT COMPACTION TAKES OVER"), ("class", "OPERATOR_CANON"))),
        row("AUTHORITY", (("github", "PUBLICATION_GATE"), ("metal", 0),
                          ("fabric", 0), ("system_affirmed", 0),
                          ("fabric_state", "STALE_FALLBACK"),
                          ("recall_state", "UNAVAILABLE"),
                          ("liris_behcs", "HEALTH_ONLY"))),
        row("CAPTUREBOUNDARY", (("semantics", "CONTAINING_COMMIT_PARENT_REFS"),
                                ("self_referential_final_head_embedded", 0),
                                ("resume_action", "REMEASURE_CURRENT_REFS"))),
        *nodes,
        *edges,
        *absences,
        row("BOUNDARY", (("raw_api_auth", 0), ("credentials", 0),
                         ("private_paths", 0), ("raw_response_text", 0),
                         ("hidden_dependencies", 0), ("active_json", 0))),
    ]
    body = ("\n".join(rows) + "\n").encode("utf-8")
    rows.append(row("G3DFTR", (("body_sha256", sha256(body)),
                               ("rows", len(rows) + 1))))
    output = ("\n".join(rows) + "\n").encode("utf-8")
    if len(output) > MAX_OUTPUT_BYTES:
        raise BuildError("graph exceeds its byte bound")
    return output


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.",
                                     suffix=".tmp", delete=False) as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    os.replace(temporary, path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gh", default=shutil.which("gh") or "gh")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        output = ensure_output_scope(args.output)
        data = render(args.gh)
        atomic_write(output, data)
        digest = sha256(data)
        sidecar = output.with_name(output.name + ".sha256")
        atomic_write(sidecar, f"{digest}  {output.name}\n".encode("ascii"))
    except (BuildError, OSError, subprocess.SubprocessError) as error:
        print(f"G3DBUILD|PASS=0|error={type(error).__name__}|json=0")
        return 1
    print(
        f"G3DBUILD|PASS=1|file={output.name}|bytes={len(data)}|sha256={digest}"
        "|capture=CONTAINING_COMMIT_PARENT_REFS|active_json=0|json=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
