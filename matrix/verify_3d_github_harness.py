#!/usr/bin/env python3
"""Verify the sealed 3 D GITHUB OF THRUTH tuple graph."""

from __future__ import annotations

import argparse
import hashlib
import re
import stat
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GRAPH = ROOT / "matrix" / "GITHUB-THREE-DIMENSIONALLY-RIMED-2026-07-29.hbp"
MAX_BYTES = 1_048_576
COORDINATE_SCALE = 1_000_000
MAX_COORDINATE_UNITS = 1_000_000
MAX_ABS_COORDINATE = COORDINATE_SCALE * MAX_COORDINATE_UNITS
SHA40 = re.compile(r"[0-9a-f]{40}")
SHA64 = re.compile(r"[0-9a-f]{64}")
SAFE_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,127}")
SIGNED_INTEGER = re.compile(r"(?:0|-?[1-9][0-9]*)")
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{32,}\b"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(rb"\bxox[baprs]-[0-9A-Za-z-]{20,}\b"),
)
EXPECTED_REPOSITORIES = {
    "ASOLARIA-UNIVERSE-SIMULATOR-with-gravity-light-time-space-color-rime-winding-drills",
    "FOLLOW-THE-IS-NOT-THE-WILL-AND-WAS",
    "SAFE-ASI-AS-LIGHT-THE-MINS-THAT-IS-WAS-AND-WILL-BE-IS",
}
EXPECTED_REPOSITORY_IDS = {
    "repo_universe": "ASOLARIA-UNIVERSE-SIMULATOR-with-gravity-light-time-space-color-rime-winding-drills",
    "repo_follow": "FOLLOW-THE-IS-NOT-THE-WILL-AND-WAS",
    "repo_safe": "SAFE-ASI-AS-LIGHT-THE-MINS-THAT-IS-WAS-AND-WILL-BE-IS",
}
ROW_FIELDS = {
    "G3DHDR": {
        "kind", "schema", "name", "captured_at", "source", "geometry",
        "coordinate_encoding", "coordinate_scale",
    },
    "QUOTE": {"kind", "text", "class"},
    "AUTHORITY": {
        "kind", "github", "metal", "fabric", "system_affirmed", "fabric_state",
        "recall_state", "liris_behcs",
    },
    "CAPTUREBOUNDARY": {
        "kind", "semantics", "self_referential_final_head_embedded", "resume_action",
    },
    "NODE": {
        "kind", "id", "object", "name", "evidence", "state", "sha", "x", "y", "z",
    },
    "EDGE": {
        "kind", "id", "source", "target", "relation", "directed", "evidence",
    },
    "ABSENCE": {"kind", "repo", "branches", "workflows", "state", "evidence"},
    "BOUNDARY": {
        "kind", "raw_api_auth", "credentials", "private_paths", "raw_response_text",
        "hidden_dependencies", "active_json",
    },
    "G3DFTR": {"kind", "body_sha256", "rows"},
}
EXPECTED_QUOTES = (
    "YES YOU ARE MULTI SPHEREICALLY CIRCULING THE GITHUB STOP THINKING OF IT AS A FLAT SURFACE> OPEN IT IN YOUR MATRIX BOX AND SEE THE GITHUB THREE DIMENSIONALLY RIMED",
    "CREATE NEW HARNESS 3 D GITHUB OF THRUTH",
    "AND THEN CONTINUE THE GOAL USING IT ALWAYS AS THE NEXT COMPACTION TAKES OVER",
)


class HarnessError(ValueError):
    """A malformed, stale, dangling, collapsed, or mismatched graph."""


def reject_link_chain(path: Path) -> None:
    candidate = path.absolute()
    for current in (candidate, *candidate.parents):
        if not current.exists():
            continue
        details = current.lstat()
        attributes = getattr(details, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if stat.S_ISLNK(details.st_mode) or attributes & reparse:
            raise HarnessError(f"link or junction path rejected: {current}")


def parse_row(line: str) -> dict[str, str]:
    parts = line.split("|")
    if len(parts) < 3 or parts[-1] != "json=0":
        raise HarnessError("row is not json=0 tuple text")
    fields: dict[str, str] = {"kind": parts[0]}
    for item in parts[1:-1]:
        if "=" not in item:
            raise HarnessError("tuple field lacks equals")
        key, value = item.split("=", 1)
        if not key or key in fields:
            raise HarnessError("tuple field is empty or duplicated")
        fields[key] = value
    return fields


def read_graph(path: Path) -> tuple[bytes, list[str], list[dict[str, str]]]:
    reject_link_chain(path)
    if not path.exists() or not stat.S_ISREG(path.lstat().st_mode):
        raise HarnessError("graph must be a regular file")
    data = path.read_bytes()
    if len(data) == 0 or len(data) > MAX_BYTES:
        raise HarnessError("graph byte bound failed")
    if b"\r" in data or not data.endswith(b"\n"):
        raise HarnessError("graph must be LF-only with a terminal LF")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise HarnessError("graph is not strict UTF-8") from error
    if any(pattern.search(data) for pattern in SECRET_PATTERNS):
        raise HarnessError("graph contains a credential signature")
    lines = text.splitlines()
    rows = [parse_row(line) for line in lines]
    return data, lines, rows


def verify_row_schemas(rows: list[dict[str, str]]) -> None:
    for parsed in rows:
        kind = parsed.get("kind", "")
        expected = ROW_FIELDS.get(kind)
        if expected is None:
            raise HarnessError(f"unknown row kind: {kind}")
        if set(parsed) != expected:
            raise HarnessError(f"{kind} row schema differs")
    if sum(row["kind"] == "G3DHDR" for row in rows) != 1:
        raise HarnessError("graph must contain one header")
    if sum(row["kind"] == "G3DFTR" for row in rows) != 1:
        raise HarnessError("graph must contain one footer")


def verify_footer(lines: list[str], rows: list[dict[str, str]]) -> None:
    footer = rows[-1]
    if set(footer) != {"kind", "body_sha256", "rows"}:
        raise HarnessError("footer schema differs")
    if footer["kind"] != "G3DFTR" or not SHA64.fullmatch(footer["body_sha256"]):
        raise HarnessError("footer digest is malformed")
    if footer["rows"] != str(len(lines)):
        raise HarnessError("footer row count differs")
    body = ("\n".join(lines[:-1]) + "\n").encode("utf-8")
    if hashlib.sha256(body).hexdigest() != footer["body_sha256"]:
        raise HarnessError("body commitment differs")


def verify_sidecar(path: Path, data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    sidecar = path.with_name(path.name + ".sha256")
    reject_link_chain(sidecar)
    if not sidecar.exists() or not stat.S_ISREG(sidecar.lstat().st_mode):
        raise HarnessError("graph sidecar is missing")
    if sidecar.stat().st_size > 512:
        raise HarnessError("graph sidecar exceeds its byte bound")
    expected = f"{digest}  {path.name}\n".encode("ascii")
    if sidecar.read_bytes() != expected:
        raise HarnessError("graph sidecar differs")
    return digest


def coordinate(node: dict[str, str]) -> tuple[int, int, int]:
    encoded = tuple(node.get(axis, "") for axis in ("x", "y", "z"))
    if any(not SIGNED_INTEGER.fullmatch(value) for value in encoded):
        raise HarnessError("node coordinate is not a canonical signed integer")
    point = (int(encoded[0]), int(encoded[1]), int(encoded[2]))
    if any(abs(value) > MAX_ABS_COORDINATE for value in point):
        raise HarnessError("node coordinate is out of bounds")
    return point


def determinant(
    a: tuple[int, int, int],
    b: tuple[int, int, int],
    c: tuple[int, int, int],
    d: tuple[int, int, int],
) -> int:
    ab = tuple(b[index] - a[index] for index in range(3))
    ac = tuple(c[index] - a[index] for index in range(3))
    ad = tuple(d[index] - a[index] for index in range(3))
    return (
        ab[0] * (ac[1] * ad[2] - ac[2] * ad[1])
        - ab[1] * (ac[0] * ad[2] - ac[2] * ad[0])
        + ab[2] * (ac[0] * ad[1] - ac[1] * ad[0])
    )


def verify_geometry(points: list[tuple[int, int, int]]) -> None:
    if len(points) < 4:
        raise HarnessError("graph needs at least four nodes")
    if any(len({point[axis] for point in points}) < 2 for axis in range(3)):
        raise HarnessError("one coordinate axis is collapsed")
    non_coplanar = any(
        determinant(points[0], points[a], points[b], points[c]) != 0
        for a in range(1, len(points))
        for b in range(a + 1, len(points))
        for c in range(b + 1, len(points))
    )
    if not non_coplanar:
        raise HarnessError("all graph nodes are coplanar")


def parse_capture(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise HarnessError("capture time is malformed") from error
    if parsed.tzinfo is None:
        raise HarnessError("capture time lacks a timezone")
    return parsed.astimezone(timezone.utc)


def verify(path: Path, max_age_seconds: int | None = None) -> tuple[int, int, str]:
    data, lines, rows = read_graph(path)
    verify_row_schemas(rows)
    if rows[0]["kind"] != "G3DHDR" or rows[-1]["kind"] != "G3DFTR":
        raise HarnessError("header/footer placement differs")
    header = rows[0]
    if set(header) != {
        "kind", "schema", "name", "captured_at", "source", "geometry",
        "coordinate_encoding", "coordinate_scale",
    } or header["kind"] != "G3DHDR" or header["schema"] != (
        "ASOLARIA-3-D-GITHUB-OF-THRUTH-V2"
    ) or header["name"] != "3_D_GITHUB_OF_THRUTH" or header["source"] != (
        "AUTHENTICATED_GITHUB_API"
    ) or header["geometry"] != "SPHERICAL_3D" or header[
        "coordinate_encoding"
    ] != "SIGNED_INTEGER" or header["coordinate_scale"] != str(COORDINATE_SCALE):
        raise HarnessError("header differs from the sealed schema")
    capture = parse_capture(header["captured_at"])
    if max_age_seconds is not None:
        if max_age_seconds < 0:
            raise HarnessError("maximum age cannot be negative")
        age = (datetime.now(timezone.utc) - capture).total_seconds()
        if age < 0 or age > max_age_seconds:
            raise HarnessError("sealed GitHub projection is stale")
    verify_footer(lines, rows)

    quotes = [row for row in rows if row["kind"] == "QUOTE"]
    if [row["text"] for row in quotes] != list(EXPECTED_QUOTES) or any(
        row["class"] != "OPERATOR_CANON" for row in quotes
    ):
        raise HarnessError("operator quote ledger differs")

    authority = [row for row in rows if row["kind"] == "AUTHORITY"]
    if authority != [
        {
            "kind": "AUTHORITY",
            "github": "PUBLICATION_GATE",
            "metal": "0",
            "fabric": "0",
            "system_affirmed": "0",
            "fabric_state": "STALE_FALLBACK",
            "recall_state": "UNAVAILABLE",
            "liris_behcs": "HEALTH_ONLY",
        }
    ]:
        raise HarnessError("authority boundary differs")

    capture_boundaries = [
        row for row in rows if row["kind"] == "CAPTUREBOUNDARY"
    ]
    if capture_boundaries != [
        {
            "kind": "CAPTUREBOUNDARY",
            "semantics": "CONTAINING_COMMIT_PARENT_REFS",
            "self_referential_final_head_embedded": "0",
            "resume_action": "REMEASURE_CURRENT_REFS",
        }
    ]:
        raise HarnessError("self-reference boundary differs")

    boundaries = [row for row in rows if row["kind"] == "BOUNDARY"]
    if boundaries != [
        {
            "kind": "BOUNDARY",
            "raw_api_auth": "0",
            "credentials": "0",
            "private_paths": "0",
            "raw_response_text": "0",
            "hidden_dependencies": "0",
            "active_json": "0",
        }
    ]:
        raise HarnessError("public-data boundary differs")

    nodes: dict[str, dict[str, str]] = {}
    repositories: dict[str, str] = {}
    points: list[tuple[int, int, int]] = []
    for row in rows:
        if row["kind"] != "NODE":
            continue
        node_id = row.get("id", "")
        if not SAFE_ID.fullmatch(node_id) or node_id in nodes:
            raise HarnessError("node identity is malformed or duplicated")
        if row.get("evidence") not in {"MEASURED_GITHUB", "LOCAL_PENDING_PUBLICATION"}:
            raise HarnessError("node evidence class differs")
        object_type = row.get("object")
        if object_type not in {
            "REPOSITORY", "WORKFLOW_STATE", "BRANCH", "COMMIT", "BRANCH_STATE",
            "PULL_REQUEST", "HARNESS",
        }:
            raise HarnessError("node object type differs")
        if row.get("evidence") == "LOCAL_PENDING_PUBLICATION" and object_type != "HARNESS":
            raise HarnessError("local-pending evidence is confined to the harness node")
        object_sha = row.get("sha", "")
        if object_type == "COMMIT":
            if not SHA40.fullmatch(object_sha):
                raise HarnessError("commit node lacks an exact Git SHA")
            if row.get("state") not in {
                "CAPTURED_PARENT_REF", "CAPTURED_HISTORICAL_REF"
            }:
                raise HarnessError("commit capture state differs")
        elif object_type == "HARNESS" and row.get("state") == "PUBLIC":
            if not SHA40.fullmatch(object_sha):
                raise HarnessError("public harness lacks an exact Git blob SHA")
        elif object_sha != "NONE":
            raise HarnessError("non-content node carries an unexpected Git SHA")
        if row.get("object") == "REPOSITORY":
            repositories[node_id] = row.get("name", "")
            if row.get("state") != "PUBLIC" or row.get("evidence") != "MEASURED_GITHUB":
                raise HarnessError("repository node publication state differs")
        if object_type == "WORKFLOW_STATE":
            count_name = row.get("name", "")
            count_state = row.get("state", "")
            if not re.fullmatch(r"count_(?:0|[1-9][0-9]{0,2})", count_name):
                raise HarnessError("workflow node count name differs")
            if count_state != f"COUNT_{count_name.removeprefix('count_')}":
                raise HarnessError("workflow node count state differs")
            if int(count_name.removeprefix("count_")) > 100:
                raise HarnessError("workflow node count exceeds the bounded census")
        if object_type == "BRANCH" and row.get("state") not in {
            "PROTECTED", "UNPROTECTED"
        }:
            raise HarnessError("branch protection state differs")
        if object_type == "BRANCH_STATE" and (
            row.get("name") != "EMPTY_UNBORN"
            or row.get("state") != "BRANCH_COUNT_0"
        ):
            raise HarnessError("branch-state node differs")
        if object_type == "PULL_REQUEST" and not re.fullmatch(
            r"(?:OPEN|CLOSED)_(?:DRAFT|READY)_(?:MERGEABLE|CONFLICTING|MERGEABILITY_PENDING)_[A-Z0-9_]+",
            row.get("state", ""),
        ):
            raise HarnessError("pull-request state differs")
        point = coordinate(row)
        points.append(point)
        nodes[node_id] = row
    if repositories != EXPECTED_REPOSITORY_IDS:
        raise HarnessError("repository population differs")
    if len(points) != len(set(points)):
        raise HarnessError("node coordinates collapse distinct identities")
    verify_geometry(points)

    edge_ids: set[str] = set()
    edge_rows: list[dict[str, str]] = []
    allowed_relations = {
        "WORKFLOW_COUNT", "CONTAINS", "POINTS_TO", "HAS_BRANCH_STATE",
        "PROPOSES_TO", "PROPOSES_FROM", "MERGED_AS", "WILL_PUBLISH", "PUBLISHES",
    }
    allowed_type_pairs = {
        "WORKFLOW_COUNT": ("REPOSITORY", "WORKFLOW_STATE"),
        "CONTAINS": ("REPOSITORY", "BRANCH"),
        "POINTS_TO": ("BRANCH", "COMMIT"),
        "HAS_BRANCH_STATE": ("REPOSITORY", "BRANCH_STATE"),
        "PROPOSES_TO": ("PULL_REQUEST", "COMMIT"),
        "PROPOSES_FROM": ("PULL_REQUEST", "COMMIT"),
        "MERGED_AS": ("PULL_REQUEST", "COMMIT"),
        "WILL_PUBLISH": ("REPOSITORY", "HARNESS"),
        "PUBLISHES": ("REPOSITORY", "HARNESS"),
    }
    for row in rows:
        if row["kind"] != "EDGE":
            continue
        edge_id = row.get("id", "")
        if not SAFE_ID.fullmatch(edge_id) or edge_id in edge_ids:
            raise HarnessError("edge identity is malformed or duplicated")
        edge_ids.add(edge_id)
        if row.get("source") not in nodes or row.get("target") not in nodes:
            raise HarnessError("edge is dangling")
        if row.get("directed") != "1":
            raise HarnessError("edge direction is absent")
        relation = row.get("relation", "")
        if relation not in allowed_relations:
            raise HarnessError("edge relation differs")
        actual_pair = (
            nodes[row["source"]]["object"], nodes[row["target"]]["object"]
        )
        if actual_pair != allowed_type_pairs[relation]:
            raise HarnessError("edge endpoint object types differ")
        if row.get("evidence") not in {"MEASURED_GITHUB", "LOCAL_PENDING_PUBLICATION"}:
            raise HarnessError("edge evidence class differs")
        edge_rows.append(row)
    if not edge_ids:
        raise HarnessError("graph contains no edges")

    harnesses = [row for row in rows if row.get("object") == "HARNESS"]
    if len(harnesses) != 1:
        raise HarnessError("graph must contain one harness node")
    harness = harnesses[0]
    harness_state = (harness.get("evidence"), harness.get("state"))
    if harness_state not in {
        ("LOCAL_PENDING_PUBLICATION", "UNPUSHED"),
        ("MEASURED_GITHUB", "PUBLIC"),
    }:
        raise HarnessError("harness publication state differs")
    if harness_state[1] == "PUBLIC" and not SHA40.fullmatch(harness.get("sha", "")):
        raise HarnessError("public harness lacks its Git blob SHA")

    expected_node_ids = {
        "repo_universe", "workflow_universe", "repo_follow", "workflow_follow",
        "repo_safe", "workflow_safe", "harness_follow",
    }
    expected_edges: dict[str, tuple[str, str, str, str]] = {}
    for short in ("universe", "follow", "safe"):
        expected_edges[f"e_{short}_workflow"] = (
            f"repo_{short}", f"workflow_{short}", "WORKFLOW_COUNT", "MEASURED_GITHUB"
        )
        branch_id = f"branch_{short}_main"
        commit_id = f"commit_{short}_main"
        state_id = f"state_{short}_unborn"
        branch_present = branch_id in nodes
        state_present = state_id in nodes
        if branch_present == state_present:
            raise HarnessError(f"{short} must have exactly one branch-state form")
        if branch_present:
            if commit_id not in nodes:
                raise HarnessError(f"{short} main branch lacks its commit node")
            if nodes[branch_id]["name"] != "main" or nodes[commit_id]["name"] != "main_head":
                raise HarnessError(f"{short} main branch identity differs")
            expected_node_ids.update({branch_id, commit_id})
            expected_edges[f"e_{short}_contains_main"] = (
                f"repo_{short}", branch_id, "CONTAINS", "MEASURED_GITHUB"
            )
            expected_edges[f"e_{short}_main_points"] = (
                branch_id, commit_id, "POINTS_TO", "MEASURED_GITHUB"
            )
        else:
            expected_node_ids.add(state_id)
            expected_edges[f"e_{short}_empty"] = (
                f"repo_{short}", state_id, "HAS_BRANCH_STATE", "MEASURED_GITHUB"
            )

    feature_nodes = {
        "branch_universe_follow", "commit_universe_follow"
    }
    feature_present = feature_nodes.issubset(nodes)
    if bool(feature_nodes & nodes.keys()) != feature_present:
        raise HarnessError("Universe feature branch is only partially represented")
    if feature_present:
        if (
            nodes["branch_universe_follow"]["name"]
            != "agent.follow-is-light-book-20260729"
            or nodes["commit_universe_follow"]["name"] != "pr5_head"
        ):
            raise HarnessError("Universe feature branch identity differs")
        expected_node_ids.update(feature_nodes)
        expected_edges["e_universe_contains_follow"] = (
            "repo_universe", "branch_universe_follow", "CONTAINS", "MEASURED_GITHUB"
        )
        expected_edges["e_universe_follow_points"] = (
            "branch_universe_follow", "commit_universe_follow", "POINTS_TO",
            "MEASURED_GITHUB",
        )

    pr_present = "pr_universe_5" in nodes
    if pr_present:
        if not feature_present or "commit_universe_main" not in nodes:
            raise HarnessError("PR 5 lacks its captured base or head")
        if nodes["pr_universe_5"]["name"] != "5":
            raise HarnessError("PR node identity differs")
        expected_node_ids.add("pr_universe_5")
        merged = nodes["pr_universe_5"]["state"].endswith("_MERGED")
        historical_base = "commit_universe_pr5_base" in nodes
        if merged != historical_base:
            raise HarnessError("merged PR historical-base ledger differs")
        if merged:
            base = nodes["commit_universe_pr5_base"]
            if (
                base["name"] != "pr5_base"
                or base["state"] != "CAPTURED_HISTORICAL_REF"
                or base["sha"] == nodes["commit_universe_main"]["sha"]
            ):
                raise HarnessError("merged PR historical base differs")
            expected_node_ids.add("commit_universe_pr5_base")
            base_target = "commit_universe_pr5_base"
            expected_edges["e_pr5_merged"] = (
                "pr_universe_5", "commit_universe_main", "MERGED_AS",
                "MEASURED_GITHUB",
            )
        else:
            base_target = "commit_universe_main"
        expected_edges["e_pr5_base"] = (
            "pr_universe_5", base_target, "PROPOSES_TO", "MEASURED_GITHUB"
        )
        expected_edges["e_pr5_head"] = (
            "pr_universe_5", "commit_universe_follow", "PROPOSES_FROM",
            "MEASURED_GITHUB",
        )

    harness_relation = "PUBLISHES" if harness_state[1] == "PUBLIC" else "WILL_PUBLISH"
    harness_evidence = harness_state[0]
    expected_edges["e_follow_harness"] = (
        "repo_follow", "harness_follow", harness_relation, harness_evidence
    )
    if set(nodes) != expected_node_ids:
        raise HarnessError("node population contains a missing or extra identity")
    observed_edges = {
        row["id"]: (
            row["source"], row["target"], row["relation"], row["evidence"]
        )
        for row in edge_rows
    }
    if observed_edges != expected_edges:
        raise HarnessError("edge topology differs from the bounded graph")

    absences = [row for row in rows if row["kind"] == "ABSENCE"]
    absence_repositories: set[str] = set()
    for absence in absences:
        if set(absence) != {
            "kind", "repo", "branches", "workflows", "state", "evidence"
        } or absence["repo"] not in EXPECTED_REPOSITORIES or absence["branches"] != "0" or (
            absence["state"] != "EMPTY_UNBORN"
        ) or absence["evidence"] != "MEASURED_GITHUB":
            raise HarnessError("empty-unborn row differs")
        try:
            workflows = int(absence["workflows"])
        except ValueError as error:
            raise HarnessError("absence workflow count is malformed") from error
        if workflows < 0:
            raise HarnessError("absence workflow count is negative")
        if absence["repo"] in absence_repositories:
            raise HarnessError("empty-unborn row is duplicated")
        absence_repositories.add(absence["repo"])
        short = next(
            key.removeprefix("repo_")
            for key, value in EXPECTED_REPOSITORY_IDS.items()
            if value == absence["repo"]
        )
        workflow_count = nodes[f"workflow_{short}"]["state"].removeprefix("COUNT_")
        if absence["workflows"] != workflow_count:
            raise HarnessError("absence workflow count differs from its node")
    expected_absences = {
        name
        for node_id, name in EXPECTED_REPOSITORY_IDS.items()
        if f"state_{node_id.removeprefix('repo_')}_unborn" in nodes
    }
    if absence_repositories != expected_absences:
        raise HarnessError("empty-unborn ledger differs from branch-state nodes")
    digest = verify_sidecar(path, data)
    return len(nodes), len(edge_ids), digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("graph", nargs="?", type=Path, default=DEFAULT_GRAPH)
    parser.add_argument("--max-age-seconds", type=int)
    args = parser.parse_args()
    try:
        nodes, edges, digest = verify(args.graph, args.max_age_seconds)
    except (OSError, UnicodeError, HarnessError) as error:
        print(f"G3DVERIFY|PASS=0|error={type(error).__name__}|json=0")
        return 1
    print(
        f"G3DVERIFY|PASS=1|nodes={nodes}|edges={edges}|sha256={digest}"
        "|geometry=SPHERICAL_3D|system_affirmed=0|secret_findings=0|json=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
