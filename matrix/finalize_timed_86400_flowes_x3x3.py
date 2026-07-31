#!/usr/bin/env python3
"""Mint or verify the compact public witness for the completed 86,400-second run.

The production CLI has exactly two modes.  ``mint`` verifies the complete private
expanded bundle and writes a separate six-file public evidence directory.
``verify-public`` reconstructs all five expanded artifacts in memory from the
on-demand public source plus the published restart journal.  Neither mode accepts
a target duration or timing-mode override.

``REAL_MONOTONIC`` is provenance emitted by the exact launched builder, whose watch
path requires ``SystemClock``.  The journal has no independent clock samples, so this
tool validates that provenance chain without upgrading it to independent time
attestation; every final receipt keeps ``independent_time_attestation=0``.

``mint`` acquires the builder's nonblocking output lock before reading the completed
bundle.  That lock is scoped to one OS/runtime namespace; the current Windows-owned
watch therefore pairs with Windows Python for mint, while Ubuntu/WSL cross-verification
runs after the watch has exited and released its Windows lock.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

import build_timed_86400_flowes_x3x3 as flow


FINAL_SCHEMA = "ASOLARIA-TIMED-86400-FLOWes-X3-X3-FINAL-V1"
FINAL_HBP = "LIRIS-TIMED-86400-FLOWes-X3-X3-FINAL.hbp"
FINAL_HBI = "LIRIS-TIMED-86400-FLOWes-X3-X3-FINAL.hbi"

BUILDER_REPOSITORY = "JesseBrown1980/FOLLOW-THE-IS-NOT-THE-WILL-AND-WAS"
BUILDER_COMMIT = "cf4f760f943087d312894cef5a683d99fc0119df"
BUILDER_REPOSITORY_PATH = "matrix/build_timed_86400_flowes_x3x3.py"
BUILDER_GIT_BLOB = "a38ffd2f5b00d2b0008c5be4265f173a1e2e926c"
BUILDER_BYTES = 65_159
BUILDER_SHA256 = "8d63fb45f05cd411861e2cac7a1f8abaa352ffd26fc4af32ca21a921c4b507e1"

QPRISM_BINDING_HBP_SHA256 = (
    "3c58554b0a9abd52f658ecc96cb115cb42da3e7642b06a989585da269128c3ff"
)
QPRISM_BINDING_HBI_SHA256 = (
    "1514470eec0a3c6cd8ce091fabe08c33e136f7dd849f10c75e1f949e2a17c0d9"
)
GRADIENT_AUDIT_HBP = "LIRIS-RUST-181-GRADIENT-SEMANTICS-2026-07-31.hbp"
GRADIENT_AUDIT_HBI = "LIRIS-RUST-181-GRADIENT-SEMANTICS-2026-07-31.hbi"
GRADIENT_AUDIT_HBP_SHA256 = (
    "707f73b6013f8152adc9e524e9131716f8ccaa881857fc990ef793167b302896"
)
GRADIENT_AUDIT_HBI_SHA256 = (
    "8281bdaf2901b0d376a88bcf2c6f53e731c36edd3cac65ae47b56761790f80c9"
)

ARTIFACT_ROOT_DOMAIN = (
    "ASOLARIA-TIMED-86400-FLOWes-X3-X3-FINAL-V1.LOCAL-ARTIFACTS"
)
ARTIFACT_ROOT_ALGORITHM = "SHA256_DOMAIN_UTF8_V1"

EXPANDED_SPECS = (
    ("EXPANDED_HBP", flow.OUTPUT_HBP),
    ("EXPANDED_HBI", flow.OUTPUT_HBI),
    ("SVG", flow.OUTPUT_SVG),
    ("GGUF", flow.OUTPUT_GGUF),
    ("STDOUT_HBP", flow.OUTPUT_STDOUT),
)
EXPANDED_ORDER = ",".join(kind for kind, _ in EXPANDED_SPECS)
PUBLIC_NAMES = (
    flow.OUTPUT_JOURNAL,
    flow.OUTPUT_JOURNAL + ".sha256",
    FINAL_HBP,
    FINAL_HBP + ".sha256",
    FINAL_HBI,
    FINAL_HBI + ".sha256",
)
LOCAL_NAMES = tuple(
    name
    for artifact in flow.OUTPUT_NAMES
    for name in (artifact, artifact + ".sha256")
)
SAFE_BASENAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


@dataclass(frozen=True)
class FinalPolicy:
    target_seconds: int
    timing_mode: str
    require_committed_source: bool
    evidence: str
    clock: str
    clock_owner: str
    timing_evidence: str


@dataclass(frozen=True)
class ArtifactRecord:
    kind: str
    name: str
    size: int
    sha256: str


PRODUCTION_POLICY = FinalPolicy(
    target_seconds=flow.TARGET_SECONDS,
    timing_mode="REAL_MONOTONIC",
    require_committed_source=True,
    evidence="MEASURED_LIRIS_LOCAL",
    clock="PYTHON_TIME_MONOTONIC_NS",
    clock_owner="SystemClock",
    timing_evidence="MEASURED_MONOTONIC_SESSION_SECONDS",
)


def _injected_test_policy() -> FinalPolicy:
    """Return the sole internal short-duration policy; the CLI cannot select it."""
    return FinalPolicy(
        target_seconds=8,
        timing_mode="INJECTED_TEST_CLOCK",
        require_committed_source=False,
        evidence="INJECTED_TEST_ONLY",
        clock="INJECTED_TEST_CLOCK",
        clock_owner="TestClock",
        timing_evidence="INJECTED_CLOCK_TEST_ONLY",
    )


def _git_blob_sha1(data: bytes) -> str:
    payload = f"blob {len(data)}\0".encode("ascii") + data
    return hashlib.sha1(payload).hexdigest()


def _verify_launched_builder() -> None:
    matrix_dir = Path(__file__).resolve().parent
    expected_path = matrix_dir / (
        "build_timed_86400_flowes_x3x3.py"
    )
    actual_module_path = Path(flow.__file__).resolve()
    if actual_module_path != expected_path:
        raise flow.FlowesError("BUILDER_MODULE_PATH")
    data = flow.verify_sidecar(expected_path)
    if len(data) != BUILDER_BYTES:
        raise flow.FlowesError("BUILDER_BYTES")
    if flow.sha256_bytes(data) != BUILDER_SHA256:
        raise flow.FlowesError("BUILDER_SHA256")
    if _git_blob_sha1(data) != BUILDER_GIT_BLOB:
        raise flow.FlowesError("BUILDER_GIT_BLOB")
    if (
        flow.TARGET_SECONDS != 86_400
        or flow.COMMITTED_SOURCE_HBP_SHA256
        != "43300780cac2b85e3ed6cfa10398052f530ccbf76c43b404e650c26c9ed8b006"
        or flow.COMMITTED_SOURCE_HBI_SHA256
        != "9920d5cb2031d6453fba2d410e4b2f6e0136a4537fa6ea2ea9385c163503a28b"
        or flow.CENTER_MEMBERS != ("HBI", "HBP", "SHA", "SH", "HASH")
        or flow.CENTER_TRAVERSAL != "HBI->HBP->SH->HASH->SHA"
    ):
        raise flow.FlowesError("BUILDER_CONTRACT")
    receipt_dir = matrix_dir.parent / "receipts"
    for name, expected in (
        (GRADIENT_AUDIT_HBP, GRADIENT_AUDIT_HBP_SHA256),
        (GRADIENT_AUDIT_HBI, GRADIENT_AUDIT_HBI_SHA256),
    ):
        data = flow.verify_sidecar(receipt_dir / name)
        if flow.sha256_bytes(data) != expected:
            raise flow.FlowesError("GRADIENT_AUDIT_SHA256:" + name)


def _semantic_fields(
    source: flow.SourceBundle, policy: FinalPolicy,
) -> dict[str, object]:
    """Derive the finite gradient ledger without changing the launched builder."""
    if len(source.leaves) != source.folder_count * len(flow.FAMILIES):
        raise flow.FlowesError("SEMANTIC_SOURCE_POPULATION")
    by_folder: dict[int, list[flow.SourceLeaf]] = {}
    for leaf in source.leaves:
        if re.fullmatch(r"RGB\.[0-9A-F]{6}", leaf.color) is None:
            raise flow.FlowesError("SEMANTIC_COLOR_FORMAT")
        numeric = (
            leaf.index, leaf.folder_i, leaf.family_i, leaf.source_level,
            leaf.view_x, leaf.view_y, leaf.view_z,
            leaf.projected_u, leaf.projected_v,
        )
        if any(type(value) is not int for value in numeric):
            raise flow.FlowesError("SEMANTIC_NON_INTEGER_FIELD")
        by_folder.setdefault(leaf.folder_i, []).append(leaf)
    if len(by_folder) != source.folder_count:
        raise flow.FlowesError("SEMANTIC_FOLDER_POPULATION")
    for folder_i in range(source.folder_count):
        group = by_folder.get(folder_i, [])
        if tuple(leaf.family for leaf in group) != flow.FAMILIES:
            raise flow.FlowesError("SEMANTIC_FAMILY_COMPLETENESS")
        if len({leaf.color for leaf in group}) != len(flow.FAMILIES):
            raise flow.FlowesError("SEMANTIC_FAMILY_COLOR_COLLAPSE")

    gradient_states = len({leaf.color for leaf in source.leaves})
    unique_3d_positions = len(
        {(leaf.view_x, leaf.view_y, leaf.view_z) for leaf in source.leaves}
    )
    unique_2d_projections = len(
        {(leaf.projected_u, leaf.projected_v) for leaf in source.leaves}
    )
    if gradient_states <= 2:
        raise flow.FlowesError("SEMANTIC_BINARY_COLLAPSE")
    source_matches_audit = (
        source.hbp_sha256 == flow.COMMITTED_SOURCE_HBP_SHA256
        and source.hbi_sha256 == flow.COMMITTED_SOURCE_HBI_SHA256
    )
    if policy.require_committed_source and (
        not source_matches_audit
        or source.folder_count != 3_536
        or len(source.leaves) != 10_608
        or gradient_states != 10_586
        or unique_3d_positions != 10_608
        or unique_2d_projections != 10_397
    ):
        raise flow.FlowesError("PRODUCTION_GRADIENT_SEMANTICS")
    return {
        "transport": "OCTETS",
        "semantic_binary": 0,
        "semantic_families": len(flow.FAMILIES),
        "gradient_states": gradient_states,
        "family_colors_distinct_per_folder": 1,
        "unique_3d_positions": unique_3d_positions,
        "unique_2d_projections": unique_2d_projections,
        "integer_fields_only": 1,
        "finite_capture": 1,
        "actual_infinite_capture": 0,
        "n_level_open": 1,
        "logical_identity_ceiling": 0,
        "reflection_window_per_observed_level": flow.OBSERVATION_LIMIT,
        "source_renderer": (
            "RUST_1_81_CHECKED_INTEGER"
            if source_matches_audit
            else "INJECTED_INTEGER_TEST_SOURCE"
        ),
        "gradient_audit_source_match": int(source_matches_audit),
        "source_hbp_sha256": source.hbp_sha256,
        "source_hbi_sha256": source.hbi_sha256,
        "gradient_audit_hbp_sha256": GRADIENT_AUDIT_HBP_SHA256,
        "gradient_audit_hbi_sha256": GRADIENT_AUDIT_HBI_SHA256,
        "json": 0,
    }


def _require_directory(path: Path, context: str) -> Path:
    if not path.exists() or not path.is_dir() or path.is_symlink():
        raise flow.FlowesError(context + "_DIRECTORY")
    return path.resolve()


def _require_exact_files(directory: Path, expected: Sequence[str], context: str) -> None:
    entries = tuple(directory.iterdir())
    if any(not item.is_file() or item.is_symlink() for item in entries):
        raise flow.FlowesError(context + "_NON_FILE")
    names = tuple(item.name for item in entries)
    if len(names) != len(set(names)):
        raise flow.FlowesError(context + "_DUPLICATE")
    if set(names) != set(expected) or len(names) != len(expected):
        raise flow.FlowesError(context + "_FILE_SET")


def _require_empty_destination(path: Path) -> Path:
    if path.exists():
        if not path.is_dir() or path.is_symlink():
            raise flow.FlowesError("PUBLIC_EVIDENCE_DIRECTORY")
        if any(path.iterdir()):
            raise flow.FlowesError("PUBLIC_EVIDENCE_NOT_EMPTY")
    else:
        path.mkdir(parents=True, exist_ok=False)
    return path.resolve()


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _safe_basename(name: str, context: str) -> str:
    if SAFE_BASENAME_RE.fullmatch(name) is None or name in (".", ".."):
        raise flow.FlowesError("PRIVATE_PATH:" + context)
    return name


def _load_complete_journal(
    source: flow.SourceBundle,
    directory: Path,
    policy: FinalPolicy,
) -> tuple[flow.Journal, bytes]:
    journal_path = directory / flow.OUTPUT_JOURNAL
    journal_data = flow.verify_sidecar(journal_path)
    try:
        journal = flow.parse_journal_bytes(
            journal_data, source, policy.target_seconds, policy.timing_mode
        )
    except (KeyError, IndexError) as exc:
        raise flow.FlowesError("FINAL_JOURNAL_STRUCTURE") from exc
    expected_schedule = flow.schedule(policy.target_seconds)
    if not journal.complete:
        raise flow.FlowesError("FINAL_JOURNAL_INCOMPLETE")
    if tuple(item.checkpoint_seconds for item in journal.checkpoints) != expected_schedule:
        raise flow.FlowesError("FINAL_JOURNAL_CHECKPOINT_SET")
    if len(journal.checkpoints) != len(expected_schedule):
        raise flow.FlowesError("FINAL_JOURNAL_CHECKPOINT_COUNT")
    if (
        policy.target_seconds == flow.TARGET_SECONDS
        and policy.timing_mode == "REAL_MONOTONIC"
        and len(journal.checkpoints) != 19
    ):
        raise flow.FlowesError("PRODUCTION_CHECKPOINT_COUNT")
    if not journal.sessions:
        raise flow.FlowesError("FINAL_JOURNAL_SESSIONS")
    lines = journal_data.decode("utf-8").splitlines()
    boundary_rows = [
        flow.parse_tuple(line, "BOUNDARY")
        for line in lines
        if line.startswith("BOUNDARY|")
    ]
    if len(boundary_rows) != 1:
        raise flow.FlowesError("FINAL_JOURNAL_BOUNDARY_COUNT")
    flow.require_fields(
        boundary_rows[0],
        {
            "wall_clock": "0",
            "supplied_start_time": "0",
            "cross_process_gap_credit": "0",
            "uncheckpointed_credit": "0",
            "network": "0",
            "execution": "0",
            "authority": "0",
            "physical_energy": "0",
            "json": "0",
        },
        "FINAL_JOURNAL_BOUNDARY",
    )
    return journal, journal_data


def _build_twice(
    source: flow.SourceBundle, journal: flow.Journal
) -> tuple[dict[str, bytes], dict[str, bytes]]:
    first = flow.build_bundle(source, journal)
    second = flow.build_bundle(source, journal)
    if set(first) != set(flow.OUTPUT_NAMES) or set(second) != set(flow.OUTPUT_NAMES):
        raise flow.FlowesError("REBUILD_FILE_SET")
    for name in flow.OUTPUT_NAMES:
        if first[name] != second[name]:
            raise flow.FlowesError("REBUILD_A_NE_B:" + name)
    return first, second


def _records(bundle: dict[str, bytes]) -> tuple[ArtifactRecord, ...]:
    records = tuple(
        ArtifactRecord(kind, _safe_basename(name, kind), len(bundle[name]), flow.sha256_bytes(bundle[name]))
        for kind, name in EXPANDED_SPECS
    )
    if tuple(record.kind for record in records) != tuple(
        kind for kind, _ in EXPANDED_SPECS
    ):
        raise AssertionError("artifact record order")
    return records


def artifact_root(records: Sequence[ArtifactRecord]) -> str:
    if tuple(record.kind for record in records) != tuple(
        kind for kind, _ in EXPANDED_SPECS
    ):
        raise flow.FlowesError("ARTIFACT_ROOT_ORDER")
    digest = hashlib.sha256()
    digest.update(ARTIFACT_ROOT_DOMAIN.encode("utf-8") + b"\0")
    for record in records:
        _safe_basename(record.name, record.kind)
        flow.require_hash(record.sha256, record.kind)
        digest.update(record.kind.encode("utf-8") + b"\0")
        digest.update(record.name.encode("utf-8") + b"\0")
        digest.update(str(record.size).encode("ascii") + b"\0")
        digest.update(record.sha256.encode("ascii") + b"\n")
    return digest.hexdigest()


def _expanded_commitments(hbp: bytes, hbi: bytes) -> tuple[str, str, str]:
    lines = flow.verify_text_artifact(hbp, "FLOWEX9V2FTR")
    hash_rows = [
        flow.parse_tuple(line, "HASH")
        for line in lines
        if line.startswith("HASH|")
    ]
    if len(hash_rows) != 1 or hash_rows[0].get("role") != "FLOWEX9_V2_OBJECT_COMMITMENT":
        raise flow.FlowesError("EXPANDED_OBJECT_HASH_ROW")
    row = hash_rows[0]
    object_hash = flow.require_hash(row.get("value", ""), "EXPANDED_OBJECT")
    ring_commitment = flow.require_hash(
        row.get("ring_commitment", ""), "EXPANDED_RINGS"
    )
    cell_commitment = flow.require_hash(
        row.get("cell_commitment", ""), "EXPANDED_CELLS"
    )
    hbi_lines = flow.verify_text_artifact(hbi, "FLOWEX9V2IDXFTR")
    hbi_centers = [
        flow.parse_tuple(line, "CENTER")
        for line in hbi_lines
        if line.startswith("CENTER|")
    ]
    if len(hbi_centers) != 1:
        raise flow.FlowesError("EXPANDED_HBI_CENTER_COUNT")
    if hbi_centers[0].get("object_hash") != object_hash:
        raise flow.FlowesError("EXPANDED_HBI_OBJECT_HASH")
    cell_rows = [
        flow.parse_tuple(line, "FLOWE")
        for line in lines
        if line.startswith("FLOWE|")
    ]
    for row in cell_rows:
        values = tuple(row.get(key, "") for key in ("hbi", "hbp", "sha", "sh", "hash"))
        if any(flow.SHA256_RE.fullmatch(value) is None for value in values):
            raise flow.FlowesError("EXPANDED_CENTER_HASH")
        if len(set(values)) != 5:
            raise flow.FlowesError("EXPANDED_CENTER_NOT_DISTINCT")
    return object_hash, ring_commitment, cell_commitment


def _final_hbp(
    source: flow.SourceBundle,
    journal: flow.Journal,
    journal_data: bytes,
    records: Sequence[ArtifactRecord],
    root: str,
    bundle: dict[str, bytes],
    policy: FinalPolicy,
    semantics: dict[str, object],
) -> bytes:
    object_hash, ring_commitment, cell_commitment = _expanded_commitments(
        bundle[flow.OUTPUT_HBP], bundle[flow.OUTPUT_HBI]
    )
    checkpoints = len(flow.schedule(policy.target_seconds))
    rows = [
        flow.tuple_row(
            "LIRISFLOWEX9FINALHDR", schema=FINAL_SCHEMA,
            evidence=policy.evidence, status="COMPLETE",
            timing_mode=policy.timing_mode, target_seconds=policy.target_seconds,
            checkpoints=checkpoints, independent_time_attestation=0,
            system_affirmed=0, json=0,
        ),
        flow.tuple_row(
            "BUILDER", repo=BUILDER_REPOSITORY, commit=BUILDER_COMMIT,
            path=BUILDER_REPOSITORY_PATH, git_blob=BUILDER_GIT_BLOB,
            bytes=BUILDER_BYTES, sha256=BUILDER_SHA256,
            sidecar_verified=1, json=0,
        ),
        flow.tuple_row(
            "SOURCE", kind="HBP", file=flow.SOURCE_HBP,
            bytes=len(source.hbp), sha256=source.hbp_sha256,
            source_mode="ON_DEMAND", sidecar_verified=1, json=0,
        ),
        flow.tuple_row(
            "SOURCE", kind="HBI", file=flow.SOURCE_HBI,
            bytes=len(source.hbi), sha256=source.hbi_sha256,
            source_mode="ON_DEMAND", sidecar_verified=1, json=0,
        ),
        flow.tuple_row(
            "REGENERATOR", input="PUBLIC-FOLDER-3D-TREE.hbp",
            generator="matrix/rust-qprism-181/src/bin/folder-calming-oils.rs",
            rust="1.81.0", qprism_binding_hbp_sha256=QPRISM_BINDING_HBP_SHA256,
            qprism_binding_hbi_sha256=QPRISM_BINDING_HBI_SHA256,
            preexpanded_source_required=0, json=0,
        ),
        flow.tuple_row(
            "JOURNAL", file=flow.OUTPUT_JOURNAL, bytes=len(journal_data),
            sha256=flow.sha256_bytes(journal_data), sidecar_verified=1,
            sessions=len(journal.sessions), checkpoint_count=len(journal.checkpoints),
            accumulated_monotonic_session_seconds=journal.accumulated_seconds,
            final_checkpoint_seconds=journal.checkpoints[-1].checkpoint_seconds,
            final_checkpoint_hash=journal.checkpoints[-1].checkpoint_hash,
            wall_clock_credit=0, cross_process_gap_credit=0,
            uncheckpointed_credit=0, published=1, json=0,
        ),
        flow.tuple_row(
            "CLOCK", clock=policy.clock, owner=policy.clock_owner,
            timing_evidence=policy.timing_evidence,
            independent_time_attestation=0, wall_clock_attestation=0, json=0,
        ),
    ]
    for record in records:
        fields: dict[str, object] = {
            "kind": record.kind,
            "file": record.name,
            "bytes": record.size,
            "sha256": record.sha256,
            "sidecar_verified": 1,
            "published": 0,
            "regenerable": 1,
        }
        if record.kind == "SVG":
            fields.update(static=1, script=0, network=0, execution=0)
        if record.kind == "GGUF":
            fields.update(descriptor_only=1)
        fields["json"] = 0
        rows.append(flow.tuple_row("LOCALARTIFACT", **fields))
    rows.extend(
        [
            flow.tuple_row(
                "ARTIFACTROOT", algorithm=ARTIFACT_ROOT_ALGORITHM,
                domain=ARTIFACT_ROOT_DOMAIN, order=EXPANDED_ORDER,
                value=root, json=0,
            ),
            flow.tuple_row(
                "REGENERATION",
                inputs="PINNED_BUILDER,ON_DEMAND_PUBLIC_SOURCE,FINAL_REAL_JOURNAL",
                runs=2, a_equals_b=1, a_equals_live=1, expanded_artifacts=5,
                a_equals_live_scope="MINT_LOCAL_PROVENANCE",
                required_hidden_dependencies=0, json=0,
            ),
            flow.tuple_row(
                "SHAPE", folders=source.folder_count, families=3, directions=3,
                final_cells=source.folder_count * 9, checkpoints=checkpoints,
                ring_summaries=checkpoints * 9,
                observation_limit=flow.OBSERVATION_LIMIT, json=0,
            ),
            flow.tuple_row("SEMANTICS", **semantics),
            flow.tuple_row(
                "CENTER", members=",".join(flow.CENTER_MEMBERS),
                traversal=flow.CENTER_TRAVERSAL, commitments_per_cell=5,
                domain_separated=1, sha_equals_hash=0,
                expanded_object_hash=object_hash,
                ring_commitment=ring_commitment,
                cell_commitment=cell_commitment, json=0,
            ),
            flow.tuple_row(
                "SUPERSEDES",
                historical_pointer="TIMED-86400-FLOWes-X3-X3-RUNNING.hbi",
                historical_pointer_retained=1, current_pointer=FINAL_HBI, json=0,
            ),
            flow.tuple_row(
                "BOUNDARY", local_output_path=0, private_paths=0,
                credentials=0, raw_console_published=0,
                expanded_artifacts_published=0, network=0,
                execution_authority=0, physical_energy=0,
                independent_time_attestation=0, system_affirmed=0, json=0,
            ),
        ]
    )
    if len(rows) != 19:
        raise AssertionError("final HBP body row count")
    body = ("\n".join(rows) + "\n").encode("utf-8")
    rows.append(
        flow.tuple_row(
            "LIRISFLOWEX9FINALFTR", body_sha256=flow.sha256_bytes(body),
            rows=20, json=0,
        )
    )
    return ("\n".join(rows) + "\n").encode("utf-8")


def _final_hbi(
    source: flow.SourceBundle,
    journal_data: bytes,
    final_hbp: bytes,
    root: str,
    semantics: dict[str, object],
) -> bytes:
    rows = [
        flow.tuple_row(
            "FLOWEX9FINALIDX", schema=FINAL_SCHEMA, status="COMPLETE",
            hbp_file=FINAL_HBP, hbp_bytes=len(final_hbp),
            hbp_sha256=flow.sha256_bytes(final_hbp),
            journal_file=flow.OUTPUT_JOURNAL, journal_bytes=len(journal_data),
            journal_sha256=flow.sha256_bytes(journal_data),
            artifact_root_sha256=root, json=0,
        ),
        flow.tuple_row(
            "PUBLIC", journal=1, final_hbp=1, final_hbi=1,
            expanded_hbp=0, expanded_hbi=0, svg=0, gguf=0,
            stdout_hbp=0, json=0,
        ),
        flow.tuple_row(
            "REGENERATION", builder_commit=BUILDER_COMMIT,
            builder_sha256=BUILDER_SHA256,
            source_hbp_sha256=source.hbp_sha256,
            source_hbi_sha256=source.hbi_sha256,
            regenerable=1, required_hidden_dependencies=0, json=0,
        ),
        flow.tuple_row("SEMANTICS", **semantics),
        flow.tuple_row(
            "CENTER", members=",".join(flow.CENTER_MEMBERS),
            traversal=flow.CENTER_TRAVERSAL, sha_equals_hash=0, json=0,
        ),
        flow.tuple_row(
            "BOUNDARY", local_output_path=0, private_paths=0,
            credentials=0, independent_time_attestation=0,
            system_affirmed=0, json=0,
        ),
    ]
    body = ("\n".join(rows) + "\n").encode("utf-8")
    rows.append(
        flow.tuple_row(
            "FLOWEX9FINALIDXFTR", body_sha256=flow.sha256_bytes(body),
            rows=7, json=0,
        )
    )
    return ("\n".join(rows) + "\n").encode("utf-8")


def _validate_final_text(hbp: bytes, hbi: bytes) -> None:
    hbp_lines = flow.verify_text_artifact(hbp, "LIRISFLOWEX9FINALFTR")
    hbi_lines = flow.verify_text_artifact(hbi, "FLOWEX9FINALIDXFTR")
    expected_hbp_tags = (
        "LIRISFLOWEX9FINALHDR", "BUILDER", "SOURCE", "SOURCE",
        "REGENERATOR", "JOURNAL", "CLOCK",
        "LOCALARTIFACT", "LOCALARTIFACT", "LOCALARTIFACT",
        "LOCALARTIFACT", "LOCALARTIFACT", "ARTIFACTROOT",
        "REGENERATION", "SHAPE", "SEMANTICS", "CENTER", "SUPERSEDES",
        "BOUNDARY",
        "LIRISFLOWEX9FINALFTR",
    )
    expected_hbi_tags = (
        "FLOWEX9FINALIDX", "PUBLIC", "REGENERATION", "SEMANTICS", "CENTER",
        "BOUNDARY", "FLOWEX9FINALIDXFTR",
    )
    if tuple(line.split("|", 1)[0] for line in hbp_lines) != expected_hbp_tags:
        raise flow.FlowesError("FINAL_HBP_ROW_ORDER")
    if tuple(line.split("|", 1)[0] for line in hbi_lines) != expected_hbi_tags:
        raise flow.FlowesError("FINAL_HBI_ROW_ORDER")
    local_rows = [
        flow.parse_tuple(line, "LOCALARTIFACT")
        for line in hbp_lines
        if line.startswith("LOCALARTIFACT|")
    ]
    for row, (kind, name) in zip(local_rows, EXPANDED_SPECS):
        if row.get("kind") != kind or row.get("file") != name:
            raise flow.FlowesError("FINAL_LOCAL_ARTIFACT_ORDER")
        _safe_basename(row.get("file", ""), kind)
        flow.require_fields(
            row,
            {"published": "0", "regenerable": "1", "sidecar_verified": "1"},
            "FINAL_LOCAL_ARTIFACT",
        )
    hbp_semantics = flow.parse_tuple(hbp_lines[15], "SEMANTICS")
    hbi_semantics = flow.parse_tuple(hbi_lines[3], "SEMANTICS")
    if hbp_semantics != hbi_semantics:
        raise flow.FlowesError("FINAL_SEMANTICS_CROSS_BINDING")
    flow.require_fields(
        hbp_semantics,
        {
            "transport": "OCTETS",
            "semantic_binary": "0",
            "semantic_families": "3",
            "family_colors_distinct_per_folder": "1",
            "integer_fields_only": "1",
            "finite_capture": "1",
            "actual_infinite_capture": "0",
            "n_level_open": "1",
            "logical_identity_ceiling": "0",
            "reflection_window_per_observed_level": str(flow.OBSERVATION_LIMIT),
            "gradient_audit_hbp_sha256": GRADIENT_AUDIT_HBP_SHA256,
            "gradient_audit_hbi_sha256": GRADIENT_AUDIT_HBI_SHA256,
            "json": "0",
        },
        "FINAL_SEMANTICS",
    )
    for key in (
        "gradient_states", "unique_3d_positions", "unique_2d_projections",
    ):
        if int(hbp_semantics.get(key, "0")) < 3:
            raise flow.FlowesError("FINAL_SEMANTICS_CARDINALITY:" + key)
    for key in (
        "source_hbp_sha256", "source_hbi_sha256",
        "gradient_audit_hbp_sha256", "gradient_audit_hbi_sha256",
    ):
        flow.require_hash(hbp_semantics.get(key, ""), "FINAL_SEMANTICS_" + key)
    source_match = hbp_semantics.get("gradient_audit_source_match")
    renderer = hbp_semantics.get("source_renderer")
    if source_match == "1":
        if (
            renderer != "RUST_1_81_CHECKED_INTEGER"
            or hbp_semantics.get("source_hbp_sha256")
            != flow.COMMITTED_SOURCE_HBP_SHA256
            or hbp_semantics.get("source_hbi_sha256")
            != flow.COMMITTED_SOURCE_HBI_SHA256
            or hbp_semantics.get("gradient_states") != "10586"
            or hbp_semantics.get("unique_3d_positions") != "10608"
            or hbp_semantics.get("unique_2d_projections") != "10397"
        ):
            raise flow.FlowesError("FINAL_SEMANTICS_PRODUCTION_BINDING")
    elif source_match != "0" or renderer != "INJECTED_INTEGER_TEST_SOURCE":
        raise flow.FlowesError("FINAL_SEMANTICS_SOURCE_MODE")

    center = flow.parse_tuple(hbp_lines[16], "CENTER")
    flow.require_fields(
        center,
        {
            "members": ",".join(flow.CENTER_MEMBERS),
            "traversal": flow.encode_value(flow.CENTER_TRAVERSAL),
            "sha_equals_hash": "0",
            "json": "0",
        },
        "FINAL_CENTER",
    )


def _build_final_files(
    source: flow.SourceBundle,
    journal: flow.Journal,
    journal_data: bytes,
    bundle: dict[str, bytes],
    policy: FinalPolicy,
) -> tuple[bytes, bytes, tuple[ArtifactRecord, ...], str]:
    semantics = _semantic_fields(source, policy)
    records = _records(bundle)
    root = artifact_root(records)
    hbp = _final_hbp(
        source, journal, journal_data, records, root, bundle, policy, semantics
    )
    hbi = _final_hbi(source, journal_data, hbp, root, semantics)
    _validate_final_text(hbp, hbi)
    return hbp, hbi, records, root


def _assert_paths_absent(blobs: Sequence[bytes], paths: Sequence[Path]) -> None:
    for path in paths:
        plain = {str(path), str(path).replace("\\", "/")}
        variants = plain | {flow.encode_value(value) for value in plain}
        for value in variants:
            needle = value.encode("utf-8").lower()
            if needle and any(needle in blob.lower() for blob in blobs):
                raise flow.FlowesError("PRIVATE_PATH_EMBEDDED")


def _mint(
    source_dir: Path,
    completed_output_dir: Path,
    public_evidence_dir: Path,
    policy: FinalPolicy,
) -> dict[str, str]:
    _verify_launched_builder()
    source_path = _require_directory(source_dir, "SOURCE")
    output_path = _require_directory(completed_output_dir, "COMPLETED_OUTPUT")
    evidence_candidate = public_evidence_dir.resolve()
    if _paths_overlap(output_path, evidence_candidate) or _paths_overlap(
        source_path, evidence_candidate
    ):
        raise flow.FlowesError("PUBLIC_EVIDENCE_NOT_SEPARATE")
    # Mint is a reader of the completed watch bundle, but it must still own the
    # same nonblocking OS lock as the writer.  This prevents a complete-looking
    # checkpoint from being read while the watch process remains able to mutate
    # that output.  Lock contention occurs before the public destination is
    # created or inspected for publication.
    with flow.WriterLock(output_path, "compact-final-mint"):
        source = flow.load_source(
            source_path, require_committed=policy.require_committed_source
        )
        journal, journal_data = _load_complete_journal(source, output_path, policy)
        _require_exact_files(output_path, LOCAL_NAMES, "COMPLETED_OUTPUT")
        first, second = _build_twice(source, journal)
        if first != second:
            raise flow.FlowesError("REBUILD_A_NE_B")
        live: dict[str, bytes] = {}
        for name in flow.OUTPUT_NAMES:
            live[name] = flow.verify_sidecar(output_path / name)
            if live[name] != first[name]:
                raise flow.FlowesError("REBUILD_A_NE_LIVE:" + name)
        if live[flow.OUTPUT_JOURNAL] != journal_data:
            raise flow.FlowesError("LIVE_JOURNAL_CHANGED")
        final_hbp, final_hbi, _, _ = _build_final_files(
            source, journal, journal_data, live, policy
        )
        _assert_paths_absent(
            (journal_data, final_hbp, final_hbi), (source_path, output_path)
        )
        evidence_path = _require_empty_destination(public_evidence_dir)
        flow.write_sealed(evidence_path / flow.OUTPUT_JOURNAL, journal_data)
        flow.write_sealed(evidence_path / FINAL_HBP, final_hbp)
        flow.write_sealed(evidence_path / FINAL_HBI, final_hbi)
        _require_exact_files(evidence_path, PUBLIC_NAMES, "PUBLIC_EVIDENCE")
        return _verify_public(source_path, evidence_path, policy)


def _verify_public(
    source_dir: Path, public_evidence_dir: Path, policy: FinalPolicy
) -> dict[str, str]:
    _verify_launched_builder()
    source_path = _require_directory(source_dir, "SOURCE")
    evidence_path = _require_directory(public_evidence_dir, "PUBLIC_EVIDENCE")
    _require_exact_files(evidence_path, PUBLIC_NAMES, "PUBLIC_EVIDENCE")
    source = flow.load_source(
        source_path, require_committed=policy.require_committed_source
    )
    journal, journal_data = _load_complete_journal(source, evidence_path, policy)
    first, second = _build_twice(source, journal)
    if first != second:
        raise flow.FlowesError("PUBLIC_REBUILD_A_NE_B")
    actual_hbp = flow.verify_sidecar(evidence_path / FINAL_HBP)
    actual_hbi = flow.verify_sidecar(evidence_path / FINAL_HBI)
    _validate_final_text(actual_hbp, actual_hbi)
    expected_hbp, expected_hbi, records, root = _build_final_files(
        source, journal, journal_data, first, policy
    )
    if actual_hbp != expected_hbp:
        raise flow.FlowesError("FINAL_HBP_REBUILD_MISMATCH")
    if actual_hbi != expected_hbi:
        raise flow.FlowesError("FINAL_HBI_REBUILD_MISMATCH")
    for record, (kind, name) in zip(records, EXPANDED_SPECS):
        if record.kind != kind or record.name != name:
            raise flow.FlowesError("PUBLIC_EXPANDED_ARTIFACT_ORDER")
        if record.sha256 != flow.sha256_bytes(first[name]):
            raise flow.FlowesError("PUBLIC_EXPANDED_ARTIFACT_HASH:" + name)
    if root != artifact_root(records):
        raise flow.FlowesError("PUBLIC_ARTIFACT_ROOT")
    _assert_paths_absent((journal_data, actual_hbp, actual_hbi), (source_path,))
    return {
        flow.OUTPUT_JOURNAL: flow.sha256_bytes(journal_data),
        FINAL_HBP: flow.sha256_bytes(actual_hbp),
        FINAL_HBI: flow.sha256_bytes(actual_hbi),
        "artifact_root": root,
    }


def mint_public_evidence(
    source_dir: Path, completed_output_dir: Path, public_evidence_dir: Path
) -> dict[str, str]:
    return _mint(
        source_dir, completed_output_dir, public_evidence_dir, PRODUCTION_POLICY
    )


def verify_public_evidence(
    source_dir: Path, public_evidence_dir: Path
) -> dict[str, str]:
    return _verify_public(source_dir, public_evidence_dir, PRODUCTION_POLICY)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    mint = modes.add_parser("mint", help="mint a separate six-file public witness")
    mint.add_argument("source_dir", type=Path)
    mint.add_argument("completed_output_dir", type=Path)
    mint.add_argument("public_evidence_dir", type=Path)
    verify = modes.add_parser(
        "verify-public", help="rebuild and verify a six-file public witness"
    )
    verify.add_argument("source_dir", type=Path)
    verify.add_argument("public_evidence_dir", type=Path)
    return parser.parse_args(argv)


def _result_row(mode: str, hashes: dict[str, str]) -> str:
    return flow.tuple_row(
        "LIRISFLOWEX9FINAL", PASS=1, mode=mode,
        journal_sha256=hashes[flow.OUTPUT_JOURNAL],
        hbp_sha256=hashes[FINAL_HBP], hbi_sha256=hashes[FINAL_HBI],
        artifact_root_sha256=hashes["artifact_root"],
        independent_time_attestation=0, system_affirmed=0,
        credentials=0, json=0,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.mode == "mint":
            hashes = mint_public_evidence(
                args.source_dir, args.completed_output_dir, args.public_evidence_dir
            )
            mode = "MINT"
        else:
            hashes = verify_public_evidence(
                args.source_dir, args.public_evidence_dir
            )
            mode = "VERIFY_PUBLIC"
        print(_result_row(mode, hashes))
        return 0
    except (
        flow.FlowesError, OSError, UnicodeError, ValueError, KeyError,
        IndexError, struct.error
    ) as exc:
        code = type(exc).__name__
        if isinstance(exc, flow.FlowesError):
            code = str(exc).split(":", 1)[0]
        code = re.sub(r"[^A-Za-z0-9_-]", "_", code)[:80]
        print(
            flow.tuple_row("LIRISFLOWEX9FINAL", PASS=0, error=code, json=0),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
