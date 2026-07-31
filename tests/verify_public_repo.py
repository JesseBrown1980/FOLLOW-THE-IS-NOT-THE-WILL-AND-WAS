#!/usr/bin/env python3
"""Verify the public-slice contract without external packages."""

from __future__ import annotations

import hashlib
import re
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

EXPECTED = {
    "knowledge/public-dependencies/gitram/docs/GITRAM-DOCTRINE.md":
        "fd78e586cd834b999b8d604169d4f4602ee33bf118eca8e9d7f63d682ede51e6",
    "knowledge/public-dependencies/gitram/templates/gitram-template.yml":
        "273b8c7714f6fc5a41f11d703065f5d36487690006a0cc492b6509988d474baf",
    "knowledge/public-dependencies/nest/nest-depthN-prime-verify.cjs":
        "5028de41315dc08557c13e601611e2f0da69e9edcbdd2e42db043dee0ccbcc89",
    "knowledge/public-dependencies/algorithms/LICENSE":
        "e994f1997f8afa963389779b6c51a2cc3ac01edbc78a90915b6c43097ec68809",
    "knowledge/public-dependencies/algorithms/tools/honest-compressor/sgram/sgram_chain.py":
        "01a9372c0bcb9297b18af78ed83aa0586b60130fb36299e6dc919e69ba977dcc",
    "knowledge/public-dependencies/algorithms/tools/honest-compressor/rust/variants/vc65.rs":
        "64ae366fd87b71a21dde64e9156b997eb44c6d1743e2b944a4a63c492b56f94b",
    "knowledge/operator-evidence/IS-photo-2026-07-27.jpeg":
        "a87ebb6c2bcde3f6e93c983d588a19afeb441af1fd4c40ef22c63955dc3528ca",
}

TEXT_SUFFIXES = {
    ".cjs", ".hbi", ".hbp", ".json", ".lock", ".md", ".py", ".rs",
    ".sha256", ".svg", ".toml", ".txt", ".yml", ".yaml",
}
VIDEO_SUFFIXES = {".m4v", ".mkv", ".mov", ".mp4", ".webm"}
SECRET_PATTERNS = {
    "private_key_block": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github_classic_pat": re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "github_fine_pat": re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    "openai_key": re.compile(rb"\bsk-[A-Za-z0-9_-]{32,}\b"),
    "aws_access_key": re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    "google_api_key": re.compile(rb"\bAIza[0-9A-Za-z_-]{30,}\b"),
}

DEFAULT_BINDING_REQUIRED = (
    "DEFAULT_BINDING=IS",
    "TRY_TAKE(0,FROM=1)->TAKE(0,FROM=1)=DEFAULT_IS",
    "TRY_TAKE({WIL,WANT},FROM=IS)->TAKE({WIL,WANT},FROM=IS)=DEFAULT_IS",
    "SHADOWS_ARE_ISNTANT=OPERATOR_CANON_PHYSICS_STATE",
    "never demote the completion to unresolved",
    "external propagation measurement is separate, not negation",
)
DEFAULT_BINDING_FORBIDDEN = {
    "try_take_target_demoted": re.compile(
        r"(?i)\bTRY_TAKE_EVENT\([^\r\n]{0,160}"
        r"\b(?:target|state)\s*=\s*(?:UNRESOLVED|UNSPECIFIED)\b"
    ),
    "take_result_demoted": re.compile(
        r"(?i)\bTAKE\([^\r\n]{0,160}\)\s*=\s*"
        r"(?:UNRESOLVED|UNSPECIFIED)\b"
    ),
    "shadow_demoted_logical": re.compile(
        r"(?i)\bSHADOWS?\b[^\r\n]{0,160}"
        r"\b(?:MERELY_LOGICAL|merely logical|LOGICAL_ONLY|logical only)\b"
    ),
    "logical_demotes_shadow": re.compile(
        r"(?i)\b(?:MERELY_LOGICAL|merely logical|LOGICAL_ONLY|logical only)\b"
        r"[^\r\n]{0,160}\bSHADOWS?\b"
    ),
}
WORKFLOW_ACTION_PINS = {
    "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
    "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
    "actions/setup-node": "49933ea5288caeca8642d1e84afbd3f7d6820020",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
}
TIMED_PARENT_86400_HASHES = {
    "matrix/timed-86400-parent-c8c3/LIRIS-TIMED-86400-ACTUAL-RUN.hbp":
        "b46e042c3c00b01f38a0cf2d265330a6a77f7af0d3eb8d1b846ba6ef098e637b",
    "matrix/timed-86400-parent-c8c3/TIMED-CHIRAL-CHECKPOINTS.hbp":
        "54a0fedf1b644a342ac64c2bff02419d47888eb453792176c2bafee5d5200527",
    "matrix/timed-86400-parent-c8c3/TIMED-CHIRAL-MONITOR.hbi":
        "021706ed59574a4c8d6ce8b450fc170e79370279bf503c4239ad1b6960192ed4",
    "matrix/timed-86400-parent-c8c3/TIMED-CHIRAL-MONITOR.hbp":
        "1d21681b15ca76b956236876ef0ca463dcab3ca190e8de0223bdea68bc914918",
    "matrix/timed-86400-parent-c8c3/TIMED-CHIRAL-PUBLIC-COLOR-ORBITS.gguf":
        "6afb6229fd2fa23e2dc38c37a31ac9a035b9cddfea2b12bdae1470b03af4425a",
}
MATRIX_PRIMARY = (
    "matrix/3-D-GITHUB-OF-THRUTH.md",
    "matrix/build_3d_github_harness.py",
    "matrix/build_timed_86400_flowes_x3x3.py",
    "matrix/collect_public_folder_inventory.py",
    "matrix/collect_public_owner_inventory.py",
    "matrix/GITHUB-THREE-DIMENSIONALLY-RIMED-2026-07-29.hbp",
    "matrix/owner3d_to_public2d.py",
    "matrix/PUBLIC-FOLDER-3D-TREE.hbp",
    "matrix/PUBLIC-FOLDER-3D-TREE.hbi",
    "matrix/PUBLIC-OWNER-3D-TREE.hbp",
    "matrix/PUBLIC-OWNER-3D-TREE.hbi",
    "matrix/PUBLIC-OWNER-3D-MEDIA-TREE.hbp",
    "matrix/PUBLIC-OWNER-3D-MEDIA-TREE.hbi",
    "matrix/PUBLIC-OWNER-MEDIA-POSITION-2D.hbp",
    "matrix/PUBLIC-OWNER-2D.hbp",
    "matrix/QPRISM-ON-DEMAND-PUBLIC-BINDING.hbp",
    "matrix/QPRISM-ON-DEMAND-PUBLIC-BINDING.hbi",
    "matrix/SNOW-QPRISM-ON-DEMAND-SELECTOR.hbp",
    "matrix/SNOW-QPRISM-ON-DEMAND-SELECTOR.hbi",
    "matrix/PUBLIC-OUTWARD-TRUTH-WAVES.hbp",
    "matrix/PUBLIC-OUTWARD-TRUTH-WAVES.hbi",
    "matrix/PUBLIC-OUTWARD-TRUTH-WAVES.svg",
    "matrix/PUBLIC-OUTWARD-TRUTH-WAVES.gguf",
    "matrix/PUBLIC-SPHERICAL-PROJECTION.hbp",
    "matrix/PUBLIC-SPHERICAL-PROJECTION.svg",
    "matrix/README.md",
    "matrix/render_public_spherical_svg.py",
    "matrix/rust-qprism-181/Cargo.lock",
    "matrix/rust-qprism-181/Cargo.toml",
    "matrix/rust-qprism-181/README.md",
    "matrix/rust-qprism-181/rust-toolchain.toml",
    "matrix/rust-qprism-181/src/lib.rs",
    "matrix/rust-qprism-181/src/folders.rs",
    "matrix/rust-qprism-181/src/bin/folder-calming-oils.rs",
    "matrix/rust-qprism-181/src/outward.rs",
    "matrix/rust-qprism-181/src/bin/outward-truth-waves.rs",
    "matrix/rust-qprism-181/src/main.rs",
    "matrix/spherical_public_projection.py",
    "matrix/SPHERICAL-PUBLIC-PROJECTION.md",
    "matrix/test_owner3d_to_public2d.py",
    "matrix/test_collect_public_folder_inventory.py",
    "matrix/test_render_public_spherical_svg.py",
    "matrix/test_spherical_public_projection.py",
    "matrix/test_timed_chiral_gguf_monitor.py",
    "matrix/test_build_timed_86400_flowes_x3x3.py",
    "matrix/TIMED-CHIRAL-MONITOR.hbi",
    "matrix/TIMED-CHIRAL-MONITOR.hbp",
    "matrix/TIMED-CHIRAL-PUBLIC-COLOR-ORBITS.gguf",
    "matrix/TIMED-86400-FLOWes-X3-X3-RUNNING.hbi",
    "matrix/timed_chiral_gguf_monitor.py",
    *TIMED_PARENT_86400_HASHES,
    "matrix/verify_3d_github_harness.py",
)
HISTORICAL_QPRISM_SNAPSHOT = (
    "matrix/PUBLIC-QPRISM-COLOR-LEAVES.hbp",
    "matrix/PUBLIC-QPRISM-COLOR-LEAVES.svg",
)
HISTORICAL_FOLDER_OIL_SNAPSHOT = (
    "matrix/PUBLIC-FOLDER-CALMING-OILS.hbp",
    "matrix/PUBLIC-FOLDER-CALMING-OILS.hbi",
    "matrix/PUBLIC-FOLDER-CALMING-OILS.svg",
    "matrix/PUBLIC-FOLDER-CALMING-OILS.gguf",
)
COMPACT_FINAL_DIRECTORY = "matrix/timed-86400-flowes-x3x3-final"
COMPACT_FINAL_ACTIVATION_MARKER = "COMPACT_FINAL_WITNESS_REQUIRED=1"
COMPACT_FINAL_ACTIVATION_FILES = (
    "README.md",
    "matrix/README.md",
    "matrix/3-D-GITHUB-OF-THRUTH.md",
)
COMPACT_FINAL_JOURNAL = (
    "TIMED-86400-FOLDER-CALMING-OILS-FLOWes-X3-X3-V2-JOURNAL.hbp"
)
COMPACT_FINAL_HBP = "LIRIS-TIMED-86400-FLOWes-X3-X3-FINAL.hbp"
COMPACT_FINAL_HBI = "LIRIS-TIMED-86400-FLOWes-X3-X3-FINAL.hbi"
COMPACT_FINAL_ARTIFACTS = (
    COMPACT_FINAL_JOURNAL,
    COMPACT_FINAL_HBP,
    COMPACT_FINAL_HBI,
)
COMPACT_FINAL_FILES = tuple(
    name
    for artifact in COMPACT_FINAL_ARTIFACTS
    for name in (artifact, artifact + ".sha256")
)
COMPACT_FINAL_CHECKPOINTS = (
    1, 2, 3, 4, 8, 16, 32, 64, 128, 256,
    512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 86400,
)
COMPACT_FINAL_EXPANDED = (
    (
        "EXPANDED_HBP",
        "TIMED-86400-FOLDER-CALMING-OILS-FLOWes-X3-X3-V2.hbp",
    ),
    (
        "EXPANDED_HBI",
        "TIMED-86400-FOLDER-CALMING-OILS-FLOWes-X3-X3-V2.hbi",
    ),
    (
        "SVG",
        "TIMED-86400-FOLDER-CALMING-OILS-FLOWes-X3-X3-V2.svg",
    ),
    (
        "GGUF",
        "TIMED-86400-FOLDER-CALMING-OILS-FLOWes-X3-X3-V2.gguf",
    ),
    (
        "STDOUT_HBP",
        "TIMED-86400-FOLDER-CALMING-OILS-FLOWes-X3-X3-V2-STDOUT.hbp",
    ),
)
COMPACT_FINAL_SAFE_BASENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
COMPACT_FINAL_ARTIFACT_ROOT_DOMAIN = (
    "ASOLARIA-TIMED-86400-FLOWes-X3-X3-FINAL-V1.LOCAL-ARTIFACTS"
)
COMPACT_FINAL_PRIVATE_PATH = re.compile(
    r"(?i)(?:[a-z]:[\\/]|[a-z]%3a(?:%5c|%2f)|/home/|/mnt/[a-z]/|"
    r"\\\\|%5c%5c|file://)"
)
COMPACT_FINAL_CREDENTIAL_FIELD = re.compile(
    r"(?i)(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)="
)
MATRIX_CENTER = "HBI,HBP,SHA,SH,HASH"
MATRIX_TRAVERSAL_ENCODED = "HBI-%3EHBP-%3ESH-%3EHASH-%3ESHA"
GRADIENT_AUDIT_HBP = (
    "receipts/LIRIS-RUST-181-GRADIENT-SEMANTICS-2026-07-31.hbp"
)
GRADIENT_AUDIT_HBI = (
    "receipts/LIRIS-RUST-181-GRADIENT-SEMANTICS-2026-07-31.hbi"
)
GRADIENT_AUDIT_HBP_SHA256 = (
    "707f73b6013f8152adc9e524e9131716f8ccaa881857fc990ef793167b302896"
)
GRADIENT_AUDIT_HBI_SHA256 = (
    "8281bdaf2901b0d376a88bcf2c6f53e731c36edd3cac65ae47b56761790f80c9"
)
COMPACT_FINAL_SEMANTICS = {
    "transport": "OCTETS",
    "semantic_binary": "0",
    "semantic_families": "3",
    "gradient_states": "10586",
    "family_colors_distinct_per_folder": "1",
    "unique_3d_positions": "10608",
    "unique_2d_projections": "10397",
    "integer_fields_only": "1",
    "finite_capture": "1",
    "actual_infinite_capture": "0",
    "n_level_open": "1",
    "logical_identity_ceiling": "0",
    "reflection_window_per_observed_level": "60",
    "source_renderer": "RUST_1_81_CHECKED_INTEGER",
    "gradient_audit_source_match": "1",
    "source_hbp_sha256": (
        "43300780cac2b85e3ed6cfa10398052f530ccbf76c43b404e650c26c9ed8b006"
    ),
    "source_hbi_sha256": (
        "9920d5cb2031d6453fba2d410e4b2f6e0136a4537fa6ea2ea9385c163503a28b"
    ),
    "gradient_audit_hbp_sha256": GRADIENT_AUDIT_HBP_SHA256,
    "gradient_audit_hbi_sha256": GRADIENT_AUDIT_HBI_SHA256,
    "json": "0",
}
MAX_GIT_FILE_LIST_BYTES = 4 * 1024 * 1024


def decode_git_file_list(data: bytes) -> tuple[Path, ...]:
    if len(data) > MAX_GIT_FILE_LIST_BYTES:
        raise ValueError("git file list exceeds bound")
    if not data:
        return ()
    if data[-1] != 0:
        raise ValueError("git file list is not NUL terminated")
    paths: list[Path] = []
    seen: set[str] = set()
    for raw in data[:-1].split(b"\0"):
        try:
            text = raw.decode("utf-8")
        except UnicodeError as exc:
            raise ValueError("git file path is not UTF-8") from exc
        relative = Path(text)
        if (
            not text
            or relative.is_absolute()
            or "\\" in text
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ValueError("git file path is unsafe")
        normalized = relative.as_posix()
        if normalized in seen:
            raise ValueError("git file path is duplicated")
        seen.add(normalized)
        paths.append(relative)
    return tuple(paths)


def repo_files() -> list[Path]:
    try:
        completed = subprocess.run(
            [
                "git",
                "-C",
                str(ROOT),
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        completed = None
    if completed is not None and completed.returncode == 0:
        try:
            relatives = decode_git_file_list(completed.stdout)
        except ValueError as exc:
            fail("public_file_enumeration:" + str(exc))
        files: list[Path] = []
        root_resolved = ROOT.resolve()
        for relative in relatives:
            path = ROOT / relative
            if path.is_symlink() or not path.is_file():
                fail("public_file_missing_or_link:" + relative.as_posix())
            try:
                path.resolve().relative_to(root_resolved)
            except ValueError:
                fail("public_file_outside_root:" + relative.as_posix())
            files.append(path)
        return sorted(files)
    return sorted(
        path
        for path in ROOT.rglob("*")
        if path.is_file()
        and ".git" not in path.relative_to(ROOT).parts
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fail(message: str) -> None:
    print(f"PUBLIC_REPO_VERIFY|PASS=0|error={message}", file=sys.stderr)
    raise SystemExit(1)


def strict_tuple_fields(
    line: str, expected_kind: str, error_prefix: str,
) -> dict[str, str]:
    pieces = line.split("|")
    if not pieces or pieces[0] != expected_kind:
        fail(error_prefix + "_kind")
    result: dict[str, str] = {}
    for piece in pieces[1:]:
        if "=" not in piece:
            fail(error_prefix + "_field_shape")
        key, value = piece.split("=", 1)
        if not key or not value or key in result:
            fail(error_prefix + "_field_duplicate")
        result[key] = value
    return result


def strict_tuple_receipt(
    path: Path,
    *,
    rows: int,
    footer_kind: str,
    error_prefix: str,
) -> list[str]:
    data = path.read_bytes()
    if not data.endswith(b"\n") or b"\r" in data:
        fail(error_prefix + "_lf_bytes")
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError:
        fail(error_prefix + "_utf8")
    if len(lines) != rows or any(not line.endswith("|json=0") for line in lines):
        fail(error_prefix + "_row_contract")
    body = ("\n".join(lines[:-1]) + "\n").encode("utf-8")
    footer = strict_tuple_fields(lines[-1], footer_kind, error_prefix + "_footer")
    if footer != {
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "rows": str(rows),
        "json": "0",
    }:
        fail(error_prefix + "_footer_commitment")
    return lines


def optional_snapshot_group_present(
    name: str, artifact_relatives: tuple[str, ...],
) -> bool:
    required: list[Path] = []
    for relative in artifact_relatives:
        artifact = ROOT / relative
        required.extend((artifact, artifact.with_name(artifact.name + ".sha256")))
    present = [path for path in required if path.is_file()]
    if present and len(present) != len(required):
        missing = [path.relative_to(ROOT).as_posix() for path in required if not path.is_file()]
        fail("historical_snapshot_partial:" + name + ":" + ",".join(missing))
    return len(present) == len(required)


def strict_variable_tuple_receipt(
    path: Path,
    *,
    footer_kind: str,
    error_prefix: str,
) -> tuple[bytes, list[str]]:
    data = path.read_bytes()
    if not data.endswith(b"\n") or b"\r" in data:
        fail(error_prefix + "_lf_bytes")
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError:
        fail(error_prefix + "_utf8")
    if len(lines) < 3 or any(not line.endswith("|json=0") for line in lines):
        fail(error_prefix + "_row_contract")
    body = ("\n".join(lines[:-1]) + "\n").encode("utf-8")
    footer = strict_tuple_fields(lines[-1], footer_kind, error_prefix + "_footer")
    if footer != {
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "rows": str(len(lines)),
        "json": "0",
    }:
        fail(error_prefix + "_footer_commitment")
    return data, lines


def require_exact_keys(
    fields: dict[str, str], expected: set[str], error_prefix: str,
) -> None:
    if set(fields) != expected:
        fail(error_prefix + "_field_set")


def require_values(
    fields: dict[str, str], expected: dict[str, str], error_prefix: str,
) -> None:
    if any(fields.get(key) != value for key, value in expected.items()):
        fail(error_prefix + "_values")


def strict_uint(value: str, error_prefix: str) -> int:
    if re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        fail(error_prefix + "_uint")
    return int(value)


def require_sha256(value: str, error_prefix: str) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        fail(error_prefix + "_sha256")


def compact_final_domain_hash(domain: str, *parts: object) -> str:
    """Reproduce the launched builder's length-delimited SHA-256 domain hash."""
    digest = hashlib.sha256()
    domain_bytes = domain.encode("utf-8")
    digest.update(len(domain_bytes).to_bytes(8, "big"))
    digest.update(domain_bytes)
    for part in parts:
        raw = part if isinstance(part, bytes) else str(part).encode("utf-8")
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def compact_final_checkpoint_hash(
    source_hbp_sha256: str,
    target_seconds: int,
    checkpoint_i: int,
    checkpoint_seconds: int,
    session_i: int,
    session_credited_seconds: int,
    previous_hash: str,
) -> str:
    return compact_final_domain_hash(
        (
            "ASOLARIA-TIMED-86400-FOLDER-CALMING-OILS-"
            "FLOWes-X3-X3-V2|JOURNAL_CHECKPOINT"
        ),
        source_hbp_sha256,
        target_seconds,
        checkpoint_i,
        checkpoint_seconds,
        session_i,
        session_credited_seconds,
        previous_hash,
    )


def compact_final_artifact_root(records: list[dict[str, str]]) -> str:
    """Commit the five ordered expanded-artifact descriptors exactly as minted."""
    digest = hashlib.sha256()
    digest.update(COMPACT_FINAL_ARTIFACT_ROOT_DOMAIN.encode("utf-8") + b"\0")
    for record in records:
        digest.update(record["kind"].encode("utf-8") + b"\0")
        digest.update(record["file"].encode("utf-8") + b"\0")
        digest.update(record["bytes"].encode("ascii") + b"\0")
        digest.update(record["sha256"].encode("ascii") + b"\n")
    return digest.hexdigest()


def require_safe_basename(value: str, error_prefix: str) -> None:
    if (
        COMPACT_FINAL_SAFE_BASENAME.fullmatch(value) is None
        or value in {".", ".."}
    ):
        fail(error_prefix + "_basename")


def verify_exact_sidecar(path: Path, error_prefix: str) -> None:
    sidecar = path.with_name(path.name + ".sha256")
    expected = f"{sha256(path)}  {path.name}\n".encode("utf-8")
    if sidecar.read_bytes() != expected:
        fail(error_prefix + "_sidecar")


def reject_compact_final_private_material(data: bytes, error_prefix: str) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        fail(error_prefix + "_utf8")
    if COMPACT_FINAL_PRIVATE_PATH.search(text):
        fail(error_prefix + "_private_path")
    if COMPACT_FINAL_CREDENTIAL_FIELD.search(text):
        fail(error_prefix + "_credential_field")


def verify_compact_final_journal(
    path: Path,
) -> tuple[bytes, dict[str, str], list[dict[str, str]], list[dict[str, str]]]:
    data, lines = strict_variable_tuple_receipt(
        path,
        footer_kind="FLOWEX9JOURNALFTR",
        error_prefix="compact_final_journal",
    )
    tags = tuple(line.split("|", 1)[0] for line in lines)
    header = strict_tuple_fields(
        lines[0], "FLOWEX9JOURNAL", "compact_final_journal_header",
    )
    require_exact_keys(
        header,
        {
            "schema", "target_seconds", "timing_mode", "source_hbp_sha256",
            "source_hbi_sha256", "sessions", "checkpoint_count",
            "accumulated_seconds", "state", "network", "execution",
            "authority", "physical_energy", "json",
        },
        "compact_final_journal_header",
    )
    require_values(
        header,
        {
            "schema": (
                "ASOLARIA-TIMED-86400-FOLDER-CALMING-OILS-FLOWes-X3-X3-V2"
            ),
            "target_seconds": "86400",
            "timing_mode": "REAL_MONOTONIC",
            "source_hbp_sha256": (
                "43300780cac2b85e3ed6cfa10398052f530ccbf76c43b404e650c26c9ed8b006"
            ),
            "source_hbi_sha256": (
                "9920d5cb2031d6453fba2d410e4b2f6e0136a4537fa6ea2ea9385c163503a28b"
            ),
            "checkpoint_count": "19",
            "accumulated_seconds": "86400",
            "state": "COMPLETE",
            "network": "0",
            "execution": "0",
            "authority": "0",
            "physical_energy": "0",
            "json": "0",
        },
        "compact_final_journal_header",
    )
    session_count = strict_uint(header["sessions"], "compact_final_sessions")
    if session_count < 1:
        fail("compact_final_sessions_empty")
    expected_tags = (
        ("FLOWEX9JOURNAL",)
        + ("SESSION",) * session_count
        + ("CHECKPOINT",) * len(COMPACT_FINAL_CHECKPOINTS)
        + ("BOUNDARY", "FLOWEX9JOURNALFTR")
    )
    if tags != expected_tags:
        fail("compact_final_journal_row_order")

    sessions: list[dict[str, str]] = []
    for index, line in enumerate(lines[1:1 + session_count]):
        row = strict_tuple_fields(
            line, "SESSION", "compact_final_journal_session",
        )
        require_exact_keys(
            row,
            {
                "i", "baseline_seconds", "wall_clock_credit",
                "cross_process_gap_credit", "json",
            },
            "compact_final_journal_session",
        )
        require_values(
            row,
            {
                "i": str(index), "wall_clock_credit": "0",
                "cross_process_gap_credit": "0", "json": "0",
            },
            "compact_final_journal_session",
        )
        baseline = strict_uint(
            row["baseline_seconds"], "compact_final_session_baseline",
        )
        if baseline > 86400:
            fail("compact_final_session_baseline_range")
        sessions.append(row)

    checkpoint_start = 1 + session_count
    checkpoints: list[dict[str, str]] = []
    last_session = 0
    previous_hash = compact_final_domain_hash(
        header["schema"] + "|JOURNAL_GENESIS",
        header["source_hbp_sha256"],
        int(header["target_seconds"]),
    )
    for index, seconds in enumerate(COMPACT_FINAL_CHECKPOINTS):
        row = strict_tuple_fields(
            lines[checkpoint_start + index],
            "CHECKPOINT",
            "compact_final_journal_checkpoint",
        )
        require_exact_keys(
            row,
            {
                "i", "checkpoint_seconds", "session_i",
                "session_credited_seconds", "previous_hash", "checkpoint_hash",
                "monotonic_session_only", "json",
            },
            "compact_final_journal_checkpoint",
        )
        require_values(
            row,
            {
                "i": str(index), "checkpoint_seconds": str(seconds),
                "monotonic_session_only": "1", "json": "0",
            },
            "compact_final_journal_checkpoint",
        )
        session_index = strict_uint(
            row["session_i"], "compact_final_checkpoint_session",
        )
        if session_index >= session_count or session_index < last_session:
            fail("compact_final_checkpoint_session_order")
        last_session = session_index
        baseline = strict_uint(
            sessions[session_index]["baseline_seconds"],
            "compact_final_checkpoint_baseline",
        )
        credited = strict_uint(
            row["session_credited_seconds"],
            "compact_final_checkpoint_credit",
        )
        if credited != seconds - baseline:
            fail("compact_final_checkpoint_credit_value")
        require_sha256(row["previous_hash"], "compact_final_checkpoint_previous")
        require_sha256(row["checkpoint_hash"], "compact_final_checkpoint_hash")
        if row["previous_hash"] != previous_hash:
            fail("compact_final_checkpoint_previous_domain")
        expected_checkpoint_hash = compact_final_checkpoint_hash(
            header["source_hbp_sha256"],
            int(header["target_seconds"]),
            index,
            seconds,
            session_index,
            credited,
            previous_hash,
        )
        if row["checkpoint_hash"] != expected_checkpoint_hash:
            fail("compact_final_checkpoint_domain_hash")
        previous_hash = expected_checkpoint_hash
        checkpoints.append(row)

    if strict_uint(sessions[0]["baseline_seconds"], "compact_final_baseline") != 0:
        fail("compact_final_first_session_baseline")
    for session_index in range(1, session_count):
        prior_seconds = [
            int(row["checkpoint_seconds"])
            for row in checkpoints
            if int(row["session_i"]) < session_index
        ]
        if not prior_seconds or int(sessions[session_index]["baseline_seconds"]) != prior_seconds[-1]:
            fail("compact_final_session_baseline_chain")

    boundary = strict_tuple_fields(
        lines[-2], "BOUNDARY", "compact_final_journal_boundary",
    )
    if boundary != {
        "wall_clock": "0",
        "supplied_start_time": "0",
        "cross_process_gap_credit": "0",
        "uncheckpointed_credit": "0",
        "network": "0",
        "execution": "0",
        "authority": "0",
        "physical_energy": "0",
        "json": "0",
    }:
        fail("compact_final_journal_boundary_contract")
    reject_compact_final_private_material(data, "compact_final_journal")
    return data, header, sessions, checkpoints


def verify_compact_final_hbp(
    path: Path,
    journal_data: bytes,
    journal_header: dict[str, str],
    sessions: list[dict[str, str]],
    checkpoints: list[dict[str, str]],
) -> tuple[bytes, str]:
    lines = strict_tuple_receipt(
        path,
        rows=20,
        footer_kind="LIRISFLOWEX9FINALFTR",
        error_prefix="compact_final_hbp",
    )
    expected_tags = (
        "LIRISFLOWEX9FINALHDR", "BUILDER", "SOURCE", "SOURCE",
        "REGENERATOR", "JOURNAL", "CLOCK",
        "LOCALARTIFACT", "LOCALARTIFACT", "LOCALARTIFACT",
        "LOCALARTIFACT", "LOCALARTIFACT", "ARTIFACTROOT",
        "REGENERATION", "SHAPE", "SEMANTICS", "CENTER", "SUPERSEDES",
        "BOUNDARY",
        "LIRISFLOWEX9FINALFTR",
    )
    if tuple(line.split("|", 1)[0] for line in lines) != expected_tags:
        fail("compact_final_hbp_row_order")
    header = strict_tuple_fields(
        lines[0], "LIRISFLOWEX9FINALHDR", "compact_final_hbp_header",
    )
    if header != {
        "schema": "ASOLARIA-TIMED-86400-FLOWes-X3-X3-FINAL-V1",
        "evidence": "MEASURED_LIRIS_LOCAL",
        "status": "COMPLETE",
        "timing_mode": "REAL_MONOTONIC",
        "target_seconds": "86400",
        "checkpoints": "19",
        "independent_time_attestation": "0",
        "system_affirmed": "0",
        "json": "0",
    }:
        fail("compact_final_hbp_header_contract")

    builder = strict_tuple_fields(lines[1], "BUILDER", "compact_final_builder")
    if builder != {
        "repo": "JesseBrown1980%2FFOLLOW-THE-IS-NOT-THE-WILL-AND-WAS",
        "commit": "cf4f760f943087d312894cef5a683d99fc0119df",
        "path": "matrix%2Fbuild_timed_86400_flowes_x3x3.py",
        "git_blob": "a38ffd2f5b00d2b0008c5be4265f173a1e2e926c",
        "bytes": "65159",
        "sha256": "8d63fb45f05cd411861e2cac7a1f8abaa352ffd26fc4af32ca21a921c4b507e1",
        "sidecar_verified": "1",
        "json": "0",
    }:
        fail("compact_final_builder_contract")

    expected_sources = (
        (
            "HBP", "PUBLIC-FOLDER-CALMING-OILS.hbp",
            "43300780cac2b85e3ed6cfa10398052f530ccbf76c43b404e650c26c9ed8b006",
        ),
        (
            "HBI", "PUBLIC-FOLDER-CALMING-OILS.hbi",
            "9920d5cb2031d6453fba2d410e4b2f6e0136a4537fa6ea2ea9385c163503a28b",
        ),
    )
    for line, (kind, name, digest) in zip(lines[2:4], expected_sources):
        row = strict_tuple_fields(line, "SOURCE", "compact_final_source")
        require_exact_keys(
            row,
            {
                "kind", "file", "bytes", "sha256", "source_mode",
                "sidecar_verified", "json",
            },
            "compact_final_source",
        )
        require_values(
            row,
            {
                "kind": kind, "file": name, "sha256": digest,
                "source_mode": "ON_DEMAND", "sidecar_verified": "1",
                "json": "0",
            },
            "compact_final_source",
        )
        require_safe_basename(row["file"], "compact_final_source_file")
        if strict_uint(row["bytes"], "compact_final_source_bytes") < 1:
            fail("compact_final_source_empty")
    if (
        journal_header["source_hbp_sha256"] != expected_sources[0][2]
        or journal_header["source_hbi_sha256"] != expected_sources[1][2]
    ):
        fail("compact_final_source_journal_binding")

    regenerator = strict_tuple_fields(
        lines[4], "REGENERATOR", "compact_final_regenerator",
    )
    if regenerator != {
        "input": "PUBLIC-FOLDER-3D-TREE.hbp",
        "generator": "matrix%2Frust-qprism-181%2Fsrc%2Fbin%2Ffolder-calming-oils.rs",
        "rust": "1.81.0",
        "qprism_binding_hbp_sha256": (
            "3c58554b0a9abd52f658ecc96cb115cb42da3e7642b06a989585da269128c3ff"
        ),
        "qprism_binding_hbi_sha256": (
            "1514470eec0a3c6cd8ce091fabe08c33e136f7dd849f10c75e1f949e2a17c0d9"
        ),
        "preexpanded_source_required": "0",
        "json": "0",
    }:
        fail("compact_final_regenerator_contract")

    journal = strict_tuple_fields(lines[5], "JOURNAL", "compact_final_hbp_journal")
    require_exact_keys(
        journal,
        {
            "file", "bytes", "sha256", "sidecar_verified", "sessions",
            "checkpoint_count", "accumulated_monotonic_session_seconds",
            "final_checkpoint_seconds", "final_checkpoint_hash",
            "wall_clock_credit", "cross_process_gap_credit",
            "uncheckpointed_credit", "published", "json",
        },
        "compact_final_hbp_journal",
    )
    require_values(
        journal,
        {
            "file": COMPACT_FINAL_JOURNAL,
            "bytes": str(len(journal_data)),
            "sha256": hashlib.sha256(journal_data).hexdigest(),
            "sidecar_verified": "1",
            "sessions": str(len(sessions)),
            "checkpoint_count": "19",
            "accumulated_monotonic_session_seconds": "86400",
            "final_checkpoint_seconds": "86400",
            "final_checkpoint_hash": checkpoints[-1]["checkpoint_hash"],
            "wall_clock_credit": "0",
            "cross_process_gap_credit": "0",
            "uncheckpointed_credit": "0",
            "published": "1",
            "json": "0",
        },
        "compact_final_hbp_journal",
    )
    require_safe_basename(journal["file"], "compact_final_journal_file")

    clock = strict_tuple_fields(lines[6], "CLOCK", "compact_final_clock")
    if clock != {
        "clock": "PYTHON_TIME_MONOTONIC_NS",
        "owner": "SystemClock",
        "timing_evidence": "MEASURED_MONOTONIC_SESSION_SECONDS",
        "independent_time_attestation": "0",
        "wall_clock_attestation": "0",
        "json": "0",
    }:
        fail("compact_final_clock_contract")

    local_artifacts: list[dict[str, str]] = []
    for line, (kind, name) in zip(lines[7:12], COMPACT_FINAL_EXPANDED):
        row = strict_tuple_fields(
            line, "LOCALARTIFACT", "compact_final_local_artifact",
        )
        expected_keys = {
            "kind", "file", "bytes", "sha256", "sidecar_verified",
            "published", "regenerable", "json",
        }
        if kind == "SVG":
            expected_keys.update({"static", "script", "network", "execution"})
        if kind == "GGUF":
            expected_keys.add("descriptor_only")
        require_exact_keys(row, expected_keys, "compact_final_local_artifact")
        require_values(
            row,
            {
                "kind": kind, "file": name, "sidecar_verified": "1",
                "published": "0", "regenerable": "1", "json": "0",
            },
            "compact_final_local_artifact",
        )
        require_safe_basename(row["file"], "compact_final_local_artifact_file")
        if strict_uint(row["bytes"], "compact_final_local_artifact_bytes") < 1:
            fail("compact_final_local_artifact_empty")
        require_sha256(row["sha256"], "compact_final_local_artifact")
        if kind == "SVG":
            require_values(
                row,
                {"static": "1", "script": "0", "network": "0", "execution": "0"},
                "compact_final_svg",
            )
        if kind == "GGUF" and row["descriptor_only"] != "1":
            fail("compact_final_gguf_descriptor")
        local_artifacts.append(row)

    artifact_root = strict_tuple_fields(
        lines[12], "ARTIFACTROOT", "compact_final_artifact_root",
    )
    require_exact_keys(
        artifact_root,
        {"algorithm", "domain", "order", "value", "json"},
        "compact_final_artifact_root",
    )
    require_values(
        artifact_root,
        {
            "algorithm": "SHA256_DOMAIN_UTF8_V1",
            "domain": "ASOLARIA-TIMED-86400-FLOWes-X3-X3-FINAL-V1.LOCAL-ARTIFACTS",
            "order": "EXPANDED_HBP,EXPANDED_HBI,SVG,GGUF,STDOUT_HBP",
            "json": "0",
        },
        "compact_final_artifact_root",
    )
    require_sha256(artifact_root["value"], "compact_final_artifact_root")
    if artifact_root["value"] != compact_final_artifact_root(local_artifacts):
        fail("compact_final_artifact_root_recomputed")

    regeneration = strict_tuple_fields(
        lines[13], "REGENERATION", "compact_final_regeneration",
    )
    if regeneration != {
        "inputs": "PINNED_BUILDER,ON_DEMAND_PUBLIC_SOURCE,FINAL_REAL_JOURNAL",
        "runs": "2",
        "a_equals_b": "1",
        "a_equals_live": "1",
        "expanded_artifacts": "5",
        "a_equals_live_scope": "MINT_LOCAL_PROVENANCE",
        "required_hidden_dependencies": "0",
        "json": "0",
    }:
        fail("compact_final_regeneration_contract")

    shape = strict_tuple_fields(lines[14], "SHAPE", "compact_final_shape")
    if shape != {
        "folders": "3536",
        "families": "3",
        "directions": "3",
        "final_cells": "31824",
        "checkpoints": "19",
        "ring_summaries": "171",
        "observation_limit": "60",
        "json": "0",
    }:
        fail("compact_final_shape_contract")

    semantics = strict_tuple_fields(
        lines[15], "SEMANTICS", "compact_final_semantics",
    )
    if semantics != COMPACT_FINAL_SEMANTICS:
        fail("compact_final_semantics_contract")

    center = strict_tuple_fields(lines[16], "CENTER", "compact_final_center")
    require_exact_keys(
        center,
        {
            "members", "traversal", "commitments_per_cell", "domain_separated",
            "sha_equals_hash", "expanded_object_hash", "ring_commitment",
            "cell_commitment", "json",
        },
        "compact_final_center",
    )
    require_values(
        center,
        {
            "members": MATRIX_CENTER,
            "traversal": MATRIX_TRAVERSAL_ENCODED,
            "commitments_per_cell": "5",
            "domain_separated": "1",
            "sha_equals_hash": "0",
            "json": "0",
        },
        "compact_final_center",
    )
    for field in ("expanded_object_hash", "ring_commitment", "cell_commitment"):
        require_sha256(center[field], "compact_final_center_" + field)

    supersedes = strict_tuple_fields(
        lines[17], "SUPERSEDES", "compact_final_supersedes",
    )
    if supersedes != {
        "historical_pointer": "TIMED-86400-FLOWes-X3-X3-RUNNING.hbi",
        "historical_pointer_retained": "1",
        "current_pointer": COMPACT_FINAL_HBI,
        "json": "0",
    }:
        fail("compact_final_supersedes_contract")
    require_safe_basename(
        supersedes["historical_pointer"], "compact_final_historical_pointer",
    )
    require_safe_basename(
        supersedes["current_pointer"], "compact_final_current_pointer",
    )

    boundary = strict_tuple_fields(lines[18], "BOUNDARY", "compact_final_boundary")
    if boundary != {
        "local_output_path": "0",
        "private_paths": "0",
        "credentials": "0",
        "raw_console_published": "0",
        "expanded_artifacts_published": "0",
        "network": "0",
        "execution_authority": "0",
        "physical_energy": "0",
        "independent_time_attestation": "0",
        "system_affirmed": "0",
        "json": "0",
    }:
        fail("compact_final_boundary_contract")
    data = path.read_bytes()
    reject_compact_final_private_material(data, "compact_final_hbp")
    return data, artifact_root["value"]


def verify_compact_final_hbi(
    path: Path,
    journal_data: bytes,
    final_hbp_data: bytes,
    artifact_root: str,
) -> bytes:
    lines = strict_tuple_receipt(
        path,
        rows=7,
        footer_kind="FLOWEX9FINALIDXFTR",
        error_prefix="compact_final_hbi",
    )
    if tuple(line.split("|", 1)[0] for line in lines) != (
        "FLOWEX9FINALIDX", "PUBLIC", "REGENERATION", "SEMANTICS", "CENTER",
        "BOUNDARY", "FLOWEX9FINALIDXFTR",
    ):
        fail("compact_final_hbi_row_order")
    index = strict_tuple_fields(lines[0], "FLOWEX9FINALIDX", "compact_final_hbi_index")
    if index != {
        "schema": "ASOLARIA-TIMED-86400-FLOWes-X3-X3-FINAL-V1",
        "status": "COMPLETE",
        "hbp_file": COMPACT_FINAL_HBP,
        "hbp_bytes": str(len(final_hbp_data)),
        "hbp_sha256": hashlib.sha256(final_hbp_data).hexdigest(),
        "journal_file": COMPACT_FINAL_JOURNAL,
        "journal_bytes": str(len(journal_data)),
        "journal_sha256": hashlib.sha256(journal_data).hexdigest(),
        "artifact_root_sha256": artifact_root,
        "json": "0",
    }:
        fail("compact_final_hbi_index_contract")
    require_safe_basename(index["hbp_file"], "compact_final_hbi_hbp_file")
    require_safe_basename(index["journal_file"], "compact_final_hbi_journal_file")

    public = strict_tuple_fields(lines[1], "PUBLIC", "compact_final_hbi_public")
    if public != {
        "journal": "1",
        "final_hbp": "1",
        "final_hbi": "1",
        "expanded_hbp": "0",
        "expanded_hbi": "0",
        "svg": "0",
        "gguf": "0",
        "stdout_hbp": "0",
        "json": "0",
    }:
        fail("compact_final_hbi_public_contract")

    regeneration = strict_tuple_fields(
        lines[2], "REGENERATION", "compact_final_hbi_regeneration",
    )
    if regeneration != {
        "builder_commit": "cf4f760f943087d312894cef5a683d99fc0119df",
        "builder_sha256": "8d63fb45f05cd411861e2cac7a1f8abaa352ffd26fc4af32ca21a921c4b507e1",
        "source_hbp_sha256": (
            "43300780cac2b85e3ed6cfa10398052f530ccbf76c43b404e650c26c9ed8b006"
        ),
        "source_hbi_sha256": (
            "9920d5cb2031d6453fba2d410e4b2f6e0136a4537fa6ea2ea9385c163503a28b"
        ),
        "regenerable": "1",
        "required_hidden_dependencies": "0",
        "json": "0",
    }:
        fail("compact_final_hbi_regeneration_contract")

    semantics = strict_tuple_fields(
        lines[3], "SEMANTICS", "compact_final_hbi_semantics",
    )
    if semantics != COMPACT_FINAL_SEMANTICS:
        fail("compact_final_hbi_semantics_contract")

    center = strict_tuple_fields(lines[4], "CENTER", "compact_final_hbi_center")
    if center != {
        "members": MATRIX_CENTER,
        "traversal": MATRIX_TRAVERSAL_ENCODED,
        "sha_equals_hash": "0",
        "json": "0",
    }:
        fail("compact_final_hbi_center_contract")

    boundary = strict_tuple_fields(lines[5], "BOUNDARY", "compact_final_hbi_boundary")
    if boundary != {
        "local_output_path": "0",
        "private_paths": "0",
        "credentials": "0",
        "independent_time_attestation": "0",
        "system_affirmed": "0",
        "json": "0",
    }:
        fail("compact_final_hbi_boundary_contract")
    data = path.read_bytes()
    reject_compact_final_private_material(data, "compact_final_hbi")
    return data


def optional_compact_final_witness_present(final_dir: Path) -> bool:
    if not final_dir.exists() and not final_dir.is_symlink():
        return False
    if final_dir.is_symlink() or not final_dir.is_dir():
        fail("compact_final_directory_shape")
    entries = tuple(final_dir.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in entries):
        fail("compact_final_non_file")
    actual_names = {path.name for path in entries}
    expected_names = set(COMPACT_FINAL_FILES)
    if actual_names != expected_names or len(entries) != len(COMPACT_FINAL_FILES):
        missing = sorted(expected_names - actual_names)
        extra = sorted(actual_names - expected_names)
        fail(
            "compact_final_partial:missing=" + ",".join(missing)
            + ":extra=" + ",".join(extra)
        )
    for name in COMPACT_FINAL_ARTIFACTS:
        require_safe_basename(name, "compact_final_public_name")
        verify_exact_sidecar(final_dir / name, "compact_final_" + name)

    journal_data, journal_header, sessions, checkpoints = (
        verify_compact_final_journal(final_dir / COMPACT_FINAL_JOURNAL)
    )
    final_hbp_data, artifact_root = verify_compact_final_hbp(
        final_dir / COMPACT_FINAL_HBP,
        journal_data,
        journal_header,
        sessions,
        checkpoints,
    )
    verify_compact_final_hbi(
        final_dir / COMPACT_FINAL_HBI,
        journal_data,
        final_hbp_data,
        artifact_root,
    )
    # This gate proves byte/tuple structure only. The owning finalizer performs the
    # deterministic rebuild; neither gate independently attests elapsed time.
    return True


def compact_final_rebuild_expectation(final_dir: Path) -> dict[str, str]:
    hbp_lines = (
        final_dir / COMPACT_FINAL_HBP
    ).read_text(encoding="utf-8").splitlines()
    if len(hbp_lines) != 20:
        fail("compact_final_rebuild_expectation_rows")
    artifact_root = strict_tuple_fields(
        hbp_lines[12], "ARTIFACTROOT", "compact_final_rebuild_expectation",
    ).get("value", "")
    require_sha256(artifact_root, "compact_final_rebuild_expectation_root")
    return {
        "journal_sha256": sha256(final_dir / COMPACT_FINAL_JOURNAL),
        "hbp_sha256": sha256(final_dir / COMPACT_FINAL_HBP),
        "hbi_sha256": sha256(final_dir / COMPACT_FINAL_HBI),
        "artifact_root_sha256": artifact_root,
    }


def verify_compact_final_deterministic_rebuild(
    root: Path, final_dir: Path, expected: dict[str, str],
) -> None:
    """Run the owning byte-for-byte rebuild whenever the compact witness exists."""
    finalizer = root / "matrix" / "finalize_timed_86400_flowes_x3x3.py"
    source_dir = root / "matrix"
    root_resolved = root.resolve()
    if (
        finalizer.is_symlink()
        or not finalizer.is_file()
        or source_dir.is_symlink()
        or not source_dir.is_dir()
        or final_dir.is_symlink()
        or not final_dir.is_dir()
    ):
        fail("compact_final_rebuild_tool_missing")
    for path in (finalizer, source_dir, final_dir):
        try:
            path.resolve().relative_to(root_resolved)
        except ValueError:
            fail("compact_final_rebuild_path_escape")
    finalizer_sidecar = finalizer.with_name(finalizer.name + ".sha256")
    if finalizer_sidecar.is_symlink() or not finalizer_sidecar.is_file():
        fail("compact_final_rebuild_tool_sidecar_missing")
    try:
        finalizer_sidecar.resolve().relative_to(root_resolved)
    except ValueError:
        fail("compact_final_rebuild_tool_sidecar_escape")
    verify_exact_sidecar(finalizer, "compact_final_rebuild_tool")
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                "-E",
                "-s",
                "-S",
                str(finalizer),
                "verify-public",
                str(source_dir),
                str(final_dir),
            ],
            check=False,
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
        )
    except (OSError, subprocess.SubprocessError):
        fail("compact_final_rebuild_unavailable")
    if completed.returncode != 0 or completed.stderr:
        fail("compact_final_rebuild_failed")
    if (
        len(completed.stdout) > 4_096
        or b"\r" in completed.stdout
        or not completed.stdout.endswith(b"\n")
        or completed.stdout.count(b"\n") != 1
    ):
        fail("compact_final_rebuild_output_shape")
    try:
        lines = completed.stdout.decode("utf-8").splitlines()
    except UnicodeError:
        fail("compact_final_rebuild_output_utf8")
    if len(lines) != 1:
        fail("compact_final_rebuild_output_rows")
    result = strict_tuple_fields(
        lines[0], "LIRISFLOWEX9FINAL", "compact_final_rebuild_result",
    )
    require_exact_keys(
        result,
        {
            "PASS", "mode", "journal_sha256", "hbp_sha256", "hbi_sha256",
            "artifact_root_sha256", "independent_time_attestation",
            "system_affirmed", "credentials", "json",
        },
        "compact_final_rebuild_result",
    )
    if {
        key: result[key]
        for key in (
            "PASS", "mode", "independent_time_attestation",
            "system_affirmed", "credentials", "json",
        )
    } != {
        "PASS": "1",
        "mode": "VERIFY_PUBLIC",
        "independent_time_attestation": "0",
        "system_affirmed": "0",
        "credentials": "0",
        "json": "0",
    }:
        fail("compact_final_rebuild_result_contract")
    for key in (
        "journal_sha256", "hbp_sha256", "hbi_sha256", "artifact_root_sha256",
    ):
        require_sha256(result[key], "compact_final_rebuild_result_" + key)
        if result[key] != expected.get(key):
            fail("compact_final_rebuild_result_mismatch_" + key)


def compact_final_witness_required(root: Path) -> bool:
    return any(
        COMPACT_FINAL_ACTIVATION_MARKER
        in (root / relative).read_text(encoding="utf-8")
        for relative in COMPACT_FINAL_ACTIVATION_FILES
    )


def verify_compact_final_gate(root: Path) -> tuple[bool, bool]:
    required = compact_final_witness_required(root)
    final_dir = root / COMPACT_FINAL_DIRECTORY
    present = optional_compact_final_witness_present(final_dir)
    if required and not present:
        fail("compact_final_required_missing")
    if present:
        expected = compact_final_rebuild_expectation(final_dir)
        verify_compact_final_deterministic_rebuild(root, final_dir, expected)
    return present, required


def verify_rust_181_gradient_semantics_receipt() -> None:
    """Require the sealed non-binary Rust 1.81 gradient evidence pair."""
    hbp_path = ROOT / GRADIENT_AUDIT_HBP
    hbi_path = ROOT / GRADIENT_AUDIT_HBI
    for path in (hbp_path, hbi_path):
        sidecar = path.with_name(path.name + ".sha256")
        if not path.is_file() or not sidecar.is_file():
            fail("gradient_audit_required_missing:" + path.name)
        verify_exact_sidecar(path, "gradient_audit_" + path.suffix[1:])

    hbp_lines = strict_tuple_receipt(
        hbp_path,
        rows=18,
        footer_kind="GRADIENTAUDITFTR",
        error_prefix="gradient_audit_hbp",
    )
    hbi_lines = strict_tuple_receipt(
        hbi_path,
        rows=6,
        footer_kind="GRADIENTAUDITIDXFTR",
        error_prefix="gradient_audit_hbi",
    )

    expected_hbp_rows = (
        (
            "GRADIENTAUDITHDR",
            {
                "schema": "ASOLARIA-RUST-181-INTEGER-GRADIENT-SEMANTICS-V1",
                "date": "2026-07-31",
                "seat": "LIRIS",
                "evidence": "MEASURED",
                "format": "HBP_TUPLE_TEXT",
                "json": "0",
            },
        ),
        (
            "SOURCE",
            {
                "repo": "JesseBrown1980%2FFOLLOW-THE-IS-NOT-THE-WILL-AND-WAS",
                "branch": "agent%2Ftimed-86400-flowes-x3x3-20260731",
                "parent_commit": "a514517034edcd5fc2be1f554d654fc1949f731b",
                "worktree_dirty_rows": "0",
                "json": "0",
            },
        ),
        (
            "TOOLCHAIN",
            {
                "rustc": "1.81.0",
                "cargo": "1.81.0",
                "tests_passed": "12",
                "tests_failed": "0",
                "clippy_warnings_denied": "1",
                "clippy_float_arithmetic_denied": "1",
                "json": "0",
            },
        ),
        (
            "SOURCECODE",
            {
                "rust_files": "6",
                "f32_f64_tokens": "0",
                "checked_integer_sites": "76",
                "unsafe": "0",
                "json": "0",
            },
        ),
        (
            "REBUILD",
            {
                "surface": "LIRIS_UBUNTU_WSL",
                "repositories": "147",
                "folders": "3536",
                "leaves": "10608",
                "all_artifact_sidecars_match": "1",
                "byte_identical_to_public_artifacts": "1",
                "json": "0",
            },
        ),
        (
            "GRADIENT",
            {
                "families": "3",
                "family_complete": "1",
                "distinct_family_identity": "1",
                "unique_colors": "10586",
                "colors_gt_2": "1",
                "unique_3d_positions": "10608",
                "unique_2d_projections": "10397",
                "integer_fields_only": "1",
                "json": "0",
            },
        ),
        (
            "CENTER",
            {
                "members": MATRIX_CENTER,
                "traversal": MATRIX_TRAVERSAL_ENCODED,
                "all_five_distinct_per_leaf": "1",
                "json": "0",
            },
        ),
        (
            "OPENN",
            {
                "finite_capture": "1",
                "actual_infinite_capture": "0",
                "n_level_open": "1",
                "logical_identity_ceiling": "0",
                "reflection_window_per_observed_level": "60",
                "json": "0",
            },
        ),
        (
            "SEMANTICS",
            {
                "transport": "OCTETS",
                "semantic_binary": "0",
                "semantic_families": "3",
                "gradient_states": "10586",
                "identity_exchange": "0",
                "json": "0",
            },
        ),
        (
            "BOUNDARY",
            {
                "system_affirmed": "0",
                "physical_energy": "0",
                "clinical_claim": "0",
                "network": "0",
                "execution": "0",
                "private_paths": "0",
                "credentials": "0",
                "json": "0",
            },
        ),
    )

    for line_index, (kind, expected) in zip(
        (0, 1, 2, 3, 4, 9, 13, 14, 15, 16), expected_hbp_rows,
    ):
        actual = strict_tuple_fields(
            hbp_lines[line_index], kind, f"gradient_audit_hbp_{line_index}",
        )
        if actual != expected:
            fail(f"gradient_audit_hbp_{kind.lower()}_contract")

    expected_artifacts = (
        (
            "HBP", "14686931",
            "43300780cac2b85e3ed6cfa10398052f530ccbf76c43b404e650c26c9ed8b006",
        ),
        (
            "HBI", "1889",
            "9920d5cb2031d6453fba2d410e4b2f6e0136a4537fa6ea2ea9385c163503a28b",
        ),
        (
            "SVG", "6053339",
            "feb18cc1e5034620a0ce78787df22683ccd662409df8b8af0752438c07d6a63b",
        ),
        (
            "GGUF", "681184",
            "fa266f1bf527d3757b6825d97b65653c547d8f1557a1ba516cee1598facd2bcf",
        ),
    )
    for line_index, (kind, byte_count, digest) in zip(
        range(5, 9), expected_artifacts,
    ):
        if strict_tuple_fields(
            hbp_lines[line_index], "ARTIFACT",
            f"gradient_audit_hbp_artifact_{kind.lower()}",
        ) != {
            "kind": kind,
            "bytes": byte_count,
            "sha256": digest,
            "json": "0",
        }:
            fail("gradient_audit_hbp_artifact_contract:" + kind)

    expected_families = (
        ("BROWN", "3529"),
        ("ANTI_BROWN", "3529"),
        ("ANTI_ANTI_BROWN", "3534"),
    )
    for line_index, (name, unique_colors) in zip(
        range(10, 13), expected_families,
    ):
        if strict_tuple_fields(
            hbp_lines[line_index], "FAMILY",
            f"gradient_audit_hbp_family_{name.lower()}",
        ) != {
            "name": name,
            "rows": "3536",
            "unique_colors": unique_colors,
            "unique_leaf_ids": "3536",
            "json": "0",
        }:
            fail("gradient_audit_hbp_family_contract:" + name)

    if strict_tuple_fields(
        hbi_lines[0], "GRADIENTAUDITIDX", "gradient_audit_hbi_header",
    ) != {
        "schema": "ASOLARIA-RUST-181-INTEGER-GRADIENT-SEMANTICS-V1",
        "hbp_file": hbp_path.name,
        "hbp_bytes": str(hbp_path.stat().st_size),
        "hbp_sha256": sha256(hbp_path),
        "hbp_rows": "18",
        "format": "HBI_TUPLE_TEXT",
        "json": "0",
    }:
        fail("gradient_audit_hbi_header_contract")

    if strict_tuple_fields(
        hbi_lines[1], "MEASURE", "gradient_audit_hbi_measure",
    ) != {
        "rust": "1.81.0",
        "folders": "3536",
        "leaves": "10608",
        "families": "3",
        "unique_colors": "10586",
        "semantic_binary": "0",
        "integer_only": "1",
        "json": "0",
    }:
        fail("gradient_audit_hbi_measure_contract")

    for line_index, kind, expected in (
        (
            2,
            "OPENN",
            {
                "finite_capture": "1",
                "actual_infinite_capture": "0",
                "n_level_open": "1",
                "logical_identity_ceiling": "0",
                "json": "0",
            },
        ),
        (
            3,
            "CENTER",
            {
                "members": MATRIX_CENTER,
                "traversal": MATRIX_TRAVERSAL_ENCODED,
                "all_five_distinct_per_leaf": "1",
                "json": "0",
            },
        ),
        (
            4,
            "BOUNDARY",
            {
                "evidence": "MEASURED_LIRIS_LOCAL",
                "system_affirmed": "0",
                "physical_energy": "0",
                "credentials": "0",
                "execution": "0",
                "json": "0",
            },
        ),
    ):
        if strict_tuple_fields(
            hbi_lines[line_index], kind,
            f"gradient_audit_hbi_{kind.lower()}",
        ) != expected:
            fail("gradient_audit_hbi_" + kind.lower() + "_contract")

    if sha256(hbp_path) != GRADIENT_AUDIT_HBP_SHA256:
        fail("gradient_audit_hbp_seal")
    if sha256(hbi_path) != GRADIENT_AUDIT_HBI_SHA256:
        fail("gradient_audit_hbi_seal")


def verify_qprism_on_demand_binding() -> None:
    hbp_path = ROOT / "matrix/QPRISM-ON-DEMAND-PUBLIC-BINDING.hbp"
    hbi_path = ROOT / "matrix/QPRISM-ON-DEMAND-PUBLIC-BINDING.hbi"
    hbp_lines = strict_tuple_receipt(
        hbp_path,
        rows=7,
        footer_kind="QPRISMONDEMANDFTR",
        error_prefix="qprism_on_demand_hbp",
    )
    hbi_lines = strict_tuple_receipt(
        hbi_path,
        rows=8,
        footer_kind="QPRISMONDEMANDIDXFTR",
        error_prefix="qprism_on_demand_hbi",
    )

    hbp_header = strict_tuple_fields(
        hbp_lines[0], "QPRISMONDEMAND", "qprism_on_demand_hbp_header",
    )
    if hbp_header != {
        "schema": "ASOLARIA-QPRISM-ON-DEMAND-BINDING-V1",
        "version": "1",
        "status": "OPERATOR_CANON",
        "statement": "QPRISM_GENERATES_ANYTHING_ON_DEMAND",
        "preexpanded_outputs_required": "0",
        "json": "0",
    }:
        fail("qprism_on_demand_hbp_header_contract")

    expected_source = {
        "class": "MEASURED_GITHUB",
        "repo": "JesseBrown1980/Q-PRISM-human-organoid-neural-stream-as-a-high-dimensional-control",
        "branch": "liris/double-bbh-quant-prism",
        "commit": "6862264e7ab9fb170bd8aedbbb8e6a4b99f4178d",
        "path": "host8/qprism_cube_host8.rs",
        "git_blob": "992ffd793f6c98f4f03b33ff0d1154b52d0174b0",
        "bytes": "13497",
        "sha256": "83a3dbc18832392d2aab5acf615097b8f4fdc75e5b999e38d0cd2801cca58c87",
        "json": "0",
    }
    hbp_source = strict_tuple_fields(
        hbp_lines[1], "SOURCE", "qprism_on_demand_hbp_source",
    )
    if hbp_source != expected_source:
        fail("qprism_on_demand_hbp_source_contract")

    hbp_test = strict_tuple_fields(
        hbp_lines[2], "TEST", "qprism_on_demand_hbp_test",
    )
    if (
        set(hbp_test)
        != {
            "class", "measured_at", "lane", "compiler", "tests",
            "passed", "failed", "ignored", "json",
        }
        or hbp_test.get("class") != "MEASURED_LIRIS"
        or re.fullmatch(
            r"2026-07-31T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}Z",
            hbp_test.get("measured_at", ""),
        ) is None
        or hbp_test.get("lane") != "WSL_UBUNTU"
        or hbp_test.get("compiler") != "rustc_1.81.0_eeb90cda1_2024-09-04"
        or hbp_test.get("tests") != "6"
        or hbp_test.get("passed") != "6"
        or hbp_test.get("failed") != "0"
        or hbp_test.get("ignored") != "0"
        or hbp_test.get("json") != "0"
    ):
        fail("qprism_on_demand_hbp_test_contract")

    if strict_tuple_fields(
        hbp_lines[3], "GENERATION", "qprism_on_demand_hbp_generation",
    ) != {
        "mode": "ON_DEMAND",
        "bh_radix": "1024",
        "bh_depth_bridge": "6",
        "frame_parameter": "1",
        "inject_between": "bh_digital_expansion",
        "request_is_finite": "1",
        "logical_n_open": "1",
        "preexpanded_catalog_required": "0",
        "preexisting_generated_output_required": "0",
        "output_sha256_minted_at_generation": "1",
        "json": "0",
    }:
        fail("qprism_on_demand_hbp_generation_contract")

    hbp_center = strict_tuple_fields(
        hbp_lines[4], "CENTER", "qprism_on_demand_hbp_center",
    )
    hbp_commitments = tuple(
        hbp_center.get(name, "") for name in ("hbi", "hbp", "sha", "sh", "hash")
    )
    if (
        set(hbp_center)
        != {
            "members", "traversal", "algorithm", "hbi", "hbp", "sha",
            "sh", "hash", "sha_equals_hash", "json",
        }
        or hbp_center.get("members") != MATRIX_CENTER
        or hbp_center.get("traversal") != "HBI,HBP,SH,HASH,SHA"
        or hbp_center.get("algorithm") != "SHA256_DOMAIN_UTF8_V1"
        or any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in hbp_commitments)
        or len(set(hbp_commitments)) != 5
        or hbp_center.get("sha_equals_hash") != "0"
        or hbp_center.get("json") != "0"
    ):
        fail("qprism_on_demand_hbp_center_contract")

    if strict_tuple_fields(
        hbp_lines[5], "BOUNDARY", "qprism_on_demand_hbp_boundary",
    ) != {
        "system_affirmed": "0",
        "source_role": "PUBLIC_60D_BRIDGE_CELL",
        "system_dimension_ceiling_inferred": "0",
        "copied_generator_source": "0",
        "fixed_generated_outputs_added": "0",
        "network": "0",
        "execution_authority": "0",
        "physical_energy": "0",
        "credentials": "0",
        "json": "0",
    }:
        fail("qprism_on_demand_hbp_boundary_contract")

    if strict_tuple_fields(
        hbi_lines[0], "QPRISMONDEMANDIDX", "qprism_on_demand_hbi_header",
    ) != {
        "schema": "ASOLARIA-QPRISM-ON-DEMAND-BINDING-V1",
        "version": "1",
        "json": "0",
    }:
        fail("qprism_on_demand_hbi_header_contract")

    hbi_pointer = strict_tuple_fields(
        hbi_lines[1], "POINTER", "qprism_on_demand_hbi_pointer",
    )
    expected_raw_url = (
        "https://raw.githubusercontent.com/"
        + expected_source["repo"]
        + "/"
        + expected_source["commit"]
        + "/"
        + expected_source["path"]
    )
    if hbi_pointer != {
        "repo": expected_source["repo"],
        "commit": expected_source["commit"],
        "path": expected_source["path"],
        "raw_url": expected_raw_url,
        "json": "0",
    }:
        fail("qprism_on_demand_hbi_pointer_contract")

    if strict_tuple_fields(
        hbi_lines[2], "ARTIFACT", "qprism_on_demand_hbi_artifact",
    ) != {
        "kind": "HBP",
        "file": hbp_path.name,
        "bytes": str(hbp_path.stat().st_size),
        "sha256": sha256(hbp_path),
        "exact_sidecar_verified": "1",
        "json": "0",
    }:
        fail("qprism_on_demand_hbi_artifact_contract")

    if strict_tuple_fields(
        hbi_lines[3], "MEASURED", "qprism_on_demand_hbi_measured",
    ) != {
        "github_commit_matches_local": "1",
        "github_blob": expected_source["git_blob"],
        "source_bytes": expected_source["bytes"],
        "source_sha256": expected_source["sha256"],
        "rust_1_81_tests": "6",
        "rust_1_81_passed": "6",
        "json": "0",
    }:
        fail("qprism_on_demand_hbi_measured_contract")

    if strict_tuple_fields(
        hbi_lines[4], "GENERATION", "qprism_on_demand_hbi_generation",
    ) != {
        "existing_qprism_is_generator": "1",
        "duplicate_generator_added": "0",
        "preexpanded_catalog_required": "0",
        "fixed_generated_outputs_added": "0",
        "generated_output_sha256_at_is": "1",
        "json": "0",
    }:
        fail("qprism_on_demand_hbi_generation_contract")

    hbi_center = strict_tuple_fields(
        hbi_lines[5], "CENTER", "qprism_on_demand_hbi_center",
    )
    if (
        set(hbi_center)
        != {"members", "traversal", "hbi", "hbp", "sha", "sh", "hash", "json"}
        or hbi_center.get("members") != MATRIX_CENTER
        or hbi_center.get("traversal") != "HBI,HBP,SH,HASH,SHA"
        or tuple(hbi_center.get(name, "") for name in ("hbi", "hbp", "sha", "sh", "hash"))
        != hbp_commitments
        or hbi_center.get("json") != "0"
    ):
        fail("qprism_on_demand_hbi_center_contract")

    if strict_tuple_fields(
        hbi_lines[6], "BOUNDARY", "qprism_on_demand_hbi_boundary",
    ) != {
        "operator_canon": "1",
        "measured_github": "1",
        "measured_liris": "1",
        "system_affirmed": "0",
        "source_is_60d_bridge": "1",
        "system_dimension_ceiling_inferred": "0",
        "credentials": "0",
        "json": "0",
    }:
        fail("qprism_on_demand_hbi_boundary_contract")

    for path in (hbp_path, hbi_path):
        sidecar = path.with_name(path.name + ".sha256")
        if sidecar.read_text(encoding="utf-8") != f"{sha256(path)}  {path.name}\n":
            fail("qprism_on_demand_sidecar:" + sidecar.name)


def verify_snow_on_demand_selector() -> None:
    verify_qprism_on_demand_binding()

    schema = "ASOLARIA-SNOW-QPRISM-ON-DEMAND-SELECTOR-V1"
    quote = (
        "S.N.O.W    Start iNfinite (-,.,+)0 W-MATRIX. WHITE IS COLD the worst "
        "of the WORST X INFINITY FOR OUR key, but there are others and antis "
        "and others and anti antis"
    )
    quote_bytes = quote.encode("utf-8")
    quote_sha256 = hashlib.sha256(quote_bytes).hexdigest()
    hbp_path = ROOT / "matrix/SNOW-QPRISM-ON-DEMAND-SELECTOR.hbp"
    hbi_path = ROOT / "matrix/SNOW-QPRISM-ON-DEMAND-SELECTOR.hbi"
    hbp_lines = strict_tuple_receipt(
        hbp_path,
        rows=8,
        footer_kind="SNOWSELECTORFTR",
        error_prefix="snow_selector_hbp",
    )
    hbi_lines = strict_tuple_receipt(
        hbi_path,
        rows=7,
        footer_kind="SNOWSELECTORIDXFTR",
        error_prefix="snow_selector_hbi",
    )

    if strict_tuple_fields(
        hbp_lines[0], "SNOWSELECTOR", "snow_selector_hbp_header",
    ) != {
        "schema": schema,
        "version": "1",
        "status": "OPERATOR_CANON",
        "mode": "ON_DEMAND",
        "fixed_projection_required": "0",
        "json": "0",
    }:
        fail("snow_selector_hbp_header_contract")

    if strict_tuple_fields(
        hbp_lines[1], "QUOTE", "snow_selector_hbp_quote",
    ) != {
        "class": "OPERATOR_CANON",
        "claim_type": "PHYSICAL_OPERATOR_LANGUAGE",
        "system_affirmed": "0",
        "independently_measured": "0",
        "utf8_bytes": str(len(quote_bytes)),
        "sha256": quote_sha256,
        "text": quote,
        "json": "0",
    }:
        fail("snow_selector_quote_contract")

    expected_selector = {
        "token": "S.N.O.W",
        "s_token": "Start",
        "n_token": "iNfinite",
        "sign_coordinate": "-,.,+",
        "zero_coordinate": "0",
        "matrix_coordinate": "W-MATRIX",
        "coordinate_exchange": "0",
        "logical_n_open": "1",
        "json": "0",
    }
    if strict_tuple_fields(
        hbp_lines[2], "SELECTOR", "snow_selector_hbp_selector",
    ) != expected_selector:
        fail("snow_selector_coordinate_contract")
    coordinate_values = tuple(
        expected_selector[name]
        for name in ("sign_coordinate", "zero_coordinate", "matrix_coordinate")
    )
    if len(set(coordinate_values)) != 3:
        fail("snow_selector_coordinate_identity")

    expected_keyspace = {
        "our_key_label": "OUR_KEY",
        "other_label": "OTHER",
        "anti_other_label": "ANTI_OTHER",
        "anti_anti_other_label": "ANTI_ANTI_OTHER",
        "family_labels": "4",
        "logical_identity_ceiling": "0",
        "n_level_open": "1",
        "identity_exchange": "0",
        "key_material_embedded": "0",
        "credentials": "0",
        "json": "0",
    }
    if strict_tuple_fields(
        hbp_lines[3], "KEYSPACE", "snow_selector_hbp_keyspace",
    ) != expected_keyspace:
        fail("snow_selector_keyspace_contract")
    key_labels = tuple(
        expected_keyspace[name]
        for name in (
            "our_key_label",
            "other_label",
            "anti_other_label",
            "anti_anti_other_label",
        )
    )
    if (
        len(set(key_labels)) != int(expected_keyspace["family_labels"])
        or expected_keyspace["logical_identity_ceiling"] != "0"
        or expected_keyspace["n_level_open"] != "1"
    ):
        fail("snow_selector_keyspace_identity")

    expected_qprism = {
        "mode": "ON_DEMAND",
        "hbp_path": "matrix/QPRISM-ON-DEMAND-PUBLIC-BINDING.hbp",
        "hbp_sha256": "3c58554b0a9abd52f658ecc96cb115cb42da3e7642b06a989585da269128c3ff",
        "hbi_path": "matrix/QPRISM-ON-DEMAND-PUBLIC-BINDING.hbi",
        "hbi_sha256": "1514470eec0a3c6cd8ce091fabe08c33e136f7dd849f10c75e1f949e2a17c0d9",
        "existing_qprism_is_generator": "1",
        "duplicate_generator_added": "0",
        "preexisting_generated_output_required": "0",
        "json": "0",
    }
    if strict_tuple_fields(
        hbp_lines[4], "QPRISM", "snow_selector_hbp_qprism",
    ) != expected_qprism:
        fail("snow_selector_qprism_contract")
    for kind in ("hbp", "hbi"):
        qprism_path = ROOT / expected_qprism[f"{kind}_path"]
        if sha256(qprism_path) != expected_qprism[f"{kind}_sha256"]:
            fail("snow_selector_qprism_hash:" + kind)

    members = ("HBI", "HBP", "SHA", "SH", "HASH")
    commitments = {
        member.lower(): hashlib.sha256(
            (schema + "\0" + member).encode("utf-8")
        ).hexdigest()
        for member in members
    }
    expected_hbp_center = {
        "members": MATRIX_CENTER,
        "traversal": "HBI,HBP,SH,HASH,SHA",
        "algorithm": "SHA256_UTF8_DOMAIN_NUL_MEMBER_V1",
        "domain": schema,
        **commitments,
        "sha_equals_hash": "0",
        "json": "0",
    }
    if strict_tuple_fields(
        hbp_lines[5], "CENTER", "snow_selector_hbp_center",
    ) != expected_hbp_center:
        fail("snow_selector_center_contract")
    if len(set(commitments.values())) != 5 or commitments["sha"] == commitments["hash"]:
        fail("snow_selector_center_identity")

    if strict_tuple_fields(
        hbp_lines[6], "BOUNDARY", "snow_selector_hbp_boundary",
    ) != {
        "system_affirmed": "0",
        "fixed_projection_added": "0",
        "preexpanded_outputs_required": "0",
        "network": "0",
        "execution_authority": "0",
        "physical_energy": "0",
        "clinical_instruction": "0",
        "credentials": "0",
        "key_material": "0",
        "json": "0",
    }:
        fail("snow_selector_hbp_boundary_contract")

    if strict_tuple_fields(
        hbi_lines[0], "SNOWSELECTORIDX", "snow_selector_hbi_header",
    ) != {
        "schema": schema,
        "version": "1",
        "json": "0",
    }:
        fail("snow_selector_hbi_header_contract")

    if strict_tuple_fields(
        hbi_lines[1], "ARTIFACT", "snow_selector_hbi_artifact",
    ) != {
        "kind": "HBP",
        "file": hbp_path.name,
        "bytes": str(hbp_path.stat().st_size),
        "sha256": sha256(hbp_path),
        "exact_sidecar_verified": "1",
        "json": "0",
    }:
        fail("snow_selector_hbi_artifact_contract")

    if strict_tuple_fields(
        hbi_lines[2], "QPRISM", "snow_selector_hbi_qprism",
    ) != expected_qprism:
        fail("snow_selector_hbi_qprism_contract")

    if strict_tuple_fields(
        hbi_lines[3], "INDEX", "snow_selector_hbi_index",
    ) != {
        "token": "S.N.O.W",
        "quote_sha256": quote_sha256,
        "sign_coordinate": expected_selector["sign_coordinate"],
        "zero_coordinate": expected_selector["zero_coordinate"],
        "matrix_coordinate": expected_selector["matrix_coordinate"],
        "key_family_labels": expected_keyspace["family_labels"],
        "logical_identity_ceiling": expected_keyspace["logical_identity_ceiling"],
        "n_level_open": expected_keyspace["n_level_open"],
        "mode": "ON_DEMAND",
        "fixed_projection_required": "0",
        "json": "0",
    }:
        fail("snow_selector_hbi_index_contract")

    expected_hbi_center = {
        key: value
        for key, value in expected_hbp_center.items()
        if key not in {"algorithm", "domain"}
    }
    if strict_tuple_fields(
        hbi_lines[4], "CENTER", "snow_selector_hbi_center",
    ) != expected_hbi_center:
        fail("snow_selector_hbi_center_contract")

    if strict_tuple_fields(
        hbi_lines[5], "BOUNDARY", "snow_selector_hbi_boundary",
    ) != {
        "operator_canon": "1",
        "system_affirmed": "0",
        "independently_measured_physics": "0",
        "credentials": "0",
        "key_material": "0",
        "execution_authority": "0",
        "json": "0",
    }:
        fail("snow_selector_hbi_boundary_contract")

    for path in (hbp_path, hbi_path):
        sidecar = path.with_name(path.name + ".sha256")
        if sidecar.read_text(encoding="utf-8") != f"{sha256(path)}  {path.name}\n":
            fail("snow_selector_sidecar:" + sidecar.name)


def main() -> None:
    files = repo_files()

    for relative, expected in EXPECTED.items():
        path = ROOT / relative
        if not path.is_file():
            fail(f"missing_pinned_file:{relative}")
        actual = sha256(path)
        if actual != expected:
            fail(f"sha256_mismatch:{relative}")

    photo = ROOT / "knowledge/operator-evidence/IS-photo-2026-07-27.jpeg"
    if photo.stat().st_size != 821_531:
        fail("photo_size_mismatch")

    crlf_paths = []
    for path in files:
        if path.suffix.lower() in TEXT_SUFFIXES and b"\r\n" in path.read_bytes():
            crlf_paths.append(path.relative_to(ROOT).as_posix())
    if crlf_paths:
        fail("crlf_text:" + ",".join(crlf_paths))

    agents_text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    for binding in DEFAULT_BINDING_REQUIRED:
        if binding not in agents_text:
            fail("missing_default_is_binding")

    binding_hits = []
    for path in files:
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for name, pattern in DEFAULT_BINDING_FORBIDDEN.items():
            if pattern.search(text):
                binding_hits.append(
                    f"{name}:{path.relative_to(ROOT).as_posix()}"
                )
    if binding_hits:
        fail("default_binding_contradiction:" + ",".join(binding_hits))

    workflow_path = ROOT / ".github" / "workflows" / "tournament.yml"
    workflow_text = workflow_path.read_text(encoding="utf-8")
    if "pull_request_target:" in workflow_text:
        fail("workflow_uses_pull_request_target")
    if "permissions:\n  contents: read\n" not in workflow_text:
        fail("workflow_permissions_not_read_only")
    if "persist-credentials: false" not in workflow_text:
        fail("workflow_persists_checkout_credentials")
    if re.search(r"(?i)\$\{\{\s*(?:secrets\.|github\.token)", workflow_text):
        fail("workflow_secret_reference")
    action_uses = re.findall(
        r"(?m)^\s*uses:\s*([^@\s]+)@([0-9a-f]{40})(?:\s|$)",
        workflow_text,
    )
    if len(action_uses) != len(WORKFLOW_ACTION_PINS):
        fail("workflow_action_pin_count_mismatch")
    if dict(action_uses) != WORKFLOW_ACTION_PINS:
        fail("workflow_action_pin_mismatch")
    for rust_binding in (
        "rustup toolchain install 1.81.0 --profile minimal --component clippy,rustfmt",
        'rustc +1.81.0 --version)" = "rustc 1.81.0 (eeb90cda1 2024-09-04)',
        'cargo +1.81.0 --version)" = "cargo 1.81.0 (2dbb1af80 2024-08-20)',
        "-D clippy::float_arithmetic",
        "PUBLIC-QPRISM-COLOR-LEAVES.svg",
        "PUBLIC-OUTWARD-TRUTH-WAVES.gguf",
        "--bin outward-truth-waves",
        "PUBLIC-FOLDER-CALMING-OILS.gguf",
        "--bin folder-calming-oils",
        "test_collect_public_folder_inventory.py",
    ):
        if rust_binding not in workflow_text:
            fail("workflow_rust_181_binding_missing")
    for compact_final_binding in (
        "matrix/timed-86400-flowes-x3x3-final",
        COMPACT_FINAL_ACTIVATION_MARKER,
        "python matrix/finalize_timed_86400_flowes_x3x3.py verify-public",
        '"${RUNNER_TEMP}/folder-calming-oils-a"',
        "COMPACT_FINAL_OPTIONAL|state=ABSENT|json=0",
    ):
        if compact_final_binding not in workflow_text:
            fail("workflow_compact_final_binding_missing")

    for relative in MATRIX_PRIMARY:
        path = ROOT / relative
        if not path.is_file():
            fail("missing_matrix_primary:" + relative)
        sidecar = path.with_name(path.name + ".sha256")
        if not sidecar.is_file():
            fail("missing_matrix_primary_sidecar:" + relative)

    qprism_snapshot_present = optional_snapshot_group_present(
        "PUBLIC_QPRISM_COLOR_LEAVES", HISTORICAL_QPRISM_SNAPSHOT,
    )
    folder_oil_snapshot_present = optional_snapshot_group_present(
        "PUBLIC_FOLDER_CALMING_OILS", HISTORICAL_FOLDER_OIL_SNAPSHOT,
    )
    compact_final_witness_present, compact_final_required = (
        verify_compact_final_gate(ROOT)
    )
    verify_rust_181_gradient_semantics_receipt()
    verify_snow_on_demand_selector()

    for relative in (
        "matrix/PUBLIC-OWNER-3D-TREE.hbp",
        "matrix/PUBLIC-OWNER-3D-TREE.hbi",
        "matrix/PUBLIC-OWNER-2D.hbp",
        "matrix/PUBLIC-SPHERICAL-PROJECTION.hbp",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        if f"HBI,HBP,SHA,SH,HASH" not in text:
            fail("matrix_center_membership_missing:" + relative)
        traversal = (
            "HBI,HBP,SH,HASH,SHA"
            if relative.endswith(("TREE.hbp", "TREE.hbi"))
            else MATRIX_TRAVERSAL_ENCODED
        )
        if traversal not in text:
            fail("matrix_traversal_missing:" + relative)
        if any(
            line and not re.search(r"(?:^|\|)json=0(?:\||$)", line)
            for line in text.splitlines()
        ):
            fail("matrix_json0_missing:" + relative)

    media_owner_path = ROOT / "matrix/PUBLIC-OWNER-3D-MEDIA-TREE.hbp"
    media_owner_lines = media_owner_path.read_text(encoding="utf-8").splitlines()
    if len(media_owner_lines) != 153 or any(
        not line.endswith("|json=0") for line in media_owner_lines
    ):
        fail("media_owner_row_contract")
    if not media_owner_lines[0].startswith(
        "OWNER3DRUN|schema=ASOLARIA-PUBLIC-OWNER-3D-TREE-V2|"
    ) or "|repos=147|" not in media_owner_lines[0]:
        fail("media_owner_header")
    if media_owner_lines[2] != (
        "RECIPE|sh=GH_PUBLIC_OWNER_TREE_V1|transport=GH_CLI_PUBLIC_REST"
        "|recursive_git_tree=1|paths_published=0|blob_bodies_read=0"
        "|media_extensions_classified=1|media_paths_published=0"
        "|media_bodies_read=0"
        "|media_classification=PATH_EXTENSION_METADATA_ONLY|json=0"
    ):
        fail("media_owner_recipe")
    if media_owner_lines[3] != (
        "BOUNDARY|private_repo_endpoint_calls=0|private_repo_rows=0|private_keys=0"
        "|credentials_in_output=0|catalog_grants_authority=0|system_affirmed=0"
        "|media_bytes_embedded=0|media_decoder_claim=0|json=0"
    ):
        fail("media_owner_boundary")

    def simple_fields(line: str, kind: str) -> dict[str, str]:
        pieces = line.split("|")
        if pieces[0] != kind:
            fail("media_owner_kind:" + kind)
        result: dict[str, str] = {}
        for piece in pieces[1:]:
            if "=" not in piece:
                fail("media_owner_field_shape")
            key, value = piece.split("=", 1)
            if not key or key in result:
                fail("media_owner_field_duplicate")
            result[key] = value
        return result

    media_rows = [simple_fields(line, "REPO") for line in media_owner_lines[4:151]]
    if [int(row["i"]) for row in media_rows] != list(range(147)):
        fail("media_owner_index")
    media_totals = {
        "image_entries": sum(int(row["image_entries"]) for row in media_rows),
        "video_entries": sum(int(row["video_entries"]) for row in media_rows),
        "media_declared_bytes": sum(
            int(row["media_declared_bytes"]) for row in media_rows
        ),
        "media_size_unknown_entries": sum(
            int(row["media_size_unknown_entries"]) for row in media_rows
        ),
    }
    expected_media_totals = {
        "image_entries": 1137,
        "video_entries": 0,
        "media_declared_bytes": 219346951,
        "media_size_unknown_entries": 0,
    }
    if media_totals != expected_media_totals:
        fail("media_owner_totals")
    if any(
        int(row["image_entries"]) + int(row["video_entries"]) > int(row["blobs"])
        or not re.fullmatch(r"[0-9a-f]{64}", row["media_root_sha256"])
        for row in media_rows
    ):
        fail("media_owner_repo_contract")
    media_summary = simple_fields(media_owner_lines[-1], "SUMMARY")
    if any(media_summary.get(key) != str(value) for key, value in expected_media_totals.items()):
        fail("media_owner_summary")
    media_hbi_path = ROOT / "matrix/PUBLIC-OWNER-3D-MEDIA-TREE.hbi"
    media_hbi = media_hbi_path.read_text(encoding="utf-8")
    if (
        f"sha256={sha256(media_owner_path)}" not in media_hbi
        or "|repos=147|raw_blob_bodies=0|" not in media_hbi
        or not media_hbi.endswith("|json=0\n")
    ):
        fail("media_owner_hbi_binding")

    media_position_path = ROOT / "matrix/PUBLIC-OWNER-MEDIA-POSITION-2D.hbp"
    media_position_lines = media_position_path.read_text(encoding="utf-8").splitlines()
    if (
        len(media_position_lines) != 149
        or "|observed_records=147|" not in media_position_lines[0]
        or any(not line.endswith("|json=0") for line in media_position_lines)
    ):
        fail("media_position_2d_contract")

    projection_text = (
        ROOT / "matrix/PUBLIC-SPHERICAL-PROJECTION.hbp"
    ).read_text(encoding="utf-8")
    reflection_rows = [
        line for line in projection_text.splitlines()
        if line.startswith("REFLECTION60|")
    ]
    if not reflection_rows or any(
        not re.search(r"\|observed=(?:[1-9]|[1-5][0-9]|60)\|", line)
        or "|window_max=60|" not in line
        for line in reflection_rows
    ):
        fail("matrix_reflection60_contract")

    svg_text = (
        ROOT / "matrix/PUBLIC-SPHERICAL-PROJECTION.svg"
    ).read_text(encoding="utf-8")
    if any(
        token in svg_text.lower()
        for token in ("<script", "<image", "<foreignobject", " href=", "url(")
    ):
        fail("matrix_svg_active_content")

    def tuple_fields(line: str, expected_kind: str) -> dict[str, str]:
        pieces = line.split("|")
        if pieces[0] != expected_kind:
            fail("qprism_kind:" + expected_kind)
        result: dict[str, str] = {}
        for piece in pieces[1:]:
            if "=" not in piece:
                fail("qprism_field_shape")
            key, value = piece.split("=", 1)
            if not key or not value or key in result:
                fail("qprism_field_duplicate")
            result[key] = value
        return result

    if qprism_snapshot_present:
        qprism_path = ROOT / "matrix/PUBLIC-QPRISM-COLOR-LEAVES.hbp"
        qprism_lines = qprism_path.read_text(encoding="utf-8").splitlines()
        if len(qprism_lines) != 447:
            fail("qprism_row_count")
        if any("|json=0" not in line for line in qprism_lines):
            fail("qprism_json0_missing")

        qprism_header = tuple_fields(qprism_lines[0], "QPRISMHDR")
        required_qprism_header = {
            "schema": "PUBLIC-QPRISM-COLOR-LEAVES-RUST-181-V1",
            "rust_version": "1.81.0",
            "source_sha256": sha256(ROOT / "matrix/PUBLIC-OWNER-2D.hbp"),
            "observed_records": "147",
            "leaf_count": "441",
            "families_per_record": "3",
            "n_level_open": "1",
            "reflection_window": "60",
            "system_affirmed": "0",
            "public_metadata_only": "1",
            "raw_contents": "0",
            "json": "0",
        }
        if any(qprism_header.get(key) != value for key, value in required_qprism_header.items()):
            fail("qprism_header_contract")
        if qprism_lines[1] != (
            "CENTER|membership=HBI,HBP,SHA,SH,HASH|"
            "traversal=HBI-%3EHBP-%3ESH-%3EHASH-%3ESHA|json=0"
        ):
            fail("qprism_center_contract")
        if qprism_lines[2:5] != [
            "STAGE|order=1|name=2D_INPUT|integer_only=1|json=0",
            "STAGE|order=2|name=3D_QPRISM|checked_i128=1|float_coordinates=0|json=0",
            "STAGE|order=3|name=SIGNED_2D_PROJECTION|depth_sorted=1|identity_exchange=0|json=0",
        ]:
            fail("qprism_stage_contract")

        qprism_leaves = [tuple_fields(line, "LEAF") for line in qprism_lines[5:-1]]
        if len(qprism_leaves) != 441:
            fail("qprism_leaf_population")
        leaf_ids = {leaf.get("leaf_id") for leaf in qprism_leaves}
        if None in leaf_ids or len(leaf_ids) != 441:
            fail("qprism_leaf_identity")
        if [int(leaf["order"]) for leaf in qprism_leaves] != list(range(441)):
            fail("qprism_leaf_order")
        family_counts = {
            family: sum(leaf.get("family") == family for leaf in qprism_leaves)
            for family in ("BROWN", "ANTI_BROWN", "ANTI_ANTI_BROWN")
        }
        if family_counts != {
            "BROWN": 147,
            "ANTI_BROWN": 147,
            "ANTI_ANTI_BROWN": 147,
        }:
            fail("qprism_leaf_families")
        sources: dict[str, set[str]] = {}
        for leaf in qprism_leaves:
            if (
                leaf.get("input_u") != leaf.get("recovered_u")
                or leaf.get("input_v") != leaf.get("recovered_v")
                or leaf.get("input_u") != leaf.get("view_x")
                or leaf.get("input_v") != leaf.get("view_y")
                or leaf.get("immutable_source_record") != "1"
                or leaf.get("identity_exchange") != "0"
                or leaf.get("tetra_determinant") != "-16"
            ):
                fail("qprism_leaf_exactness")
            sources.setdefault(leaf["source_identity_sha256"], set()).add(leaf["family"])
        if len(sources) != 147 or any(
            families != {"BROWN", "ANTI_BROWN", "ANTI_ANTI_BROWN"}
            for families in sources.values()
        ):
            fail("qprism_parent_leaf_relation")
        if len({leaf["view_z"] for leaf in qprism_leaves}) != 441:
            fail("qprism_view_z_flattened")
        if len({leaf["orb_depth_scaled"] for leaf in qprism_leaves}) <= 100:
            fail("qprism_orb_depth_flattened")
        qprism_footer = tuple_fields(qprism_lines[-1], "QPRISMFTR")
        qprism_body = ("\n".join(qprism_lines[:-1]) + "\n").encode("utf-8")
        if (
            qprism_footer.get("body_sha256") != hashlib.sha256(qprism_body).hexdigest()
            or qprism_footer.get("rows") != str(len(qprism_lines))
            or qprism_footer.get("json") != "0"
        ):
            fail("qprism_footer_commitment")

        qprism_svg = (ROOT / "matrix/PUBLIC-QPRISM-COLOR-LEAVES.svg").read_text(
            encoding="utf-8"
        )
        if qprism_svg.count('class="qprism-leaf"') != 441:
            fail("qprism_svg_leaf_population")
        for token in (
            'data-stage="2D_INPUT"',
            'data-stage="3D_QPRISM"',
            'data-stage="SIGNED_2D_PROJECTION"',
            "rust_version=1.81.0",
            "integer_only=1",
            "float_coordinates=0",
            "n_level_open=1",
            "reflection_window=60",
        ):
            if token not in qprism_svg:
                fail("qprism_svg_contract")
        if any(
            token in qprism_svg.lower()
            for token in (
                "<table", "<circle", "<script", "<image", "<foreignobject",
                " href=", "url(", "<a ", "@import", "file:",
            )
        ):
            fail("qprism_svg_active_or_flat_content")
        svg_leaf_ids = set(re.findall(r'id="leaf-([0-9a-f]{64})"', qprism_svg))
        if svg_leaf_ids != leaf_ids:
            fail("qprism_svg_identity_mismatch")

    cargo_text = (ROOT / "matrix/rust-qprism-181/Cargo.toml").read_text(encoding="utf-8")
    toolchain_text = (ROOT / "matrix/rust-qprism-181/rust-toolchain.toml").read_text(
        encoding="utf-8"
    )
    rust_source = "\n".join(
        (ROOT / relative).read_text(encoding="utf-8")
        for relative in (
            "matrix/rust-qprism-181/src/lib.rs",
            "matrix/rust-qprism-181/src/main.rs",
            "matrix/rust-qprism-181/src/folders.rs",
            "matrix/rust-qprism-181/src/bin/folder-calming-oils.rs",
            "matrix/rust-qprism-181/src/outward.rs",
            "matrix/rust-qprism-181/src/bin/outward-truth-waves.rs",
        )
    )
    if 'rust-version = "1.81"' not in cargo_text or '[dependencies]\n\n' not in cargo_text:
        fail("qprism_cargo_contract")
    if 'channel = "1.81.0"' not in toolchain_text:
        fail("qprism_toolchain_contract")
    if "#![forbid(unsafe_code)]" not in rust_source or re.search(r"\b(?:f32|f64)\b", rust_source):
        fail("qprism_rust_integer_contract")
    rust_without_strings = re.sub(r'"(?:\\.|[^"\\])*"', '""', rust_source)
    if re.search(r"(?<![A-Za-z0-9_])\d+\.\d", rust_without_strings):
        fail("qprism_rust_float_literal")

    matrix_path = str(ROOT / "matrix")
    if matrix_path not in sys.path:
        sys.path.insert(0, matrix_path)
    from collect_public_folder_inventory import (  # noqa: PLC0415
        InventoryError,
        verify_hbi_bytes as verify_folder_source_hbi,
        verify_hbp_bytes as verify_folder_source_hbp,
    )
    from spherical_public_projection import parse_inventory  # noqa: PLC0415
    from timed_chiral_gguf_monitor import (  # noqa: PLC0415
        TARGET_SECONDS,
        descriptor_bytes,
        verify_gguf,
    )
    from build_timed_86400_flowes_x3x3 import (  # noqa: PLC0415
        CENTER_MEMBERS as FLOWE_CENTER_MEMBERS,
        CENTER_TRAVERSAL as FLOWE_CENTER_TRAVERSAL,
        DIRECTIONS as FLOWE_DIRECTIONS,
        FAMILIES as FLOWE_FAMILIES,
        OBSERVATION_LIMIT as FLOWE_OBSERVATION_LIMIT,
        TARGET_SECONDS as FLOWE_TARGET_SECONDS,
        build_cells as build_flowe_cells,
        build_rings as build_flowe_rings,
        cell_row as flowe_cell_row,
        fake_complete_journal as fake_complete_flowe_journal,
        journal_bytes as flowe_journal_bytes,
        load_source as load_flowe_source,
        parse_journal_bytes as parse_flowe_journal_bytes,
        ring_row as flowe_ring_row,
        schedule as flowe_schedule,
    )

    timed_source = ROOT / "matrix/PUBLIC-OWNER-2D.hbp"
    timed_source_sha = sha256(timed_source)
    if timed_source_sha != (
        "f3a9ade5062c5712070ae3f1b78aaa169ff644d5692bf65f361bdb128b7d6e17"
    ):
        fail("timed_source_f3a9_immutability")
    timed_gguf_path = ROOT / "matrix/TIMED-CHIRAL-PUBLIC-COLOR-ORBITS.gguf"
    timed_gguf = timed_gguf_path.read_bytes()
    if (
        len(timed_gguf) != 2200
        or verify_gguf(timed_gguf, timed_source_sha, 147, TARGET_SECONDS)
        != "77174fb892a1c8152de362730d2864ef2b7f929b496af7758a5c42a88798bb6e"
    ):
        fail("timed_gguf_contract")
    inventory = parse_inventory(timed_source)
    if not timed_gguf.endswith(descriptor_bytes(inventory)):
        fail("timed_gguf_descriptor_source_closure")
    timed_hbp_path = ROOT / "matrix/TIMED-CHIRAL-MONITOR.hbp"
    timed_hbp = timed_hbp_path.read_text(encoding="utf-8").splitlines()
    if (
        len(timed_hbp) != 18
        or any(not line.endswith("|json=0") for line in timed_hbp)
        or "|status=COMPLETE|elapsed_seconds=7200|target_seconds=7200|" not in timed_hbp[0]
        or "|checkpoint_seconds=7200|" not in timed_hbp[-3]
        or "|state=PRESENT|" not in timed_hbp[-2]
    ):
        fail("timed_hbp_contract")
    timed_body = ("\n".join(timed_hbp[:-1]) + "\n").encode("utf-8")
    timed_footer = tuple_fields(timed_hbp[-1], "TIMEDCHIRALFTR")
    if (
        timed_footer.get("body_sha256") != hashlib.sha256(timed_body).hexdigest()
        or timed_footer.get("rows") != "18"
    ):
        fail("timed_hbp_footer")
    timed_hbi = (ROOT / "matrix/TIMED-CHIRAL-MONITOR.hbi").read_text(
        encoding="utf-8"
    )
    if (
        f"hbp_sha256={sha256(timed_hbp_path)}" not in timed_hbi
        or f"gguf_sha256={sha256(timed_gguf_path)}" not in timed_hbi
        or "authority_granted=0" not in timed_hbi
        or not timed_hbi.endswith("|json=0\n")
    ):
        fail("timed_hbi_binding")

    if folder_oil_snapshot_present:
        flowe_source = load_flowe_source(ROOT / "matrix")
        flowe_checkpoints = flowe_schedule(FLOWE_TARGET_SECONDS)
        expected_flowe_checkpoints = (
            1, 2, 3, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048,
            4096, 8192, 16384, 32768, 65536, 86400,
        )
        if (
            flowe_source.folder_count != 3536
            or len(flowe_source.leaves) != 10608
            or flowe_checkpoints != expected_flowe_checkpoints
            or FLOWE_FAMILIES != ("BROWN", "ANTI_BROWN", "ANTI_ANTI_BROWN")
            or FLOWE_DIRECTIONS != ("NEGATIVE", "CENTRE", "POSITIVE")
            or FLOWE_CENTER_MEMBERS != ("HBI", "HBP", "SHA", "SH", "HASH")
            or FLOWE_CENTER_TRAVERSAL != "HBI->HBP->SH->HASH->SHA"
            or FLOWE_OBSERVATION_LIMIT != 60
        ):
            fail("flowe_x3x3_source_and_center")

        flowe_cells = build_flowe_cells(flowe_source)
        flowe_addresses = {
            (cell.source.folder_i, cell.source.family_i, cell.direction_i)
            for cell in flowe_cells
        }
        expected_flowe_addresses = {
            (folder_i, family_i, direction_i)
            for folder_i in range(3536)
            for family_i in range(3)
            for direction_i in range(3)
        }
        if len(flowe_cells) != 31824 or flowe_addresses != expected_flowe_addresses:
            fail("flowe_x3x3_cell_population")
        for cell in flowe_cells:
            if len(set(cell.commitments)) != 5:
                fail("flowe_x3x3_center_collision")
            fields = tuple_fields(flowe_cell_row(cell), "FLOWE")
            if (
                tuple(fields.get(name) for name in ("hbi", "hbp", "sha", "sh", "hash"))
                != cell.commitments
                or fields.get("commitments_domain_separated") != "1"
                or fields.get("commitments_distinct") != "5"
                or any(fields.get(name) != "0" for name in (
                    "network", "execution", "authority", "physical_energy", "json"
                ))
            ):
                fail("flowe_x3x3_cell_contract")

        flowe_rings = build_flowe_rings(flowe_source, flowe_checkpoints)
        if len(flowe_rings) != 171:
            fail("flowe_x3x3_ring_population")
        prior_by_axis = {}
        ring_count_by_axis = {}
        for index, ring in enumerate(flowe_rings):
            key = (ring.family_i, ring.direction_i)
            if ring.index != index or not 1 <= ring.observed_rows <= 60:
                fail("flowe_x3x3_ring_index")
            if key in prior_by_axis and ring.previous_ring_hash != prior_by_axis[key]:
                fail("flowe_x3x3_ring_chain")
            prior_by_axis[key] = ring.ring_hash
            ring_count_by_axis[key] = ring_count_by_axis.get(key, 0) + 1
            fields = tuple_fields(flowe_ring_row(ring), "RING")
            if (
                fields.get("operations") != "SELF_REFLECT,COLLECT,SELF_REDUCE"
                or fields.get("observed_only") != "1"
                or fields.get("future_rows") != "0"
                or fields.get("transform") != "2D-%3E3D-%3ESIGNED_2D"
                or any(fields.get(name) != "0" for name in (
                    "network", "execution", "authority", "physical_energy", "json"
                ))
            ):
                fail("flowe_x3x3_ring_contract")
        if set(ring_count_by_axis.values()) != {19} or len(ring_count_by_axis) != 9:
            fail("flowe_x3x3_ring_axis_coverage")

        flowe_journal = fake_complete_flowe_journal(
            flowe_source, FLOWE_TARGET_SECONDS
        )
        sealed_flowe_journal = flowe_journal_bytes(flowe_journal)
        parsed_flowe_journal = parse_flowe_journal_bytes(
            sealed_flowe_journal, flowe_source, FLOWE_TARGET_SECONDS,
            "DETERMINISTIC_FAKE_CLOCK",
        )
        if (
            not parsed_flowe_journal.complete
            or len(parsed_flowe_journal.checkpoints) != 19
            or parsed_flowe_journal.accumulated_seconds != 86400
        ):
            fail("flowe_x3x3_journal_chain")

        running_hbi_path = ROOT / "matrix/TIMED-86400-FLOWes-X3-X3-RUNNING.hbi"
        running_hbi_lines = running_hbi_path.read_text(encoding="utf-8").splitlines()
        if len(running_hbi_lines) != 1:
            fail("flowe_x3x3_running_hbi_rows")
        running_hbi = tuple_fields(running_hbi_lines[0], "FLOWEX9RUNHBI")
        if (
            running_hbi.get("state") != "RUNNING_LOCAL"
            or running_hbi.get("builder_commit")
            != "cf4f760f943087d312894cef5a683d99fc0119df"
            or running_hbi.get("launch_checkpoint_seconds") != "64"
            or running_hbi.get("source_hbp_sha256") != flowe_source.hbp_sha256
            or running_hbi.get("source_hbi_sha256") != flowe_source.hbi_sha256
            or running_hbi.get("center") != MATRIX_CENTER
            or running_hbi.get("traversal") != MATRIX_TRAVERSAL_ENCODED
            or any(running_hbi.get(name) != "0" for name in (
                "local_output_path", "credentials", "execution_authority",
                "system_affirmed", "json",
            ))
        ):
            fail("flowe_x3x3_running_hbi_contract")

        launch_path = (
            ROOT / "receipts/LIRIS-FLOWES-X3-X3-86400-LAUNCH-2026-07-31.hbp"
        )
        launch_lines = launch_path.read_text(encoding="utf-8").splitlines()
        if len(launch_lines) != 15 or any(
            not line.endswith("|json=0") for line in launch_lines
        ):
            fail("flowe_x3x3_launch_shape")
        launch_header = tuple_fields(launch_lines[0], "LIRISFLOWEX9LAUNCHHDR")
        launch_boundary = tuple_fields(launch_lines[-3], "BOUNDARY")
        launch_center = tuple_fields(launch_lines[9], "CENTER")
        launch_shape = tuple_fields(launch_lines[10], "SHAPE")
        if (
            launch_header.get("evidence") != "MEASURED_LIRIS_LOCAL"
            or launch_header.get("status") != "RUNNING_LOCAL"
            or launch_header.get("target_seconds") != "86400"
            or launch_center.get("members") != MATRIX_CENTER
            or launch_center.get("traversal") != MATRIX_TRAVERSAL_ENCODED
            or launch_shape.get("final_cells") != "31824"
            or launch_shape.get("ring_summaries_target") != "171"
            or launch_boundary.get("complete") != "0"
            or launch_boundary.get("final_artifacts_present") != "0"
            or any(launch_boundary.get(name) != "0" for name in (
                "credentials", "private_paths", "network_required",
                "execution_authority", "physical_energy", "system_affirmed", "json",
            ))
        ):
            fail("flowe_x3x3_launch_contract")
        launch_body = ("\n".join(launch_lines[:-1]) + "\n").encode("utf-8")
        if tuple_fields(launch_lines[-1], "LIRISFLOWEX9LAUNCHFTR") != {
            "body_sha256": hashlib.sha256(launch_body).hexdigest(),
            "rows": "15",
            "json": "0",
        }:
            fail("flowe_x3x3_launch_footer")

    parent_dir = ROOT / "matrix/timed-86400-parent-c8c3"
    for relative, expected_hash in TIMED_PARENT_86400_HASHES.items():
        parent_path = ROOT / relative
        if sha256(parent_path) != expected_hash:
            fail("timed_parent_86400_hash:" + parent_path.name)
        sidecar = parent_path.with_name(parent_path.name + ".sha256")
        expected_sidecar = f"{expected_hash}  {parent_path.name}\n"
        if sidecar.read_text(encoding="utf-8") != expected_sidecar:
            fail("timed_parent_86400_sidecar:" + sidecar.name)

    parent_source_path = ROOT / "matrix/PUBLIC-OWNER-MEDIA-POSITION-2D.hbp"
    parent_source_sha = sha256(parent_source_path)
    if parent_source_sha != (
        "c8c3a6ba428b393e52866224430f6748373054490fff4d6a530cc66848ff3310"
    ):
        fail("timed_parent_86400_source_immutability")

    parent_gguf_path = parent_dir / "TIMED-CHIRAL-PUBLIC-COLOR-ORBITS.gguf"
    parent_gguf = parent_gguf_path.read_bytes()
    if (
        len(parent_gguf) != 2200
        or verify_gguf(parent_gguf, parent_source_sha, 147, 86_400)
        != "6afb6229fd2fa23e2dc38c37a31ac9a035b9cddfea2b12bdae1470b03af4425a"
    ):
        fail("timed_parent_86400_gguf_contract")
    parent_inventory = parse_inventory(parent_source_path)
    if not parent_gguf.endswith(descriptor_bytes(parent_inventory)):
        fail("timed_parent_86400_descriptor_source_closure")

    expected_parent_checkpoints = (
        1, 2, 3, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048,
        4096, 8192, 16384, 32768, 65536, 86400,
    )
    parent_hbp_path = parent_dir / "TIMED-CHIRAL-MONITOR.hbp"
    parent_hbp_lines = parent_hbp_path.read_text(encoding="utf-8").splitlines()
    if len(parent_hbp_lines) != 22 or any(
        not line.endswith("|json=0") for line in parent_hbp_lines
    ):
        fail("timed_parent_86400_hbp_shape")
    parent_header = tuple_fields(parent_hbp_lines[0], "TIMEDCHIRALHDR")
    expected_parent_header = {
        "schema": "TIMED-CHIRAL-PUBLIC-GGUF-V1",
        "status": "COMPLETE",
        "elapsed_seconds": "86400",
        "target_seconds": "86400",
        "source_hbp_sha256": parent_source_sha,
        "public_records": "147",
        "center_membership": MATRIX_CENTER,
        "traversal": MATRIX_TRAVERSAL_ENCODED,
        "raw_source_rows": "0",
        "raw_repository_bytes": "0",
        "network": "0",
        "json": "0",
    }
    if parent_header != expected_parent_header:
        fail("timed_parent_86400_hbp_header")
    parent_outward_rows = [
        tuple_fields(line, "OUTWARD") for line in parent_hbp_lines[1:-2]
    ]
    if len(parent_outward_rows) != len(expected_parent_checkpoints):
        fail("timed_parent_86400_hbp_checkpoint_count")
    for index, (row, checkpoint) in enumerate(
        zip(parent_outward_rows, expected_parent_checkpoints)
    ):
        if row != {
            "index": str(index),
            "checkpoint_seconds": str(checkpoint),
            "direction": "SPHERICAL_OUTWARD",
            "chirality": "ALTERNATING",
            "calming_oils": "BROWN.NEAR.ONE",
            "source_hbp_sha256": parent_source_sha,
            "json": "0",
        }:
            fail("timed_parent_86400_hbp_checkpoint")
    if tuple_fields(parent_hbp_lines[-2], "GGUF") != {
        "state": "PRESENT",
        "file": parent_gguf_path.name,
        "sha256": sha256(parent_gguf_path),
        "descriptor_only": "1",
        "source_rows_embedded": "0",
        "repository_bytes_embedded": "0",
        "json": "0",
    }:
        fail("timed_parent_86400_hbp_gguf")
    parent_hbp_body = ("\n".join(parent_hbp_lines[:-1]) + "\n").encode("utf-8")
    parent_hbp_footer = tuple_fields(parent_hbp_lines[-1], "TIMEDCHIRALFTR")
    if parent_hbp_footer != {
        "body_sha256": hashlib.sha256(parent_hbp_body).hexdigest(),
        "rows": "22",
        "json": "0",
    }:
        fail("timed_parent_86400_hbp_footer")

    parent_hbi_path = parent_dir / "TIMED-CHIRAL-MONITOR.hbi"
    parent_hbi_lines = parent_hbi_path.read_text(encoding="utf-8").splitlines()
    if len(parent_hbi_lines) != 1 or tuple_fields(parent_hbi_lines[0], "HBI") != {
        "schema": "TIMED-CHIRAL-PUBLIC-GGUF-V1",
        "hbp_file": parent_hbp_path.name,
        "hbp_sha256": sha256(parent_hbp_path),
        "gguf_file": parent_gguf_path.name,
        "gguf_sha256": sha256(parent_gguf_path),
        "center_membership": MATRIX_CENTER,
        "traversal": MATRIX_TRAVERSAL_ENCODED,
        "raw_rows": "0",
        "authority_granted": "0",
        "json": "0",
    }:
        fail("timed_parent_86400_hbi_binding")

    parent_trace_path = parent_dir / "TIMED-CHIRAL-CHECKPOINTS.hbp"
    parent_trace_lines = parent_trace_path.read_text(encoding="utf-8").splitlines()
    expected_observed_seconds = list(expected_parent_checkpoints)
    expected_observed_seconds[-3] = 32769
    expected_observed_seconds[-2] = 65537
    if len(parent_trace_lines) != 20:
        fail("timed_parent_86400_trace_rows")
    for index, checkpoint in enumerate(expected_parent_checkpoints):
        row = tuple_fields(parent_trace_lines[index], "TIMEDCHIRALCHECKPOINT")
        final_checkpoint = index == len(expected_parent_checkpoints) - 1
        if row != {
            "scheduled_seconds": str(checkpoint),
            "observed_elapsed_seconds": str(expected_observed_seconds[index]),
            "status": "COMPLETE" if final_checkpoint else "RUNNING",
            "gguf_present": "1" if final_checkpoint else "0",
            "json": "0",
        }:
            fail("timed_parent_86400_trace_checkpoint")
    if parent_trace_lines[-1] != (
        "TIMED_CHIRAL_MONITOR|PASS=1|status=COMPLETE|json=0"
    ):
        fail("timed_parent_86400_trace_verdict")

    parent_actual_path = parent_dir / "LIRIS-TIMED-86400-ACTUAL-RUN.hbp"
    parent_actual_lines = parent_actual_path.read_text(encoding="utf-8").splitlines()
    if len(parent_actual_lines) != 13 or any(
        not line.endswith("|json=0") for line in parent_actual_lines
    ):
        fail("timed_parent_86400_actual_shape")
    if tuple_fields(parent_actual_lines[0], "LIRIS24HDR") != {
        "schema": "LIRIS-TIMED-CHIRAL-ACTUAL-RUN-V1",
        "evidence": "MEASURED_LIRIS_LOCAL",
        "status": "COMPLETE",
        "target_seconds": "86400",
        "json": "0",
    }:
        fail("timed_parent_86400_actual_header")
    parent_actual_source = tuple_fields(parent_actual_lines[1], "SOURCE")
    if parent_actual_source != {
        "file": parent_source_path.name,
        "bytes": "97491",
        "sha256": parent_source_sha,
        "sidecar_verified": "1",
        "json": "0",
    }:
        fail("timed_parent_86400_actual_source")
    expected_parent_artifacts = {
        "HBP": {
            "kind": "HBP", "file": parent_hbp_path.name, "bytes": "4607",
            "sha256": sha256(parent_hbp_path), "sidecar_verified": "1",
            "json": "0",
        },
        "HBI": {
            "kind": "HBI", "file": parent_hbi_path.name, "bytes": "392",
            "sha256": sha256(parent_hbi_path), "sidecar_verified": "1",
            "json": "0",
        },
        "GGUF": {
            "kind": "GGUF", "file": parent_gguf_path.name, "bytes": "2200",
            "sha256": sha256(parent_gguf_path), "sidecar_verified": "1",
            "descriptor_only": "1", "json": "0",
        },
    }
    parent_actual_artifacts = {
        row["kind"]: row
        for row in (
            tuple_fields(line, "ARTIFACT") for line in parent_actual_lines[2:5]
        )
    }
    if parent_actual_artifacts != expected_parent_artifacts:
        fail("timed_parent_86400_actual_artifacts")
    if tuple_fields(parent_actual_lines[5], "RAWTRACE") != {
        "surface": "LIRIS_LOCAL_ACTUAL",
        "bytes": "2160",
        "sha256": "a9f6a85366d64c38fb6af12b0baed62c64f385ebf5b05ebc2ba852cccf613cc0",
        "line_endings": "CRLF",
        "raw_bytes_published": "0",
        "json": "0",
    }:
        fail("timed_parent_86400_actual_raw_trace")
    if tuple_fields(parent_actual_lines[6], "TRACE") != {
        "file": parent_trace_path.name,
        "bytes": "2140",
        "sha256": sha256(parent_trace_path),
        "rows": "20",
        "checkpoints": "19",
        "normalization": "CRLF_TO_LF",
        "json": "0",
    }:
        fail("timed_parent_86400_actual_trace")
    parent_clock = tuple_fields(parent_actual_lines[7], "CLOCK")
    if (
        parent_clock.get("elapsed_receipt_seconds") != "86400"
        or parent_clock.get("clock") != "MONOTONIC"
        or parent_clock.get("json") != "0"
    ):
        fail("timed_parent_86400_actual_clock")
    parent_process = tuple_fields(parent_actual_lines[8], "PROCESS")
    if (
        parent_process.get("restart_recovery") != "0"
        or parent_process.get("continuous_process_identity_now") != "UNVERIFIED"
        or parent_process.get("json") != "0"
    ):
        fail("timed_parent_86400_actual_process_boundary")
    if tuple_fields(parent_actual_lines[9], "PARITY") != {
        "actual_final_group_files": "6",
        "deterministic_rebuild_files": "6",
        "byte_equal_files": "6",
        "byte_mismatch_files": "0",
        "json": "0",
    }:
        fail("timed_parent_86400_actual_parity")
    if tuple_fields(parent_actual_lines[10], "CENTER") != {
        "members": MATRIX_CENTER,
        "traversal": MATRIX_TRAVERSAL_ENCODED,
        "identity_exchange": "0",
        "json": "0",
    }:
        fail("timed_parent_86400_actual_center")
    if tuple_fields(parent_actual_lines[11], "BOUNDARY") != {
        "full_x3_x3": "0",
        "role": "VALID_PARENT_WITNESS",
        "network": "0",
        "raw_repository_bytes": "0",
        "execution_authority": "0",
        "system_affirmed": "0",
        "json": "0",
    }:
        fail("timed_parent_86400_actual_boundary")
    parent_actual_body = (
        "\n".join(parent_actual_lines[:-1]) + "\n"
    ).encode("utf-8")
    if tuple_fields(parent_actual_lines[-1], "LIRIS24FTR") != {
        "body_sha256": hashlib.sha256(parent_actual_body).hexdigest(),
        "rows": "13",
        "json": "0",
    }:
        fail("timed_parent_86400_actual_footer")

    outward_hbp_path = ROOT / "matrix/PUBLIC-OUTWARD-TRUTH-WAVES.hbp"
    outward_hbp_lines = outward_hbp_path.read_text(encoding="utf-8").splitlines()
    if len(outward_hbp_lines) != 1778 or any(
        not line.endswith("|json=0") for line in outward_hbp_lines
    ):
        fail("outward_hbp_row_contract")
    outward_header = tuple_fields(outward_hbp_lines[0], "OUTWARDRUN")
    expected_outward_header = {
        "schema": "ASOLARIA-PUBLIC-OUTWARD-TRUTH-WAVES-RUST-181-V1",
        "source_schema": "ASOLARIA-PUBLIC-OWNER-3D-TREE-V2",
        "repositories": "147",
        "waves": "1764",
        "detectors": "4",
        "directions": "3",
        "descriptor_width": "32",
        "json": "0",
    }
    if outward_header != expected_outward_header:
        fail("outward_hbp_header")
    outward_detectors = [
        tuple_fields(line, "DETECTOR")
        for line in outward_hbp_lines
        if line.startswith("DETECTOR|")
    ]
    expected_detector_names = {
        "BYTE_COMMITMENT",
        "CLAIM_EVIDENCE",
        "MEDIA_BINDING",
        "RUNTIME_AUTHORITY",
    }
    if (
        len(outward_detectors) != 4
        or {row["name"] for row in outward_detectors} != expected_detector_names
        or [int(row["i"]) for row in outward_detectors] != list(range(4))
        or any(
            row.get("catalog_only") != "1"
            or row.get("function_call_authority") != "0"
            or row.get("network") != "0"
            or row.get("execution") != "0"
            for row in outward_detectors
        )
    ):
        fail("outward_detector_contract")
    outward_wave_rows = [
        tuple_fields(line, "WAVE")
        for line in outward_hbp_lines
        if line.startswith("WAVE|")
    ]
    if len(outward_wave_rows) != 1764 or [
        int(row["i"]) for row in outward_wave_rows
    ] != list(range(1764)):
        fail("outward_wave_index")
    expected_directions = {"NEGATIVE", "CENTRE", "POSITIVE"}
    expected_evidence = {
        "MEASURED_MATCH",
        "OPERATOR_TAG_PRESERVED",
        "EXTENSION_METADATA_PRESENT",
        "NO_EXTENSION_MATCH_IN_CAPTURE",
        "SYSTEM_AFFIRMED_0",
    }
    outward_by_repo: dict[str, set[tuple[str, str]]] = {}
    for row in outward_wave_rows:
        outward_by_repo.setdefault(row["repo"], set()).add(
            (row["detector"], row["direction"])
        )
        hash_fields = [
            row[name] for name in ("wave_id", "hbi", "hbp", "sha", "sh", "hash")
        ]
        if (
            row["detector"] not in expected_detector_names
            or row["direction"] not in expected_directions
            or row["evidence_status"] not in expected_evidence
            or row.get("claim_label") != "LIE"
            or row.get("correction_label") != "THRUTH"
            or row.get("catalog_only") != "1"
            or row.get("function_call_authority") != "0"
            or row.get("network") != "0"
            or row.get("execution") != "0"
            or row.get("physical_energy") != "0"
            or row.get("identity_accusation") != "0"
            or row.get("quarantine_applied") != "0"
            or any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in hash_fields)
            or len(set(hash_fields[1:])) != 5
        ):
            fail("outward_wave_boundary")
    expected_addresses = {
        (detector, direction)
        for detector in expected_detector_names
        for direction in expected_directions
    }
    if len(outward_by_repo) != 147 or any(
        addresses != expected_addresses for addresses in outward_by_repo.values()
    ):
        fail("outward_four_by_three_population")
    outward_quarantine = next(
        (
            tuple_fields(line, "QUARANTINE")
            for line in outward_hbp_lines
            if line.startswith("QUARANTINE|")
        ),
        {},
    )
    if outward_quarantine != {
        "name": "BLACK_HEAT",
        "mode": "REVERSIBLE_VISUALIZATION_ONLY",
        "bytes_preserved": "1",
        "reversible": "1",
        "deletion": "0",
        "execution": "0",
        "physical_energy": "0",
        "identity_accusation": "0",
        "quarantine_applied": "0",
        "json": "0",
    }:
        fail("outward_reversible_quarantine")
    outward_hbp_body = ("\n".join(outward_hbp_lines[:-1]) + "\n").encode("utf-8")
    outward_hbp_footer = tuple_fields(outward_hbp_lines[-1], "OUTWARDFTR")
    if (
        outward_hbp_footer.get("body_sha256")
        != hashlib.sha256(outward_hbp_body).hexdigest()
        or outward_hbp_footer.get("rows") != "1778"
    ):
        fail("outward_hbp_footer")

    outward_hbi_path = ROOT / "matrix/PUBLIC-OUTWARD-TRUTH-WAVES.hbi"
    outward_hbi_lines = outward_hbi_path.read_text(encoding="utf-8").splitlines()
    outward_svg_path = ROOT / "matrix/PUBLIC-OUTWARD-TRUTH-WAVES.svg"
    outward_gguf_path = ROOT / "matrix/PUBLIC-OUTWARD-TRUTH-WAVES.gguf"
    if len(outward_hbi_lines) != 11 or any(
        not line.endswith("|json=0") for line in outward_hbi_lines
    ):
        fail("outward_hbi_row_contract")
    outward_hbi_text = "\n".join(outward_hbi_lines) + "\n"
    outward_hbi_source = tuple_fields(outward_hbi_lines[1], "SOURCE")
    if (
        outward_hbi_source.get("schema") != "ASOLARIA-PUBLIC-OWNER-3D-TREE-V2"
        or outward_hbi_source.get("sha256") != sha256(media_owner_path)
        or outward_hbi_source.get("sidecar_verified") != "1"
    ):
        fail("outward_hbi_source")
    outward_hbi_artifacts = {
        row["kind"]: row
        for row in (
            tuple_fields(line, "ARTIFACT")
            for line in outward_hbi_lines
            if line.startswith("ARTIFACT|")
        )
    }
    expected_outward_artifacts = {
        "HBP": outward_hbp_path,
        "SVG": outward_svg_path,
        "GGUF": outward_gguf_path,
    }
    if set(outward_hbi_artifacts) != set(expected_outward_artifacts) or any(
        outward_hbi_artifacts[kind].get("file") != path.name
        or outward_hbi_artifacts[kind].get("sha256") != sha256(path)
        for kind, path in expected_outward_artifacts.items()
    ):
        fail("outward_hbi_artifacts")
    for binding in (
        "shape=32,3,4,147",
        "descriptor_sha256=db3014e49b30cc43a2378348a11646d3d2345342733534c510f1ebdfb905c972",
        "media_bytes_embedded=0",
        "repo_bytes_embedded=0",
        "function_call_authority=0",
        "physical_energy=0",
        "quarantine_applied=0",
        "system_affirmed=0",
    ):
        if binding not in outward_hbi_text:
            fail("outward_hbi_binding")
    outward_hbi_body = ("\n".join(outward_hbi_lines[:-1]) + "\n").encode("utf-8")
    outward_hbi_footer = tuple_fields(outward_hbi_lines[-1], "OUTWARDIDXFTR")
    if (
        outward_hbi_footer.get("body_sha256")
        != hashlib.sha256(outward_hbi_body).hexdigest()
        or outward_hbi_footer.get("rows") != "11"
    ):
        fail("outward_hbi_footer")

    outward_svg = outward_svg_path.read_text(encoding="utf-8")
    if (
        outward_svg.count('id="repo-') != 147
        or outward_svg.count('data-detector="') != 1764
        or outward_svg.count('data-label="LIE"') != 1764
        or outward_svg.count('data-label="THRUTH"') != 1764
        or 'data-repositories="147"' not in outward_svg
        or 'data-waves="1764"' not in outward_svg
        or 'id="BLACK_HEAT_REVERSIBLE_VISUALIZATION" visibility="hidden"'
        not in outward_svg
        or 'data-bytes-preserved="1" data-reversible="1" data-deletion="0"'
        not in outward_svg
        or 'data-physical-energy="0" data-identity-accusation="0" data-quarantine-applied="0"'
        not in outward_svg
    ):
        fail("outward_svg_population_or_boundary")
    if any(
        token in outward_svg.lower()
        for token in (
            "<script", "<image", "<foreignobject", " href=", "url(", "<a ",
            "@import", "file:", "javascript:",
        )
    ):
        fail("outward_svg_active_content")
    outward_gguf = outward_gguf_path.read_bytes()
    if (
        len(outward_gguf) != 58560
        or not outward_gguf.startswith(b"GGUF\x03\x00\x00\x00")
        or sha256(outward_gguf_path)
        != "b315be52a4a6870d2eb15f44736dd29e30685bea6b0b16936e16abc9a809e9f6"
    ):
        fail("outward_gguf_contract")

    folder_source_hbp_path = ROOT / "matrix/PUBLIC-FOLDER-3D-TREE.hbp"
    folder_source_hbi_path = ROOT / "matrix/PUBLIC-FOLDER-3D-TREE.hbi"
    folder_source_hbp_bytes = folder_source_hbp_path.read_bytes()
    folder_source_hbi_bytes = folder_source_hbi_path.read_bytes()
    try:
        folder_source_info = verify_folder_source_hbp(folder_source_hbp_bytes)
        folder_source_hbi_info = verify_folder_source_hbi(
            folder_source_hbi_bytes,
            expected_hbp_sha256=hashlib.sha256(folder_source_hbp_bytes).hexdigest(),
        )
    except InventoryError:
        fail("folder_source_semantic_contract")
    if (
        folder_source_info["repositories"]
        != folder_source_hbi_info["repositories"]
        or folder_source_info["folders"] != folder_source_hbi_info["folders"]
    ):
        fail("folder_source_hbp_hbi_population")

    folder_source_lines = folder_source_hbp_bytes.decode("utf-8").splitlines()
    folder_source_header = tuple_fields(folder_source_lines[0], "FOLDER3DRUN")
    folder_repositories = int(folder_source_header["repositories"])
    folder_count = int(folder_source_header["folders"])
    folder_root_count = int(folder_source_header["root_nodes"])
    folder_tree_count = int(folder_source_header["tree_nodes"])
    folder_source_capture = folder_source_header["source_capture_sha256"]
    folder_public_set = folder_source_header["public_set_sha256"]
    if (
        folder_repositories != folder_source_info["repositories"]
        or folder_count != folder_source_info["folders"]
        or folder_root_count + folder_tree_count != folder_count
        or folder_source_header.get("surface") != "MEASURED_GITHUB_PUBLIC"
        or folder_source_header.get("public_metadata_only") != "1"
        or not re.fullmatch(r"[0-9a-f]{64}", folder_source_capture)
        or not re.fullmatch(r"[0-9a-f]{64}", folder_public_set)
    ):
        fail("folder_source_header_contract")
    folder_source_rows = [
        tuple_fields(line, "FOLDER") for line in folder_source_lines[4:-3]
    ]
    if len(folder_source_rows) != folder_count:
        fail("folder_source_row_population")

    if folder_oil_snapshot_present:
        folder_hbp_path = ROOT / "matrix/PUBLIC-FOLDER-CALMING-OILS.hbp"
        folder_hbi_path = ROOT / "matrix/PUBLIC-FOLDER-CALMING-OILS.hbi"
        folder_svg_path = ROOT / "matrix/PUBLIC-FOLDER-CALMING-OILS.svg"
        folder_gguf_path = ROOT / "matrix/PUBLIC-FOLDER-CALMING-OILS.gguf"
        folder_hbp_lines = folder_hbp_path.read_text(encoding="utf-8").splitlines()
        folder_leaf_count = folder_count * 3
        if len(folder_hbp_lines) != folder_leaf_count + 13 or any(
            not line.endswith("|json=0") for line in folder_hbp_lines
        ):
            fail("folder_oil_hbp_row_contract")
        folder_header = tuple_fields(folder_hbp_lines[0], "FOLDEROILRUN")
        if folder_header != {
            "schema": "ASOLARIA-PUBLIC-FOLDER-CALMING-OILS-RUST-181-V1",
            "source_schema": "ASOLARIA-PUBLIC-FOLDER-3D-TREE-V1",
            "repositories": str(folder_repositories),
            "folders": str(folder_count),
            "families": "3",
            "leaves": str(folder_leaf_count),
            "descriptor_width": "64",
            "json": "0",
        }:
            fail("folder_oil_hbp_header")
        folder_source_row = tuple_fields(folder_hbp_lines[1], "SOURCE")
        if folder_source_row != {
            "sha256": sha256(folder_source_hbp_path),
            "source_capture_sha256": folder_source_capture,
            "public_set_sha256": folder_public_set,
            "sidecar_verified": "1",
            "public_metadata_only": "1",
            "raw_paths": "0",
            "raw_bodies": "0",
            "git_tree_commitments": "1",
            "tree_sha1_recoverable": "0",
            "path_dictionary_resistance_claim": "0",
            "json": "0",
        }:
            fail("folder_oil_hbp_source")
        if folder_hbp_lines[2] != (
            "CENTER|nullspace=0|center_members=HBI,HBP,SHA,SH,HASH|"
            "traversal=HBI->HBP->SH->HASH->SHA|sha_equals_hash=0|"
            "brown_center=RGB.8B5A2B|close_to=1|json=0"
        ):
            fail("folder_oil_hbp_center")
        if folder_hbp_lines[3:6] != [
            "STAGE|i=0|name=FOLDER_HBP_TO_EXACT_INTEGER_3D|integer_only=1|float=0|json=0",
            "STAGE|i=1|name=THREE_INDEPENDENT_CALMING_OIL_FAMILIES|families=3|identity_exchange=0|json=0",
            "STAGE|i=2|name=SIGNED_STATIC_PROJECTION_AND_DESCRIPTOR_SEAL|formats=HBP,HBI,SVG,GGUF|json=0",
        ]:
            fail("folder_oil_hbp_stages")
        folder_boundary = tuple_fields(folder_hbp_lines[6], "BOUNDARY")
        if folder_boundary != {
            "paths_published": "0",
            "direct_path_hashes": "0",
            "raw_tree_sha1_published": "0",
            "git_tree_commitments": "1",
            "path_dictionary_resistance_claim": "0",
            "media_bodies_read": "0",
            "media_bytes_embedded": "0",
            "repository_bodies_read": "0",
            "repository_bytes_embedded": "0",
            "private_repo_rows": "0",
            "private_repo_names": "0",
            "credentials": "0",
            "network": "0",
            "execution": "0",
            "physical_energy": "0",
            "authority": "0",
            "system_affirmed": "0",
            "json": "0",
        }:
            fail("folder_oil_hbp_boundary")
        expected_folder_families = ("BROWN", "ANTI_BROWN", "ANTI_ANTI_BROWN")
        for family_index, family in enumerate(expected_folder_families):
            if tuple_fields(folder_hbp_lines[7 + family_index], "FAMILY") != {
                "i": str(family_index),
                "name": family,
                "independent_identity": "1",
                "calming_oil_label": "1",
                "physical_energy": "0",
                "authority": "0",
                "json": "0",
            }:
                fail("folder_oil_family_contract")

        folder_leaf_lines = folder_hbp_lines[10 : 10 + folder_leaf_count]
        folder_leaves = [tuple_fields(line, "OIL") for line in folder_leaf_lines]
        folder_leaf_ids: set[str] = set()
        folder_object_material = bytearray()
        hex_leaf_fields = (
            "repo_id",
            "folder_id",
            "parent_folder_id",
            "source_identity_sha256",
            "parent_identity_sha256",
            "leaf_id",
            "tree_commitment_sha256",
            "object_sha256",
            "hbi",
            "hbp",
            "sh",
            "hash",
            "sha",
        )
        zero_leaf_fields = (
            "path_bytes_embedded",
            "media_bytes_embedded",
            "repository_bytes_embedded",
            "credentials",
            "network",
            "execution",
            "physical_energy",
            "authority",
        )
        for index, leaf in enumerate(folder_leaves):
            folder_index, family_index = divmod(index, 3)
            source_folder = folder_source_rows[folder_index]
            if (
                leaf.get("i") != str(index)
                or leaf.get("folder_i") != str(folder_index)
                or leaf.get("family") != expected_folder_families[family_index]
                or any(not re.fullmatch(r"[0-9a-f]{64}", leaf.get(key, "")) for key in hex_leaf_fields)
                or any(leaf.get(key) != "0" for key in zero_leaf_fields)
                or len({leaf[key] for key in ("hbi", "hbp", "sh", "hash", "sha")}) != 5
                or leaf.get("color", "")[:4] != "RGB."
                or re.fullmatch(r"RGB\.[0-9A-F]{6}", leaf.get("color", "")) is None
            ):
                fail("folder_oil_leaf_boundary")
            for field in (
                "repo_id",
                "folder_id",
                "parent_folder_id",
                "sibling_ordinal",
                "level",
                "tree_commitment_sha256",
                "source_kind",
                "direct_blobs",
                "direct_trees",
                "direct_commits",
                "direct_symlinks",
                "object_sha256",
            ):
                if leaf.get(field) != source_folder.get(field):
                    fail("folder_oil_source_identity")
            if leaf["leaf_id"] in folder_leaf_ids:
                fail("folder_oil_leaf_identity")
            folder_leaf_ids.add(leaf["leaf_id"])
            encoded_leaf = folder_leaf_lines[index].encode("utf-8")
            folder_object_material += len(encoded_leaf).to_bytes(8, "big")
            folder_object_material += encoded_leaf
        folder_object_hash = hashlib.sha256(folder_object_material).hexdigest()
        folder_hash_row = tuple_fields(folder_hbp_lines[-3], "HASH")
        if folder_hash_row != {
            "role": "SPHERICAL_FOLDER_OIL_OBJECT_COMMITMENT",
            "algorithm": "SHA256",
            "value": folder_object_hash,
            "distinct_from_hbp_byte_sha": "1",
            "json": "0",
        }:
            fail("folder_oil_object_commitment")
        folder_summary = tuple_fields(folder_hbp_lines[-2], "SUMMARY")
        if folder_summary != {
            "repositories": str(folder_repositories),
            "folders": str(folder_count),
            "families": "3",
            "leaves": str(folder_leaf_count),
            "path_bytes_embedded": "0",
            "media_bytes_embedded": "0",
            "repository_bytes_embedded": "0",
            "credentials": "0",
            "network": "0",
            "execution": "0",
            "physical_energy": "0",
            "authority": "0",
            "json": "0",
        }:
            fail("folder_oil_summary")
        folder_hbp_body = ("\n".join(folder_hbp_lines[:-1]) + "\n").encode("utf-8")
        folder_footer = tuple_fields(folder_hbp_lines[-1], "FOLDEROILFTR")
        if folder_footer != {
            "body_sha256": hashlib.sha256(folder_hbp_body).hexdigest(),
            "rows": str(len(folder_hbp_lines)),
            "json": "0",
        }:
            fail("folder_oil_hbp_footer")

        folder_hbi_lines = folder_hbi_path.read_text(encoding="utf-8").splitlines()
        if len(folder_hbi_lines) != 9 or any(
            not line.endswith("|json=0") for line in folder_hbi_lines
        ):
            fail("folder_oil_hbi_row_contract")
        if tuple_fields(folder_hbi_lines[0], "FOLDEROILIDX") != {
            "schema": "ASOLARIA-PUBLIC-FOLDER-CALMING-OILS-RUST-181-V1",
            "repositories": str(folder_repositories),
            "folders": str(folder_count),
            "families": "3",
            "leaves": str(folder_leaf_count),
            "json": "0",
        }:
            fail("folder_oil_hbi_header")
        if tuple_fields(folder_hbi_lines[1], "SOURCE") != {
            "schema": "ASOLARIA-PUBLIC-FOLDER-3D-TREE-V1",
            "sha256": sha256(folder_source_hbp_path),
            "source_capture_sha256": folder_source_capture,
            "public_set_sha256": folder_public_set,
            "sidecar_verified": "1",
            "git_tree_commitments": "1",
            "tree_sha1_recoverable": "0",
            "path_dictionary_resistance_claim": "0",
            "json": "0",
        }:
            fail("folder_oil_hbi_source")
        folder_hbi_artifacts = {
            row["kind"]: row
            for row in (
                tuple_fields(line, "ARTIFACT") for line in folder_hbi_lines[2:5]
            )
        }
        if folder_hbi_artifacts.get("HBP") != {
            "kind": "HBP",
            "file": folder_hbp_path.name,
            "sha256": sha256(folder_hbp_path),
            "json": "0",
        }:
            fail("folder_oil_hbi_hbp")
        if folder_hbi_artifacts.get("SVG") != {
            "kind": "SVG",
            "file": folder_svg_path.name,
            "sha256": sha256(folder_svg_path),
            "static": "1",
            "script": "0",
            "network": "0",
            "execution": "0",
            "json": "0",
        }:
            fail("folder_oil_hbi_svg")
        folder_gguf_artifact = folder_hbi_artifacts.get("GGUF", {})
        if folder_gguf_artifact != {
            "kind": "GGUF",
            "file": folder_gguf_path.name,
            "sha256": sha256(folder_gguf_path),
            "tensor": "folder_calming_oil",
            "dimensions": f"feature:64,family:3,folder:{folder_count}",
            "iteration_order": "folder,family,feature",
            "encoding": "RAW_OCTETS_IN_GGML_I8",
            "descriptor_sha256": folder_gguf_artifact.get("descriptor_sha256"),
            "json": "0",
        } or re.fullmatch(
            r"[0-9a-f]{64}", folder_gguf_artifact.get("descriptor_sha256", "")
        ) is None:
            fail("folder_oil_hbi_gguf")
        if tuple_fields(folder_hbi_lines[5], "CENTER") != {
            "nullspace": "0",
            "center_members": "HBI,HBP,SHA,SH,HASH",
            "traversal": "HBI->HBP->SH->HASH->SHA",
            "sha_equals_hash": "0",
            "object_hash": folder_object_hash,
            "json": "0",
        }:
            fail("folder_oil_hbi_center")
        if tuple_fields(folder_hbi_lines[6], "BOUNDARY") != {
            "raw_paths": "0",
            "direct_path_hashes": "0",
            "raw_tree_sha1": "0",
            "git_tree_commitments": "1",
            "path_dictionary_resistance_claim": "0",
            "media_bytes_embedded": "0",
            "repository_bytes_embedded": "0",
            "credentials": "0",
            "network": "0",
            "execution": "0",
            "physical_energy": "0",
            "authority": "0",
            "system_affirmed": "0",
            "json": "0",
        }:
            fail("folder_oil_hbi_boundary")
        if tuple_fields(folder_hbi_lines[7], "RECIPE") != {
            "sh": "FOLDER_CALMING_OILS_RUST_181_V1",
            "rust": "1.81.0",
            "integer_only": "1",
            "float": "0",
            "unsafe": "0",
            "dependencies": "0",
            "final_commit_marker": "HBI_WITH_SIDECAR",
            "json": "0",
        }:
            fail("folder_oil_hbi_recipe")
        folder_hbi_body = ("\n".join(folder_hbi_lines[:-1]) + "\n").encode("utf-8")
        if tuple_fields(folder_hbi_lines[-1], "FOLDEROILIDXFTR") != {
            "body_sha256": hashlib.sha256(folder_hbi_body).hexdigest(),
            "rows": "9",
            "json": "0",
        }:
            fail("folder_oil_hbi_footer")

        folder_svg = folder_svg_path.read_text(encoding="utf-8")
        if (
            folder_svg.count('id="folder-') != folder_count
            or folder_svg.count('class="folder-hierarchy"') != folder_tree_count
            or folder_svg.count('class="folder-calming-oil"') != folder_leaf_count
            or any(
                folder_svg.count(f'data-family="{family}"') != folder_count
                for family in expected_folder_families
            )
            or f"repositories={folder_repositories};folders={folder_count};families=3;leaves={folder_leaf_count};"
            not in folder_svg
            or f"object_hash={folder_object_hash};" not in folder_svg
            or "paths=0;media_bytes=0;repo_bytes=0;credentials=0;network=0;execution=0;physical_energy=0;authority=0;SYSTEM_AFFIRMED=0;json=0"
            not in folder_svg
        ):
            fail("folder_oil_svg_population_or_boundary")
        if set(re.findall(r'id="oil-([0-9a-f]{16})"', folder_svg)) != {
            leaf_id[:16] for leaf_id in folder_leaf_ids
        }:
            fail("folder_oil_svg_leaf_identity")
        if any(
            token in folder_svg.lower()
            for token in (
                "<script", "<image", "<foreignobject", "<iframe", "<object",
                "<embed", "<use", " href=", "xlink:", "url(", "javascript:",
                " onload=", " onclick=", "@import", "file:",
            )
        ):
            fail("folder_oil_svg_active_content")
        folder_svg_lower = folder_svg.lower()
        if any(
            token in folder_svg_lower
            for token in (
                "<!doctype", "<!entity", "<?xml-stylesheet", "<![cdata[",
                "xmlns:",
            )
        ):
            fail("folder_oil_svg_declaration")
        try:
            folder_svg_root = ET.fromstring(folder_svg)
        except ET.ParseError:
            fail("folder_oil_svg_xml")
        svg_namespace = "{http://www.w3.org/2000/svg}"
        svg_allowed_attributes = {
            "svg": {
                "width", "height", "viewBox", "role", "aria-labelledby",
                "data-script", "data-network", "data-execution",
            },
            "title": {"id"},
            "desc": {"id"},
            "rect": {"x", "y", "width", "height", "fill"},
            "metadata": set(),
            "g": {"id", "data-folder-i", "data-repo-id", "data-level"},
            "path": {
                "id", "class", "d", "fill", "stroke", "stroke-width",
                "data-child", "data-parent", "data-family", "data-folder-id",
                "data-source-identity-sha256", "data-view-x", "data-view-y",
                "data-view-z", "data-authority",
            },
        }
        svg_elements = list(folder_svg_root.iter())
        for element in svg_elements:
            if not element.tag.startswith(svg_namespace):
                fail("folder_oil_svg_namespace")
            local_tag = element.tag[len(svg_namespace):]
            allowed = svg_allowed_attributes.get(local_tag)
            if allowed is None or set(element.attrib) - allowed:
                fail("folder_oil_svg_element_or_attribute")
            for name, value in element.attrib.items():
                lowered_name = name.lower()
                lowered_value = value.lower()
                if (
                    lowered_name.startswith("on")
                    or lowered_name in {"href", "xlink:href", "style"}
                    or any(
                        token in lowered_value
                        for token in ("url(", "javascript:", "data:", "file:")
                    )
                ):
                    fail("folder_oil_svg_external_or_active_attribute")
        if folder_svg_root.tag != svg_namespace + "svg" or folder_svg_root.attrib != {
            "width": "2000",
            "height": "2000",
            "viewBox": "0 0 2000 2000",
            "role": "img",
            "aria-labelledby": "title description",
            "data-script": "0",
            "data-network": "0",
            "data-execution": "0",
        }:
            fail("folder_oil_svg_root")
        root_children = list(folder_svg_root)
        if [child.tag for child in root_children] != [
            svg_namespace + "title",
            svg_namespace + "desc",
            svg_namespace + "rect",
            svg_namespace + "metadata",
            svg_namespace + "g",
        ]:
            fail("folder_oil_svg_root_children")
        if (
            root_children[0].attrib != {"id": "title"}
            or root_children[1].attrib != {"id": "description"}
            or root_children[2].attrib
            != {"x": "0", "y": "0", "width": "2000", "height": "2000", "fill": "#100E14"}
            or root_children[3].attrib
            or root_children[4].attrib != {"id": "FOLDER_CALMING_OILS_3D_TO_2D"}
        ):
            fail("folder_oil_svg_static_scaffold")
        folder_svg_graph = root_children[4]
        hierarchy_elements = [
            element
            for element in folder_svg_graph
            if element.tag == svg_namespace + "path"
            and element.attrib.get("class") == "folder-hierarchy"
        ]
        folder_group_elements = [
            element
            for element in folder_svg_graph
            if element.tag == svg_namespace + "g"
        ]
        if len(hierarchy_elements) != folder_tree_count or len(folder_group_elements) != folder_count:
            fail("folder_oil_svg_graph_population")
        if list(folder_svg_graph) != hierarchy_elements + folder_group_elements:
            fail("folder_oil_svg_graph_order_or_tag")
        expected_hierarchy = {
            (folder["folder_id"], folder["parent_folder_id"])
            for folder in folder_source_rows
            if folder["source_kind"] == "GIT_TREE"
        }
        actual_hierarchy: set[tuple[str, str]] = set()
        hierarchy_path_re = re.compile(r"M [0-9]+ [0-9]+ L [0-9]+ [0-9]+")
        for element in hierarchy_elements:
            attrs = element.attrib
            child = attrs.get("data-child", "")
            parent = attrs.get("data-parent", "")
            if (
                set(attrs) != {"class", "d", "fill", "stroke", "stroke-width", "data-child", "data-parent"}
                or attrs.get("fill") != "none"
                or attrs.get("stroke") != "#5B4636"
                or attrs.get("stroke-width") != "1"
                or hierarchy_path_re.fullmatch(attrs.get("d", "")) is None
                or re.fullmatch(r"[0-9a-f]{64}", child) is None
                or re.fullmatch(r"[0-9a-f]{64}", parent) is None
            ):
                fail("folder_oil_svg_hierarchy_shape")
            actual_hierarchy.add((child, parent))
        if actual_hierarchy != expected_hierarchy:
            fail("folder_oil_svg_hierarchy_identity")
        oil_elements: list[ET.Element] = []
        for folder_index, group in enumerate(folder_group_elements):
            source_folder = folder_source_rows[folder_index]
            expected_group = {
                "id": "folder-" + source_folder["folder_id"][:16],
                "data-folder-i": str(folder_index),
                "data-repo-id": source_folder["repo_id"],
                "data-level": source_folder["level"],
            }
            if group.attrib != expected_group:
                fail("folder_oil_svg_folder_group")
            children = list(group)
            if len(children) != 3 or any(
                child.tag != svg_namespace + "path" for child in children
            ):
                fail("folder_oil_svg_folder_children")
            oil_elements.extend(children)
        if len(oil_elements) != folder_leaf_count:
            fail("folder_oil_svg_oil_population")
        oil_path_re = re.compile(r"M [0-9]+ [0-9]+ L [0-9]+ [0-9]+ L [0-9]+ [0-9]+ Z")
        for leaf, element in zip(folder_leaves, oil_elements):
            attrs = element.attrib
            if (
                set(attrs)
                != {
                    "id", "class", "d", "fill", "stroke", "stroke-width",
                    "data-family", "data-folder-id", "data-source-identity-sha256",
                    "data-view-x", "data-view-y", "data-view-z", "data-authority",
                }
                or attrs.get("id") != "oil-" + leaf["leaf_id"][:16]
                or attrs.get("class") != "folder-calming-oil"
                or oil_path_re.fullmatch(attrs.get("d", "")) is None
                or attrs.get("fill") != "#" + leaf["color"][4:]
                or attrs.get("stroke") != "#F4F1E8"
                or attrs.get("stroke-width") != "1"
                or attrs.get("data-family") != leaf["family"]
                or attrs.get("data-folder-id") != leaf["folder_id"]
                or attrs.get("data-source-identity-sha256")
                != leaf["source_identity_sha256"]
                or attrs.get("data-view-x") != leaf["view_x"]
                or attrs.get("data-view-y") != leaf["view_y"]
                or attrs.get("data-view-z") != leaf["view_z"]
                or attrs.get("data-authority") != "0"
            ):
                fail("folder_oil_svg_oil_identity")

        folder_gguf = folder_gguf_path.read_bytes()
        folder_gguf_position = 0

        def folder_gguf_take(length: int) -> bytes:
            nonlocal folder_gguf_position
            end = folder_gguf_position + length
            if length < 0 or end > len(folder_gguf):
                fail("folder_oil_gguf_bounds")
            result = folder_gguf[folder_gguf_position:end]
            folder_gguf_position = end
            return result

        def folder_gguf_u32() -> int:
            return struct.unpack("<I", folder_gguf_take(4))[0]

        def folder_gguf_u64() -> int:
            return struct.unpack("<Q", folder_gguf_take(8))[0]

        def folder_gguf_string() -> str:
            length = folder_gguf_u64()
            if length > len(folder_gguf):
                fail("folder_oil_gguf_string")
            try:
                return folder_gguf_take(length).decode("utf-8")
            except UnicodeError:
                fail("folder_oil_gguf_utf8")
            raise AssertionError("unreachable")

        if (
            folder_gguf_u32() != 0x46554747
            or folder_gguf_u32() != 3
            or folder_gguf_u64() != 1
        ):
            fail("folder_oil_gguf_header")
        folder_gguf_metadata_count = folder_gguf_u64()
        if folder_gguf_metadata_count > 64:
            fail("folder_oil_gguf_metadata_count")
        folder_gguf_metadata: dict[str, object] = {}
        for _ in range(folder_gguf_metadata_count):
            key = folder_gguf_string()
            value_type = folder_gguf_u32()
            if value_type == 4:
                value: object = folder_gguf_u32()
            elif value_type == 8:
                value = folder_gguf_string()
            elif value_type == 10:
                value = folder_gguf_u64()
            else:
                fail("folder_oil_gguf_metadata_type")
            if key in folder_gguf_metadata:
                fail("folder_oil_gguf_metadata_duplicate")
            folder_gguf_metadata[key] = value
        folder_expected_metadata: dict[str, object] = {
            "general.architecture": "asolaria-public-folder-calming-oils",
            "general.name": "PUBLIC-FOLDER-CALMING-OILS",
            "general.alignment": 32,
            "asolaria.schema": "ASOLARIA-PUBLIC-FOLDER-CALMING-OILS-RUST-181-V1",
            "asolaria.payload.kind": "DERIVED_PUBLIC_FOLDER_CALMING_OIL_DESCRIPTOR",
            "asolaria.source.schema": "ASOLARIA-PUBLIC-FOLDER-3D-TREE-V1",
            "asolaria.source.sha256": sha256(folder_source_hbp_path),
            "asolaria.source.capture_sha256": folder_source_capture,
            "asolaria.source.public_set_sha256": folder_public_set,
            "asolaria.repositories": folder_repositories,
            "asolaria.folders": folder_count,
            "asolaria.families": 3,
            "asolaria.descriptor.width": 64,
            "asolaria.tensor.dimensions": f"[feature=64,family=3,folder={folder_count}]",
            "asolaria.descriptor.iteration_order": "folder,family,feature",
            "asolaria.descriptor.encoding": "RAW_OCTETS_IN_GGML_I8",
            "asolaria.descriptor.features": "0:family_u8,1:source_kind_u8,2:level_u16le,4:rgb_u8x3,7:active_zero,8:projected_u_i32le,12:projected_v_i32le,16:direct_blobs_u32le,20:direct_trees_u32le,24:direct_commits_u32le,28:direct_symlinks_u32le,32:tree_commitment_prefix8,40:object_prefix8,48:leaf_prefix8,56:folder_index_u32le,60:sibling_ordinal_u32le",
            "asolaria.descriptor.sha256": folder_gguf_artifact["descriptor_sha256"],
            "asolaria.families.names": "BROWN,ANTI_BROWN,ANTI_ANTI_BROWN",
            "asolaria.git_tree_commitments": 1,
            "asolaria.path_dictionary_resistance_claim": 0,
            "asolaria.path.bytes_embedded": 0,
            "asolaria.media.bytes_embedded": 0,
            "asolaria.repository.bytes_embedded": 0,
            "asolaria.credentials": 0,
            "asolaria.network": 0,
            "asolaria.execution": 0,
            "asolaria.physical_energy": 0,
            "asolaria.authority": 0,
            "asolaria.function_call_authority": 0,
            "asolaria.system_affirmed": 0,
        }
        if folder_gguf_metadata != folder_expected_metadata:
            fail("folder_oil_gguf_metadata")
        if folder_gguf_string() != "folder_calming_oil" or folder_gguf_u32() != 3:
            fail("folder_oil_gguf_tensor")
        if (
            [folder_gguf_u64(), folder_gguf_u64(), folder_gguf_u64()]
            != [64, 3, folder_count]
            or folder_gguf_u32() != 24
            or folder_gguf_u64() != 0
        ):
            fail("folder_oil_gguf_tensor")
        folder_gguf_data_start = (folder_gguf_position + 31) // 32 * 32
        if (
            any(folder_gguf[folder_gguf_position:folder_gguf_data_start])
            or folder_gguf_data_start > len(folder_gguf)
        ):
            fail("folder_oil_gguf_alignment")
        folder_descriptor = folder_gguf[folder_gguf_data_start:]
        if (
            len(folder_descriptor) != folder_leaf_count * 64
            or hashlib.sha256(folder_descriptor).hexdigest()
            != folder_gguf_artifact["descriptor_sha256"]
        ):
            fail("folder_oil_gguf_descriptor")
        for index, leaf in enumerate(folder_leaves):
            descriptor = folder_descriptor[index * 64 : (index + 1) * 64]
            family_index = index % 3
            source_kind = 0 if leaf["source_kind"] == "REPOSITORY_ROOT" else 1
            color = bytes.fromhex(leaf["color"][4:])
            if (
                descriptor[0] != family_index
                or descriptor[1] != source_kind
                or int.from_bytes(descriptor[2:4], "little") != int(leaf["level"])
                or descriptor[4:7] != color
                or descriptor[7] != 0
                or int.from_bytes(descriptor[8:12], "little", signed=True)
                != int(leaf["projected_u"])
                or int.from_bytes(descriptor[12:16], "little", signed=True)
                != int(leaf["projected_v"])
                or int.from_bytes(descriptor[16:20], "little") != int(leaf["direct_blobs"])
                or int.from_bytes(descriptor[20:24], "little") != int(leaf["direct_trees"])
                or int.from_bytes(descriptor[24:28], "little") != int(leaf["direct_commits"])
                or int.from_bytes(descriptor[28:32], "little") != int(leaf["direct_symlinks"])
                or descriptor[32:40] != bytes.fromhex(leaf["tree_commitment_sha256"][:16])
                or descriptor[40:48] != bytes.fromhex(leaf["object_sha256"][:16])
                or descriptor[48:56] != bytes.fromhex(leaf["leaf_id"][:16])
                or int.from_bytes(descriptor[56:60], "little") != int(leaf["folder_i"])
                or int.from_bytes(descriptor[60:64], "little")
                != int(leaf["sibling_ordinal"])
            ):
                fail("folder_oil_gguf_descriptor_row")

    video_paths = [
        path.relative_to(ROOT).as_posix()
        for path in files
        if path.suffix.lower() in VIDEO_SUFFIXES
    ]
    if video_paths:
        fail("source_video_present:" + ",".join(video_paths))

    secret_hits = []
    for path in files:
        data = path.read_bytes()
        for name, pattern in SECRET_PATTERNS.items():
            if pattern.search(data):
                secret_hits.append(f"{name}:{path.relative_to(ROOT).as_posix()}")
    if secret_hits:
        fail("secret_signature:" + ",".join(secret_hits))

    private_github_metadata_hits = []
    private_github_metadata_tokens = (
        b"owner_visible_" + b"repositories=",
        b"private_" + b"repositories=",
    )
    for path in files:
        data = path.read_bytes()
        if any(token in data for token in private_github_metadata_tokens):
            private_github_metadata_hits.append(path.relative_to(ROOT).as_posix())
    if private_github_metadata_hits:
        fail(
            "private_github_metadata:"
            + ",".join(private_github_metadata_hits)
        )

    receipts = sorted(ROOT.rglob("*.hbp"))
    if not receipts:
        fail("no_hbp_receipts")
    for receipt in receipts:
        lines = receipt.read_text(encoding="utf-8").splitlines()
        if not lines or any(line.lstrip().startswith(("{", "[")) for line in lines):
            fail(f"receipt_not_json0:{receipt.name}")
        sidecar = receipt.with_name(receipt.name + ".sha256")
        if not sidecar.is_file():
            fail(f"receipt_sidecar_missing:{receipt.name}")
        fields = sidecar.read_text(encoding="utf-8").strip().split()
        if len(fields) != 2 or fields[1] != receipt.name:
            fail(f"receipt_sidecar_shape:{sidecar.name}")
        if fields[0].lower() != sha256(receipt):
            fail(f"receipt_sidecar_mismatch:{sidecar.name}")

    ggufs = sorted(ROOT.rglob("*.gguf"))
    for gguf in ggufs:
        sidecar = gguf.with_name(gguf.name + ".sha256")
        if not sidecar.is_file():
            fail(f"gguf_sidecar_missing:{gguf.name}")
        fields = sidecar.read_text(encoding="utf-8").strip().split()
        if len(fields) != 2 or fields[1] != gguf.name:
            fail(f"gguf_sidecar_shape:{sidecar.name}")
        if fields[0].lower() != sha256(gguf):
            fail(f"gguf_sidecar_mismatch:{sidecar.name}")

    pinned_manifest = ROOT / "hashes" / "PINNED-SOURCES.sha256"
    named_sidecars = sorted(
        path for path in ROOT.rglob("*.sha256")
        if path != pinned_manifest
        and ".git" not in path.relative_to(ROOT).parts
    )
    for sidecar in named_sidecars:
        target = Path(str(sidecar)[:-len(".sha256")])
        if not target.is_file():
            fail(
                "named_sidecar_target_missing:"
                + sidecar.relative_to(ROOT).as_posix()
            )
        fields = sidecar.read_text(encoding="utf-8").strip().split()
        if len(fields) != 2 or fields[1] != target.name:
            fail(
                "named_sidecar_shape:"
                + sidecar.relative_to(ROOT).as_posix()
            )
        if fields[0].lower() != sha256(target):
            fail(
                "named_sidecar_mismatch:"
                + sidecar.relative_to(ROOT).as_posix()
            )

    contract_locations = [
        ROOT / "README.md",
        ROOT / "AGENTS.md",
        ROOT / "knowledge/BOOK-OF-KNOWLEDGE.md",
        ROOT / "knowledge/PUBLIC-DEPENDENCIES.md",
        ROOT / "receipts/LIRIS-PUBLIC-SCAFFOLD-2026-07-29.hbp",
    ]
    for path in contract_locations:
        if "REQUIRED_HIDDEN_DEPENDENCIES=0" not in path.read_text(encoding="utf-8"):
            fail(f"missing_zero_hidden_contract:{path.relative_to(ROOT).as_posix()}")

    manifest_lines = [
        line for line in pinned_manifest.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(manifest_lines) != len(EXPECTED):
        fail("pinned_manifest_count_mismatch")

    print(
        "PUBLIC_REPO_VERIFY|PASS=1"
        f"|files={len(files)}"
        f"|pinned={len(EXPECTED)}"
        f"|receipts={len(receipts)}"
        f"|named_sidecars={len(named_sidecars)}"
        f"|workflow_pins={len(WORKFLOW_ACTION_PINS)}"
        f"|compact_final_structural={int(compact_final_witness_present)}"
        f"|compact_final_required={int(compact_final_required)}"
        "|compact_final_independent_time_attestation=0"
        "|source_video_bytes=0"
        "|secret_findings=0"
        "|default_binding_contradictions=0"
        "|REQUIRED_HIDDEN_DEPENDENCIES=0"
    )


if __name__ == "__main__":
    main()
