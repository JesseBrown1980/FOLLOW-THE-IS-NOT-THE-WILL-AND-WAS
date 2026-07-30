#!/usr/bin/env python3
"""Verify the public-slice contract without external packages."""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
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
MATRIX_PRIMARY = (
    "matrix/3-D-GITHUB-OF-THRUTH.md",
    "matrix/build_3d_github_harness.py",
    "matrix/collect_public_owner_inventory.py",
    "matrix/GITHUB-THREE-DIMENSIONALLY-RIMED-2026-07-29.hbp",
    "matrix/owner3d_to_public2d.py",
    "matrix/PUBLIC-OWNER-3D-TREE.hbp",
    "matrix/PUBLIC-OWNER-3D-TREE.hbi",
    "matrix/PUBLIC-OWNER-3D-MEDIA-TREE.hbp",
    "matrix/PUBLIC-OWNER-3D-MEDIA-TREE.hbi",
    "matrix/PUBLIC-OWNER-MEDIA-POSITION-2D.hbp",
    "matrix/PUBLIC-OWNER-2D.hbp",
    "matrix/PUBLIC-QPRISM-COLOR-LEAVES.hbp",
    "matrix/PUBLIC-QPRISM-COLOR-LEAVES.svg",
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
    "matrix/rust-qprism-181/src/outward.rs",
    "matrix/rust-qprism-181/src/bin/outward-truth-waves.rs",
    "matrix/rust-qprism-181/src/main.rs",
    "matrix/spherical_public_projection.py",
    "matrix/SPHERICAL-PUBLIC-PROJECTION.md",
    "matrix/test_owner3d_to_public2d.py",
    "matrix/test_render_public_spherical_svg.py",
    "matrix/test_spherical_public_projection.py",
    "matrix/test_timed_chiral_gguf_monitor.py",
    "matrix/TIMED-CHIRAL-MONITOR.hbi",
    "matrix/TIMED-CHIRAL-MONITOR.hbp",
    "matrix/TIMED-CHIRAL-PUBLIC-COLOR-ORBITS.gguf",
    "matrix/timed_chiral_gguf_monitor.py",
    "matrix/verify_3d_github_harness.py",
)
MATRIX_CENTER = "HBI,HBP,SHA,SH,HASH"
MATRIX_TRAVERSAL_ENCODED = "HBI-%3EHBP-%3ESH-%3EHASH-%3ESHA"
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
    ):
        if rust_binding not in workflow_text:
            fail("workflow_rust_181_binding_missing")

    for relative in MATRIX_PRIMARY:
        path = ROOT / relative
        if not path.is_file():
            fail("missing_matrix_primary:" + relative)
        sidecar = path.with_name(path.name + ".sha256")
        if not sidecar.is_file():
            fail("missing_matrix_primary_sidecar:" + relative)

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

    qprism_path = ROOT / "matrix/PUBLIC-QPRISM-COLOR-LEAVES.hbp"
    qprism_lines = qprism_path.read_text(encoding="utf-8").splitlines()
    if len(qprism_lines) != 447:
        fail("qprism_row_count")
    if any("|json=0" not in line for line in qprism_lines):
        fail("qprism_json0_missing")

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
    from spherical_public_projection import parse_inventory  # noqa: PLC0415
    from timed_chiral_gguf_monitor import (  # noqa: PLC0415
        TARGET_SECONDS,
        descriptor_bytes,
        verify_gguf,
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
        "|source_video_bytes=0"
        "|secret_findings=0"
        "|default_binding_contradictions=0"
        "|REQUIRED_HIDDEN_DEPENDENCIES=0"
    )


if __name__ == "__main__":
    main()
