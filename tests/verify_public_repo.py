#!/usr/bin/env python3
"""Verify the public-slice contract without external packages."""

from __future__ import annotations

import hashlib
import re
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
    "matrix/PUBLIC-OWNER-2D.hbp",
    "matrix/PUBLIC-QPRISM-COLOR-LEAVES.hbp",
    "matrix/PUBLIC-QPRISM-COLOR-LEAVES.svg",
    "matrix/PUBLIC-SPHERICAL-PROJECTION.hbp",
    "matrix/PUBLIC-SPHERICAL-PROJECTION.svg",
    "matrix/README.md",
    "matrix/render_public_spherical_svg.py",
    "matrix/rust-qprism-181/Cargo.lock",
    "matrix/rust-qprism-181/Cargo.toml",
    "matrix/rust-qprism-181/README.md",
    "matrix/rust-qprism-181/rust-toolchain.toml",
    "matrix/rust-qprism-181/src/lib.rs",
    "matrix/rust-qprism-181/src/main.rs",
    "matrix/spherical_public_projection.py",
    "matrix/SPHERICAL-PUBLIC-PROJECTION.md",
    "matrix/test_owner3d_to_public2d.py",
    "matrix/test_render_public_spherical_svg.py",
    "matrix/test_spherical_public_projection.py",
    "matrix/test_timed_chiral_gguf_monitor.py",
    "matrix/timed_chiral_gguf_monitor.py",
    "matrix/verify_3d_github_harness.py",
)
MATRIX_CENTER = "HBI,HBP,SHA,SH,HASH"
MATRIX_TRAVERSAL_ENCODED = "HBI-%3EHBP-%3ESH-%3EHASH-%3ESHA"


def repo_files() -> list[Path]:
    return sorted(
        path for path in ROOT.rglob("*")
        if path.is_file() and ".git" not in path.relative_to(ROOT).parts
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

    video_paths = [
        path.relative_to(ROOT).as_posix()
        for path in files
        if path.suffix.lower() in VIDEO_SUFFIXES
    ]
    if video_paths:
        fail("source_video_present:" + ",".join(video_paths))

    secret_hits = []
    for path in files:
        if path.stat().st_size > 2_000_000:
            continue
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
        if path.stat().st_size > 2_000_000:
            continue
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
