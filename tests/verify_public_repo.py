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
    ".cjs", ".hbi", ".hbp", ".json", ".md", ".py", ".rs", ".sha256",
    ".txt", ".yml", ".yaml",
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

    manifest = ROOT / "hashes/PINNED-SOURCES.sha256"
    manifest_lines = [
        line for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(manifest_lines) != len(EXPECTED):
        fail("pinned_manifest_count_mismatch")

    print(
        "PUBLIC_REPO_VERIFY|PASS=1"
        f"|files={len(files)}"
        f"|pinned={len(EXPECTED)}"
        f"|receipts={len(receipts)}"
        "|source_video_bytes=0"
        "|secret_findings=0"
        "|REQUIRED_HIDDEN_DEPENDENCIES=0"
    )


if __name__ == "__main__":
    main()
