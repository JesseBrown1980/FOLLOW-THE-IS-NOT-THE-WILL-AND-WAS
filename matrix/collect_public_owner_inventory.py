#!/usr/bin/env python3
"""Seal every public owner repository's Git tree into a bounded HBP/HBI inventory.

The collector reads GitHub's public REST surface through the authenticated ``gh``
transport, but requests only ``users/{owner}/repos`` and public repository objects.
It stores repository names and aggregate Git-object commitments. It does not copy
blob bodies, publish individual paths, enumerate private repositories, or treat a
catalog entry as runtime authority.
"""

from __future__ import annotations

import argparse
import colorsys
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote


SCHEMA = "ASOLARIA-PUBLIC-OWNER-3D-TREE-V1"
DEFAULT_OWNER = "JesseBrown1980"
CENTER_MEMBERS = "HBI,HBP,SHA,SH,HASH"
CENTER_TRAVERSAL = "HBI,HBP,SH,HASH,SHA"
MAX_REPOS = 512
MAX_API_BYTES = 32 * 1024 * 1024
MAX_ENTRIES_PER_REPO = 200_000
MAX_ENTRIES_TOTAL = 1_000_000
MAX_VALUE_BYTES = 2_048
ZERO_SHA1 = "0" * 40
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
WORD_RE = re.compile(r"[A-Za-z0-9]+")


class InventoryError(ValueError):
    """A bounded acquisition, shape, or integrity failure."""


@dataclass(frozen=True)
class RepoSeal:
    index: int
    name: str
    branch: str
    state: str
    commit: str
    tree: str
    entries: int
    blobs: int
    trees: int
    commits: int
    symlinks: int
    object_root_sha256: str
    word_rime_root_sha256: str
    word_count: int
    color: str

    def row(self) -> str:
        return (
            f"REPO|i={self.index}|name={field(self.name)}|branch={field(self.branch)}"
            f"|state={self.state}|commit={self.commit}|tree={self.tree}"
            f"|entries={self.entries}|blobs={self.blobs}|trees={self.trees}"
            f"|commits={self.commits}|symlinks={self.symlinks}"
            f"|object_root_sha256={self.object_root_sha256}"
            f"|word_rime_root_sha256={self.word_rime_root_sha256}"
            f"|word_count={self.word_count}|color={self.color}|json=0"
        )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def field(value: str) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) > MAX_VALUE_BYTES:
        raise InventoryError("tuple field exceeds byte limit")
    if any(ord(character) < 32 for character in value):
        raise InventoryError("tuple field contains a control character")
    return quote(value, safe="-._/")


def is_link_like(path: Path) -> bool:
    try:
        return path.is_symlink() or path.is_junction()
    except (OSError, ValueError):
        return True


def reject_link_chain(path: Path) -> None:
    candidate = path.absolute()
    for part in (candidate, *candidate.parents):
        if part.exists() and is_link_like(part):
            raise InventoryError(f"link-like path component rejected: {part}")


def atomic_write(path: Path, data: bytes) -> None:
    reject_link_chain(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    reject_link_chain(path.parent)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    if temporary.exists() or is_link_like(temporary):
        raise InventoryError(f"unsafe temporary path: {temporary}")
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists() and not is_link_like(temporary):
            temporary.unlink()


def write_sidecar(path: Path, digest: str) -> None:
    atomic_write(
        path.with_name(path.name + ".sha256"),
        f"{digest}  {path.name}\n".encode("ascii"),
    )


def run_gh_json(gh: str, endpoint: str) -> Any:
    completed = subprocess.run(
        [gh, "api", "--method", "GET", endpoint],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
    )
    if len(completed.stdout) > MAX_API_BYTES or len(completed.stderr) > 64 * 1024:
        raise InventoryError("GitHub response exceeds acquisition bound")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()[:512]
        raise InventoryError(f"GitHub API request failed: {detail}")
    try:
        return json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise InventoryError("GitHub response is not bounded UTF-8 JSON") from exc


def public_repositories(gh: str, owner: str) -> list[dict[str, Any]]:
    repositories: list[dict[str, Any]] = []
    for page in range(1, 8):
        endpoint = (
            f"users/{quote(owner, safe='')}/repos?type=owner&sort=full_name"
            f"&direction=asc&per_page=100&page={page}"
        )
        payload = run_gh_json(gh, endpoint)
        if not isinstance(payload, list):
            raise InventoryError("public repository page is not a list")
        if not payload:
            break
        for repository in payload:
            if not isinstance(repository, dict):
                raise InventoryError("repository entry is not an object")
            if repository.get("private") is not False:
                raise InventoryError("non-public repository reached public-only collector")
            owner_record = repository.get("owner")
            if not isinstance(owner_record, dict) or owner_record.get("login") != owner:
                raise InventoryError("repository owner mismatch")
            repositories.append(repository)
            if len(repositories) > MAX_REPOS:
                raise InventoryError("public repository count exceeds bound")
        if len(payload) < 100:
            break
    names = [repository.get("name") for repository in repositories]
    if any(not isinstance(name, str) or not name for name in names):
        raise InventoryError("repository name is missing")
    if len(set(names)) != len(names):
        raise InventoryError("duplicate repository name")
    return sorted(repositories, key=lambda repository: repository["name"].casefold())


def valid_sha1(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise InventoryError("invalid Git SHA-1 object identifier")
    return value


def hash_words(hasher: "hashlib._Hash", text: str) -> int:
    count = 0
    for token in WORD_RE.findall(text.casefold()):
        encoded = token.encode("utf-8")
        hasher.update(len(encoded).to_bytes(2, "big"))
        hasher.update(encoded)
        count += 1
    return count


def color_from_root(root: str) -> str:
    hue = int(root[:8], 16) / 0xFFFFFFFF
    saturation = 0.52 + (int(root[8:10], 16) / 255.0) * 0.28
    value = 0.66 + (int(root[10:12], 16) / 255.0) * 0.26
    red, green, blue = colorsys.hsv_to_rgb(hue, saturation, value)
    return f"#{round(red * 255):02X}{round(green * 255):02X}{round(blue * 255):02X}"


def seal_empty(index: int, repository: dict[str, Any]) -> RepoSeal:
    name = repository["name"]
    branch = repository.get("default_branch") or "UNBORN"
    words = hashlib.sha256()
    word_count = hash_words(words, name)
    return RepoSeal(
        index=index,
        name=name,
        branch=str(branch),
        state="EMPTY_UNBORN",
        commit=ZERO_SHA1,
        tree=ZERO_SHA1,
        entries=0,
        blobs=0,
        trees=0,
        commits=0,
        symlinks=0,
        object_root_sha256=EMPTY_SHA256,
        word_rime_root_sha256=words.hexdigest(),
        word_count=word_count,
        color=color_from_root(EMPTY_SHA256),
    )


def seal_repository(
    gh: str, owner: str, index: int, repository: dict[str, Any]
) -> RepoSeal:
    name = repository["name"]
    branch = repository.get("default_branch")
    size = repository.get("size")
    if not isinstance(size, int) or size < 0:
        raise InventoryError("repository size is invalid")
    if not isinstance(branch, str) or not branch:
        return seal_empty(index, repository)

    base = f"repos/{quote(owner, safe='')}/{quote(name, safe='')}"
    try:
        commit_payload = run_gh_json(gh, f"{base}/commits/{quote(branch, safe='')}")
    except InventoryError as exc:
        detail = str(exc)
        if size == 0 and ("HTTP 409" in detail or "Repository is empty" in detail):
            return seal_empty(index, repository)
        raise
    if not isinstance(commit_payload, dict):
        raise InventoryError("commit response is not an object")
    commit = valid_sha1(commit_payload.get("sha"))
    commit_record = commit_payload.get("commit")
    tree_record = commit_record.get("tree") if isinstance(commit_record, dict) else None
    if not isinstance(tree_record, dict):
        raise InventoryError("commit tree record is missing")
    tree_sha = valid_sha1(tree_record.get("sha"))
    tree_payload = run_gh_json(gh, f"{base}/git/trees/{tree_sha}?recursive=1")
    if not isinstance(tree_payload, dict) or tree_payload.get("truncated") is not False:
        raise InventoryError(f"recursive public tree is incomplete: {name}")
    entries = tree_payload.get("tree")
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES_PER_REPO:
        raise InventoryError(f"public tree entry count exceeds bound: {name}")

    object_hasher = hashlib.sha256()
    word_hasher = hashlib.sha256()
    word_count = hash_words(word_hasher, name)
    blobs = trees = commits = symlinks = 0
    normalized: list[tuple[str, str, str, str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise InventoryError("tree entry is not an object")
        path = entry.get("path")
        mode = entry.get("mode")
        kind = entry.get("type")
        oid = entry.get("sha")
        size_value = entry.get("size", "")
        if not all(isinstance(value, str) for value in (path, mode, kind, oid)):
            raise InventoryError("tree entry shape mismatch")
        valid_sha1(oid)
        if "\x00" in path or len(path.encode("utf-8")) > 4_096:
            raise InventoryError("tree path exceeds safe commitment shape")
        if kind not in {"blob", "tree", "commit"}:
            raise InventoryError(f"unknown Git object type: {kind}")
        if size_value != "" and (not isinstance(size_value, int) or size_value < 0):
            raise InventoryError("tree entry size mismatch")
        normalized.append((path, mode, kind, oid, str(size_value)))
        blobs += kind == "blob"
        trees += kind == "tree"
        commits += kind == "commit"
        symlinks += mode == "120000"

    for path, mode, kind, oid, size_text in sorted(normalized):
        record = "\0".join((path, mode, kind, oid, size_text)).encode("utf-8") + b"\n"
        object_hasher.update(record)
        word_count += hash_words(word_hasher, path)
    object_root = object_hasher.hexdigest()
    return RepoSeal(
        index=index,
        name=name,
        branch=branch,
        state="PUBLIC_TREE_COMPLETE",
        commit=commit,
        tree=tree_sha,
        entries=len(entries),
        blobs=blobs,
        trees=trees,
        commits=commits,
        symlinks=symlinks,
        object_root_sha256=object_root,
        word_rime_root_sha256=word_hasher.hexdigest(),
        word_count=word_count,
        color=color_from_root(object_root),
    )


def spherical_root(seals: Iterable[RepoSeal]) -> str:
    hasher = hashlib.sha256()
    for seal in seals:
        row = seal.row().encode("utf-8")
        hasher.update(len(row).to_bytes(8, "big"))
        hasher.update(row)
    return hasher.hexdigest()


def build_hbp(owner: str, captured_at: str, seals: list[RepoSeal]) -> bytes:
    root = spherical_root(seals)
    rows = [
        (
            f"OWNER3DRUN|schema={SCHEMA}|owner={field(owner)}|captured_at={captured_at}"
            f"|surface=PUBLIC_API_SUBSET|repos={len(seals)}|json=0"
        ),
        (
            f"CENTER|nullspace=0|center_members={CENTER_MEMBERS}"
            f"|traversal={CENTER_TRAVERSAL}|sha_equals_hash=0"
            "|brown_center=#8B5A2B|close_to=1|json=0"
        ),
        (
            "RECIPE|sh=GH_PUBLIC_OWNER_TREE_V1|transport=GH_CLI_PUBLIC_REST"
            "|recursive_git_tree=1|paths_published=0|blob_bodies_read=0|json=0"
        ),
        (
            "BOUNDARY|private_repo_endpoint_calls=0|private_repo_rows=0|private_keys=0"
            "|credentials_in_output=0|catalog_grants_authority=0|system_affirmed=0|json=0"
        ),
        *[seal.row() for seal in seals],
        (
            f"HASH|role=SPHERICAL_OBJECT_COMMITMENT|algorithm=SHA256"
            f"|value={root}|distinct_from_hbp_byte_sha=1|json=0"
        ),
        (
            f"SUMMARY|repos={len(seals)}|branched={sum(seal.state == 'PUBLIC_TREE_COMPLETE' for seal in seals)}"
            f"|unborn={sum(seal.state == 'EMPTY_UNBORN' for seal in seals)}"
            f"|entries={sum(seal.entries for seal in seals)}"
            f"|blobs={sum(seal.blobs for seal in seals)}|trees={sum(seal.trees for seal in seals)}"
            f"|commits={sum(seal.commits for seal in seals)}"
            f"|symlinks={sum(seal.symlinks for seal in seals)}|json=0"
        ),
    ]
    return ("\n".join(rows) + "\n").encode("utf-8")


def build_hbi(hbp_path: Path, hbp_sha: str, root: str, repo_count: int) -> bytes:
    rows = [
        f"OWNER3DHBI|schema={SCHEMA}|version=1|json=0",
        (
            f"CENTER|nullspace=0|center_members={CENTER_MEMBERS}"
            f"|traversal={CENTER_TRAVERSAL}|sha_equals_hash=0|json=0"
        ),
        (
            f"HBP|path={field(hbp_path.name)}|sha256={hbp_sha}|repos={repo_count}"
            "|raw_blob_bodies=0|json=0"
        ),
        f"HASH|role=SPHERICAL_OBJECT_COMMITMENT|value={root}|json=0",
        "SH|recipe=GH_PUBLIC_OWNER_TREE_V1|executed_authority=0|json=0",
    ]
    body = ("\n".join(rows) + "\n").encode("utf-8")
    rows.append(f"OWNER3DHBIFTR|body_sha256={sha256(body)}|rows={len(rows) + 1}|json=0")
    return ("\n".join(rows) + "\n").encode("utf-8")


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", default=DEFAULT_OWNER)
    parser.add_argument("--gh", default=shutil.which("gh") or "gh")
    parser.add_argument("--output", type=Path, default=root / "PUBLIC-OWNER-3D-TREE.hbp")
    parser.add_argument("--index", type=Path, default=root / "PUBLIC-OWNER-3D-TREE.hbi")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if re.fullmatch(r"[A-Za-z0-9-]{1,39}", args.owner) is None:
        raise InventoryError("invalid GitHub owner login")
    gh = shutil.which(args.gh) if os.path.sep not in args.gh else args.gh
    if not gh or not Path(gh).is_file():
        raise InventoryError("gh executable not found")
    captured_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    repositories = public_repositories(gh, args.owner)
    seals: list[RepoSeal] = []
    entries_total = 0
    for index, repository in enumerate(repositories):
        seal = seal_repository(gh, args.owner, index, repository)
        entries_total += seal.entries
        if entries_total > MAX_ENTRIES_TOTAL:
            raise InventoryError("aggregate public tree entries exceed bound")
        seals.append(seal)
        print(
            f"OWNER3DPROGRESS|i={index}|repos={len(repositories)}|state={seal.state}"
            f"|entries={seal.entries}|json=0",
            file=sys.stderr,
        )
    hbp = build_hbp(args.owner, captured_at, seals)
    hbp_path = args.output.resolve()
    hbp_sha = sha256(hbp)
    atomic_write(hbp_path, hbp)
    write_sidecar(hbp_path, hbp_sha)
    root = spherical_root(seals)
    hbi = build_hbi(hbp_path, hbp_sha, root, len(seals))
    hbi_path = args.index.resolve()
    hbi_sha = sha256(hbi)
    atomic_write(hbi_path, hbi)
    write_sidecar(hbi_path, hbi_sha)
    print(
        f"OWNER3D|PASS=1|repos={len(seals)}|branched={sum(seal.state == 'PUBLIC_TREE_COMPLETE' for seal in seals)}"
        f"|unborn={sum(seal.state == 'EMPTY_UNBORN' for seal in seals)}"
        f"|entries={entries_total}|hbp_sha256={hbp_sha}|hbi_sha256={hbi_sha}"
        f"|hash={root}|private_repo_rows=0|json=0"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (InventoryError, OSError, subprocess.SubprocessError) as exc:
        print(f"OWNER3D|PASS=0|error={type(exc).__name__}|json=0", file=sys.stderr)
        raise SystemExit(1) from None
