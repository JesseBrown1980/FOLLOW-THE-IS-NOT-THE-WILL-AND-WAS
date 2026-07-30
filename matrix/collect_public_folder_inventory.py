#!/usr/bin/env python3
"""Collect an opaque, public-only folder occurrence tree through authenticated ``gh``.

The hot artifacts are LF HBP/HBI tuple text (``json=0``).  Repository names,
branches, raw Git paths, direct path hashes, raw Git SHA-1 values, blob bodies,
symlink targets, and gitlink targets stay acquisition-local.  One synthetic root
is emitted for each public branched repository and one occurrence is emitted for
each recursive Git tree entry of type ``tree``.

Network acquisition is deliberately narrow:

* ``gh repo list OWNER --visibility public`` lists the public set.
* ``gh api repos/OWNER/REPO/commits/REF`` resolves a public branch.
* ``gh api repos/OWNER/REPO/git/trees/OID?recursive=1`` gets its complete tree.

The public set is fetched again after tree acquisition.  A visibility, identity,
or default-branch change fails closed instead of sealing a mixed capture.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol, Sequence
from urllib.parse import quote


SCHEMA = "ASOLARIA-PUBLIC-FOLDER-3D-TREE-V1"
DEFAULT_OWNER = "JesseBrown1980"
CENTER_MEMBERS = "HBI,HBP,SHA,SH,HASH"
CENTER_TRAVERSAL = "HBI,HBP,SH,HASH,SHA"

MAX_REPOSITORIES = 512
MAX_API_BYTES = 32 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_ENTRIES_PER_REPOSITORY = 200_000
MAX_ENTRIES_TOTAL = 1_000_000
MAX_FOLDERS_TOTAL = 250_000
MAX_PATH_BYTES = 4_096
MAX_LEVEL = 256
MAX_DECLARED_BLOB_BYTES = 1_000_000_000_000_000
MAX_OUTPUT_BYTES = 256 * 1024 * 1024
MAX_TUPLE_VALUE_BYTES = 2_048
COMMAND_TIMEOUT_SECONDS = 180
MAX_GH_COMMANDS = 2 * MAX_REPOSITORIES + 4
ACQUISITION_DEADLINE_SECONDS = 2 * 60 * 60
COORDINATE_LIMIT = 1_000_000
COORDINATE_SPAN = COORDINATE_LIMIT * 2 + 1

ZERO_SHA1_BYTES = b"\x00" * 20
ZERO_SHA256 = "0" * 64
UINT64_MAX = (1 << 64) - 1
HEX40_RE = re.compile(r"[0-9a-f]{40}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
OWNER_RE = re.compile(r"[A-Za-z0-9-]{1,39}")
REPOSITORY_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,100}")

TREE_MODE = "040000"
BLOB_MODES = {"100644", "100755", "120000"}
COMMIT_MODE = "160000"
KIND_TAGS = {"blob": 1, "tree": 2, "commit": 3}
SOURCE_KIND_TAGS = {"REPOSITORY_ROOT": 1, "GIT_TREE": 2}

HEADER_FIELDS = (
    "schema",
    "owner",
    "captured_at",
    "source_capture_sha256",
    "public_set_sha256",
    "surface",
    "repositories",
    "branched",
    "unborn",
    "root_nodes",
    "tree_nodes",
    "folders",
    "public_metadata_only",
    "json",
)
FOLDER_FIELDS = (
    "i",
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
    "x",
    "y",
    "z",
    "color",
    "json",
)
SUMMARY_FIELDS = (
    "repositories",
    "branched",
    "unborn",
    "repository_roots",
    "git_tree_folder_occurrences",
    "folders",
    "max_level",
    "direct_blobs",
    "direct_trees",
    "direct_commits",
    "gitlinks",
    "symlinks",
    "unique_tree_objects",
    "json",
)
CENTER_FIELDS = (
    "nullspace",
    "center_members",
    "traversal",
    "sha_equals_hash",
    "brown_center",
    "close_to",
    "json",
)
RECIPE_FIELDS = (
    "transport",
    "recursive_git_tree",
    "complete_tree_required",
    "paths_published",
    "path_hashes_published",
    "tree_sha1_published",
    "blob_bodies_read",
    "private_repo_endpoint_calls",
    "git_tree_commitments",
    "path_dictionary_resistance_claim",
    "json",
)
BOUNDARY_FIELDS = (
    "private_repo_rows",
    "private_repo_names",
    "credentials",
    "raw_paths",
    "raw_bodies",
    "network_in_renderer",
    "execution",
    "system_affirmed",
    "json",
)
HASH_FIELDS = (
    "role",
    "algorithm",
    "value",
    "distinct_from_hbp_byte_sha",
    "json",
)


class InventoryError(ValueError):
    """A bounded acquisition, schema, or integrity failure."""


class CommandError(InventoryError):
    """An authenticated ``gh`` command failed without exposing its response body."""


@dataclass(frozen=True)
class PublicRepository:
    owner: str
    node_id: str
    name: str
    branch: str | None
    repo_id: str

    def stable_tuple(self) -> tuple[str, str, str, str | None, str]:
        return (self.owner.casefold(), self.node_id, self.name, self.branch, self.repo_id)


@dataclass(frozen=True)
class GitEntry:
    path: str
    path_bytes: bytes
    mode: str
    kind: str
    oid: bytes
    size: int | None
    level: int
    parent_path: str


@dataclass(frozen=True)
class RepositoryCapture:
    repository: PublicRepository
    state: str
    commit_oid: bytes
    root_tree_oid: bytes
    entries: tuple[GitEntry, ...]


@dataclass(frozen=True)
class FolderNode:
    index: int
    repo_id: str
    folder_id: str
    parent_folder_id: str
    sibling_ordinal: int
    level: int
    tree_commitment_sha256: str
    source_kind: str
    direct_blobs: int
    direct_trees: int
    direct_commits: int
    direct_symlinks: int
    object_sha256: str
    x: int
    y: int
    z: int
    color: str

    def row(self) -> str:
        return (
            f"FOLDER|i={self.index}|repo_id={self.repo_id}"
            f"|folder_id={self.folder_id}|parent_folder_id={self.parent_folder_id}"
            f"|sibling_ordinal={self.sibling_ordinal}|level={self.level}"
            f"|tree_commitment_sha256={self.tree_commitment_sha256}"
            f"|source_kind={self.source_kind}|direct_blobs={self.direct_blobs}"
            f"|direct_trees={self.direct_trees}|direct_commits={self.direct_commits}"
            f"|direct_symlinks={self.direct_symlinks}"
            f"|object_sha256={self.object_sha256}|x={self.x}|y={self.y}|z={self.z}"
            f"|color={self.color}|json=0"
        )


@dataclass(frozen=True)
class Inventory:
    owner: str
    captured_at: str
    source_capture_sha256: str
    public_set_sha256: str
    repositories: int
    branched: int
    unborn: int
    repository_roots: int
    git_tree_folder_occurrences: int
    max_level: int
    direct_blobs: int
    direct_trees: int
    direct_commits: int
    symlinks: int
    unique_tree_objects: int
    folders: tuple[FolderNode, ...]


class PublicSource(Protocol):
    def list_public_repositories(self, owner: str) -> list[PublicRepository]:
        """Return the exact public set and no owner-visible private entries."""

    def get_commit(self, owner: str, name: str, branch: str) -> Any:
        """Return the public REST commit payload."""

    def get_recursive_tree(self, owner: str, name: str, tree_oid: str) -> Any:
        """Return the complete public REST recursive-tree payload."""


CommandRunner = Callable[[Sequence[str], int, int, int, dict[str, str]], bytes]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def domain_prefix(label: bytes) -> bytes:
    return SCHEMA.encode("ascii") + b"\0" + label + b"\0"


def checked_u32(value: int, label: str) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFFFFFF:
        raise InventoryError(f"{label} exceeds uint32")
    return value.to_bytes(4, "big")


def checked_u64(value: int, label: str) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= UINT64_MAX:
        raise InventoryError(f"{label} exceeds uint64")
    return value.to_bytes(8, "big")


def tuple_field(value: str) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) > MAX_TUPLE_VALUE_BYTES:
        raise InventoryError("tuple value exceeds byte bound")
    if any(byte < 32 or byte == 127 for byte in encoded):
        raise InventoryError("tuple value contains a control character")
    return quote(value, safe="-._:")


def valid_sha1_bytes(value: Any) -> bytes:
    if not isinstance(value, str) or HEX40_RE.fullmatch(value) is None:
        raise InventoryError("invalid Git SHA-1 object identifier")
    return bytes.fromhex(value)


def valid_sha256(value: str, label: str = "SHA-256") -> str:
    if HEX64_RE.fullmatch(value) is None:
        raise InventoryError(f"invalid {label}")
    return value


def repository_id(owner: str, node_id: str) -> str:
    node_bytes = node_id.encode("utf-8")
    owner_bytes = owner.casefold().encode("utf-8")
    if not 1 <= len(node_bytes) <= 512:
        raise InventoryError("repository node ID exceeds byte bound")
    material = (
        domain_prefix(b"REPOSITORY-ID")
        + checked_u32(len(owner_bytes), "owner length")
        + owner_bytes
        + checked_u32(len(node_bytes), "repository node ID length")
        + node_bytes
    )
    return sha256(material)


def tree_commitment(raw_oid: bytes) -> str:
    if len(raw_oid) != 20:
        raise InventoryError("Git tree object ID is not 20 bytes")
    return sha256(domain_prefix(b"GIT-TREE-OID") + raw_oid)


def folder_occurrence_id(
    source_capture_sha256: str,
    repo_id: str,
    parent_folder_id: str,
    sibling_ordinal: int,
    tree_commitment_sha256: str,
) -> str:
    material = (
        domain_prefix(b"FOLDER-ID")
        + bytes.fromhex(valid_sha256(source_capture_sha256, "source capture"))
        + bytes.fromhex(valid_sha256(repo_id, "repository ID"))
        + bytes.fromhex(valid_sha256(parent_folder_id, "parent folder ID"))
        + checked_u32(sibling_ordinal, "sibling ordinal")
        + bytes.fromhex(valid_sha256(tree_commitment_sha256, "tree commitment"))
    )
    return sha256(material)


def folder_object_sha256(
    *,
    index: int,
    repo_id: str,
    folder_id: str,
    parent_folder_id: str,
    sibling_ordinal: int,
    level: int,
    tree_commitment_sha256: str,
    source_kind: str,
    direct_blobs: int,
    direct_trees: int,
    direct_commits: int,
    direct_symlinks: int,
) -> str:
    try:
        source_tag = SOURCE_KIND_TAGS[source_kind]
    except KeyError as exc:
        raise InventoryError("invalid folder source kind") from exc
    material = (
        domain_prefix(b"FOLDER-OBJECT")
        + checked_u64(index, "folder index")
        + bytes.fromhex(valid_sha256(repo_id, "repository ID"))
        + bytes.fromhex(valid_sha256(folder_id, "folder ID"))
        + bytes.fromhex(valid_sha256(parent_folder_id, "parent folder ID"))
        + checked_u32(sibling_ordinal, "sibling ordinal")
        + checked_u32(level, "folder level")
        + bytes.fromhex(valid_sha256(tree_commitment_sha256, "tree commitment"))
        + bytes((source_tag,))
        + checked_u64(direct_blobs, "direct blob count")
        + checked_u64(direct_trees, "direct tree count")
        + checked_u64(direct_commits, "direct commit count")
        + checked_u64(direct_symlinks, "direct symlink count")
    )
    return sha256(material)


def projection_from_object(object_sha256: str) -> tuple[int, int, int, str]:
    raw = bytes.fromhex(valid_sha256(object_sha256, "folder object commitment"))
    coordinates = tuple(
        int.from_bytes(raw[offset : offset + 4], "big") % COORDINATE_SPAN
        - COORDINATE_LIMIT
        for offset in (0, 4, 8)
    )
    if any(not -COORDINATE_LIMIT <= value <= COORDINATE_LIMIT for value in coordinates):
        raise InventoryError("derived coordinate exceeds checked range")
    components = tuple(48 + raw[12 + offset] % 160 for offset in range(3))
    if any(not 48 <= component <= 207 for component in components):
        raise InventoryError("derived color exceeds checked range")
    color = "RGB." + "".join(f"{component:02X}" for component in components)
    return coordinates[0], coordinates[1], coordinates[2], color


def run_bounded_command(
    argv: Sequence[str],
    stdout_limit: int,
    stderr_limit: int,
    timeout_seconds: int,
    environment: dict[str, str],
) -> bytes:
    """Run a process while two reader threads enforce hard pipe byte caps."""

    if stdout_limit <= 0 or stderr_limit <= 0:
        raise InventoryError("command byte bounds must be positive")
    process = subprocess.Popen(
        list(argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        raise InventoryError("bounded command pipes were not created")

    stdout = bytearray()
    stderr = bytearray()
    overflow: list[str] = []
    lock = threading.Lock()

    def consume(stream: Any, destination: bytearray, limit: int, role: str) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                with lock:
                    if len(destination) + len(chunk) > limit:
                        overflow.append(role)
                        try:
                            process.kill()
                        except OSError:
                            pass
                        return
                    destination.extend(chunk)
        finally:
            try:
                stream.close()
            except OSError:
                pass

    readers = (
        threading.Thread(
            target=consume,
            args=(process.stdout, stdout, stdout_limit, "stdout"),
            daemon=True,
        ),
        threading.Thread(
            target=consume,
            args=(process.stderr, stderr, stderr_limit, "stderr"),
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()
    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        for reader in readers:
            reader.join(timeout=5)
        raise CommandError("authenticated gh command timed out") from None
    for reader in readers:
        reader.join(timeout=5)
    if any(reader.is_alive() for reader in readers):
        process.kill()
        raise CommandError("authenticated gh stream reader did not terminate")
    if overflow:
        raise CommandError(f"authenticated gh {overflow[0]} exceeded byte bound")
    if return_code != 0:
        raise CommandError("authenticated gh command failed")
    return bytes(stdout)


class GhPublicSource:
    """Authenticated ``gh`` transport with a closed public endpoint vocabulary."""

    def __init__(
        self,
        gh: str,
        runner: CommandRunner = run_bounded_command,
        *,
        max_commands: int = MAX_GH_COMMANDS,
        acquisition_deadline_seconds: int = ACQUISITION_DEADLINE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_commands <= 0 or acquisition_deadline_seconds <= 0:
            raise InventoryError("gh request and deadline bounds must be positive")
        self.gh = gh
        self.runner = runner
        self.max_commands = max_commands
        self.command_count = 0
        self.clock = clock
        self.deadline_at = clock() + acquisition_deadline_seconds
        self.environment = os.environ.copy()
        self.environment.update(
            {
                "GH_HOST": "github.com",
                "GH_PROMPT_DISABLED": "1",
                "GH_PAGER": "cat",
            }
        )

    def _run(self, arguments: Sequence[str], stdout_limit: int) -> bytes:
        if self.command_count >= self.max_commands:
            raise InventoryError("authenticated gh request count exceeds bound")
        remaining = self.deadline_at - self.clock()
        if remaining <= 0:
            raise InventoryError("authenticated gh acquisition deadline elapsed")
        self.command_count += 1
        timeout = max(1, min(COMMAND_TIMEOUT_SECONDS, math.ceil(remaining)))
        result = self.runner(
            [self.gh, *arguments],
            stdout_limit,
            MAX_STDERR_BYTES,
            timeout,
            self.environment,
        )
        if self.clock() > self.deadline_at:
            raise InventoryError("authenticated gh acquisition deadline elapsed")
        return result

    def ensure_authenticated(self) -> None:
        self._run(
            ["auth", "status", "--active", "--hostname", "github.com"],
            MAX_STDERR_BYTES,
        )

    def _json(self, arguments: Sequence[str], stdout_limit: int = MAX_API_BYTES) -> Any:
        payload = self._run(arguments, stdout_limit)
        try:
            return json.loads(payload.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise InventoryError("authenticated gh response is not bounded UTF-8 JSON") from exc

    @staticmethod
    def validate_public_api_endpoint(endpoint: str) -> None:
        commit = re.fullmatch(
            r"repos/[A-Za-z0-9%._-]+/[A-Za-z0-9%._-]+/commits/[A-Za-z0-9%._~-]+",
            endpoint,
        )
        tree = re.fullmatch(
            r"repos/[A-Za-z0-9%._-]+/[A-Za-z0-9%._-]+/git/trees/[0-9a-f]{40}"
            r"\?recursive=1",
            endpoint,
        )
        if commit is None and tree is None:
            raise InventoryError("endpoint is outside the public commit/tree allowlist")

    def list_public_repositories(self, owner: str) -> list[PublicRepository]:
        payload = self._json(
            [
                "repo",
                "list",
                owner,
                "--limit",
                str(MAX_REPOSITORIES + 1),
                "--visibility",
                "public",
                "--json",
                "id,name,nameWithOwner,isPrivate,defaultBranchRef",
            ]
        )
        return normalize_public_repositories(payload, owner)

    def _api_get(self, endpoint: str) -> Any:
        self.validate_public_api_endpoint(endpoint)
        return self._json(
            ["api", "--hostname", "github.com", "--method", "GET", endpoint]
        )

    def get_commit(self, owner: str, name: str, branch: str) -> Any:
        endpoint = (
            f"repos/{quote(owner, safe='')}/{quote(name, safe='')}/commits/"
            f"{quote(branch, safe='')}"
        )
        return self._api_get(endpoint)

    def get_recursive_tree(self, owner: str, name: str, tree_oid: str) -> Any:
        if HEX40_RE.fullmatch(tree_oid) is None:
            raise InventoryError("tree endpoint received an invalid Git object ID")
        endpoint = (
            f"repos/{quote(owner, safe='')}/{quote(name, safe='')}/git/trees/"
            f"{tree_oid}?recursive=1"
        )
        return self._api_get(endpoint)


def normalize_public_repositories(payload: Any, owner: str) -> list[PublicRepository]:
    if not isinstance(payload, list):
        raise InventoryError("public repository list is not an array")
    if len(payload) > MAX_REPOSITORIES:
        raise InventoryError("public repository count exceeds bound")
    repositories: list[PublicRepository] = []
    seen_names: set[str] = set()
    seen_ids: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            raise InventoryError("public repository entry is not an object")
        if item.get("isPrivate") is not False:
            raise InventoryError("private repository reached public-only collector")
        name = item.get("name")
        full_name = item.get("nameWithOwner")
        node_id = item.get("id")
        if not all(isinstance(value, str) and value for value in (name, full_name, node_id)):
            raise InventoryError("public repository identity is incomplete")
        if REPOSITORY_NAME_RE.fullmatch(name) is None:
            raise InventoryError("public repository name is outside GitHub bounds")
        expected_full_name = f"{owner}/{name}"
        if full_name.casefold() != expected_full_name.casefold():
            raise InventoryError("public repository exact-owner check failed")
        if full_name.split("/", 1)[0].casefold() != owner.casefold():
            raise InventoryError("public repository owner mismatch")
        branch_record = item.get("defaultBranchRef")
        if branch_record is None:
            branch = None
        elif isinstance(branch_record, dict) and isinstance(
            branch_record.get("name"), str
        ):
            branch = branch_record["name"] or None
        else:
            raise InventoryError("public default-branch shape is invalid")
        for raw_value in (name, full_name, node_id, branch or ""):
            encoded = raw_value.encode("utf-8")
            if len(encoded) > MAX_TUPLE_VALUE_BYTES or b"\x00" in encoded:
                raise InventoryError("public repository metadata exceeds safe bounds")
        name_key = name.casefold()
        if name_key in seen_names:
            raise InventoryError("duplicate public repository name")
        seen_names.add(name_key)
        opaque_id = repository_id(owner, node_id)
        if opaque_id in seen_ids:
            raise InventoryError("duplicate opaque repository ID")
        seen_ids.add(opaque_id)
        repositories.append(
            PublicRepository(owner, node_id, name, branch, opaque_id)
        )
    return sorted(
        repositories,
        key=lambda repository: (
            repository.name.casefold(),
            repository.name.encode("utf-8"),
        ),
    )


def validate_path(path: str) -> tuple[bytes, int, str]:
    if not path or path.startswith("/") or path.endswith("/"):
        raise InventoryError("Git path has an invalid hierarchy shape")
    encoded = path.encode("utf-8")
    if len(encoded) > MAX_PATH_BYTES or b"\x00" in encoded:
        raise InventoryError("Git path exceeds acquisition bound")
    components = path.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise InventoryError("Git path has a non-canonical component")
    level = len(components)
    if level > MAX_LEVEL:
        raise InventoryError("Git path level exceeds bound")
    return encoded, level, "/".join(components[:-1])


def normalize_git_entries(payload: Any, expected_root_oid: bytes) -> tuple[GitEntry, ...]:
    if not isinstance(payload, dict):
        raise InventoryError("recursive Git tree response is not an object")
    if payload.get("truncated") is not False:
        raise InventoryError("recursive Git tree is incomplete")
    response_oid = valid_sha1_bytes(payload.get("sha"))
    if response_oid != expected_root_oid:
        raise InventoryError("recursive Git tree root changed during acquisition")
    raw_entries = payload.get("tree")
    if not isinstance(raw_entries, list):
        raise InventoryError("recursive Git tree entries are not an array")
    if len(raw_entries) > MAX_ENTRIES_PER_REPOSITORY:
        raise InventoryError("recursive Git tree entry count exceeds bound")

    entries: list[GitEntry] = []
    paths: set[str] = set()
    declared_bytes = 0
    for raw in raw_entries:
        if not isinstance(raw, dict):
            raise InventoryError("recursive Git tree entry is not an object")
        path = raw.get("path")
        mode = raw.get("mode")
        kind = raw.get("type")
        if not all(isinstance(value, str) for value in (path, mode, kind)):
            raise InventoryError("recursive Git tree entry shape is invalid")
        path_bytes, level, parent_path = validate_path(path)
        if path in paths:
            raise InventoryError("duplicate recursive Git tree path")
        paths.add(path)
        oid = valid_sha1_bytes(raw.get("sha"))
        if kind == "tree" and mode != TREE_MODE:
            raise InventoryError("Git tree entry mode/type mismatch")
        if kind == "blob" and mode not in BLOB_MODES:
            raise InventoryError("Git blob entry mode/type mismatch")
        if kind == "commit" and mode != COMMIT_MODE:
            raise InventoryError("Git commit entry mode/type mismatch")
        if kind not in KIND_TAGS:
            raise InventoryError("unsupported Git tree object type")
        size_raw = raw.get("size")
        if size_raw is None:
            size = None
        elif (
            isinstance(size_raw, int)
            and not isinstance(size_raw, bool)
            and 0 <= size_raw <= MAX_DECLARED_BLOB_BYTES
        ):
            size = size_raw
        else:
            raise InventoryError("Git entry declared size exceeds bound")
        if kind != "blob" and size is not None:
            raise InventoryError("non-blob Git entry declares a body size")
        if size is not None:
            declared_bytes += size
            if declared_bytes > MAX_DECLARED_BLOB_BYTES:
                raise InventoryError("declared Git blob bytes exceed aggregate bound")
        entries.append(
            GitEntry(path, path_bytes, mode, kind, oid, size, level, parent_path)
        )

    tree_paths = {entry.path for entry in entries if entry.kind == "tree"}
    for entry in entries:
        if entry.parent_path and entry.parent_path not in tree_paths:
            raise InventoryError("recursive Git tree has an unbound parent occurrence")
    return tuple(sorted(entries, key=lambda entry: entry.path_bytes))


def acquire_repository(source: PublicSource, repository: PublicRepository) -> RepositoryCapture:
    if repository.branch is None:
        return RepositoryCapture(
            repository,
            "EMPTY_UNBORN",
            ZERO_SHA1_BYTES,
            ZERO_SHA1_BYTES,
            (),
        )
    commit_payload = source.get_commit(
        repository.owner, repository.name, repository.branch
    )
    if not isinstance(commit_payload, dict):
        raise InventoryError("public commit response is not an object")
    commit_oid = valid_sha1_bytes(commit_payload.get("sha"))
    commit_record = commit_payload.get("commit")
    tree_record = commit_record.get("tree") if isinstance(commit_record, dict) else None
    if not isinstance(tree_record, dict):
        raise InventoryError("public commit tree record is missing")
    root_tree_oid = valid_sha1_bytes(tree_record.get("sha"))
    tree_payload = source.get_recursive_tree(
        repository.owner, repository.name, root_tree_oid.hex()
    )
    entries = normalize_git_entries(tree_payload, root_tree_oid)
    return RepositoryCapture(
        repository,
        "PUBLIC_TREE_COMPLETE",
        commit_oid,
        root_tree_oid,
        entries,
    )


def source_capture_sha256(captures: Iterable[RepositoryCapture]) -> str:
    hasher = hashlib.sha256()
    hasher.update(domain_prefix(b"SOURCE-CAPTURE"))
    for capture in captures:
        hasher.update(b"R")
        hasher.update(bytes.fromhex(capture.repository.repo_id))
        hasher.update(b"\x01" if capture.state == "PUBLIC_TREE_COMPLETE" else b"\x00")
        hasher.update(capture.commit_oid)
        hasher.update(capture.root_tree_oid)
        hasher.update(checked_u64(len(capture.entries), "repository entry count"))
        for entry in capture.entries:
            hasher.update(b"E")
            hasher.update(checked_u32(len(entry.path_bytes), "Git path byte length"))
            hasher.update(entry.path_bytes)
            hasher.update(entry.mode.encode("ascii"))
            hasher.update(bytes((KIND_TAGS[entry.kind],)))
            hasher.update(entry.oid)
            hasher.update(
                checked_u64(
                    entry.size if entry.size is not None else UINT64_MAX,
                    "Git entry size",
                )
            )
    return hasher.hexdigest()


def public_repository_set_sha256(
    repositories: Iterable[PublicRepository],
) -> str:
    raw_ids = sorted(
        bytes.fromhex(valid_sha256(repository.repo_id, "repository ID"))
        for repository in repositories
    )
    if len(raw_ids) != len(set(raw_ids)):
        raise InventoryError("duplicate repository ID in public set commitment")
    hasher = hashlib.sha256()
    hasher.update(domain_prefix(b"PUBLIC-REPOSITORY-SET"))
    for raw_id in raw_ids:
        hasher.update(raw_id)
    return hasher.hexdigest()


def direct_counts(
    entries: Iterable[GitEntry],
) -> dict[str, tuple[int, int, int, int]]:
    mutable: dict[str, list[int]] = {}
    for entry in entries:
        counts = mutable.setdefault(entry.parent_path, [0, 0, 0, 0])
        if entry.kind == "blob":
            counts[0] += 1
            counts[3] += entry.mode == "120000"
        elif entry.kind == "tree":
            counts[1] += 1
        else:
            counts[2] += 1
    return {parent: tuple(values) for parent, values in mutable.items()}


def build_folder_nodes(
    captures: Sequence[RepositoryCapture], capture_sha256: str
) -> tuple[FolderNode, ...]:
    nodes: list[FolderNode] = []
    seen_folder_ids: set[str] = set()
    next_index = 0
    for capture in captures:
        if capture.state != "PUBLIC_TREE_COMPLETE":
            continue
        counts = direct_counts(capture.entries)
        tree_entries = [entry for entry in capture.entries if entry.kind == "tree"]
        tree_by_path = {entry.path: entry for entry in tree_entries}
        children: dict[str, list[GitEntry]] = {}
        for entry in tree_entries:
            children.setdefault(entry.parent_path, []).append(entry)
        sibling_ordinals: dict[str, int] = {}
        for siblings in children.values():
            siblings.sort(key=lambda entry: entry.path_bytes)
            for ordinal, entry in enumerate(siblings):
                sibling_ordinals[entry.path] = ordinal

        repo_id = capture.repository.repo_id
        root_commitment = tree_commitment(capture.root_tree_oid)
        root_id = folder_occurrence_id(
            capture_sha256, repo_id, ZERO_SHA256, 0, root_commitment
        )
        ids_by_path = {"": root_id}
        ordered_entries = sorted(
            tree_entries, key=lambda entry: (entry.level, entry.path_bytes)
        )
        structural_rows: list[
            tuple[str, str, int, int, str, str, tuple[int, int, int, int]]
        ] = [
            (
                "",
                ZERO_SHA256,
                0,
                0,
                root_commitment,
                "REPOSITORY_ROOT",
                counts.get("", (0, 0, 0, 0)),
            )
        ]
        for entry in ordered_entries:
            parent_id = ids_by_path.get(entry.parent_path)
            if parent_id is None:
                raise InventoryError("folder occurrence parent was not materialized")
            ordinal = sibling_ordinals[entry.path]
            commitment = tree_commitment(entry.oid)
            folder_id = folder_occurrence_id(
                capture_sha256, repo_id, parent_id, ordinal, commitment
            )
            ids_by_path[entry.path] = folder_id
            structural_rows.append(
                (
                    entry.path,
                    parent_id,
                    ordinal,
                    entry.level,
                    commitment,
                    "GIT_TREE",
                    counts.get(entry.path, (0, 0, 0, 0)),
                )
            )

        for path, parent_id, ordinal, level, commitment, source_kind, child_counts in structural_rows:
            folder_id = ids_by_path[path]
            if folder_id in seen_folder_ids:
                raise InventoryError("opaque folder occurrence ID collision")
            seen_folder_ids.add(folder_id)
            blobs, trees, commits, symlinks = child_counts
            object_sha = folder_object_sha256(
                index=next_index,
                repo_id=repo_id,
                folder_id=folder_id,
                parent_folder_id=parent_id,
                sibling_ordinal=ordinal,
                level=level,
                tree_commitment_sha256=commitment,
                source_kind=source_kind,
                direct_blobs=blobs,
                direct_trees=trees,
                direct_commits=commits,
                direct_symlinks=symlinks,
            )
            x, y, z, color = projection_from_object(object_sha)
            nodes.append(
                FolderNode(
                    next_index,
                    repo_id,
                    folder_id,
                    parent_id,
                    ordinal,
                    level,
                    commitment,
                    source_kind,
                    blobs,
                    trees,
                    commits,
                    symlinks,
                    object_sha,
                    x,
                    y,
                    z,
                    color,
                )
            )
            next_index += 1
            if next_index > MAX_FOLDERS_TOTAL:
                raise InventoryError("folder occurrence count exceeds bound")
    return tuple(nodes)


def acquire_inventory(
    source: PublicSource,
    owner: str,
    captured_at: str,
) -> Inventory:
    if OWNER_RE.fullmatch(owner) is None:
        raise InventoryError("invalid GitHub owner login")
    tuple_field(captured_at)
    repositories = source.list_public_repositories(owner)
    captures: list[RepositoryCapture] = []
    entries_total = 0
    for repository in repositories:
        if repository.owner.casefold() != owner.casefold():
            raise InventoryError("public source returned a different owner")
        capture = acquire_repository(source, repository)
        entries_total += len(capture.entries)
        if entries_total > MAX_ENTRIES_TOTAL:
            raise InventoryError("aggregate recursive Git entries exceed bound")
        captures.append(capture)

    postflight = source.list_public_repositories(owner)
    before = [repository.stable_tuple() for repository in repositories]
    after = [repository.stable_tuple() for repository in postflight]
    if before != after:
        raise InventoryError("public repository set changed during acquisition")

    capture_sha = source_capture_sha256(captures)
    public_set_sha = public_repository_set_sha256(repositories)
    if public_set_sha != public_repository_set_sha256(postflight):
        raise InventoryError("public repository set commitment changed during acquisition")
    folders = build_folder_nodes(captures, capture_sha)
    branched = sum(capture.state == "PUBLIC_TREE_COMPLETE" for capture in captures)
    unborn = len(captures) - branched
    tree_occurrences = sum(
        entry.kind == "tree" for capture in captures for entry in capture.entries
    )
    direct_blobs_total = sum(
        entry.kind == "blob" for capture in captures for entry in capture.entries
    )
    direct_commits_total = sum(
        entry.kind == "commit" for capture in captures for entry in capture.entries
    )
    symlinks = sum(
        entry.kind == "blob" and entry.mode == "120000"
        for capture in captures
        for entry in capture.entries
    )
    unique_tree_objects = len(
        {
            oid
            for capture in captures
            if capture.state == "PUBLIC_TREE_COMPLETE"
            for oid in (
                capture.root_tree_oid,
                *(entry.oid for entry in capture.entries if entry.kind == "tree"),
            )
        }
    )
    expected_folders = branched + tree_occurrences
    if len(folders) != expected_folders:
        raise InventoryError("folder occurrence accounting mismatch")
    if sum(folder.direct_trees for folder in folders) != tree_occurrences:
        raise InventoryError("direct tree accounting mismatch")
    return Inventory(
        owner=owner,
        captured_at=captured_at,
        source_capture_sha256=capture_sha,
        public_set_sha256=public_set_sha,
        repositories=len(captures),
        branched=branched,
        unborn=unborn,
        repository_roots=branched,
        git_tree_folder_occurrences=tree_occurrences,
        max_level=max((folder.level for folder in folders), default=0),
        direct_blobs=direct_blobs_total,
        direct_trees=tree_occurrences,
        direct_commits=direct_commits_total,
        symlinks=symlinks,
        unique_tree_objects=unique_tree_objects,
        folders=folders,
    )


def folder_object_root(folders: Iterable[FolderNode]) -> str:
    hasher = hashlib.sha256()
    for folder in folders:
        row = folder.row().encode("utf-8")
        hasher.update(checked_u64(len(row), "folder row length"))
        hasher.update(row)
    return hasher.hexdigest()


def build_hbp(inventory: Inventory) -> bytes:
    object_root = folder_object_root(inventory.folders)
    rows = [
        (
            f"FOLDER3DRUN|schema={SCHEMA}|owner={tuple_field(inventory.owner)}"
            f"|captured_at={tuple_field(inventory.captured_at)}"
            f"|source_capture_sha256={inventory.source_capture_sha256}"
            f"|public_set_sha256={inventory.public_set_sha256}"
            "|surface=MEASURED_GITHUB_PUBLIC"
            f"|repositories={inventory.repositories}|branched={inventory.branched}"
            f"|unborn={inventory.unborn}|root_nodes={inventory.repository_roots}"
            f"|tree_nodes={inventory.git_tree_folder_occurrences}"
            f"|folders={len(inventory.folders)}|public_metadata_only=1|json=0"
        ),
        (
            f"CENTER|nullspace=0|center_members={CENTER_MEMBERS}"
            f"|traversal={CENTER_TRAVERSAL}|sha_equals_hash=0"
            "|brown_center=RGB.8B5A2B|close_to=1|json=0"
        ),
        (
            "RECIPE|transport=GH_CLI_AUTHENTICATED_PUBLIC|recursive_git_tree=1"
            "|complete_tree_required=1|paths_published=0|path_hashes_published=0"
            "|tree_sha1_published=0|blob_bodies_read=0"
            "|private_repo_endpoint_calls=0|git_tree_commitments=1"
            "|path_dictionary_resistance_claim=0|json=0"
        ),
        (
            "BOUNDARY|private_repo_rows=0|private_repo_names=0|credentials=0"
            "|raw_paths=0|raw_bodies=0|network_in_renderer=0|execution=0"
            "|system_affirmed=0|json=0"
        ),
        *[folder.row() for folder in inventory.folders],
        (
            "HASH|role=SPHERICAL_OBJECT_COMMITMENT|algorithm=SHA256"
            f"|value={object_root}|distinct_from_hbp_byte_sha=1|json=0"
        ),
        (
            f"SUMMARY|repositories={inventory.repositories}|branched={inventory.branched}"
            f"|unborn={inventory.unborn}|repository_roots={inventory.repository_roots}"
            f"|git_tree_folder_occurrences={inventory.git_tree_folder_occurrences}"
            f"|folders={len(inventory.folders)}|max_level={inventory.max_level}"
            f"|direct_blobs={inventory.direct_blobs}|direct_trees={inventory.direct_trees}"
            f"|direct_commits={inventory.direct_commits}"
            f"|gitlinks={inventory.direct_commits}|symlinks={inventory.symlinks}"
            f"|unique_tree_objects={inventory.unique_tree_objects}|json=0"
        ),
    ]
    body = ("\n".join(rows) + "\n").encode("utf-8")
    footer = (
        f"FOLDER3DFTR|body_sha256={sha256(body)}|rows={len(rows) + 1}"
        f"|repositories={inventory.repositories}|folders={len(inventory.folders)}|json=0"
    )
    result = body + footer.encode("utf-8") + b"\n"
    if len(result) > MAX_OUTPUT_BYTES:
        raise InventoryError("HBP bytes exceed output bound")
    verify_hbp_bytes(result)
    return result


def build_hbi(
    hbp_name: str,
    hbp_bytes: bytes,
    object_root: str,
    inventory: Inventory,
) -> bytes:
    rows = [
        f"FOLDER3DHBI|schema={SCHEMA}|version=1|json=0",
        (
            f"SOURCE|public_set_sha256={inventory.public_set_sha256}"
            f"|source_capture_sha256={inventory.source_capture_sha256}"
            "|surface=MEASURED_GITHUB_PUBLIC|json=0"
        ),
        (
            f"HBP|path={tuple_field(hbp_name)}|sha256={sha256(hbp_bytes)}"
            f"|bytes={len(hbp_bytes)}|repositories={inventory.repositories}"
            f"|folders={len(inventory.folders)}|json=0"
        ),
        (
            "HASH|role=SPHERICAL_OBJECT_COMMITMENT|algorithm=SHA256"
            f"|value={valid_sha256(object_root, 'object root')}|json=0"
        ),
        (
            "BOUNDARY|paths_published=0|path_hashes_published=0"
            "|tree_sha1_published=0|private_repo_rows=0|raw_bodies=0"
            "|execution_authority=0|json=0"
        ),
    ]
    body = ("\n".join(rows) + "\n").encode("utf-8")
    footer = (
        f"FOLDER3DHBIFTR|body_sha256={sha256(body)}|rows={len(rows) + 1}|json=0"
    )
    result = body + footer.encode("utf-8") + b"\n"
    verify_hbi_bytes(result, expected_hbp_sha256=sha256(hbp_bytes))
    return result


def parse_tuple_line(line: str) -> tuple[str, dict[str, str]]:
    pieces = line.split("|")
    if not pieces or not pieces[0]:
        raise InventoryError("tuple row has no tag")
    fields: dict[str, str] = {}
    for piece in pieces[1:]:
        if "=" not in piece:
            raise InventoryError("tuple row has a field without equals")
        key, value = piece.split("=", 1)
        if not key or key in fields:
            raise InventoryError("tuple row has an invalid or duplicate key")
        fields[key] = value
    if fields.get("json") != "0":
        raise InventoryError("tuple row is not json=0")
    return pieces[0], fields


def parse_uint(value: str, label: str, maximum: int = UINT64_MAX) -> int:
    if re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        raise InventoryError(f"{label} is not canonical unsigned decimal")
    result = int(value)
    if result > maximum:
        raise InventoryError(f"{label} exceeds bound")
    return result


def tuple_lines(data: bytes, maximum_bytes: int = MAX_OUTPUT_BYTES) -> list[str]:
    if len(data) > maximum_bytes:
        raise InventoryError("tuple artifact exceeds byte bound")
    if not data.endswith(b"\n") or b"\r" in data or b"\x00" in data:
        raise InventoryError("tuple artifact is not canonical LF text")
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise InventoryError("tuple artifact is not UTF-8") from exc
    lines = text[:-1].split("\n")
    if not lines or any(not line for line in lines):
        raise InventoryError("tuple artifact contains an empty row")
    return lines


def verify_hbp_bytes(data: bytes) -> dict[str, int | str]:
    lines = tuple_lines(data)
    parsed = [parse_tuple_line(line) for line in lines]
    if parsed[0][0] != "FOLDER3DRUN" or tuple(parsed[0][1]) != HEADER_FIELDS:
        raise InventoryError("HBP header field contract mismatch")
    header = parsed[0][1]
    if header["schema"] != SCHEMA:
        raise InventoryError("HBP schema mismatch")
    valid_sha256(header["source_capture_sha256"], "source capture")
    valid_sha256(header["public_set_sha256"], "public repository set")
    if header["surface"] != "MEASURED_GITHUB_PUBLIC":
        raise InventoryError("HBP surface mismatch")
    if header["public_metadata_only"] != "1":
        raise InventoryError("HBP public metadata boundary mismatch")
    expected_middle_tags = ("CENTER", "RECIPE", "BOUNDARY")
    if tuple(tag for tag, _ in parsed[1:4]) != expected_middle_tags:
        raise InventoryError("HBP prelude row order mismatch")
    if tuple(parsed[1][1]) != CENTER_FIELDS:
        raise InventoryError("HBP center field contract mismatch")
    recipe = parsed[2][1]
    if tuple(recipe) != RECIPE_FIELDS:
        raise InventoryError("HBP recipe field contract mismatch")
    required_zero = (
        "paths_published",
        "path_hashes_published",
        "tree_sha1_published",
        "blob_bodies_read",
        "private_repo_endpoint_calls",
        "path_dictionary_resistance_claim",
    )
    if any(recipe.get(key) != "0" for key in required_zero):
        raise InventoryError("HBP acquisition disclosure boundary mismatch")
    if recipe.get("git_tree_commitments") != "1":
        raise InventoryError("HBP tree commitment flag mismatch")
    boundary = parsed[3][1]
    if tuple(boundary) != BOUNDARY_FIELDS:
        raise InventoryError("HBP boundary field contract mismatch")
    if any(
        boundary.get(key) != "0"
        for key in (
            "private_repo_rows",
            "private_repo_names",
            "credentials",
            "raw_paths",
            "raw_bodies",
            "network_in_renderer",
            "execution",
            "system_affirmed",
        )
    ):
        raise InventoryError("HBP boundary row mismatch")
    if parsed[-3][0] != "HASH" or parsed[-2][0] != "SUMMARY":
        raise InventoryError("HBP terminal row order mismatch")
    if parsed[-1][0] != "FOLDER3DFTR":
        raise InventoryError("HBP footer tag mismatch")

    folder_pairs = parsed[4:-3]
    folder_lines = lines[4:-3]
    if any(tag != "FOLDER" or tuple(fields) != FOLDER_FIELDS for tag, fields in folder_pairs):
        raise InventoryError("FOLDER field contract mismatch")
    repositories = parse_uint(header["repositories"], "repository count", MAX_REPOSITORIES)
    branched = parse_uint(header["branched"], "branched count", repositories)
    unborn = parse_uint(header["unborn"], "unborn count", repositories)
    root_nodes = parse_uint(header["root_nodes"], "root node count", repositories)
    tree_nodes = parse_uint(
        header["tree_nodes"], "tree node count", MAX_FOLDERS_TOTAL
    )
    folders_count = parse_uint(header["folders"], "folder count", MAX_FOLDERS_TOTAL)
    if branched + unborn != repositories or root_nodes != branched:
        raise InventoryError("HBP repository strata do not add up")
    if root_nodes + tree_nodes != folders_count or folders_count != len(folder_pairs):
        raise InventoryError("HBP folder strata do not add up")

    by_id: dict[str, tuple[str, dict[str, str]]] = {}
    roots_by_repo: dict[str, int] = {}
    direct_blobs = direct_trees = direct_commits = direct_symlinks = 0
    for expected_index, (tag, fields) in enumerate(folder_pairs):
        del tag
        index = parse_uint(fields["i"], "folder index", MAX_FOLDERS_TOTAL)
        if index != expected_index:
            raise InventoryError("FOLDER indexes are not contiguous")
        repo_id = valid_sha256(fields["repo_id"], "repository ID")
        folder_id = valid_sha256(fields["folder_id"], "folder ID")
        parent_id = valid_sha256(fields["parent_folder_id"], "parent folder ID")
        if folder_id in by_id:
            raise InventoryError("duplicate FOLDER occurrence ID")
        sibling = parse_uint(fields["sibling_ordinal"], "sibling ordinal", 0xFFFFFFFF)
        level = parse_uint(fields["level"], "folder level", MAX_LEVEL)
        tree_sha = valid_sha256(fields["tree_commitment_sha256"], "tree commitment")
        source_kind = fields["source_kind"]
        blobs = parse_uint(fields["direct_blobs"], "direct blob count", MAX_ENTRIES_TOTAL)
        trees = parse_uint(fields["direct_trees"], "direct tree count", MAX_ENTRIES_TOTAL)
        commits = parse_uint(
            fields["direct_commits"], "direct commit count", MAX_ENTRIES_TOTAL
        )
        symlinks = parse_uint(
            fields["direct_symlinks"], "direct symlink count", MAX_ENTRIES_TOTAL
        )
        if symlinks > blobs:
            raise InventoryError("direct symlinks exceed direct blobs")
        if source_kind == "REPOSITORY_ROOT":
            if level != 0 or parent_id != ZERO_SHA256 or sibling != 0:
                raise InventoryError("repository root occurrence invariant failed")
            roots_by_repo[repo_id] = roots_by_repo.get(repo_id, 0) + 1
        elif source_kind == "GIT_TREE":
            if level == 0 or parent_id == ZERO_SHA256:
                raise InventoryError("Git tree occurrence invariant failed")
        else:
            raise InventoryError("unknown FOLDER source kind")
        expected_folder_id = folder_occurrence_id(
            header["source_capture_sha256"], repo_id, parent_id, sibling, tree_sha
        )
        if folder_id != expected_folder_id:
            raise InventoryError("FOLDER occurrence commitment mismatch")
        expected_object = folder_object_sha256(
            index=index,
            repo_id=repo_id,
            folder_id=folder_id,
            parent_folder_id=parent_id,
            sibling_ordinal=sibling,
            level=level,
            tree_commitment_sha256=tree_sha,
            source_kind=source_kind,
            direct_blobs=blobs,
            direct_trees=trees,
            direct_commits=commits,
            direct_symlinks=symlinks,
        )
        if fields["object_sha256"] != expected_object:
            raise InventoryError("FOLDER object commitment mismatch")
        expected_x, expected_y, expected_z, expected_color = projection_from_object(
            expected_object
        )
        if (
            fields["x"],
            fields["y"],
            fields["z"],
            fields["color"],
        ) != (
            str(expected_x),
            str(expected_y),
            str(expected_z),
            expected_color,
        ):
            raise InventoryError("FOLDER checked projection mismatch")
        by_id[folder_id] = (repo_id, fields)
        direct_blobs += blobs
        direct_trees += trees
        direct_commits += commits
        direct_symlinks += symlinks
    if len(roots_by_repo) != branched or any(count != 1 for count in roots_by_repo.values()):
        raise InventoryError("repository root occurrence accounting mismatch")

    children: dict[str, list[dict[str, str]]] = {}
    for _, fields in by_id.values():
        if fields["source_kind"] == "GIT_TREE":
            parent = by_id.get(fields["parent_folder_id"])
            if parent is None:
                raise InventoryError("FOLDER parent occurrence is missing")
            parent_repo, parent_fields = parent
            if parent_repo != fields["repo_id"]:
                raise InventoryError("FOLDER parent crosses repository identity")
            if int(fields["level"]) != int(parent_fields["level"]) + 1:
                raise InventoryError("FOLDER level does not follow its parent")
            children.setdefault(fields["parent_folder_id"], []).append(fields)
    for folder_id, (_, fields) in by_id.items():
        child_rows = children.get(folder_id, [])
        ordinals = sorted(int(child["sibling_ordinal"]) for child in child_rows)
        if ordinals != list(range(len(child_rows))):
            raise InventoryError("FOLDER sibling ordinals are not contiguous")
        if int(fields["direct_trees"]) != len(child_rows):
            raise InventoryError("FOLDER direct tree count differs from children")

    object_hasher = hashlib.sha256()
    for row in folder_lines:
        encoded = row.encode("utf-8")
        object_hasher.update(checked_u64(len(encoded), "folder row length"))
        object_hasher.update(encoded)
    object_root = object_hasher.hexdigest()
    hash_fields = parsed[-3][1]
    if tuple(hash_fields) != HASH_FIELDS:
        raise InventoryError("HBP hash field contract mismatch")
    if (
        hash_fields.get("role") != "SPHERICAL_OBJECT_COMMITMENT"
        or hash_fields.get("algorithm") != "SHA256"
        or hash_fields.get("value") != object_root
        or hash_fields.get("distinct_from_hbp_byte_sha") != "1"
    ):
        raise InventoryError("HBP spherical object commitment mismatch")

    summary = parsed[-2][1]
    if tuple(summary) != SUMMARY_FIELDS:
        raise InventoryError("HBP summary field contract mismatch")
    summary_expected = {
        "repositories": repositories,
        "branched": branched,
        "unborn": unborn,
        "repository_roots": root_nodes,
        "git_tree_folder_occurrences": tree_nodes,
        "folders": folders_count,
        "max_level": max((int(fields["level"]) for _, fields in by_id.values()), default=0),
        "direct_blobs": direct_blobs,
        "direct_trees": direct_trees,
        "direct_commits": direct_commits,
        "gitlinks": direct_commits,
        "symlinks": direct_symlinks,
        "unique_tree_objects": len(
            {fields["tree_commitment_sha256"] for _, fields in by_id.values()}
        ),
    }
    for key, expected in summary_expected.items():
        if parse_uint(summary[key], f"summary {key}", UINT64_MAX) != expected:
            raise InventoryError(f"HBP summary {key} mismatch")
    if direct_trees != tree_nodes:
        raise InventoryError("summary direct tree and occurrence counts differ")

    footer = parsed[-1][1]
    if tuple(footer) != ("body_sha256", "rows", "repositories", "folders", "json"):
        raise InventoryError("HBP footer field contract mismatch")
    body = ("\n".join(lines[:-1]) + "\n").encode("utf-8")
    if footer["body_sha256"] != sha256(body):
        raise InventoryError("HBP footer body hash mismatch")
    if parse_uint(footer["rows"], "HBP footer rows") != len(lines):
        raise InventoryError("HBP footer row count mismatch")
    if parse_uint(footer["repositories"], "HBP footer repositories") != repositories:
        raise InventoryError("HBP footer repository count mismatch")
    if parse_uint(footer["folders"], "HBP footer folders") != folders_count:
        raise InventoryError("HBP footer folder count mismatch")
    return {
        "repositories": repositories,
        "branched": branched,
        "unborn": unborn,
        "folders": folders_count,
        "object_root": object_root,
        "public_set_sha256": header["public_set_sha256"],
        "body_sha256": footer["body_sha256"],
    }


def verify_hbi_bytes(
    data: bytes, expected_hbp_sha256: str | None = None
) -> dict[str, int | str]:
    lines = tuple_lines(data, maximum_bytes=64 * 1024)
    parsed = [parse_tuple_line(line) for line in lines]
    if [tag for tag, _ in parsed] != [
        "FOLDER3DHBI",
        "SOURCE",
        "HBP",
        "HASH",
        "BOUNDARY",
        "FOLDER3DHBIFTR",
    ]:
        raise InventoryError("HBI row order mismatch")
    if parsed[0][1] != {"schema": SCHEMA, "version": "1", "json": "0"}:
        raise InventoryError("HBI header mismatch")
    source = parsed[1][1]
    if tuple(source) != (
        "public_set_sha256",
        "source_capture_sha256",
        "surface",
        "json",
    ):
        raise InventoryError("HBI source field contract mismatch")
    public_set_sha = valid_sha256(
        source.get("public_set_sha256", ""), "public repository set"
    )
    valid_sha256(source.get("source_capture_sha256", ""), "source capture")
    if source.get("surface") != "MEASURED_GITHUB_PUBLIC":
        raise InventoryError("HBI source surface mismatch")
    hbp = parsed[2][1]
    if tuple(hbp) != (
        "path",
        "sha256",
        "bytes",
        "repositories",
        "folders",
        "json",
    ):
        raise InventoryError("HBI HBP field contract mismatch")
    hbp_sha = valid_sha256(hbp.get("sha256", ""), "HBP byte commitment")
    if expected_hbp_sha256 is not None and hbp_sha != expected_hbp_sha256:
        raise InventoryError("HBI references a different HBP byte commitment")
    parse_uint(hbp.get("bytes", ""), "HBP byte count", MAX_OUTPUT_BYTES)
    repositories = parse_uint(
        hbp.get("repositories", ""), "HBI repository count", MAX_REPOSITORIES
    )
    folders = parse_uint(
        hbp.get("folders", ""), "HBI folder count", MAX_FOLDERS_TOTAL
    )
    if tuple(parsed[3][1]) != ("role", "algorithm", "value", "json"):
        raise InventoryError("HBI hash field contract mismatch")
    valid_sha256(parsed[3][1].get("value", ""), "HBI object root")
    boundary = parsed[4][1]
    if tuple(boundary) != (
        "paths_published",
        "path_hashes_published",
        "tree_sha1_published",
        "private_repo_rows",
        "raw_bodies",
        "execution_authority",
        "json",
    ):
        raise InventoryError("HBI boundary field contract mismatch")
    if any(
        boundary.get(key) != "0"
        for key in (
            "paths_published",
            "path_hashes_published",
            "tree_sha1_published",
            "private_repo_rows",
            "raw_bodies",
            "execution_authority",
        )
    ):
        raise InventoryError("HBI boundary mismatch")
    footer = parsed[-1][1]
    if tuple(footer) != ("body_sha256", "rows", "json"):
        raise InventoryError("HBI footer field contract mismatch")
    body = ("\n".join(lines[:-1]) + "\n").encode("utf-8")
    if footer.get("body_sha256") != sha256(body):
        raise InventoryError("HBI footer body hash mismatch")
    if parse_uint(footer.get("rows", ""), "HBI footer rows") != len(lines):
        raise InventoryError("HBI footer row count mismatch")
    return {
        "repositories": repositories,
        "folders": folders,
        "hbp_sha256": hbp_sha,
        "public_set_sha256": public_set_sha,
        "body_sha256": footer["body_sha256"],
    }


def is_link_like(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        junction = getattr(path, "is_junction", None)
        return bool(junction and junction())
    except (OSError, ValueError):
        return True


def reject_link_chain(path: Path) -> None:
    candidate = path.absolute()
    for part in (candidate, *candidate.parents):
        if part.exists() and is_link_like(part):
            raise InventoryError("link-like output path component rejected")


def reject_existing_hardlink(path: Path) -> None:
    if path.exists():
        try:
            if path.stat(follow_symlinks=False).st_nlink != 1:
                raise InventoryError("hard-linked output role rejected")
        except TypeError:
            if os.stat(path, follow_symlinks=False).st_nlink != 1:
                raise InventoryError("hard-linked output role rejected")


def output_roles(hbp_path: Path, hbi_path: Path) -> tuple[Path, Path, Path, Path]:
    hbp = hbp_path.absolute()
    hbi = hbi_path.absolute()
    roles = (
        hbp,
        hbp.with_name(hbp.name + ".sha256"),
        hbi,
        hbi.with_name(hbi.name + ".sha256"),
    )
    normalized: set[str] = set()
    for role in roles:
        reject_link_chain(role)
        reject_existing_hardlink(role)
        key = os.path.normcase(str(role.resolve(strict=False)))
        if key in normalized:
            raise InventoryError("output path role collision")
        normalized.add(key)
    for left_index, left in enumerate(roles):
        for right in roles[left_index + 1 :]:
            if left.exists() and right.exists() and os.path.samefile(left, right):
                raise InventoryError("physical output path role collision")
    return roles


def atomic_write(path: Path, data: bytes) -> None:
    reject_link_chain(path)
    reject_existing_hardlink(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    reject_link_chain(path.parent)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    if temporary.exists() or is_link_like(temporary):
        raise InventoryError("unsafe temporary output role")
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if temporary.stat(follow_symlinks=False).st_nlink != 1:
            raise InventoryError("temporary output role became hard-linked")
        reject_link_chain(path)
        reject_existing_hardlink(path)
        os.replace(temporary, path)
    finally:
        if temporary.exists() and not is_link_like(temporary):
            temporary.unlink()


def sidecar_bytes(path: Path, data: bytes) -> bytes:
    return f"{sha256(data)}  {path.name}\n".encode("ascii")


def verify_sidecar_bytes(path: Path, data: bytes, sidecar: bytes) -> None:
    expected = sidecar_bytes(path, data)
    if sidecar != expected or b"\r" in sidecar:
        raise InventoryError("SHA-256 sidecar mismatch")


def write_inventory(
    hbp_path: Path,
    hbi_path: Path,
    hbp: bytes,
    hbi: bytes,
) -> None:
    hbp_role, hbp_sidecar, hbi_role, hbi_sidecar = output_roles(
        hbp_path, hbi_path
    )
    verify_hbp_bytes(hbp)
    verify_hbi_bytes(hbi, expected_hbp_sha256=sha256(hbp))
    hbp_sidecar_bytes = sidecar_bytes(hbp_role, hbp)
    hbi_sidecar_bytes = sidecar_bytes(hbi_role, hbi)
    verify_sidecar_bytes(hbp_role, hbp, hbp_sidecar_bytes)
    verify_sidecar_bytes(hbi_role, hbi, hbi_sidecar_bytes)
    atomic_write(hbp_role, hbp)
    atomic_write(hbp_sidecar, hbp_sidecar_bytes)
    # The HBI is the final commit marker.  Its already-computed sidecar is placed
    # first so a crash cannot expose a new HBI without its matching commitment.
    atomic_write(hbi_sidecar, hbi_sidecar_bytes)
    atomic_write(hbi_role, hbi)


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", default=DEFAULT_OWNER)
    parser.add_argument("--gh", default=shutil.which("gh") or "gh")
    parser.add_argument(
        "--output", type=Path, default=root / "PUBLIC-FOLDER-3D-TREE.hbp"
    )
    parser.add_argument(
        "--index", type=Path, default=root / "PUBLIC-FOLDER-3D-TREE.hbi"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if OWNER_RE.fullmatch(args.owner) is None:
        raise InventoryError("invalid GitHub owner login")
    gh = shutil.which(args.gh) if os.path.sep not in args.gh else args.gh
    if not gh or not Path(gh).is_file():
        raise InventoryError("gh executable not found")
    output, _, index, _ = output_roles(args.output, args.index)
    source = GhPublicSource(gh)
    source.ensure_authenticated()
    captured_at = (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    inventory = acquire_inventory(source, args.owner, captured_at)
    hbp = build_hbp(inventory)
    object_root = folder_object_root(inventory.folders)
    hbi = build_hbi(output.name, hbp, object_root, inventory)
    write_inventory(output, index, hbp, hbi)
    print(
        f"FOLDER3D|PASS=1|repositories={inventory.repositories}"
        f"|branched={inventory.branched}|unborn={inventory.unborn}"
        f"|folders={len(inventory.folders)}|max_level={inventory.max_level}"
        f"|hbp_sha256={sha256(hbp)}|hbi_sha256={sha256(hbi)}"
        f"|source_capture_sha256={inventory.source_capture_sha256}"
        "|private_repo_rows=0|raw_paths=0|path_hashes_published=0|json=0"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (InventoryError, OSError, subprocess.SubprocessError) as exc:
        del exc
        print(
            "FOLDER3D|PASS=0|error=BOUNDED_ACQUISITION_OR_INTEGRITY|json=0",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
