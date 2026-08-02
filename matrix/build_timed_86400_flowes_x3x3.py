#!/usr/bin/env python3
"""Build or watch the additive folder-Calming-OIL FLOWes X3 X3 V2 bundle.

The production watch credits only elapsed ``time.monotonic_ns()`` within a live
session.  A restart resumes from the last sealed checkpoint; wall-clock gaps and
uncheckpointed seconds receive no credit.  ``--fake-clock-build`` is a deterministic
CI fixture and is explicitly tagged as non-measured timing.

This program is a static public descriptor builder.  It performs no network access,
grants no execution authority, and emits no physical light or energy.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import re
import struct
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Protocol, Sequence
from urllib.parse import quote


SCHEMA = "ASOLARIA-TIMED-86400-FOLDER-CALMING-OILS-FLOWes-X3-X3-V2"
SOURCE_SCHEMA = "ASOLARIA-PUBLIC-FOLDER-CALMING-OILS-RUST-181-V1"
TARGET_SECONDS = 86_400
SOURCE_HBP = "PUBLIC-FOLDER-CALMING-OILS.hbp"
SOURCE_HBI = "PUBLIC-FOLDER-CALMING-OILS.hbi"
COMMITTED_SOURCE_HBP_SHA256 = (
    "43300780cac2b85e3ed6cfa10398052f530ccbf76c43b404e650c26c9ed8b006"
)
COMMITTED_SOURCE_HBI_SHA256 = (
    "9920d5cb2031d6453fba2d410e4b2f6e0136a4537fa6ea2ea9385c163503a28b"
)

BASE = "TIMED-86400-FOLDER-CALMING-OILS-FLOWes-X3-X3-V2"
OUTPUT_HBP = BASE + ".hbp"
OUTPUT_HBI = BASE + ".hbi"
OUTPUT_SVG = BASE + ".svg"
OUTPUT_GGUF = BASE + ".gguf"
OUTPUT_STDOUT = BASE + "-STDOUT.hbp"
OUTPUT_JOURNAL = BASE + "-JOURNAL.hbp"
OUTPUT_NAMES = (
    OUTPUT_HBP,
    OUTPUT_HBI,
    OUTPUT_SVG,
    OUTPUT_GGUF,
    OUTPUT_STDOUT,
    OUTPUT_JOURNAL,
)

FAMILIES = ("BROWN", "ANTI_BROWN", "ANTI_ANTI_BROWN")
DIRECTIONS = ("NEGATIVE", "CENTRE", "POSITIVE")
CENTER_MEMBERS = ("HBI", "HBP", "SHA", "SH", "HASH")
CENTER_TRAVERSAL = "HBI->HBP->SH->HASH->SHA"
COMMITMENT_LABELS = CENTER_MEMBERS
OBSERVATION_LIMIT = 60

GGUF_MAGIC = 0x46554747
GGUF_VERSION = 3
GGUF_TYPE_UINT32 = 4
GGUF_TYPE_STRING = 8
GGUF_TYPE_UINT64 = 10
GGML_TYPE_I8 = 24
GGUF_ALIGNMENT = 32
DESCRIPTOR_WIDTH = 64
SHA256_RE = re.compile(r"[0-9a-f]{64}")


class FlowesError(ValueError):
    """A closed-bundle or journal invariant failed."""


@dataclass(frozen=True)
class SourceLeaf:
    index: int
    folder_i: int
    family_i: int
    family: str
    source_level: int
    repo_id: str
    folder_id: str
    leaf_id: str
    tree_commitment: str
    object_sha256: str
    view_x: int
    view_y: int
    view_z: int
    projected_u: int
    projected_v: int
    color: str
    hbi: str
    hbp: str
    sh: str
    hash_value: str
    sha: str


@dataclass(frozen=True)
class SourceBundle:
    hbp: bytes
    hbi: bytes
    hbp_sha256: str
    hbi_sha256: str
    folder_count: int
    leaves: tuple[SourceLeaf, ...]


@dataclass(frozen=True)
class Session:
    index: int
    baseline_seconds: int


@dataclass(frozen=True)
class Checkpoint:
    index: int
    checkpoint_seconds: int
    session_i: int
    session_credited_seconds: int
    previous_hash: str
    checkpoint_hash: str


@dataclass(frozen=True)
class Journal:
    target_seconds: int
    timing_mode: str
    source_hbp_sha256: str
    source_hbi_sha256: str
    sessions: tuple[Session, ...]
    checkpoints: tuple[Checkpoint, ...]

    @property
    def accumulated_seconds(self) -> int:
        return self.checkpoints[-1].checkpoint_seconds if self.checkpoints else 0

    @property
    def complete(self) -> bool:
        return self.accumulated_seconds == self.target_seconds


@dataclass(frozen=True)
class Ring:
    index: int
    level: int
    checkpoint_seconds: int
    family_i: int
    family: str
    direction_i: int
    direction: str
    window_start: int
    observed_rows: int
    reflect_2d_hash: str
    collect_3d_hash: str
    signed_2d_hash: str
    previous_ring_hash: str
    ring_hash: str


@dataclass(frozen=True)
class Cell:
    index: int
    source: SourceLeaf
    direction_i: int
    direction: str
    flowe_id: str
    commitments: tuple[str, str, str, str, str]


class Clock(Protocol):
    def monotonic_ns(self) -> int: ...
    def sleep(self, seconds: float) -> None: ...


class SystemClock:
    def monotonic_ns(self) -> int:
        return time.monotonic_ns()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


class WriterLock:
    """Nonblocking OS-held lock keyed to one resolved output directory.

    The lock file lives in the platform temporary directory so normal builds do
    not leave repository artifacts.  Its tuple bytes are diagnostic only; the OS
    advisory lock is the authority and is released automatically on process death.
    """

    def __init__(self, output_dir: Path, mode: str):
        self.output_dir = output_dir.resolve()
        self.output_identity = os.path.normcase(
            os.path.realpath(str(self.output_dir))
        )
        self.mode = mode
        self.path: Path | None = None
        self.fd: int | None = None
        self._windows = os.name == "nt"

    def __enter__(self) -> "WriterLock":
        lock_root = Path(tempfile.gettempdir()) / "asolaria-flowes-writer-locks"
        lock_root.mkdir(parents=True, exist_ok=True)
        key = sha256_bytes(self.output_identity.encode("utf-8"))
        self.path = lock_root / (key + ".lock")
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if self._windows:
                import msvcrt

                if os.fstat(fd).st_size < 1:
                    os.write(fd, b"\0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as exc:
            os.close(fd)
            raise FlowesError("WRITER_LOCK_ACTIVE") from exc
        self.fd = fd
        metadata = (
            tuple_row(
                "FLOWEX9WRITERLOCK", schema=SCHEMA, pid=os.getpid(), mode=self.mode,
                output_dir_sha256=key, os_advisory_lock=1,
                lock_bytes_authority=0, json=0,
            )
            + "\n"
        ).encode("utf-8")
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        os.write(fd, metadata)
        os.fsync(fd)
        return self

    def assert_held(self, output_dir: Path) -> None:
        candidate_identity = os.path.normcase(
            os.path.realpath(str(output_dir.resolve()))
        )
        if self.fd is None or candidate_identity != self.output_identity:
            raise FlowesError("WRITER_LOCK_REQUIRED")

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self.fd is None:
            return
        fd = self.fd
        self.fd = None
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            if self._windows:
                import msvcrt

                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def domain_hash(domain: str, *parts: object) -> str:
    digest = hashlib.sha256()
    domain_bytes = domain.encode("utf-8")
    digest.update(len(domain_bytes).to_bytes(8, "big"))
    digest.update(domain_bytes)
    for part in parts:
        raw = part if isinstance(part, bytes) else str(part).encode("utf-8")
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def encode_value(value: object) -> str:
    return quote(str(value), safe="._,-")


def tuple_row(tag: str, **fields: object) -> str:
    return tag + "|" + "|".join(
        f"{key}={encode_value(value)}" for key, value in fields.items()
    )


def parse_tuple(line: str, expected_tag: str | None = None) -> dict[str, str]:
    parts = line.split("|")
    if not parts or not parts[0]:
        raise FlowesError("TUPLE_TAG")
    if expected_tag is not None and parts[0] != expected_tag:
        raise FlowesError(f"TUPLE_TAG:{parts[0]}:{expected_tag}")
    fields: dict[str, str] = {}
    for part in parts[1:]:
        if "=" not in part:
            raise FlowesError("TUPLE_FIELD")
        key, value = part.split("=", 1)
        if not key or key in fields:
            raise FlowesError("TUPLE_DUPLICATE")
        fields[key] = value
    return fields


def require_fields(
    fields: dict[str, str], expected: dict[str, str], context: str
) -> None:
    for key, value in expected.items():
        if fields.get(key) != value:
            raise FlowesError(f"{context}:{key}")


def require_hash(value: str, context: str) -> str:
    if SHA256_RE.fullmatch(value) is None:
        raise FlowesError(f"HASH:{context}")
    return value


def sidecar_bytes(name: str, data: bytes) -> bytes:
    return f"{sha256_bytes(data)}  {name}\n".encode("ascii")


def verify_sidecar(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise FlowesError(f"MISSING_OR_LINK:{path.name}")
    data = path.read_bytes()
    sidecar = path.with_name(path.name + ".sha256")
    if not sidecar.is_file() or sidecar.is_symlink():
        raise FlowesError(f"SIDECAR_MISSING_OR_LINK:{path.name}")
    raw = sidecar.read_bytes()
    if raw != sidecar_bytes(path.name, data):
        raise FlowesError(f"SIDECAR_MISMATCH:{path.name}")
    return data


def verify_footer(lines: Sequence[str], tag: str) -> None:
    footer = parse_tuple(lines[-1], tag)
    body = ("\n".join(lines[:-1]) + "\n").encode("utf-8")
    require_fields(
        footer,
        {"body_sha256": sha256_bytes(body), "rows": str(len(lines)), "json": "0"},
        tag,
    )


def schedule(target_seconds: int) -> tuple[int, ...]:
    if target_seconds < 1:
        raise FlowesError("TARGET_SECONDS")
    values = [1, 2, 3, 4]
    value = 8
    while value < target_seconds:
        values.append(value)
        value *= 2
    values.append(target_seconds)
    return tuple(sorted(set(value for value in values if value <= target_seconds)))


def load_source(directory: Path, *, require_committed: bool = True) -> SourceBundle:
    directory = directory.resolve()
    if not directory.is_dir() or directory.is_symlink():
        raise FlowesError("SOURCE_DIRECTORY")
    hbp = verify_sidecar(directory / SOURCE_HBP)
    hbi = verify_sidecar(directory / SOURCE_HBI)
    if b"\r" in hbp or b"\r" in hbi:
        raise FlowesError("SOURCE_CR")
    hbp_sha = sha256_bytes(hbp)
    hbi_sha = sha256_bytes(hbi)
    if require_committed and (
        hbp_sha != COMMITTED_SOURCE_HBP_SHA256
        or hbi_sha != COMMITTED_SOURCE_HBI_SHA256
    ):
        raise FlowesError("COMMITTED_SOURCE_SHA256")
    try:
        hbp_lines = hbp.decode("utf-8").splitlines()
        hbi_lines = hbi.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise FlowesError("SOURCE_UTF8") from exc
    if any(not line.endswith("|json=0") for line in hbp_lines + hbi_lines):
        raise FlowesError("SOURCE_JSON0")
    verify_footer(hbp_lines, "FOLDEROILFTR")
    verify_footer(hbi_lines, "FOLDEROILIDXFTR")
    header = parse_tuple(hbp_lines[0], "FOLDEROILRUN")
    require_fields(header, {"schema": SOURCE_SCHEMA, "families": "3", "json": "0"}, "SOURCE_HEADER")
    folder_count = int(header["folders"])
    leaf_count = int(header["leaves"])
    if folder_count < 1 or leaf_count != folder_count * len(FAMILIES):
        raise FlowesError("SOURCE_POPULATION")
    if len(hbp_lines) != leaf_count + 13 or len(hbi_lines) != 9:
        raise FlowesError("SOURCE_ROW_COUNT")
    index_header = parse_tuple(hbi_lines[0], "FOLDEROILIDX")
    require_fields(
        index_header,
        {
            "schema": SOURCE_SCHEMA,
            "folders": str(folder_count),
            "families": "3",
            "leaves": str(leaf_count),
            "json": "0",
        },
        "SOURCE_INDEX",
    )
    hbp_artifacts = [
        parse_tuple(line, "ARTIFACT")
        for line in hbi_lines
        if line.startswith("ARTIFACT|")
        and parse_tuple(line).get("kind") == "HBP"
    ]
    if len(hbp_artifacts) != 1:
        raise FlowesError("SOURCE_HBI_HBP_COUNT")
    require_fields(
        hbp_artifacts[0],
        {"file": SOURCE_HBP, "sha256": hbp_sha, "json": "0"},
        "SOURCE_HBI_HBP",
    )
    family_rows = [parse_tuple(line, "FAMILY") for line in hbp_lines if line.startswith("FAMILY|")]
    if tuple(row.get("name") for row in family_rows) != FAMILIES:
        raise FlowesError("SOURCE_FAMILIES")

    leaves: list[SourceLeaf] = []
    by_folder: dict[int, list[SourceLeaf]] = {}
    for line in hbp_lines:
        if not line.startswith("OIL|"):
            continue
        row = parse_tuple(line, "OIL")
        for key in (
            "path_bytes_embedded", "media_bytes_embedded", "repository_bytes_embedded",
            "credentials", "network", "execution", "physical_energy", "authority", "json",
        ):
            if row.get(key) != "0":
                raise FlowesError(f"SOURCE_BOUNDARY:{key}")
        family = row["family"]
        if family not in FAMILIES:
            raise FlowesError("SOURCE_LEAF_FAMILY")
        commitments = tuple(
            require_hash(row[key], f"SOURCE_{key}") for key in ("hbi", "hbp", "sha", "sh", "hash")
        )
        if len(set(commitments)) != len(commitments):
            raise FlowesError("SOURCE_COMMITMENT_COLLISION")
        leaf = SourceLeaf(
            index=int(row["i"]), folder_i=int(row["folder_i"]),
            family_i=FAMILIES.index(family), family=family,
            source_level=int(row["level"]), repo_id=require_hash(row["repo_id"], "repo_id"),
            folder_id=require_hash(row["folder_id"], "folder_id"),
            leaf_id=require_hash(row["leaf_id"], "leaf_id"),
            tree_commitment=require_hash(row["tree_commitment_sha256"], "tree_commitment"),
            object_sha256=require_hash(row["object_sha256"], "object_sha256"),
            view_x=int(row["view_x"]), view_y=int(row["view_y"]), view_z=int(row["view_z"]),
            projected_u=int(row["projected_u"]), projected_v=int(row["projected_v"]),
            color=row["color"], hbi=commitments[0], hbp=commitments[1],
            sha=commitments[2], sh=commitments[3], hash_value=commitments[4],
        )
        if leaf.index != len(leaves) or not 0 <= leaf.folder_i < folder_count:
            raise FlowesError("SOURCE_LEAF_INDEX")
        leaves.append(leaf)
        by_folder.setdefault(leaf.folder_i, []).append(leaf)
    if len(leaves) != leaf_count or len(by_folder) != folder_count:
        raise FlowesError("SOURCE_LEAF_COUNT")
    for folder_i in range(folder_count):
        group = by_folder.get(folder_i, [])
        if tuple(leaf.family for leaf in group) != FAMILIES:
            raise FlowesError(f"SOURCE_FOLDER_FAMILIES:{folder_i}")
        if len({leaf.folder_id for leaf in group}) != 1:
            raise FlowesError(f"SOURCE_FOLDER_ID:{folder_i}")
    return SourceBundle(hbp, hbi, hbp_sha, hbi_sha, folder_count, tuple(leaves))


def checkpoint_hash(
    source_hbp_sha256: str,
    target_seconds: int,
    checkpoint_i: int,
    seconds: int,
    session_i: int,
    credited: int,
    previous_hash: str,
) -> str:
    return domain_hash(
        SCHEMA + "|JOURNAL_CHECKPOINT",
        source_hbp_sha256, target_seconds, checkpoint_i, seconds,
        session_i, credited, previous_hash,
    )


def journal_bytes(journal: Journal) -> bytes:
    rows = [
        tuple_row(
            "FLOWEX9JOURNAL",
            schema=SCHEMA, target_seconds=journal.target_seconds,
            timing_mode=journal.timing_mode, source_hbp_sha256=journal.source_hbp_sha256,
            source_hbi_sha256=journal.source_hbi_sha256, sessions=len(journal.sessions),
            checkpoint_count=len(journal.checkpoints),
            accumulated_seconds=journal.accumulated_seconds,
            state="COMPLETE" if journal.complete else "IN_PROGRESS",
            network=0, execution=0, authority=0, physical_energy=0, json=0,
        )
    ]
    rows.extend(
        tuple_row(
            "SESSION", i=session.index, baseline_seconds=session.baseline_seconds,
            wall_clock_credit=0, cross_process_gap_credit=0, json=0,
        )
        for session in journal.sessions
    )
    rows.extend(
        tuple_row(
            "CHECKPOINT", i=item.index, checkpoint_seconds=item.checkpoint_seconds,
            session_i=item.session_i, session_credited_seconds=item.session_credited_seconds,
            previous_hash=item.previous_hash, checkpoint_hash=item.checkpoint_hash,
            monotonic_session_only=1, json=0,
        )
        for item in journal.checkpoints
    )
    rows.append(
        tuple_row(
            "BOUNDARY", wall_clock=0, supplied_start_time=0, cross_process_gap_credit=0,
            uncheckpointed_credit=0, network=0, execution=0, authority=0,
            physical_energy=0, json=0,
        )
    )
    body = ("\n".join(rows) + "\n").encode("utf-8")
    rows.append(tuple_row("FLOWEX9JOURNALFTR", body_sha256=sha256_bytes(body), rows=len(rows) + 1, json=0))
    return ("\n".join(rows) + "\n").encode("utf-8")


def parse_journal_bytes(
    data: bytes, source: SourceBundle, target_seconds: int, timing_mode: str
) -> Journal:
    if b"\r" in data:
        raise FlowesError("JOURNAL_CR")
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise FlowesError("JOURNAL_UTF8") from exc
    if len(lines) < 3 or any(not line.endswith("|json=0") for line in lines):
        raise FlowesError("JOURNAL_JSON0")
    verify_footer(lines, "FLOWEX9JOURNALFTR")
    header = parse_tuple(lines[0], "FLOWEX9JOURNAL")
    require_fields(
        header,
        {
            "schema": SCHEMA, "target_seconds": str(target_seconds),
            "timing_mode": timing_mode, "source_hbp_sha256": source.hbp_sha256,
            "source_hbi_sha256": source.hbi_sha256, "network": "0",
            "execution": "0", "authority": "0", "physical_energy": "0", "json": "0",
        },
        "JOURNAL_HEADER",
    )
    session_rows = [parse_tuple(line, "SESSION") for line in lines if line.startswith("SESSION|")]
    checkpoint_rows = [
        parse_tuple(line, "CHECKPOINT") for line in lines if line.startswith("CHECKPOINT|")
    ]
    sessions: list[Session] = []
    for row in session_rows:
        session = Session(int(row["i"]), int(row["baseline_seconds"]))
        if session.index != len(sessions):
            raise FlowesError("JOURNAL_SESSION_INDEX")
        if session.baseline_seconds < 0 or session.baseline_seconds > target_seconds:
            raise FlowesError("JOURNAL_SESSION_BASELINE")
        require_fields(
            row,
            {"wall_clock_credit": "0", "cross_process_gap_credit": "0", "json": "0"},
            "JOURNAL_SESSION",
        )
        prior_rows = [
            item for item in checkpoint_rows if int(item["session_i"]) < session.index
        ]
        expected_baseline = int(prior_rows[-1]["checkpoint_seconds"]) if prior_rows else 0
        if session.baseline_seconds != expected_baseline:
            raise FlowesError("JOURNAL_SESSION_BASELINE_CHAIN")
        sessions.append(session)
    if checkpoint_rows and not sessions:
        raise FlowesError("JOURNAL_CHECKPOINT_WITHOUT_SESSION")

    expected_schedule = schedule(target_seconds)
    checkpoints: list[Checkpoint] = []
    genesis = domain_hash(SCHEMA + "|JOURNAL_GENESIS", source.hbp_sha256, target_seconds)
    previous = genesis
    last_seconds = 0
    last_session_i = 0
    for row in checkpoint_rows:
        index = int(row["i"])
        seconds = int(row["checkpoint_seconds"])
        session_i = int(row["session_i"])
        credited = int(row["session_credited_seconds"])
        if index != len(checkpoints) or index >= len(expected_schedule):
            raise FlowesError("JOURNAL_CHECKPOINT_INDEX")
        if seconds != expected_schedule[index] or not 0 <= session_i < len(sessions):
            raise FlowesError("JOURNAL_CHECKPOINT_POSITION")
        if checkpoints and session_i < last_session_i:
            raise FlowesError("JOURNAL_SESSION_ROLLBACK")
        session = sessions[session_i]
        if session.baseline_seconds > last_seconds:
            raise FlowesError("JOURNAL_SESSION_FUTURE_BASELINE")
        expected_credited = seconds - session.baseline_seconds
        if credited != expected_credited or credited < 0:
            raise FlowesError("JOURNAL_CREDIT")
        expected_hash = checkpoint_hash(
            source.hbp_sha256, target_seconds, index, seconds,
            session_i, credited, previous,
        )
        require_fields(
            row,
            {
                "previous_hash": previous, "checkpoint_hash": expected_hash,
                "monotonic_session_only": "1", "json": "0",
            },
            "JOURNAL_CHECKPOINT",
        )
        checkpoints.append(
            Checkpoint(index, seconds, session_i, credited, previous, expected_hash)
        )
        previous = expected_hash
        last_seconds = seconds
        last_session_i = session_i
    journal = Journal(
        target_seconds, timing_mode, source.hbp_sha256, source.hbi_sha256,
        tuple(sessions), tuple(checkpoints),
    )
    require_fields(
        header,
        {
            "sessions": str(len(sessions)), "checkpoint_count": str(len(checkpoints)),
            "accumulated_seconds": str(journal.accumulated_seconds),
            "state": "COMPLETE" if journal.complete else "IN_PROGRESS",
        },
        "JOURNAL_SUMMARY",
    )
    if journal_bytes(journal) != data:
        raise FlowesError("JOURNAL_CANONICAL")
    return journal


def atomic_write(path: Path, data: bytes) -> None:
    if path.exists() and path.is_symlink():
        raise FlowesError(f"OUTPUT_LINK:{path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="wb", dir=path.parent, prefix=path.name + ".", delete=False
    ) as handle:
        temporary = Path(handle.name)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_sealed(path: Path, data: bytes) -> None:
    atomic_write(path, data)
    atomic_write(path.with_name(path.name + ".sha256"), sidecar_bytes(path.name, data))


def load_journal(
    output_dir: Path, source: SourceBundle, target_seconds: int, timing_mode: str
) -> Journal | None:
    path = output_dir.resolve() / OUTPUT_JOURNAL
    if not path.exists():
        if path.with_name(path.name + ".sha256").exists():
            raise FlowesError("ORPHAN_JOURNAL_SIDECAR")
        return None
    data = verify_sidecar(path)
    return parse_journal_bytes(data, source, target_seconds, timing_mode)


def save_journal(output_dir: Path, journal: Journal, writer_lock: WriterLock) -> None:
    writer_lock.assert_held(output_dir)
    write_sealed(output_dir.resolve() / OUTPUT_JOURNAL, journal_bytes(journal))


def begin_session(journal: Journal) -> Journal:
    if journal.complete:
        return journal
    session = Session(len(journal.sessions), journal.accumulated_seconds)
    return Journal(
        journal.target_seconds, journal.timing_mode,
        journal.source_hbp_sha256, journal.source_hbi_sha256,
        journal.sessions + (session,), journal.checkpoints,
    )


def append_reached_checkpoints(journal: Journal, available_seconds: int) -> Journal:
    if not journal.sessions:
        raise FlowesError("NO_ACTIVE_SESSION")
    active = journal.sessions[-1]
    checkpoints = list(journal.checkpoints)
    expected = schedule(journal.target_seconds)
    genesis = domain_hash(
        SCHEMA + "|JOURNAL_GENESIS", journal.source_hbp_sha256, journal.target_seconds
    )
    previous = checkpoints[-1].checkpoint_hash if checkpoints else genesis
    while len(checkpoints) < len(expected) and expected[len(checkpoints)] <= available_seconds:
        index = len(checkpoints)
        seconds = expected[index]
        credited = seconds - active.baseline_seconds
        if credited < 0:
            raise FlowesError("NEGATIVE_SESSION_CREDIT")
        digest = checkpoint_hash(
            journal.source_hbp_sha256, journal.target_seconds, index,
            seconds, active.index, credited, previous,
        )
        checkpoints.append(
            Checkpoint(index, seconds, active.index, credited, previous, digest)
        )
        previous = digest
    return Journal(
        journal.target_seconds, journal.timing_mode,
        journal.source_hbp_sha256, journal.source_hbi_sha256,
        journal.sessions, tuple(checkpoints),
    )


def fake_complete_journal(source: SourceBundle, target_seconds: int) -> Journal:
    journal = Journal(
        target_seconds, "DETERMINISTIC_FAKE_CLOCK", source.hbp_sha256,
        source.hbi_sha256, (), (),
    )
    journal = begin_session(journal)
    return append_reached_checkpoints(journal, target_seconds)


def _family_leaves(source: SourceBundle) -> tuple[tuple[SourceLeaf, ...], ...]:
    groups = tuple(
        tuple(leaf for leaf in source.leaves if leaf.family == family)
        for family in FAMILIES
    )
    if any(len(group) != source.folder_count for group in groups):
        raise FlowesError("FAMILY_POPULATION")
    return groups


def build_rings(source: SourceBundle, checkpoints: Sequence[int]) -> tuple[Ring, ...]:
    groups = _family_leaves(source)
    previous: dict[tuple[int, int], str] = {
        (family_i, direction_i): domain_hash(
            SCHEMA + "|RING_GENESIS", source.hbp_sha256, family, direction
        )
        for family_i, family in enumerate(FAMILIES)
        for direction_i, direction in enumerate(DIRECTIONS)
    }
    rings: list[Ring] = []
    for level, checkpoint_seconds in enumerate(checkpoints):
        for family_i, family in enumerate(FAMILIES):
            group = groups[family_i]
            observed_rows = min(OBSERVATION_LIMIT, len(group))
            for direction_i, direction in enumerate(DIRECTIONS):
                start = (
                    level * OBSERVATION_LIMIT + direction_i * max(1, OBSERVATION_LIMIT // 3)
                ) % len(group)
                observed = tuple(group[(start + offset) % len(group)] for offset in range(observed_rows))
                reflect_2d = domain_hash(
                    SCHEMA + "|SELF_REFLECT_2D", family, direction, checkpoint_seconds,
                    *(f"{leaf.projected_u},{leaf.projected_v},{leaf.color},{leaf.leaf_id}" for leaf in observed),
                )
                collect_3d = domain_hash(
                    SCHEMA + "|COLLECT_3D", family, direction, checkpoint_seconds,
                    *(f"{leaf.view_x},{leaf.view_y},{leaf.view_z},{leaf.tree_commitment}" for leaf in observed),
                )
                signed_2d = domain_hash(
                    SCHEMA + "|SELF_REDUCE_SIGNED_2D", direction,
                    reflect_2d, collect_3d,
                    *(leaf.leaf_id for leaf in observed),
                )
                prior = previous[(family_i, direction_i)]
                ring_hash = domain_hash(
                    SCHEMA + "|RING_CHAIN", prior, level, checkpoint_seconds,
                    family, direction, observed_rows, reflect_2d, collect_3d, signed_2d,
                )
                rings.append(
                    Ring(
                        len(rings), level, checkpoint_seconds,
                        family_i, family, direction_i, direction,
                        start, observed_rows, reflect_2d, collect_3d,
                        signed_2d, prior, ring_hash,
                    )
                )
                previous[(family_i, direction_i)] = ring_hash
    expected = len(checkpoints) * len(FAMILIES) * len(DIRECTIONS)
    if len(rings) != expected:
        raise AssertionError("ring population")
    return tuple(rings)


def build_cells(source: SourceBundle) -> tuple[Cell, ...]:
    cells: list[Cell] = []
    for leaf in source.leaves:
        for direction_i, direction in enumerate(DIRECTIONS):
            flowe_id = domain_hash(
                SCHEMA + "|FLOWE_ID", source.hbp_sha256,
                leaf.folder_i, leaf.family, leaf.leaf_id, direction,
            )
            commitments = tuple(
                domain_hash(
                    SCHEMA + "|CELL_COMMITMENT|" + label,
                    source.hbp_sha256, leaf.folder_i, leaf.family,
                    leaf.leaf_id, direction, flowe_id,
                )
                for label in COMMITMENT_LABELS
            )
            if len(set(commitments)) != len(COMMITMENT_LABELS):
                raise AssertionError("domain-separated commitment collision")
            cells.append(
                Cell(
                    len(cells), leaf, direction_i, direction, flowe_id,
                    commitments,  # type: ignore[arg-type]
                )
            )
    expected = source.folder_count * len(FAMILIES) * len(DIRECTIONS)
    if len(cells) != expected:
        raise AssertionError("cell population")
    return tuple(cells)


def ring_row(ring: Ring) -> str:
    return tuple_row(
        "RING", i=ring.index, level=ring.level,
        checkpoint_seconds=ring.checkpoint_seconds,
        family_i=ring.family_i, family=ring.family,
        direction_i=ring.direction_i, direction=ring.direction,
        operations="SELF_REFLECT,COLLECT,SELF_REDUCE",
        observed_only=1, future_rows=0, observation_limit=OBSERVATION_LIMIT,
        window_start=ring.window_start, observed_rows=ring.observed_rows,
        transform="2D->3D->SIGNED_2D", reflect_2d_hash=ring.reflect_2d_hash,
        collect_3d_hash=ring.collect_3d_hash, signed_2d_hash=ring.signed_2d_hash,
        previous_ring_hash=ring.previous_ring_hash, ring_hash=ring.ring_hash,
        network=0, execution=0, authority=0, physical_energy=0, json=0,
    )


def cell_row(cell: Cell) -> str:
    hbi, hbp, sha, sh, hash_value = cell.commitments
    leaf = cell.source
    return tuple_row(
        "FLOWE", i=cell.index, folder_i=leaf.folder_i,
        family_i=leaf.family_i, family=leaf.family,
        direction_i=cell.direction_i, direction=cell.direction,
        source_leaf_i=leaf.index, source_leaf_id=leaf.leaf_id,
        source_folder_id=leaf.folder_id, source_tree_commitment=leaf.tree_commitment,
        source_object_sha256=leaf.object_sha256, flowe_id=cell.flowe_id,
        hbi=hbi, hbp=hbp, sha=sha, sh=sh, hash=hash_value,
        commitments_domain_separated=1, commitments_distinct=5,
        network=0, execution=0, authority=0, physical_energy=0, json=0,
    )


def cell_aggregate_hash(cells: Sequence[Cell]) -> str:
    cell_hashes = (
        domain_hash(
            SCHEMA + "|CELL_OBJECT",
            cell.index,
            cell.source.index,
            cell.source.leaf_id,
            cell.direction,
            cell.flowe_id,
            *cell.commitments,
        )
        for cell in cells
    )
    return domain_hash(SCHEMA + "|ALL_CELLS", *cell_hashes)


def build_stdout(source: SourceBundle, journal: Journal) -> bytes:
    rows = [
        tuple_row(
            "FLOWEX9STDOUT", schema=SCHEMA,
            timing_mode=journal.timing_mode, target_seconds=journal.target_seconds,
            source_hbp_sha256=source.hbp_sha256, checkpoint_count=len(journal.checkpoints),
            network=0, execution=0, authority=0, physical_energy=0, json=0,
        )
    ]
    rows.extend(
        tuple_row(
            "OUTWARD", i=item.index, checkpoint_seconds=item.checkpoint_seconds,
            session_i=item.session_i, monotonic_session_only=1,
            checkpoint_hash=item.checkpoint_hash,
            network=0, execution=0, authority=0, physical_energy=0, json=0,
        )
        for item in journal.checkpoints
    )
    rows.append(
        tuple_row(
            "FLOWEX9PASS", complete=1 if journal.complete else 0,
            accumulated_seconds=journal.accumulated_seconds,
            folders=source.folder_count, families=len(FAMILIES), directions=len(DIRECTIONS),
            final_cells=source.folder_count * 9,
            ring_summaries=len(journal.checkpoints) * 9,
            system_affirmed=0, network=0, execution=0, authority=0,
            physical_energy=0, json=0,
        )
    )
    body = ("\n".join(rows) + "\n").encode("utf-8")
    rows.append(
        tuple_row("FLOWEX9STDOUTFTR", body_sha256=sha256_bytes(body), rows=len(rows) + 1, json=0)
    )
    return ("\n".join(rows) + "\n").encode("utf-8")


def build_hbp(
    source: SourceBundle,
    journal: Journal,
    rings: Sequence[Ring],
    cells: Sequence[Cell],
    journal_data: bytes,
) -> tuple[bytes, str]:
    expected_rings = len(schedule(journal.target_seconds)) * 9
    expected_cells = source.folder_count * 9
    if len(rings) != expected_rings or len(cells) != expected_cells:
        raise AssertionError("bundle population")
    ring_commitment = domain_hash(
        SCHEMA + "|ALL_RINGS", *(ring.ring_hash for ring in rings)
    )
    cell_commitment = cell_aggregate_hash(cells)
    object_hash = domain_hash(
        SCHEMA + "|OBJECT", source.hbp_sha256, source.hbi_sha256,
        sha256_bytes(journal_data), ring_commitment, cell_commitment,
    )
    rows = [
        tuple_row(
            "FLOWEX9V2HDR", schema=SCHEMA, status="COMPLETE",
            timing_mode=journal.timing_mode,
            timing_evidence=(
                "MEASURED_MONOTONIC_SESSION_SECONDS"
                if journal.timing_mode == "REAL_MONOTONIC"
                else (
                    "DETERMINISTIC_CI_TEST_ONLY"
                    if journal.timing_mode == "DETERMINISTIC_FAKE_CLOCK"
                    else "INJECTED_CLOCK_TEST_ONLY"
                )
            ),
            target_seconds=journal.target_seconds,
            checkpoints=len(schedule(journal.target_seconds)),
            folders=source.folder_count, families=3, directions=3,
            source_leaves=len(source.leaves), final_cells=len(cells),
            ring_summaries=len(rings), observation_limit=OBSERVATION_LIMIT,
            system_affirmed=0, network=0, execution=0, authority=0,
            physical_energy=0, json=0,
        ),
        tuple_row(
            "SOURCE", kind="HBP", file=SOURCE_HBP, bytes=len(source.hbp),
            sha256=source.hbp_sha256, exact_sidecar_verified=1, json=0,
        ),
        tuple_row(
            "SOURCE", kind="HBI", file=SOURCE_HBI, bytes=len(source.hbi),
            sha256=source.hbi_sha256, exact_sidecar_verified=1, json=0,
        ),
        tuple_row(
            "JOURNAL", file=OUTPUT_JOURNAL, bytes=len(journal_data),
            sha256=sha256_bytes(journal_data), sessions=len(journal.sessions),
            accumulated_monotonic_session_seconds=journal.accumulated_seconds,
            wall_clock_credit=0, cross_process_gap_credit=0,
            uncheckpointed_credit=0, json=0,
        ),
        tuple_row(
            "CENTER", nullspace=0, center_members=",".join(CENTER_MEMBERS),
            traversal=CENTER_TRAVERSAL, commitments_per_cell=5,
            domain_separated=1, sha_equals_hash=0, json=0,
        ),
        tuple_row(
            "AXIS", name="FAMILY", members=",".join(FAMILIES), cardinality=3,
            independent_from="DIRECTION", json=0,
        ),
        tuple_row(
            "AXIS", name="DIRECTION", members=",".join(DIRECTIONS), cardinality=3,
            independent_from="FAMILY", json=0,
        ),
        tuple_row(
            "TRANSFORM", operations="SELF_REFLECT,COLLECT,SELF_REDUCE",
            path="2D->3D->SIGNED_2D", observed_only=1, future_rows=0,
            previous_ring_chaining=1, per_level_max_observed=OBSERVATION_LIMIT, json=0,
        ),
        tuple_row(
            "BOUNDARY", raw_paths=0, media_bytes_embedded=0,
            repository_bytes_embedded=0, credentials=0, network=0,
            execution=0, authority=0, physical_energy=0,
            physical_light_emitted=0, system_affirmed=0, json=0,
        ),
    ]
    rows.extend(ring_row(ring) for ring in rings)
    rows.extend(cell_row(cell) for cell in cells)
    rows.extend(
        [
            tuple_row(
                "HASH", role="FLOWEX9_V2_OBJECT_COMMITMENT", algorithm="SHA256",
                value=object_hash, ring_commitment=ring_commitment,
                cell_commitment=cell_commitment, distinct_from_hbp_byte_sha=1, json=0,
            ),
            tuple_row(
                "SUMMARY", folders=source.folder_count, families=3, directions=3,
                final_cells=len(cells), checkpoints=len(schedule(journal.target_seconds)),
                ring_summaries=len(rings), commitments_per_cell=5,
                sessions=len(journal.sessions), target_seconds=journal.target_seconds,
                accumulated_seconds=journal.accumulated_seconds,
                network=0, execution=0, authority=0, physical_energy=0, json=0,
            ),
        ]
    )
    body = ("\n".join(rows) + "\n").encode("utf-8")
    rows.append(
        tuple_row("FLOWEX9V2FTR", body_sha256=sha256_bytes(body), rows=len(rows) + 1, json=0)
    )
    return ("\n".join(rows) + "\n").encode("utf-8"), object_hash


def _cell_color(family_i: int, direction_i: int) -> str:
    palettes = (
        ("#4A271E", "#8B5A2B", "#D39A63"),
        ("#2E3458", "#665B91", "#A698D3"),
        ("#244A38", "#528461", "#91C78D"),
    )
    return palettes[family_i][direction_i]


def build_svg(
    source: SourceBundle, journal: Journal, rings: Sequence[Ring],
    cells: Sequence[Cell], object_hash: str,
) -> bytes:
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<svg xmlns="http://www.w3.org/2000/svg" width="2400" height="2400" '
        'viewBox="0 0 2400 2400" role="img" aria-labelledby="title description" '
        'data-script="0" data-network="0" data-execution="0" data-authority="0" '
        'data-physical-energy="0">',
        '<title id="title">Folder Calming OIL FLOWes X3 X3 V2</title>',
        '<desc id="description">A static integer projection of every committed folder '
        'Calming-OIL family through three independent signed directions.</desc>',
        '<rect width="2400" height="2400" fill="#0E0C12"/>',
        (
            "<metadata>"
            f"schema={SCHEMA};timing_mode={journal.timing_mode};"
            f"target_seconds={journal.target_seconds};folders={source.folder_count};"
            f"families=3;directions=3;cells={len(cells)};rings={len(rings)};"
            f"source_hbp_sha256={source.hbp_sha256};object_hash={object_hash};"
            "integer_only=1;float=0;script=0;network=0;execution=0;authority=0;"
            "physical_energy=0;SYSTEM_AFFIRMED=0;json=0</metadata>"
        ),
        '<g id="FLOWes-X3-X3-V2">',
    ]
    for cell in cells:
        leaf = cell.source
        # Integer wrapping is only a deterministic static projection, never a physical position.
        x = 1200 + ((leaf.projected_u * 7 + cell.direction_i * 29) % 2200) - 1100
        y = 1200 + ((leaf.projected_v * 7 + leaf.family_i * 31) % 2200) - 1100
        radius = 1 + ((leaf.source_level + cell.direction_i) % 3)
        lines.append(
            f'<circle id="flowe-{cell.flowe_id[:20]}" class="flowe-cell" cx="{x}" cy="{y}" r="{radius}" '
            f'fill="{_cell_color(leaf.family_i, cell.direction_i)}" '
            f'data-folder-i="{leaf.folder_i}" data-family="{leaf.family}" '
            f'data-direction="{cell.direction}" data-source-leaf-id="{leaf.leaf_id}" '
            f'data-flowe-id="{cell.flowe_id}"/>'
        )
    lines.extend(
        [
            "</g>",
            '<g font-family="system-ui,sans-serif" fill="#F4F1E8">',
            '<text x="70" y="90" font-size="38" font-weight="700">FLOWes ×3 ×3 V2</text>',
            f'<text x="70" y="130" font-size="19">{source.folder_count} folders × 3 families × 3 directions = {len(cells)} cells</text>',
            f'<text x="70" y="164" font-size="17">{len(schedule(journal.target_seconds))} checkpoints × 9 axes = {len(rings)} chained rings</text>',
            '<text x="70" y="198" font-size="16">HBI · HBP · SHA · SH · HASH are domain-separated per cell</text>',
            "</g>",
            "</svg>",
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def gguf_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack("<Q", len(raw)) + raw


def metadata_string(key: str, value: str) -> bytes:
    return gguf_string(key) + struct.pack("<I", GGUF_TYPE_STRING) + gguf_string(value)


def metadata_u32(key: str, value: int) -> bytes:
    return gguf_string(key) + struct.pack("<II", GGUF_TYPE_UINT32, value)


def metadata_u64(key: str, value: int) -> bytes:
    return gguf_string(key) + struct.pack("<IQ", GGUF_TYPE_UINT64, value)


def align_up(value: int, alignment: int = GGUF_ALIGNMENT) -> int:
    return (value + alignment - 1) // alignment * alignment


def descriptor_bytes(cells: Sequence[Cell]) -> bytes:
    output = bytearray()
    for cell in cells:
        leaf = cell.source
        output.extend(bytes.fromhex(cell.flowe_id[:16]))
        for commitment in cell.commitments:
            output.extend(bytes.fromhex(commitment[:16]))
        output.extend(bytes.fromhex(leaf.leaf_id[:16]))
        output.extend(leaf.folder_i.to_bytes(4, "little"))
        output.extend(
            bytes(
                (
                    leaf.family_i,
                    cell.direction_i,
                    (0, 128, 255)[cell.direction_i],
                    min(255, leaf.source_level),
                )
            )
        )
    expected = len(cells) * DESCRIPTOR_WIDTH
    if len(output) != expected:
        raise AssertionError(f"descriptor bytes {len(output)} != {expected}")
    return bytes(output)


def build_gguf(
    source: SourceBundle, journal: Journal, cells: Sequence[Cell], object_hash: str
) -> bytes:
    descriptor = descriptor_bytes(cells)
    entries = (
        metadata_string("general.architecture", "asolaria-folder-flowes-x3x3-v2"),
        metadata_string("general.name", BASE),
        metadata_u32("general.alignment", GGUF_ALIGNMENT),
        metadata_string("asolaria.schema", SCHEMA),
        metadata_string("asolaria.payload.kind", "STATIC_PUBLIC_DESCRIPTOR"),
        metadata_string("asolaria.source.hbp.sha256", source.hbp_sha256),
        metadata_string("asolaria.source.hbi.sha256", source.hbi_sha256),
        metadata_u64("asolaria.monitor.target_seconds", journal.target_seconds),
        metadata_string("asolaria.monitor.timing_mode", journal.timing_mode),
        metadata_u32("asolaria.folders", source.folder_count),
        metadata_u32("asolaria.families", len(FAMILIES)),
        metadata_u32("asolaria.directions", len(DIRECTIONS)),
        metadata_u32("asolaria.cells", len(cells)),
        metadata_u32("asolaria.descriptor.width", DESCRIPTOR_WIDTH),
        metadata_string(
            "asolaria.tensor.dimensions",
            f"[feature=64,direction=3,family=3,folder={source.folder_count}]",
        ),
        metadata_string(
            "asolaria.descriptor.iteration_order", "folder,family,direction,feature"
        ),
        metadata_string("asolaria.descriptor.sha256", sha256_bytes(descriptor)),
        metadata_string("asolaria.flowes.object_hash", object_hash),
        metadata_string("asolaria.center.members", ",".join(CENTER_MEMBERS)),
        metadata_u32("asolaria.network_access", 0),
        metadata_u32("asolaria.execution_authority", 0),
        metadata_u32("asolaria.physical_energy_emitted", 0),
        metadata_u32("asolaria.system_affirmed", 0),
    )
    metadata = b"".join(entries)
    dimensions = (DESCRIPTOR_WIDTH, len(DIRECTIONS), len(FAMILIES), source.folder_count)
    tensor = bytearray(gguf_string("folder_flowes_x3x3_v2"))
    tensor += struct.pack("<I", len(dimensions))
    for dimension in dimensions:
        tensor += struct.pack("<Q", dimension)
    tensor += struct.pack("<IQ", GGML_TYPE_I8, 0)
    header = struct.pack("<IIQQ", GGUF_MAGIC, GGUF_VERSION, 1, len(entries))
    prefix = header + metadata + bytes(tensor)
    return prefix + b"\0" * (align_up(len(prefix)) - len(prefix)) + descriptor


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def read(self, length: int) -> bytes:
        end = self.offset + length
        if length < 0 or end > len(self.data):
            raise FlowesError("GGUF_TRUNCATED")
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def unpack(self, fmt: str) -> tuple[object, ...]:
        return struct.unpack(fmt, self.read(struct.calcsize(fmt)))

    def string(self) -> str:
        length = int(self.unpack("<Q")[0])
        try:
            return self.read(length).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FlowesError("GGUF_UTF8") from exc

    def value(self, value_type: int) -> object:
        if value_type == GGUF_TYPE_UINT32:
            return int(self.unpack("<I")[0])
        if value_type == GGUF_TYPE_UINT64:
            return int(self.unpack("<Q")[0])
        if value_type == GGUF_TYPE_STRING:
            return self.string()
        raise FlowesError(f"GGUF_METADATA_TYPE:{value_type}")


def verify_gguf_bytes(
    data: bytes, source: SourceBundle, target_seconds: int
) -> dict[str, object]:
    reader = _Reader(data)
    magic, version, tensors, metadata_count = reader.unpack("<IIQQ")
    if (magic, version, tensors) != (GGUF_MAGIC, GGUF_VERSION, 1):
        raise FlowesError("GGUF_HEADER")
    metadata: dict[str, object] = {}
    for _ in range(int(metadata_count)):
        key = reader.string()
        value_type = int(reader.unpack("<I")[0])
        if key in metadata:
            raise FlowesError("GGUF_DUPLICATE_METADATA")
        metadata[key] = reader.value(value_type)
    name = reader.string()
    dimension_count = int(reader.unpack("<I")[0])
    dimensions = tuple(int(reader.unpack("<Q")[0]) for _ in range(dimension_count))
    tensor_type, tensor_offset = reader.unpack("<IQ")
    if (
        name != "folder_flowes_x3x3_v2"
        or dimensions != (DESCRIPTOR_WIDTH, 3, 3, source.folder_count)
        or int(tensor_type) != GGML_TYPE_I8
        or int(tensor_offset) != 0
    ):
        raise FlowesError("GGUF_TENSOR")
    data_start = align_up(reader.offset)
    if data_start > len(data) or any(data[reader.offset:data_start]):
        raise FlowesError("GGUF_ALIGNMENT")
    descriptor = data[data_start:]
    if len(descriptor) != math.prod(dimensions):
        raise FlowesError("GGUF_DESCRIPTOR_SIZE")
    expected = {
        "general.architecture": "asolaria-folder-flowes-x3x3-v2",
        "general.name": BASE,
        "general.alignment": GGUF_ALIGNMENT,
        "asolaria.schema": SCHEMA,
        "asolaria.source.hbp.sha256": source.hbp_sha256,
        "asolaria.source.hbi.sha256": source.hbi_sha256,
        "asolaria.monitor.target_seconds": target_seconds,
        "asolaria.folders": source.folder_count,
        "asolaria.families": 3,
        "asolaria.directions": 3,
        "asolaria.cells": source.folder_count * 9,
        "asolaria.descriptor.width": DESCRIPTOR_WIDTH,
        "asolaria.network_access": 0,
        "asolaria.execution_authority": 0,
        "asolaria.physical_energy_emitted": 0,
        "asolaria.system_affirmed": 0,
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise FlowesError(f"GGUF_METADATA:{key}")
    if metadata.get("asolaria.descriptor.sha256") != sha256_bytes(descriptor):
        raise FlowesError("GGUF_DESCRIPTOR_SHA256")
    return metadata


def build_hbi(
    source: SourceBundle,
    journal: Journal,
    files: dict[str, bytes],
    object_hash: str,
    ring_count: int,
    cell_count: int,
) -> bytes:
    rows = [
        tuple_row(
            "FLOWEX9V2IDX", schema=SCHEMA, status="COMPLETE",
            target_seconds=journal.target_seconds,
            timing_mode=journal.timing_mode,
            checkpoints=len(schedule(journal.target_seconds)),
            folders=source.folder_count, families=3, directions=3,
            ring_summaries=ring_count, final_cells=cell_count, json=0,
        ),
        tuple_row(
            "SOURCE", kind="HBP", file=SOURCE_HBP,
            sha256=source.hbp_sha256, exact_sidecar_verified=1, json=0,
        ),
        tuple_row(
            "SOURCE", kind="HBI", file=SOURCE_HBI,
            sha256=source.hbi_sha256, exact_sidecar_verified=1, json=0,
        ),
    ]
    for kind, name in (
        ("HBP", OUTPUT_HBP), ("SVG", OUTPUT_SVG), ("GGUF", OUTPUT_GGUF),
        ("STDOUT_HBP", OUTPUT_STDOUT), ("RESTART_JOURNAL_HBP", OUTPUT_JOURNAL),
    ):
        data = files[name]
        fields: dict[str, object] = {
            "kind": kind, "file": name, "bytes": len(data),
            "sha256": sha256_bytes(data),
        }
        if kind == "GGUF":
            fields.update(
                descriptor_only=1,
                dimensions=f"feature:64,direction:3,family:3,folder:{source.folder_count}",
                iteration_order="folder,family,direction,feature",
            )
        if kind == "SVG":
            fields.update(static=1, script=0, network=0, execution=0)
        fields["json"] = 0
        rows.append(tuple_row("ARTIFACT", **fields))
    rows.extend(
        [
            tuple_row(
                "CENTER", members=",".join(CENTER_MEMBERS),
                traversal=CENTER_TRAVERSAL, commitments_per_cell=5,
                domain_separated=1, object_hash=object_hash,
                sha="ARTIFACT_BYTE_SHA256", sha_equals_hash=0, json=0,
            ),
            tuple_row(
                "SHAPE", checkpoints=len(schedule(journal.target_seconds)),
                ring_summaries=ring_count, folders=source.folder_count,
                families=3, directions=3, final_cells=cell_count,
                observation_limit=OBSERVATION_LIMIT, json=0,
            ),
            tuple_row(
                "BOUNDARY", credentials=0, network=0, execution=0,
                authority=0, physical_energy=0, physical_light=0,
                system_affirmed=0, json=0,
            ),
        ]
    )
    body = ("\n".join(rows) + "\n").encode("utf-8")
    rows.append(
        tuple_row("FLOWEX9V2IDXFTR", body_sha256=sha256_bytes(body), rows=len(rows) + 1, json=0)
    )
    return ("\n".join(rows) + "\n").encode("utf-8")


def build_bundle(source: SourceBundle, journal: Journal) -> dict[str, bytes]:
    if not journal.complete:
        raise FlowesError("JOURNAL_INCOMPLETE")
    if (
        journal.source_hbp_sha256 != source.hbp_sha256
        or journal.source_hbi_sha256 != source.hbi_sha256
    ):
        raise FlowesError("JOURNAL_SOURCE")
    checkpoints = schedule(journal.target_seconds)
    if tuple(item.checkpoint_seconds for item in journal.checkpoints) != checkpoints:
        raise FlowesError("JOURNAL_CHECKPOINT_SET")
    rings = build_rings(source, checkpoints)
    cells = build_cells(source)
    journal_data = journal_bytes(journal)
    hbp, object_hash = build_hbp(source, journal, rings, cells, journal_data)
    stdout_data = build_stdout(source, journal)
    svg = build_svg(source, journal, rings, cells, object_hash)
    gguf = build_gguf(source, journal, cells, object_hash)
    partial = {
        OUTPUT_HBP: hbp,
        OUTPUT_SVG: svg,
        OUTPUT_GGUF: gguf,
        OUTPUT_STDOUT: stdout_data,
        OUTPUT_JOURNAL: journal_data,
    }
    hbi = build_hbi(source, journal, partial, object_hash, len(rings), len(cells))
    return {
        OUTPUT_HBP: hbp,
        OUTPUT_HBI: hbi,
        OUTPUT_SVG: svg,
        OUTPUT_GGUF: gguf,
        OUTPUT_STDOUT: stdout_data,
        OUTPUT_JOURNAL: journal_data,
    }


def write_bundle(
    output_dir: Path,
    files: dict[str, bytes],
    *,
    replace: bool,
    writer_lock: WriterLock,
) -> None:
    output_dir = output_dir.resolve()
    writer_lock.assert_held(output_dir)
    if output_dir.exists() and (not output_dir.is_dir() or output_dir.is_symlink()):
        raise FlowesError("OUTPUT_DIRECTORY")
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        path = output_dir / name
        sidecar = path.with_name(path.name + ".sha256")
        artifact_exists = path.exists()
        sidecar_exists = sidecar.exists()
        if artifact_exists != sidecar_exists:
            raise FlowesError(f"ORPHAN_OUTPUT_PAIR:{name}")
        if artifact_exists:
            actual = verify_sidecar(path)
            if actual == data:
                continue
            if not replace:
                raise FlowesError(f"EXISTING_OUTPUT_MISMATCH:{name}")
        write_sealed(path, data)


def verify_text_artifact(data: bytes, footer_tag: str) -> list[str]:
    if b"\r" in data:
        raise FlowesError("OUTPUT_CR")
    lines = data.decode("utf-8").splitlines()
    if not lines or any(not line.endswith("|json=0") for line in lines):
        raise FlowesError("OUTPUT_JSON0")
    verify_footer(lines, footer_tag)
    return lines


def verify_bundle(
    source_dir: Path,
    output_dir: Path,
    *,
    require_committed: bool = True,
    target_seconds: int = TARGET_SECONDS,
    timing_mode: str | None = None,
) -> dict[str, str]:
    source = load_source(source_dir, require_committed=require_committed)
    journal_data = verify_sidecar(output_dir.resolve() / OUTPUT_JOURNAL)
    if timing_mode is None:
        header = parse_tuple(journal_data.decode("utf-8").splitlines()[0], "FLOWEX9JOURNAL")
        timing_mode = header.get("timing_mode", "")
    if timing_mode not in (
        "REAL_MONOTONIC", "DETERMINISTIC_FAKE_CLOCK", "INJECTED_TEST_CLOCK"
    ):
        raise FlowesError("TIMING_MODE")
    journal = parse_journal_bytes(journal_data, source, target_seconds, timing_mode)
    expected = build_bundle(source, journal)
    hashes: dict[str, str] = {}
    for name, expected_data in expected.items():
        actual = verify_sidecar(output_dir.resolve() / name)
        if actual != expected_data:
            raise FlowesError(f"DERIVED_MISMATCH:{name}")
        hashes[name] = sha256_bytes(actual)
    hbp_lines = verify_text_artifact(expected[OUTPUT_HBP], "FLOWEX9V2FTR")
    hbi_lines = verify_text_artifact(expected[OUTPUT_HBI], "FLOWEX9V2IDXFTR")
    verify_text_artifact(expected[OUTPUT_STDOUT], "FLOWEX9STDOUTFTR")
    verify_text_artifact(expected[OUTPUT_JOURNAL], "FLOWEX9JOURNALFTR")
    if sum(line.startswith("RING|") for line in hbp_lines) != len(schedule(target_seconds)) * 9:
        raise FlowesError("RING_COUNT")
    if sum(line.startswith("FLOWE|") for line in hbp_lines) != source.folder_count * 9:
        raise FlowesError("CELL_COUNT")
    if not any(
        line.startswith("ARTIFACT|") and f"file={OUTPUT_STDOUT}" in line
        for line in hbi_lines
    ):
        raise FlowesError("STDOUT_BINDING")
    verify_gguf_bytes(expected[OUTPUT_GGUF], source, target_seconds)
    svg = expected[OUTPUT_SVG]
    if b"<script" in svg.lower():
        raise FlowesError("SVG_STATIC")
    try:
        root = ET.fromstring(svg)
    except ET.ParseError as exc:
        raise FlowesError("SVG_XML") from exc
    namespace = "{http://www.w3.org/2000/svg}"
    if root.tag != namespace + "svg":
        raise FlowesError("SVG_ROOT")
    for key in ("data-script", "data-network", "data-execution", "data-authority", "data-physical-energy"):
        if root.get(key) != "0":
            raise FlowesError(f"SVG_BOUNDARY:{key}")
    circles = root.findall(".//" + namespace + "circle")
    if len(circles) != source.folder_count * 9:
        raise FlowesError("SVG_CELL_COUNT")
    if any(circle.get("class") != "flowe-cell" for circle in circles):
        raise FlowesError("SVG_CELL_CLASS")
    return hashes


def checkpoint_stdout_row(item: Checkpoint) -> str:
    return tuple_row(
        "OUTWARD", i=item.index, checkpoint_seconds=item.checkpoint_seconds,
        session_i=item.session_i, monotonic_session_only=1,
        checkpoint_hash=item.checkpoint_hash,
        network=0, execution=0, authority=0, physical_energy=0, json=0,
    )


def _watch_locked(
    source_dir: Path,
    output_dir: Path,
    *,
    writer_lock: WriterLock,
    timing_mode: str,
    require_committed: bool = True,
    target_seconds: int = TARGET_SECONDS,
    clock: Clock,
    poll_seconds: float = 0.25,
    stop_after_checkpoints: int | None = None,
    emit: Callable[[str], None] = print,
) -> Journal:
    if poll_seconds <= 0:
        raise FlowesError("POLL_SECONDS")
    if timing_mode == "REAL_MONOTONIC" and not isinstance(clock, SystemClock):
        raise FlowesError("REAL_MONOTONIC_REQUIRES_SYSTEM_CLOCK")
    source = load_source(source_dir, require_committed=require_committed)
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    journal = load_journal(
        output_dir, source, target_seconds, timing_mode
    ) or Journal(
        target_seconds, timing_mode, source.hbp_sha256,
        source.hbi_sha256, (), (),
    )
    if journal.complete:
        files = build_bundle(source, journal)
        write_bundle(
            output_dir, files, replace=False, writer_lock=writer_lock
        )
        verify_bundle(
            source_dir, output_dir, require_committed=require_committed,
            target_seconds=target_seconds, timing_mode=timing_mode,
        )
        return journal
    journal = begin_session(journal)
    save_journal(output_dir, journal, writer_lock)
    active = journal.sessions[-1]
    timer = clock
    started_ns = timer.monotonic_ns()
    if started_ns < 0:
        raise FlowesError("MONOTONIC_NEGATIVE")
    while not journal.complete:
        now_ns = timer.monotonic_ns()
        if now_ns < started_ns:
            raise FlowesError("MONOTONIC_REVERSED")
        available = min(
            target_seconds,
            active.baseline_seconds + (now_ns - started_ns) // 1_000_000_000,
        )
        before = len(journal.checkpoints)
        journal = append_reached_checkpoints(journal, int(available))
        if len(journal.checkpoints) != before:
            save_journal(output_dir, journal, writer_lock)
            for item in journal.checkpoints[before:]:
                emit(checkpoint_stdout_row(item))
            if (
                stop_after_checkpoints is not None
                and len(journal.checkpoints) >= stop_after_checkpoints
            ):
                return journal
        if not journal.complete:
            timer.sleep(poll_seconds)
    files = build_bundle(source, journal)
    write_bundle(output_dir, files, replace=False, writer_lock=writer_lock)
    return journal


def completed_hashes(output_dir: Path) -> tuple[dict[str, str], int, int]:
    hashes = {
        name: sha256_bytes(verify_sidecar(output_dir.resolve() / name))
        for name in OUTPUT_NAMES
    }
    header = parse_tuple(
        verify_sidecar(output_dir.resolve() / OUTPUT_HBP)
        .decode("utf-8")
        .splitlines()[0],
        "FLOWEX9V2HDR",
    )
    return hashes, int(header["folders"]), int(header["target_seconds"])


def result_row(
    mode: str, hashes: dict[str, str], folders: int, target_seconds: int
) -> str:
    checkpoints = len(schedule(target_seconds))
    return tuple_row(
        "FLOWEX9V2", PASS=1, mode=mode,
        target_seconds=target_seconds, checkpoints=checkpoints,
        ring_summaries=checkpoints * 9, folders=folders,
        families=3, directions=3, final_cells=folders * 9,
        hbp_sha256=hashes[OUTPUT_HBP], hbi_sha256=hashes[OUTPUT_HBI],
        svg_sha256=hashes[OUTPUT_SVG], gguf_sha256=hashes[OUTPUT_GGUF],
        stdout_sha256=hashes[OUTPUT_STDOUT],
        journal_sha256=hashes[OUTPUT_JOURNAL],
        network=0, execution=0, authority=0, physical_energy=0, json=0,
    )


def watch(
    source_dir: Path,
    output_dir: Path,
    *,
    require_committed: bool = True,
    target_seconds: int = TARGET_SECONDS,
    clock: Clock | None = None,
    poll_seconds: float = 0.25,
    stop_after_checkpoints: int | None = None,
    emit: Callable[[str], None] = print,
) -> Journal:
    timing_mode = "REAL_MONOTONIC" if clock is None else "INJECTED_TEST_CLOCK"
    timer: Clock = SystemClock() if clock is None else clock
    with WriterLock(output_dir, "watch") as writer_lock:
        journal = _watch_locked(
            source_dir, output_dir, writer_lock=writer_lock,
            timing_mode=timing_mode,
            require_committed=require_committed, target_seconds=target_seconds,
            clock=timer, poll_seconds=poll_seconds,
            stop_after_checkpoints=stop_after_checkpoints, emit=emit,
        )
        if journal.complete:
            hashes, folders, verified_target = completed_hashes(output_dir)
            emit(result_row("watch", hashes, folders, verified_target))
        return journal


def _fake_clock_build_locked(
    source_dir: Path,
    output_dir: Path,
    *,
    writer_lock: WriterLock,
    replace: bool = False,
    require_committed: bool = True,
    target_seconds: int = TARGET_SECONDS,
) -> dict[str, str]:
    source = load_source(source_dir, require_committed=require_committed)
    output_dir = output_dir.resolve()
    existing_journal = load_journal(
        output_dir, source, target_seconds, "DETERMINISTIC_FAKE_CLOCK"
    )
    if existing_journal is not None and not replace:
        raise FlowesError("OUTPUT_EXISTS:" + OUTPUT_JOURNAL)
    journal = fake_complete_journal(source, target_seconds)
    files = build_bundle(source, journal)
    write_bundle(
        output_dir, files, replace=replace, writer_lock=writer_lock
    )
    return {name: sha256_bytes(data) for name, data in files.items()}


def fake_clock_build(
    source_dir: Path,
    output_dir: Path,
    *,
    replace: bool = False,
    require_committed: bool = True,
    target_seconds: int = TARGET_SECONDS,
    emit: Callable[[str], None] | None = None,
) -> dict[str, str]:
    with WriterLock(output_dir, "fake-clock-build") as writer_lock:
        hashes = _fake_clock_build_locked(
            source_dir, output_dir, writer_lock=writer_lock,
            replace=replace, require_committed=require_committed,
            target_seconds=target_seconds,
        )
        sealed_hashes, folders, verified_target = completed_hashes(output_dir)
        if sealed_hashes != hashes:
            raise FlowesError("POST_WRITE_HASH_MISMATCH")
        if emit is not None:
            emit(result_row("fake-clock-build", hashes, folders, verified_target))
        return hashes


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--watch", action="store_true",
        help="run the real fixed 86,400-second monotonic-session monitor",
    )
    mode.add_argument(
        "--fake-clock-build", action="store_true",
        help="build deterministic CI fixtures tagged as non-measured timing",
    )
    mode.add_argument("--verify", action="store_true", help="deep-verify a completed bundle")
    parser.add_argument("--replace", action="store_true", help="replace this additive V2 output set")
    parser.add_argument("--poll-seconds", type=float, default=0.25)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        reported_inside_writer_lock = False
        if args.watch:
            if args.replace:
                raise FlowesError("WATCH_REPLACE")
            journal = watch(
                args.source_dir, args.output_dir, poll_seconds=args.poll_seconds,
                emit=lambda row: print(row, flush=True),
            )
            hashes = {}
            reported_inside_writer_lock = journal.complete
            mode_name = "watch"
        elif args.fake_clock_build:
            hashes = fake_clock_build(
                args.source_dir, args.output_dir, replace=args.replace,
                emit=lambda row: print(row, flush=True),
            )
            reported_inside_writer_lock = True
            mode_name = "fake-clock-build"
        else:
            if args.replace:
                raise FlowesError("VERIFY_REPLACE")
            hashes = verify_bundle(args.source_dir, args.output_dir)
            mode_name = "verify"
        if hashes and not reported_inside_writer_lock:
            print(result_row(mode_name, hashes, 3536, TARGET_SECONDS))
        return 0
    except (FlowesError, OSError, UnicodeError, ValueError, struct.error) as exc:
        print(tuple_row("FLOWEX9V2", PASS=0, error=exc, json=0), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
