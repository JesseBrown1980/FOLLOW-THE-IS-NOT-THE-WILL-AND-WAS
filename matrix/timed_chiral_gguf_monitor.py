#!/usr/bin/env python3
"""Offline timed chiral monitor for a verified PUBLIC2D HBP.

The running phase writes only a bounded HBP/HBI status pair.  At the target
elapsed time it additionally writes a GGUF v3 containing derived public
color/orbit bytes and source commitments.  It has no network, subprocess,
repository-content, credential, or publication capability.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import struct
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Sequence

try:
    from .spherical_public_projection import (
        ParsedInventory,
        ProjectionError,
        digest,
        parse_inventory,
        reject_link_chain,
        tuple_row,
    )
except ImportError:
    from spherical_public_projection import (
        ParsedInventory,
        ProjectionError,
        digest,
        parse_inventory,
        reject_link_chain,
        tuple_row,
    )


SCHEMA = "TIMED-CHIRAL-PUBLIC-GGUF-V1"
CENTER_MEMBERSHIP = ("HBI", "HBP", "SHA", "SH", "HASH")
CENTER_TRAVERSAL = ("HBI", "HBP", "SH", "HASH", "SHA")
TARGET_SECONDS = 7_200
MAX_TARGET_SECONDS = 172_800
GGUF_MAGIC = 0x46554747
GGUF_VERSION = 3
GGUF_TYPE_UINT32 = 4
GGUF_TYPE_STRING = 8
GGUF_TYPE_UINT64 = 10
GGML_TYPE_I8 = 24
ALIGNMENT = 32

HBP_NAME = "TIMED-CHIRAL-MONITOR.hbp"
HBI_NAME = "TIMED-CHIRAL-MONITOR.hbi"
GGUF_NAME = "TIMED-CHIRAL-PUBLIC-COLOR-ORBITS.gguf"
ALLOWED_NAMES = {
    HBP_NAME,
    HBI_NAME,
    GGUF_NAME,
    HBP_NAME + ".sha256",
    HBI_NAME + ".sha256",
    GGUF_NAME + ".sha256",
}


class MonitorError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def schedule(target_seconds: int) -> tuple[int, ...]:
    if not 4 <= target_seconds <= MAX_TARGET_SECONDS:
        raise MonitorError("TARGET_RANGE")
    values = [1, 2, 3, 4]
    checkpoint = 8
    while checkpoint < target_seconds:
        values.append(checkpoint)
        checkpoint *= 2
    if values[-1] != target_seconds:
        values.append(target_seconds)
    return tuple(values)


def elapsed_seconds(started_ns: int, now_ns: int) -> int:
    if started_ns < 0 or now_ns < started_ns:
        raise MonitorError("CLOCK_RANGE")
    return (now_ns - started_ns) // 1_000_000_000


def descriptor_bytes(inventory: ParsedInventory) -> bytes:
    """Eight derived bytes per public record; no identifiers or source rows."""
    output = bytearray()
    for record in inventory.records:
        source = bytes.fromhex(record.blob_sha256)
        output.extend(source[:3])
        output.append(0 if record.chirality == "LEFT" else 1)
        output.append(int(record.system_instant_is))
        output.append(record.level)
        output.append(abs(record.u) & 0xFF)
        output.append(abs(record.v) & 0xFF)
    return bytes(output)


def gguf_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack("<Q", len(raw)) + raw


def metadata_string(key: str, value: str) -> bytes:
    return gguf_string(key) + struct.pack("<I", GGUF_TYPE_STRING) + gguf_string(value)


def metadata_u32(key: str, value: int) -> bytes:
    return gguf_string(key) + struct.pack("<II", GGUF_TYPE_UINT32, value)


def metadata_u64(key: str, value: int) -> bytes:
    return gguf_string(key) + struct.pack("<IQ", GGUF_TYPE_UINT64, value)


def align_up(value: int) -> int:
    return (value + ALIGNMENT - 1) // ALIGNMENT * ALIGNMENT


def build_gguf(
    inventory: ParsedInventory, source_sha256: str, target_seconds: int
) -> bytes:
    descriptor = descriptor_bytes(inventory)
    entries = (
        metadata_string("general.architecture", "asolaria-public-color-orbit"),
        metadata_string("general.name", "TIMED-CHIRAL-PUBLIC-COLOR-ORBITS"),
        metadata_u32("general.alignment", ALIGNMENT),
        metadata_string("asolaria.schema", SCHEMA),
        metadata_string("asolaria.payload.kind", "DERIVED_PUBLIC_COLOR_ORBITS"),
        metadata_string("asolaria.source.hbp.sha256", source_sha256),
        metadata_u64("asolaria.source.public_records", len(inventory.records)),
        metadata_u64("asolaria.monitor.target_seconds", target_seconds),
        metadata_string(
            "asolaria.center.membership", ",".join(CENTER_MEMBERSHIP)
        ),
        metadata_string(
            "asolaria.center.traversal", "->".join(CENTER_TRAVERSAL)
        ),
        metadata_string("asolaria.descriptor.sha256", sha256(descriptor)),
        metadata_string(
            "asolaria.boundary",
            "derived public descriptors only; no source rows or repository bytes",
        ),
        metadata_u32("asolaria.raw_repository_bytes", 0),
        metadata_u32("asolaria.network_access", 0),
    )
    metadata = b"".join(entries)
    tensor_info = (
        gguf_string("public_color_orbit")
        + struct.pack("<IQQIQ", 2, 8, len(inventory.records), GGML_TYPE_I8, 0)
    )
    header = struct.pack("<IIQQ", GGUF_MAGIC, GGUF_VERSION, 1, len(entries))
    prefix = header + metadata + tensor_info
    blob = prefix + b"\0" * (align_up(len(prefix)) - len(prefix)) + descriptor
    verify_gguf(blob, source_sha256, len(inventory.records), target_seconds)
    return blob


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def read(self, size: int) -> bytes:
        end = self.offset + size
        if size < 0 or end > len(self.data):
            raise MonitorError("GGUF_TRUNCATED")
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def unpack(self, fmt: str) -> tuple[object, ...]:
        return struct.unpack(fmt, self.read(struct.calcsize(fmt)))

    def string(self) -> str:
        (length,) = self.unpack("<Q")
        assert isinstance(length, int)
        return self.read(length).decode("utf-8")


def verify_gguf(
    blob: bytes, source_sha256: str, record_count: int, target_seconds: int
) -> str:
    reader = Reader(blob)
    magic, version, tensors, metadata_count = reader.unpack("<IIQQ")
    if (magic, version, tensors) != (GGUF_MAGIC, GGUF_VERSION, 1):
        raise MonitorError("GGUF_HEADER")
    metadata: dict[str, object] = {}
    for _ in range(int(metadata_count)):
        key = reader.string()
        (value_type,) = reader.unpack("<I")
        if key in metadata:
            raise MonitorError("GGUF_DUPLICATE_METADATA")
        if value_type == GGUF_TYPE_STRING:
            value: object = reader.string()
        elif value_type == GGUF_TYPE_UINT32:
            (value,) = reader.unpack("<I")
        elif value_type == GGUF_TYPE_UINT64:
            (value,) = reader.unpack("<Q")
        else:
            raise MonitorError("GGUF_METADATA_TYPE")
        metadata[key] = value
    tensor_name = reader.string()
    (dimensions,) = reader.unpack("<I")
    if dimensions != 2:
        raise MonitorError("GGUF_DIMENSIONS")
    dim0, dim1, tensor_type, tensor_offset = reader.unpack("<QQIQ")
    data_start = align_up(reader.offset)
    if any(blob[reader.offset:data_start]):
        raise MonitorError("GGUF_ALIGNMENT_PADDING")
    if (
        tensor_name != "public_color_orbit"
        or (dim0, dim1) != (8, record_count)
        or tensor_type != GGML_TYPE_I8
        or tensor_offset != 0
        or data_start + 8 * record_count != len(blob)
    ):
        raise MonitorError("GGUF_TENSOR")
    descriptor = blob[data_start:]
    expected = {
        "general.architecture": "asolaria-public-color-orbit",
        "general.name": "TIMED-CHIRAL-PUBLIC-COLOR-ORBITS",
        "general.alignment": ALIGNMENT,
        "asolaria.schema": SCHEMA,
        "asolaria.payload.kind": "DERIVED_PUBLIC_COLOR_ORBITS",
        "asolaria.source.hbp.sha256": source_sha256,
        "asolaria.source.public_records": record_count,
        "asolaria.monitor.target_seconds": target_seconds,
        "asolaria.center.membership": ",".join(CENTER_MEMBERSHIP),
        "asolaria.center.traversal": "->".join(CENTER_TRAVERSAL),
        "asolaria.raw_repository_bytes": 0,
        "asolaria.network_access": 0,
        "asolaria.descriptor.sha256": sha256(descriptor),
        "asolaria.boundary": (
            "derived public descriptors only; no source rows or repository bytes"
        ),
    }
    if set(metadata) != set(expected) or any(
        metadata.get(key) != value for key, value in expected.items()
    ):
        raise MonitorError("GGUF_METADATA")
    return sha256(blob)


def report_hbp(
    *,
    source_sha256: str,
    record_count: int,
    elapsed: int,
    target_seconds: int,
    gguf_sha256: str | None,
) -> bytes:
    complete = elapsed >= target_seconds
    lines = [
        tuple_row(
            "TIMEDCHIRALHDR",
            schema=SCHEMA,
            status="COMPLETE" if complete else "RUNNING",
            elapsed_seconds=elapsed,
            target_seconds=target_seconds,
            source_hbp_sha256=source_sha256,
            public_records=record_count,
            center_membership=",".join(CENTER_MEMBERSHIP),
            traversal="->".join(CENTER_TRAVERSAL),
            raw_source_rows=0,
            raw_repository_bytes=0,
            network=0,
        )
    ]
    for index, checkpoint in enumerate(schedule(target_seconds)):
        if checkpoint <= elapsed:
            lines.append(
                tuple_row(
                    "OUTWARD",
                    index=index,
                    checkpoint_seconds=checkpoint,
                    direction="SPHERICAL_OUTWARD",
                    chirality="ALTERNATING",
                    calming_oils="BROWN.NEAR.ONE",
                    source_hbp_sha256=source_sha256,
                )
            )
    lines.append(
        tuple_row(
            "GGUF",
            state="PRESENT" if complete else "ABSENT",
            file=GGUF_NAME if complete else "NONE",
            sha256=gguf_sha256 if complete else "NONE",
            descriptor_only=1,
            source_rows_embedded=0,
            repository_bytes_embedded=0,
        )
    )
    body = ("\n".join(lines) + "\n").encode("utf-8")
    lines.append(
        tuple_row(
            "TIMEDCHIRALFTR",
            body_sha256=sha256(body),
            rows=len(lines) + 1,
            json=0,
        )
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def pointer_hbi(hbp: bytes, gguf_sha256: str | None) -> bytes:
    return (
        tuple_row(
            "HBI",
            schema=SCHEMA,
            hbp_file=HBP_NAME,
            hbp_sha256=sha256(hbp),
            gguf_file=GGUF_NAME if gguf_sha256 else "NONE",
            gguf_sha256=gguf_sha256 or "NONE",
            center_membership=",".join(CENTER_MEMBERSHIP),
            traversal="->".join(CENTER_TRAVERSAL),
            raw_rows=0,
            authority_granted=0,
        )
        + "\n"
    ).encode("utf-8")


def validate_output_dir(path: Path) -> Path:
    reject_link_chain(path)
    if not path.is_dir():
        raise MonitorError("OUTPUT_DIR")
    return path.absolute()


def verify_source_sidecar(source: Path, source_bytes: bytes) -> str:
    if source.suffix.lower() != ".hbp":
        raise MonitorError("SOURCE_NOT_HBP")
    sidecar_path = source.with_name(source.name + ".sha256")
    reject_link_chain(sidecar_path)
    try:
        with sidecar_path.open("rb") as handle:
            sidecar_bytes = handle.read(257)
    except FileNotFoundError as exc:
        raise MonitorError("SOURCE_SIDECAR_MISSING") from exc
    reject_link_chain(sidecar_path)
    if len(sidecar_bytes) > 256:
        raise MonitorError("SOURCE_SIDECAR_TOO_LARGE")
    expected_hash = digest(source_bytes)
    expected = f"{expected_hash}  {source.name}\n".encode("utf-8")
    if sidecar_bytes != expected:
        raise MonitorError("SOURCE_SIDECAR_MISMATCH")
    return expected_hash


def atomic_write(path: Path, data: bytes) -> None:
    if path.name not in ALLOWED_NAMES:
        raise MonitorError("OUTPUT_NOT_ALLOWLISTED")
    reject_link_chain(path)
    if path.exists() and not path.is_file():
        raise MonitorError("OUTPUT_NOT_REGULAR")
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{path.name}.pending-", dir=path.parent, delete=False
        ) as handle:
            temporary = handle.name
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if Path(temporary).read_bytes() != data:
            raise MonitorError("WRITE_READBACK")
        reject_link_chain(path.parent)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def sidecar(name: str, data: bytes) -> bytes:
    return f"{sha256(data)}  {name}\n".encode("ascii")


def run_monitor(
    source: Path,
    output_dir: Path,
    *,
    started_ns: int,
    clock_ns: Callable[[], int] = time.monotonic_ns,
    target_seconds: int = TARGET_SECONDS,
) -> str:
    output_dir = validate_output_dir(output_dir)
    source = source.absolute()
    if source.parent == output_dir and source.name in ALLOWED_NAMES:
        raise MonitorError("PATH_ROLE_COLLISION")
    inventory = parse_inventory(source)
    source_sha256 = verify_source_sidecar(source, inventory.source_bytes)
    elapsed = elapsed_seconds(started_ns, clock_ns())
    complete = elapsed >= target_seconds
    gguf_path = output_dir / GGUF_NAME
    if not complete and gguf_path.exists():
        raise MonitorError("EARLY_GGUF_PRESENT")
    gguf: bytes | None = None
    gguf_sha256: str | None = None
    if complete:
        gguf = build_gguf(inventory, source_sha256, target_seconds)
        gguf_sha256 = sha256(gguf)
    hbp = report_hbp(
        source_sha256=source_sha256,
        record_count=len(inventory.records),
        elapsed=elapsed,
        target_seconds=target_seconds,
        gguf_sha256=gguf_sha256,
    )
    hbi = pointer_hbi(hbp, gguf_sha256)
    if gguf is not None:
        atomic_write(gguf_path, gguf)
        atomic_write(output_dir / (GGUF_NAME + ".sha256"), sidecar(GGUF_NAME, gguf))
    atomic_write(output_dir / HBP_NAME, hbp)
    atomic_write(output_dir / (HBP_NAME + ".sha256"), sidecar(HBP_NAME, hbp))
    atomic_write(output_dir / HBI_NAME, hbi)
    atomic_write(output_dir / (HBI_NAME + ".sha256"), sidecar(HBI_NAME, hbi))
    return "COMPLETE" if complete else "RUNNING"


def watch_monitor(
    source: Path,
    output_dir: Path,
    *,
    started_ns: int | None = None,
    clock_ns: Callable[[], int] = time.monotonic_ns,
    wait: Callable[[float], None] = time.sleep,
    progress: Callable[[str], None] = print,
    target_seconds: int = TARGET_SECONDS,
) -> str:
    """Wait monotonically and write at each bounded outward checkpoint."""
    start = clock_ns() if started_ns is None else started_ns
    for checkpoint in schedule(target_seconds):
        while True:
            now = clock_ns()
            elapsed = elapsed_seconds(start, now)
            if elapsed >= checkpoint:
                break
            wait(min(1.0, float(checkpoint - elapsed)))
        status = run_monitor(
            source,
            output_dir,
            started_ns=start,
            clock_ns=clock_ns,
            target_seconds=target_seconds,
        )
        observed = elapsed_seconds(start, clock_ns())
        progress(
            tuple_row(
                "TIMEDCHIRALCHECKPOINT",
                scheduled_seconds=checkpoint,
                observed_elapsed_seconds=observed,
                status=status,
                gguf_present=int(status == "COMPLETE"),
            )
        )
    return "COMPLETE"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--started-ns", type=int)
    parser.add_argument("--now-ns", type=int)
    parser.add_argument("--target-seconds", type=int, default=TARGET_SECONDS)
    parser.add_argument("--watch", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.watch:
            if args.now_ns is not None:
                raise MonitorError("WATCH_NOW_OVERRIDE")
            status = watch_monitor(
                args.source,
                args.output_dir,
                started_ns=args.started_ns,
                target_seconds=args.target_seconds,
            )
        else:
            now_ns = time.monotonic_ns() if args.now_ns is None else args.now_ns
            started_ns = now_ns if args.started_ns is None else args.started_ns
            status = run_monitor(
                args.source,
                args.output_dir,
                started_ns=started_ns,
                clock_ns=lambda: now_ns,
                target_seconds=args.target_seconds,
            )
        print(f"TIMED_CHIRAL_MONITOR|PASS=1|status={status}|json=0")
        return 0
    except (MonitorError, ProjectionError, OSError, UnicodeError) as exc:
        code = getattr(exc, "code", "FILESYSTEM")
        print(
            f"TIMED_CHIRAL_MONITOR|PASS=0|reason={code}|json=0",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
