#!/usr/bin/env python3
"""Parse and verify the exact-size Double Rainbow color-state GGUF."""

from __future__ import annotations

import argparse
import hashlib
import math
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from double_rainbow_to_gguf import (
    DEFAULT_OUTPUT,
    FIELD_NAMES,
    GGML_TYPE_I8,
    GGUF_ALIGNMENT,
    GGUF_MAGIC,
    GGUF_VERSION,
    SAMPLE_COUNT,
    SCHEMA,
    SOURCE_ID,
    SOURCE_URL,
    TARGET_BYTES,
)


TYPE_SIZES = {
    0: 1,   # UINT8
    1: 1,   # INT8
    2: 2,   # UINT16
    3: 2,   # INT16
    4: 4,   # UINT32
    5: 4,   # INT32
    6: 4,   # FLOAT32
    7: 1,   # BOOL
    10: 8,  # UINT64
    11: 8,  # INT64
    12: 8,  # FLOAT64
}


@dataclass(frozen=True)
class Tensor:
    name: str
    dimensions: tuple[int, ...]
    tensor_type: int
    offset: int
    byte_length: int


@dataclass(frozen=True)
class ParsedGGUF:
    version: int
    metadata: dict[str, Any]
    tensors: tuple[Tensor, ...]
    data_start: int
    blob: bytes

    def tensor_bytes(self, name: str) -> bytes:
        tensor = next(tensor for tensor in self.tensors if tensor.name == name)
        start = self.data_start + tensor.offset
        return self.blob[start : start + tensor.byte_length]


class Reader:
    def __init__(self, blob: bytes):
        self.blob = blob
        self.position = 0

    def read(self, length: int) -> bytes:
        end = self.position + length
        if length < 0 or end > len(self.blob):
            raise ValueError("GGUF ended before the declared value")
        value = self.blob[self.position : end]
        self.position = end
        return value

    def unpack(self, fmt: str) -> tuple[Any, ...]:
        size = struct.calcsize(fmt)
        return struct.unpack(fmt, self.read(size))

    def string(self) -> str:
        (length,) = self.unpack("<Q")
        if length > len(self.blob) - self.position:
            raise ValueError("GGUF string length exceeds remaining bytes")
        return self.read(length).decode("utf-8")

    def value(self, value_type: int) -> Any:
        if value_type == 0:
            return self.unpack("<B")[0]
        if value_type == 1:
            return self.unpack("<b")[0]
        if value_type == 2:
            return self.unpack("<H")[0]
        if value_type == 3:
            return self.unpack("<h")[0]
        if value_type == 4:
            return self.unpack("<I")[0]
        if value_type == 5:
            return self.unpack("<i")[0]
        if value_type == 6:
            return self.unpack("<f")[0]
        if value_type == 7:
            raw = self.unpack("<B")[0]
            if raw not in (0, 1):
                raise ValueError(f"invalid GGUF bool value {raw}")
            return bool(raw)
        if value_type == 8:
            return self.string()
        if value_type == 9:
            element_type, length = self.unpack("<IQ")
            return [self.value(element_type) for _ in range(length)]
        if value_type == 10:
            return self.unpack("<Q")[0]
        if value_type == 11:
            return self.unpack("<q")[0]
        if value_type == 12:
            return self.unpack("<d")[0]
        raise ValueError(f"unsupported GGUF metadata type {value_type}")


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def parse_gguf(blob: bytes) -> ParsedGGUF:
    reader = Reader(blob)
    magic, version, tensor_count, metadata_count = reader.unpack("<IIQQ")
    if magic != GGUF_MAGIC:
        raise ValueError(f"bad GGUF magic 0x{magic:08x}")
    if version != GGUF_VERSION:
        raise ValueError(f"GGUF version {version}, expected {GGUF_VERSION}")
    metadata: dict[str, Any] = {}
    for _ in range(metadata_count):
        key = reader.string()
        (value_type,) = reader.unpack("<I")
        if key in metadata:
            raise ValueError(f"duplicate metadata key {key!r}")
        metadata[key] = reader.value(value_type)
    tensors_unmeasured: list[tuple[str, tuple[int, ...], int, int]] = []
    for _ in range(tensor_count):
        name = reader.string()
        (dimension_count,) = reader.unpack("<I")
        if dimension_count == 0 or dimension_count > 4:
            raise ValueError(f"invalid dimension count {dimension_count} for {name!r}")
        dimensions = tuple(reader.unpack("<Q")[0] for _ in range(dimension_count))
        tensor_type, offset = reader.unpack("<IQ")
        if tensor_type != GGML_TYPE_I8:
            raise ValueError(f"unsupported tensor type {tensor_type} for {name!r}")
        if any(dimension == 0 for dimension in dimensions):
            raise ValueError(f"zero tensor dimension for {name!r}")
        tensors_unmeasured.append((name, dimensions, tensor_type, offset))
    alignment = int(metadata.get("general.alignment", GGUF_ALIGNMENT))
    if alignment <= 0 or alignment & (alignment - 1):
        raise ValueError(f"invalid GGUF alignment {alignment}")
    data_start = align_up(reader.position, alignment)
    if data_start > len(blob):
        raise ValueError("aligned GGUF data section is outside the file")
    if any(blob[reader.position:data_start]):
        raise ValueError("non-zero bytes in GGUF header alignment padding")

    tensors: list[Tensor] = []
    names: set[str] = set()
    for name, dimensions, tensor_type, offset in tensors_unmeasured:
        if name in names:
            raise ValueError(f"duplicate tensor name {name!r}")
        names.add(name)
        if offset % alignment:
            raise ValueError(f"tensor {name!r} offset is not {alignment}-byte aligned")
        byte_length = math.prod(dimensions)  # GGML I8 has block size 1, one byte.
        start = data_start + offset
        end = start + byte_length
        if start < data_start or end > len(blob):
            raise ValueError(f"tensor {name!r} exceeds the GGUF data section")
        tensors.append(Tensor(name, dimensions, tensor_type, offset, byte_length))

    intervals = sorted(
        (
            data_start + tensor.offset,
            data_start + tensor.offset + tensor.byte_length,
            tensor.name,
        )
        for tensor in tensors
    )
    for (_, previous_end, previous_name), (start, _, name) in zip(
        intervals, intervals[1:]
    ):
        if start < previous_end:
            raise ValueError(f"tensors {previous_name!r} and {name!r} overlap")
    if intervals and intervals[-1][1] != len(blob):
        raise ValueError("last declared tensor does not end at end-of-file")
    return ParsedGGUF(version, metadata, tuple(tensors), data_start, blob)


def unsigned_descriptor(parsed: ParsedGGUF) -> bytes:
    raw = parsed.tensor_bytes("color_state")
    return bytes((((value if value < 128 else value - 256) + 128) for value in raw))


def verify(path: Path) -> tuple[ParsedGGUF, str]:
    blob = path.read_bytes()
    if len(blob) != TARGET_BYTES:
        raise ValueError(f"file is {len(blob)} bytes, expected {TARGET_BYTES}")
    parsed = parse_gguf(blob)
    metadata = parsed.metadata
    expected_metadata = {
        "general.architecture": "asolaria-color-state",
        "general.name": "DOUBLE-RAINBOW-OIL-3174",
        "general.alignment": GGUF_ALIGNMENT,
        "asolaria.schema": SCHEMA,
        "asolaria.payload.kind": "COLOR_STATE_DESCRIPTOR",
        "asolaria.source.youtube_id": SOURCE_ID,
        "asolaria.source.url": SOURCE_URL,
        "asolaria.sample.count": SAMPLE_COUNT,
        "asolaria.video_bytes_embedded": 0,
        "asolaria.audio_bytes_embedded": 0,
        "asolaria.lossless_video_claim": 0,
        "asolaria.reconstructs_source_video": 0,
    }
    for key, expected in expected_metadata.items():
        actual = metadata.get(key)
        if actual != expected:
            raise ValueError(f"{key}: got {actual!r}, expected {expected!r}")
    fields = metadata.get("asolaria.descriptor.fields", "").split(",")
    if tuple(fields) != FIELD_NAMES:
        raise ValueError("descriptor field ordering does not match the schema")
    by_name = {tensor.name: tensor for tensor in parsed.tensors}
    if set(by_name) != {"color_state", "size_padding"}:
        raise ValueError(f"unexpected tensors: {sorted(by_name)}")
    color = by_name["color_state"]
    padding = by_name["size_padding"]
    if color.dimensions != (len(FIELD_NAMES), SAMPLE_COUNT):
        raise ValueError(f"unexpected color tensor shape {color.dimensions}")
    if color.offset != 0 or color.byte_length != len(FIELD_NAMES) * SAMPLE_COUNT:
        raise ValueError("color tensor offset or length is wrong")
    if padding.offset != color.byte_length:
        raise ValueError("size-padding tensor does not immediately follow color tensor")
    if any(parsed.tensor_bytes("size_padding")):
        raise ValueError("size-padding tensor contains non-zero bytes")
    descriptor = unsigned_descriptor(parsed)
    descriptor_digest = hashlib.sha256(descriptor).hexdigest()
    if descriptor_digest != metadata.get("asolaria.descriptor.sha256"):
        raise ValueError("decoded descriptor SHA-256 differs from metadata")
    if descriptor[FIELD_NAMES.index("temporal_gradient")] != 0:
        raise ValueError("first temporal-gradient value must be zero")
    sidecar = path.with_name(path.name + ".sha256")
    digest = hashlib.sha256(blob).hexdigest()
    if not sidecar.is_file():
        raise ValueError(f"missing SHA-256 sidecar: {sidecar}")
    sidecar_fields = sidecar.read_text(encoding="utf-8").strip().split()
    if sidecar_fields != [digest, path.name]:
        raise ValueError("SHA-256 sidecar does not match GGUF bytes and filename")
    return parsed, digest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gguf", type=Path, nargs="?", default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    parsed, digest = verify(args.gguf.resolve())
    color = next(tensor for tensor in parsed.tensors if tensor.name == "color_state")
    padding = next(tensor for tensor in parsed.tensors if tensor.name == "size_padding")
    print(
        f"VERIFY|status=PASS|gguf={args.gguf.resolve()}|bytes={len(parsed.blob)}"
        f"|sha256={digest}|version={parsed.version}|samples={SAMPLE_COUNT}"
        f"|fields={len(FIELD_NAMES)}|color_bytes={color.byte_length}"
        f"|padding_bytes={padding.byte_length}|json=0"
    )
    print(
        "BOUNDARY|payload=COLOR_STATE_DESCRIPTOR|video_bytes_embedded=0"
        "|audio_bytes_embedded=0|lossless_video_claim=0"
        "|reconstructs_source_video=0|json=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
