#!/usr/bin/env python3
"""Build the exact-size Double Rainbow color-state GGUF.

The generated GGUF contains small, derived color/time descriptors. It does not
contain source frames, audio, or video bytes, and it cannot reconstruct the
source video. The source URL, source-copy SHA-256, sampling recipe, and those
boundaries are embedded in the GGUF metadata.

Only the Python standard library, ffprobe, and ffmpeg are required.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Iterable, Sequence


GGUF_MAGIC = 0x46554747
GGUF_VERSION = 3
GGUF_TYPE_UINT32 = 4
GGUF_TYPE_STRING = 8
GGUF_TYPE_UINT64 = 10
GGML_TYPE_I8 = 24
GGUF_ALIGNMENT = 32

TARGET_BYTES = 3_174
SAMPLE_COUNT = 64
SAMPLE_WIDTH = 16
SAMPLE_HEIGHT = 12
PIXELS_PER_SAMPLE = SAMPLE_WIDTH * SAMPLE_HEIGHT

SOURCE_URL = "https://www.youtube.com/watch?v=OQSNhk5ICTI"
SOURCE_ID = "OQSNhk5ICTI"
SOURCE_TITLE = "Yosemitebear Mountain Double Rainbow 1-8-10"
SCHEMA = "ASOLARIA-DOUBLE-RAINBOW-COLOR-STATE-V1"

FIELD_NAMES = (
    "mean_r",
    "mean_g",
    "mean_b",
    "mean_luma",
    "mean_chroma",
    "mean_saturation",
    "oil_amplitude",
    "spatial_gradient",
    "temporal_gradient",
    "negative_share",
    "centre_share",
    "positive_share",
    "red_dominance",
    "green_dominance",
    "blue_dominance",
    "warm_share",
    "cool_share",
    "hue_coverage",
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = REPO_ROOT / "colors" / "DOUBLE-RAINBOW-OIL-3174.gguf"
DEFAULT_RECEIPT = REPO_ROOT / "colors" / "DOUBLE-RAINBOW-COLOR-SLICES.hbp"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_checked(argv: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            argv,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise SystemExit(f"required executable not found: {argv[0]}") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode("utf-8", "replace").strip()
        raise SystemExit(f"command failed ({exc.returncode}): {stderr}") from exc


def tool_path(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved:
        raise SystemExit(f"{name} is required but was not found on PATH")
    return resolved


def probe_video(video: Path, ffprobe: str) -> dict[str, object]:
    completed = run_checked(
        [
            ffprobe,
            "-v",
            "error",
            "-count_frames",
            "-select_streams",
            "v:0",
            "-show_entries",
            (
                "stream=codec_name,width,height,r_frame_rate,avg_frame_rate,"
                "time_base,start_time,duration,nb_frames,nb_read_frames:"
                "format=format_name,duration,size"
            ),
            "-of",
            "json",
            str(video),
        ]
    )
    payload = json.loads(completed.stdout.decode("utf-8"))
    streams = payload.get("streams") or []
    if len(streams) != 1:
        raise SystemExit("expected exactly one selected video stream")
    stream = streams[0]
    fmt = payload.get("format") or {}
    frame_text = stream.get("nb_read_frames") or stream.get("nb_frames")
    if not frame_text or frame_text == "N/A":
        raise SystemExit("ffprobe did not report a video frame count")
    frame_count = int(frame_text)
    if frame_count < SAMPLE_COUNT:
        raise SystemExit(
            f"source has {frame_count} frames; at least {SAMPLE_COUNT} are required"
        )
    stream_duration = stream.get("duration")
    format_duration = fmt.get("duration")
    duration_seconds = float(
        stream_duration
        if stream_duration not in (None, "N/A")
        else format_duration
    )
    return {
        "codec": str(stream.get("codec_name", "unknown")),
        "width": int(stream["width"]),
        "height": int(stream["height"]),
        "frame_rate": str(stream.get("avg_frame_rate", "unknown")),
        "time_base": str(stream.get("time_base", "unknown")),
        "frame_count": frame_count,
        "duration_ms": int(round(duration_seconds * 1000.0)),
        "format_duration_ms": int(round(float(format_duration) * 1000.0)),
        "format_name": str(fmt.get("format_name", "unknown")),
        "size": int(fmt.get("size", video.stat().st_size)),
    }


def uniform_frame_indices(frame_count: int) -> list[int]:
    """Return SAMPLE_COUNT nearest-integer positions including both endpoints."""
    last = frame_count - 1
    denominator = SAMPLE_COUNT - 1
    return [
        (sample * last + denominator // 2) // denominator
        for sample in range(SAMPLE_COUNT)
    ]


def ffmpeg_version(ffmpeg: str) -> str:
    completed = run_checked([ffmpeg, "-version"])
    first_line = completed.stdout.decode("utf-8", "replace").splitlines()[0]
    return first_line.strip()


def sample_rgb(
    video: Path, ffmpeg: str, indices: Sequence[int]
) -> tuple[bytes, str]:
    if len(indices) != SAMPLE_COUNT:
        raise ValueError(f"expected {SAMPLE_COUNT} indices")
    # Commas inside the select expression must be escaped for libavfilter. The
    # process itself is launched without a shell.
    selection = "+".join(f"eq(n\\,{index})" for index in indices)
    video_filter = (
        f"select={selection},"
        f"scale={SAMPLE_WIDTH}:{SAMPLE_HEIGHT}:flags=area,"
        "format=rgb24"
    )
    argv = [
        ffmpeg,
        "-v",
        "error",
        "-nostdin",
        "-i",
        str(video),
        "-map",
        "0:v:0",
        "-an",
        "-sn",
        "-dn",
        "-vf",
        video_filter,
        "-fps_mode",
        "passthrough",
        "-frames:v",
        str(SAMPLE_COUNT),
        "-f",
        "rawvideo",
        "-pix_fmt",
        "rgb24",
        "pipe:1",
    ]
    completed = run_checked(argv)
    expected = SAMPLE_COUNT * PIXELS_PER_SAMPLE * 3
    if len(completed.stdout) != expected:
        raise SystemExit(
            f"ffmpeg produced {len(completed.stdout)} RGB bytes; expected {expected}"
        )
    recipe = (
        "frame_index=nearest(i*(frame_count-1)/63),i=0..63;"
        "ffmpeg_select;scale=16:12:flags=area;format=rgb24;"
        "descriptor=ASOLARIA-DOUBLE-RAINBOW-COLOR-STATE-V1"
    )
    return completed.stdout, recipe


def rounded_mean(values: Iterable[int], count: int) -> int:
    return (sum(values) + count // 2) // count


def share(count: int, total: int) -> int:
    return (count * 255 + total // 2) // total


def luma(pixel: tuple[int, int, int]) -> int:
    red, green, blue = pixel
    return (54 * red + 183 * green + 19 * blue + 128) // 256


def hue_bin(pixel: tuple[int, int, int]) -> int | None:
    """Return one of 12 integer hue bins, or None for near-grey pixels."""
    red, green, blue = pixel
    high = max(pixel)
    low = min(pixel)
    chroma = high - low
    if chroma < 12:
        return None
    if high == red:
        hue = ((green - blue) * 256) // chroma
    elif high == green:
        hue = 512 + ((blue - red) * 256) // chroma
    else:
        hue = 1024 + ((red - green) * 256) // chroma
    hue %= 1536
    return min(11, (hue * 12) // 1536)


def frame_descriptor(
    frame: bytes, previous: bytes | None
) -> tuple[int, ...]:
    expected = PIXELS_PER_SAMPLE * 3
    if len(frame) != expected:
        raise ValueError(f"frame is {len(frame)} bytes; expected {expected}")
    pixels = [
        (frame[offset], frame[offset + 1], frame[offset + 2])
        for offset in range(0, len(frame), 3)
    ]
    lumas = [luma(pixel) for pixel in pixels]
    chromas = [max(pixel) - min(pixel) for pixel in pixels]
    saturations = [
        0 if max(pixel) == 0 else ((max(pixel) - min(pixel)) * 255) // max(pixel)
        for pixel in pixels
    ]
    mean_luma = rounded_mean(lumas, PIXELS_PER_SAMPLE)

    spatial_total = 0
    spatial_terms = 0
    for row in range(SAMPLE_HEIGHT):
        for column in range(SAMPLE_WIDTH):
            here = pixels[row * SAMPLE_WIDTH + column]
            if column + 1 < SAMPLE_WIDTH:
                right = pixels[row * SAMPLE_WIDTH + column + 1]
                spatial_total += sum(abs(a - b) for a, b in zip(here, right))
                spatial_terms += 3
            if row + 1 < SAMPLE_HEIGHT:
                below = pixels[(row + 1) * SAMPLE_WIDTH + column]
                spatial_total += sum(abs(a - b) for a, b in zip(here, below))
                spatial_terms += 3
    spatial_gradient = (spatial_total + spatial_terms // 2) // spatial_terms

    if previous is None:
        temporal_gradient = 0
    else:
        temporal_terms = len(frame)
        temporal_gradient = (
            sum(abs(a - b) for a, b in zip(frame, previous))
            + temporal_terms // 2
        ) // temporal_terms

    negative = sum(value < 85 for value in lumas)
    centre = sum(85 <= value <= 170 for value in lumas)
    positive = PIXELS_PER_SAMPLE - negative - centre

    red_dominant = sum(red > green and red > blue for red, green, blue in pixels)
    green_dominant = sum(
        green > red and green > blue for red, green, blue in pixels
    )
    blue_dominant = sum(blue > red and blue > green for red, green, blue in pixels)

    warm = sum(red > blue for red, _, blue in pixels)
    cool = sum(blue > red for red, _, blue in pixels)
    occupied_hues = {value for pixel in pixels if (value := hue_bin(pixel)) is not None}

    values = (
        rounded_mean((pixel[0] for pixel in pixels), PIXELS_PER_SAMPLE),
        rounded_mean((pixel[1] for pixel in pixels), PIXELS_PER_SAMPLE),
        rounded_mean((pixel[2] for pixel in pixels), PIXELS_PER_SAMPLE),
        mean_luma,
        rounded_mean(chromas, PIXELS_PER_SAMPLE),
        rounded_mean(saturations, PIXELS_PER_SAMPLE),
        rounded_mean((abs(value - mean_luma) for value in lumas), PIXELS_PER_SAMPLE),
        spatial_gradient,
        temporal_gradient,
        share(negative, PIXELS_PER_SAMPLE),
        share(centre, PIXELS_PER_SAMPLE),
        share(positive, PIXELS_PER_SAMPLE),
        share(red_dominant, PIXELS_PER_SAMPLE),
        share(green_dominant, PIXELS_PER_SAMPLE),
        share(blue_dominant, PIXELS_PER_SAMPLE),
        share(warm, PIXELS_PER_SAMPLE),
        share(cool, PIXELS_PER_SAMPLE),
        (len(occupied_hues) * 255 + 6) // 12,
    )
    if len(values) != len(FIELD_NAMES) or any(not 0 <= value <= 255 for value in values):
        raise AssertionError(f"invalid descriptor: {values!r}")
    return values


def describe_samples(rgb: bytes) -> list[tuple[int, ...]]:
    frame_bytes = PIXELS_PER_SAMPLE * 3
    descriptors: list[tuple[int, ...]] = []
    previous: bytes | None = None
    for sample in range(SAMPLE_COUNT):
        start = sample * frame_bytes
        frame = rgb[start : start + frame_bytes]
        descriptors.append(frame_descriptor(frame, previous))
        previous = frame
    return descriptors


def gguf_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack("<Q", len(encoded)) + encoded


def metadata_string(key: str, value: str) -> tuple[str, int, bytes]:
    return key, GGUF_TYPE_STRING, gguf_string(value)


def metadata_u32(key: str, value: int) -> tuple[str, int, bytes]:
    return key, GGUF_TYPE_UINT32, struct.pack("<I", value)


def metadata_u64(key: str, value: int) -> tuple[str, int, bytes]:
    return key, GGUF_TYPE_UINT64, struct.pack("<Q", value)


def encode_metadata(entries: Sequence[tuple[str, int, bytes]]) -> bytes:
    output = bytearray()
    for key, value_type, payload in entries:
        output += gguf_string(key)
        output += struct.pack("<I", value_type)
        output += payload
    return bytes(output)


def encode_tensor_info(
    name: str, dimensions: Sequence[int], tensor_type: int, offset: int
) -> bytes:
    output = bytearray(gguf_string(name))
    output += struct.pack("<I", len(dimensions))
    for dimension in dimensions:
        output += struct.pack("<Q", dimension)
    output += struct.pack("<I", tensor_type)
    output += struct.pack("<Q", offset)
    return bytes(output)


def i8_zero_point_encode(descriptors: Sequence[Sequence[int]]) -> bytes:
    encoded = bytearray()
    for descriptor in descriptors:
        for value in descriptor:
            encoded += struct.pack("<b", value - 128)
    return bytes(encoded)


def align_up(value: int, alignment: int = GGUF_ALIGNMENT) -> int:
    return (value + alignment - 1) // alignment * alignment


def build_gguf(
    *,
    source_sha256: str,
    probe: dict[str, object],
    descriptor_sha256: str,
    recipe: str,
    descriptor_bytes: bytes,
) -> tuple[bytes, int]:
    fields = ",".join(FIELD_NAMES)
    entries = [
        metadata_string("general.architecture", "asolaria-color-state"),
        metadata_string("general.name", "DOUBLE-RAINBOW-OIL-3174"),
        metadata_u32("general.alignment", GGUF_ALIGNMENT),
        metadata_string("asolaria.schema", SCHEMA),
        metadata_string("asolaria.payload.kind", "COLOR_STATE_DESCRIPTOR"),
        metadata_string("asolaria.source.youtube_id", SOURCE_ID),
        metadata_string("asolaria.source.url", SOURCE_URL),
        metadata_string("asolaria.source.sha256", source_sha256),
        metadata_u64("asolaria.source.frames", int(probe["frame_count"])),
        metadata_u64("asolaria.source.duration_ms", int(probe["duration_ms"])),
        metadata_u32("asolaria.sample.count", SAMPLE_COUNT),
        metadata_string("asolaria.sample.recipe", recipe),
        metadata_string("asolaria.descriptor.fields", fields),
        metadata_string("asolaria.descriptor.sha256", descriptor_sha256),
        metadata_string(
            "asolaria.descriptor.encoding",
            "GGML_I8;unsigned_value=signed_i8+128;shape=[18,64]",
        ),
        metadata_string(
            "asolaria.oil.axes",
            (
                "sign={NEGATIVE,CENTRE,POSITIVE};"
                "tense={WAS_OIL,IS_OIL,WILL_OIL};"
                "family={OIL,ANTI_OIL,ANTI_ANTI_OIL}"
            ),
        ),
        metadata_string(
            "asolaria.oil.sign_rule",
            "luma<85=NEGATIVE;85<=luma<=170=CENTRE;luma>170=POSITIVE",
        ),
        metadata_u32("asolaria.video_bytes_embedded", 0),
        metadata_u32("asolaria.audio_bytes_embedded", 0),
        metadata_u32("asolaria.lossless_video_claim", 0),
        metadata_u32("asolaria.reconstructs_source_video", 0),
        metadata_string(
            "asolaria.boundary",
            "derived color/time descriptors only; no source frames/audio/video bytes",
        ),
    ]
    metadata = encode_metadata(entries)
    tensor_count = 2
    # Both tensor-info records have fixed byte lengths independent of the
    # numeric padding dimension, so one sizing pass is sufficient.
    placeholder_info = b"".join(
        [
            encode_tensor_info(
                "color_state", (len(FIELD_NAMES), SAMPLE_COUNT), GGML_TYPE_I8, 0
            ),
            encode_tensor_info(
                "size_padding",
                (1,),
                GGML_TYPE_I8,
                len(descriptor_bytes),
            ),
        ]
    )
    header_prefix = struct.pack(
        "<IIQQ", GGUF_MAGIC, GGUF_VERSION, tensor_count, len(entries)
    )
    data_start = align_up(len(header_prefix) + len(metadata) + len(placeholder_info))
    padding_length = TARGET_BYTES - data_start - len(descriptor_bytes)
    if padding_length <= 0:
        raise AssertionError(
            f"metadata leaves no room in {TARGET_BYTES} bytes: pad={padding_length}"
        )
    tensor_info = b"".join(
        [
            encode_tensor_info(
                "color_state", (len(FIELD_NAMES), SAMPLE_COUNT), GGML_TYPE_I8, 0
            ),
            encode_tensor_info(
                "size_padding",
                (padding_length,),
                GGML_TYPE_I8,
                len(descriptor_bytes),
            ),
        ]
    )
    header = header_prefix + metadata + tensor_info
    if align_up(len(header)) != data_start:
        raise AssertionError("tensor dimension changed the GGUF header size")
    blob = (
        header
        + b"\0" * (data_start - len(header))
        + descriptor_bytes
        + b"\0" * padding_length
    )
    if len(blob) != TARGET_BYTES:
        raise AssertionError(f"GGUF is {len(blob)} bytes, expected {TARGET_BYTES}")
    return blob, padding_length


def write_with_sidecar(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    digest = sha256_bytes(data)
    sidecar = path.with_name(path.name + ".sha256")
    sidecar.write_text(f"{digest}  {path.name}\n", encoding="utf-8", newline="\n")
    return digest


def receipt_bytes(
    *,
    source_sha256: str,
    source_size: int,
    probe: dict[str, object],
    indices: Sequence[int],
    descriptors: Sequence[Sequence[int]],
    rgb_sha256: str,
    descriptor_sha256: str,
    recipe: str,
    ffmpeg_build: str,
    gguf_path: Path,
    gguf_sha256: str,
    padding_length: int,
) -> bytes:
    rows = [
        (
            f"DR64HDR|schema={SCHEMA}|youtube_id={SOURCE_ID}"
            f"|samples={SAMPLE_COUNT}|fields={len(FIELD_NAMES)}|json=0"
        ),
        (
            f"SOURCE|url={SOURCE_URL}|youtube_id={SOURCE_ID}|title={SOURCE_TITLE}"
            f"|sha256={source_sha256}|bytes={source_size}"
            f"|codec={probe['codec']}|width={probe['width']}|height={probe['height']}"
            f"|frames={probe['frame_count']}|duration_ms={probe['duration_ms']}|json=0"
        ),
        (
            f"RECIPE|value={recipe}|rgb_sha256={rgb_sha256}"
            f"|ffmpeg={ffmpeg_build}|json=0"
        ),
        (
            "BOUNDARY|payload=COLOR_STATE_DESCRIPTOR|video_bytes_embedded=0"
            "|audio_bytes_embedded=0|lossless_video_claim=0"
            "|reconstructs_source_video=0|json=0"
        ),
        (
            "AXES|sign=NEGATIVE,CENTRE,POSITIVE"
            "|tense=WAS_OIL,IS_OIL,WILL_OIL"
            "|family=OIL,ANTI_OIL,ANTI_ANTI_OIL|json=0"
        ),
        f"FIELDS|ordered={','.join(FIELD_NAMES)}|json=0",
    ]
    last_frame = int(probe["frame_count"]) - 1
    duration_ms = int(probe["duration_ms"])
    for sample_number, (frame_index, descriptor) in enumerate(
        zip(indices, descriptors)
    ):
        time_ms = (
            0
            if last_frame == 0
            else (frame_index * duration_ms + last_frame // 2) // last_frame
        )
        values = "|".join(
            f"{field}={value}" for field, value in zip(FIELD_NAMES, descriptor)
        )
        rows.append(
            f"SLICE|i={sample_number}|frame={frame_index}|time_ms={time_ms}"
            f"|{values}|json=0"
        )
    rows.append(
        f"DESCRIPTOR|bytes={SAMPLE_COUNT * len(FIELD_NAMES)}"
        f"|sha256={descriptor_sha256}|i8_zero_point=128|json=0"
    )
    rows.append(
        f"GGUF|file={gguf_path.name}|bytes={TARGET_BYTES}|sha256={gguf_sha256}"
        f"|padding_tensor_bytes={padding_length}|json=0"
    )
    body = ("\n".join(rows) + "\n").encode("utf-8")
    receipt_commitment = sha256_bytes(body)
    rows.append(
        f"DR64FTR|body_sha256={receipt_commitment}|rows={len(rows) + 1}|json=0"
    )
    return ("\n".join(rows) + "\n").encode("utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("video", type=Path, help="local analysis copy of the video")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--receipt", type=Path, default=DEFAULT_RECEIPT)
    parser.add_argument("--ffmpeg", default=tool_path("ffmpeg"))
    parser.add_argument("--ffprobe", default=tool_path("ffprobe"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    video = args.video.resolve()
    if not video.is_file():
        raise SystemExit(f"video not found: {video}")
    probe = probe_video(video, args.ffprobe)
    source_size = video.stat().st_size
    if int(probe["size"]) != source_size:
        raise SystemExit(
            f"ffprobe size {probe['size']} differs from file size {source_size}"
        )
    source_sha256 = sha256_file(video)
    indices = uniform_frame_indices(int(probe["frame_count"]))
    rgb, recipe = sample_rgb(video, args.ffmpeg, indices)
    descriptors = describe_samples(rgb)
    descriptor_unsigned = bytes(
        value for descriptor in descriptors for value in descriptor
    )
    descriptor_bytes = i8_zero_point_encode(descriptors)
    if len(descriptor_bytes) != SAMPLE_COUNT * len(FIELD_NAMES):
        raise AssertionError("descriptor tensor length mismatch")
    descriptor_sha256 = sha256_bytes(descriptor_unsigned)
    rgb_sha256 = sha256_bytes(rgb)
    blob, padding_length = build_gguf(
        source_sha256=source_sha256,
        probe=probe,
        descriptor_sha256=descriptor_sha256,
        recipe=recipe,
        descriptor_bytes=descriptor_bytes,
    )
    output = args.output.resolve()
    gguf_sha256 = write_with_sidecar(output, blob)
    receipt = receipt_bytes(
        source_sha256=source_sha256,
        source_size=source_size,
        probe=probe,
        indices=indices,
        descriptors=descriptors,
        rgb_sha256=rgb_sha256,
        descriptor_sha256=descriptor_sha256,
        recipe=recipe,
        ffmpeg_build=ffmpeg_version(args.ffmpeg),
        gguf_path=output,
        gguf_sha256=gguf_sha256,
        padding_length=padding_length,
    )
    receipt_sha256 = write_with_sidecar(args.receipt.resolve(), receipt)
    print(
        f"BUILD|gguf={output}|bytes={len(blob)}|sha256={gguf_sha256}"
        f"|samples={SAMPLE_COUNT}|fields={len(FIELD_NAMES)}"
        f"|padding={padding_length}|json=0"
    )
    print(
        f"SOURCE|bytes={source_size}|sha256={source_sha256}"
        f"|frames={probe['frame_count']}|duration_ms={probe['duration_ms']}|json=0"
    )
    print(
        f"RECEIPT|path={args.receipt.resolve()}|bytes={len(receipt)}"
        f"|sha256={receipt_sha256}|json=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
