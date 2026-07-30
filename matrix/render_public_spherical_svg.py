#!/usr/bin/env python3
"""Render a verified public spherical HBP projection as deterministic static SVG.

The renderer accepts only PUBLIC-SPHERICAL-PROJECTION.hbp with its exact SHA-256
sidecar. It performs no network, subprocess, repository, credential, or raw-content
operation. Its only write targets are the allowlisted sibling SVG and its sidecar.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import math
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path

try:
    from . import spherical_public_projection as projection
except ImportError:  # Direct script execution from matrix/.
    import spherical_public_projection as projection


INPUT_NAME = "PUBLIC-SPHERICAL-PROJECTION.hbp"
OUTPUT_NAME = "PUBLIC-SPHERICAL-PROJECTION.svg"
SVG_SCHEMA = "PUBLIC-SPHERICAL-STATIC-SVG-V1"
MAX_SIDECAR_BYTES = 512
MAX_SVG_BYTES = 4_000_000
CENTER_MEMBERS = ("HBI", "HBP", "SHA", "SH", "HASH")
CENTER_TRAVERSAL = ("HBI", "HBP", "SH", "HASH", "SHA")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
RGB = re.compile(r"#[0-9A-F]{6}\Z")

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "matrix" / INPUT_NAME
DEFAULT_OUTPUT = ROOT / "matrix" / OUTPUT_NAME


class RenderError(RuntimeError):
    """A stable fail-closed renderer error."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Node:
    identity: str
    repo_id: str
    tree_id: str
    word_id: str
    parent_word_id: str
    level: int
    truth_tag: str
    color: str
    x: Fraction
    y: Fraction
    z: Fraction


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_link_like(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        junction = getattr(path, "is_junction", None)
        if junction is not None and junction():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return bool(attributes & reparse)
    except FileNotFoundError:
        return False
    except OSError:
        return True


def reject_link_chain(path: Path) -> None:
    candidate = path.absolute()
    for component in (candidate, *candidate.parents):
        if (component.exists() or component.is_symlink()) and is_link_like(component):
            raise RenderError("LINK_OR_JUNCTION_CHAIN")


def read_regular_bounded(path: Path, maximum: int, code: str) -> bytes:
    reject_link_chain(path)
    if not path.exists() or not stat.S_ISREG(path.lstat().st_mode):
        raise RenderError(code)
    with path.open("rb") as handle:
        data = handle.read(maximum + 1)
        if is_link_like(path):
            raise RenderError("LINK_OR_JUNCTION_CHAIN")
    reject_link_chain(path)
    if len(data) > maximum:
        raise RenderError(code + "_TOO_LARGE")
    return data


def read_verified_projection(path: Path) -> tuple[bytes, str]:
    if path.name != INPUT_NAME:
        raise RenderError("INPUT_NAME_NOT_ALLOWLISTED")
    data = read_regular_bounded(path, projection.MAX_OUTPUT_BYTES, "INPUT_NOT_REGULAR")
    sidecar = path.with_name(path.name + ".sha256")
    sidecar_bytes = read_regular_bounded(
        sidecar, MAX_SIDECAR_BYTES, "INPUT_SIDECAR_NOT_REGULAR"
    )
    digest = sha256(data)
    expected = f"{digest}  {path.name}\n".encode("ascii")
    if sidecar_bytes != expected:
        raise RenderError("INPUT_SIDECAR_MISMATCH")
    try:
        verified = projection.verify_projection_bytes(data)
    except projection.ProjectionError as error:
        raise RenderError("INPUT_PROJECTION_INVALID") from error
    if verified != digest:
        raise RenderError("INPUT_VERIFIER_DIGEST_MISMATCH")
    return data, digest


def parse_nodes(data: bytes) -> tuple[Node, ...]:
    try:
        _, parsed = projection.parse_output_rows(data)
    except projection.ProjectionError as error:
        raise RenderError("INPUT_PROJECTION_INVALID") from error
    observed = {
        (
            fields["repo_id"], fields["tree_id"], fields["word_id"],
            int(fields["level"]), fields["truth_tag"],
        ): fields
        for kind, fields in parsed
        if kind == "OBSERVED2D"
    }
    orbs = {
        fields["identity"]: fields
        for kind, fields in parsed
        if kind == "ORB3D"
    }
    nodes: list[Node] = []
    word_keys: set[tuple[str, str, str]] = set()
    for key, fields in observed.items():
        repo_id, tree_id, word_id, level, truth_tag = key
        word_key = (repo_id, tree_id, word_id)
        if word_key in word_keys:
            raise RenderError("AMBIGUOUS_PUBLIC_WORD")
        word_keys.add(word_key)
        identity = f"{repo_id}:{tree_id}:{word_id}:{level}:{truth_tag}"
        orb = orbs.get(identity)
        if orb is None:
            raise RenderError("ORB_IDENTITY_MISSING")
        color = orb.get("derived_public_color", "")
        if not RGB.fullmatch(color):
            raise RenderError("DERIVED_PUBLIC_COLOR_INVALID")
        try:
            point = tuple(
                projection.parse_fraction(orb[f"center_{axis}"])
                for axis in ("x", "y", "z")
            )
        except (KeyError, projection.ProjectionError) as error:
            raise RenderError("ORB_CENTER_INVALID") from error
        nodes.append(
            Node(
                identity=identity,
                repo_id=repo_id,
                tree_id=tree_id,
                word_id=word_id,
                parent_word_id=fields["parent_word_id"],
                level=level,
                truth_tag=truth_tag,
                color=color,
                x=point[0],
                y=point[1],
                z=point[2],
            )
        )
    if not nodes or len(nodes) != len(orbs):
        raise RenderError("NODE_ORB_POPULATION_MISMATCH")
    return tuple(sorted(nodes, key=lambda item: (
        item.level, item.repo_id, item.tree_id, item.word_id, item.truth_tag
    )))


def xml_text(value: str) -> str:
    return html.escape(value, quote=False)


def map_fraction(
    value: Fraction,
    low: Fraction,
    high: Fraction,
    start: int,
    span: int,
) -> int:
    if high == low:
        return start + span // 2
    scaled = (value - low) * span / (high - low)
    return start + scaled.numerator // scaled.denominator


def shortened(value: str, maximum: int = 42) -> str:
    if len(value) <= maximum:
        return value
    return value[: maximum - 1] + "…"


def render_svg(data: bytes, source_sha256: str) -> bytes:
    if not HEX64.fullmatch(source_sha256) or sha256(data) != source_sha256:
        raise RenderError("SOURCE_COMMITMENT_INVALID")
    nodes = parse_nodes(data)
    columns = 2
    rows_per_column = math.ceil(len(nodes) / columns)
    height = max(1_000, 350 + rows_per_column * 26)
    width = 1_600
    plot_left, plot_top, plot_width, plot_height = 70, 150, 820, 700
    low_x, high_x = min(item.x for item in nodes), max(item.x for item in nodes)
    low_y, high_y = min(item.y for item in nodes), max(item.y for item in nodes)
    locations = {
        item.identity: (
            map_fraction(item.x, low_x, high_x, plot_left + 35, plot_width - 70),
            map_fraction(item.y, low_y, high_y, plot_top + 35, plot_height - 70),
        )
        for item in nodes
    }
    by_word = {
        (item.repo_id, item.tree_id, item.word_id): item for item in nodes
    }
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
            f'height="{height}" viewBox="0 0 {width} {height}" '
            'role="img" aria-labelledby="title description">'
        ),
        '<title id="title">Verified Public Spherical Repository Projection</title>',
        (
            '<desc id="description">Static script-free view of verified public '
            'repository nodes, their derived colors, the unordered center membership, '
            'and the distinct ordered traversal.</desc>'
        ),
        (
            f'<metadata>{SVG_SCHEMA}|source_hbp_sha256={source_sha256}'
            f'|records={len(nodes)}|public_metadata_only=1|raw_contents=0|json=0</metadata>'
        ),
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#F4E6D0"/>',
        '<text x="70" y="58" fill="#5A3524" font-family="system-ui, sans-serif" font-size="30" font-weight="700">PUBLIC SPHERICAL PROJECTION</text>',
        '<text x="70" y="92" fill="#76503A" font-family="system-ui, sans-serif" font-size="16">verified HBP → deterministic static SVG · json=0</text>',
        (
            f'<ellipse cx="{plot_left + plot_width // 2}" '
            f'cy="{plot_top + plot_height // 2}" rx="{plot_width // 2}" '
            f'ry="{plot_height // 2}" fill="#D8B58B" stroke="#70452F" '
            'stroke-width="3" opacity="0.72"/>'
        ),
        (
            f'<circle cx="{plot_left + plot_width // 2}" '
            f'cy="{plot_top + plot_height // 2}" r="9" fill="#6F4A36"/>'
        ),
    ]
    for item in nodes:
        if item.parent_word_id == "ROOT":
            continue
        parent = by_word.get((item.repo_id, item.tree_id, item.parent_word_id))
        if parent is None:
            raise RenderError("VISUAL_PARENT_MISSING")
        x1, y1 = locations[parent.identity]
        x2, y2 = locations[item.identity]
        lines.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
            'stroke="#80583F" stroke-width="2" opacity="0.55"/>'
        )
    for item in nodes:
        x, y = locations[item.identity]
        title = xml_text(
            f"{item.repo_id} · {item.word_id} · {item.truth_tag} · {item.color}"
        )
        lines.extend(
            [
                '<g>',
                f'<title>{title}</title>',
                (
                    f'<circle cx="{x}" cy="{y}" r="{7 + min(item.level, 5)}" '
                    f'fill="{item.color}" stroke="#5A3524" stroke-width="2"/>'
                ),
                '</g>',
            ]
        )
    lines.extend(
        [
            '<rect x="960" y="130" width="570" height="110" rx="18" fill="#C08A5A" stroke="#5A3524" stroke-width="2"/>',
            '<text x="990" y="166" fill="#3E251A" font-family="system-ui, sans-serif" font-size="18" font-weight="700">UNORDERED CENTER MEMBERSHIP · NULLSPACE 0</text>',
            '<text x="990" y="207" fill="#3E251A" font-family="ui-monospace, monospace" font-size="22">{HBI, HBP, SHA, SH, HASH}</text>',
            '<rect x="960" y="255" width="570" height="110" rx="18" fill="#E2C29D" stroke="#5A3524" stroke-width="2"/>',
            '<text x="990" y="291" fill="#3E251A" font-family="system-ui, sans-serif" font-size="18" font-weight="700">ORDERED TRAVERSAL · DISTINCT FROM CENTER</text>',
            '<text x="990" y="332" fill="#3E251A" font-family="ui-monospace, monospace" font-size="20">HBI → HBP → SH → HASH → SHA</text>',
            '<text x="960" y="410" fill="#5A3524" font-family="system-ui, sans-serif" font-size="20" font-weight="700">PUBLIC REPOSITORY NODES</text>',
        ]
    )
    list_top = 445
    list_width = 285
    for index, item in enumerate(nodes):
        column = index // rows_per_column
        row = index % rows_per_column
        x = 960 + column * list_width
        y = list_top + row * 26
        visible = shortened(item.repo_id)
        lines.extend(
            [
                '<g>',
                f'<title>{xml_text(item.repo_id)}</title>',
                f'<circle cx="{x + 7}" cy="{y - 5}" r="7" fill="{item.color}" stroke="#5A3524" stroke-width="1"/>',
                (
                    f'<text x="{x + 22}" y="{y}" fill="#4A3023" '
                    f'font-family="system-ui, sans-serif" font-size="13">'
                    f'{xml_text(visible)}</text>'
                ),
                '</g>',
            ]
        )
    lines.extend(
        [
            f'<text x="70" y="{height - 38}" fill="#76503A" font-family="ui-monospace, monospace" font-size="13">{SVG_SCHEMA} · records={len(nodes)} · script=0 · external_refs=0 · raw_contents=0 · json=0</text>',
            '</svg>',
        ]
    )
    output = ("\n".join(lines) + "\n").encode("utf-8")
    if len(output) > MAX_SVG_BYTES:
        raise RenderError("SVG_TOO_LARGE")
    forbidden = (
        b"<script", b"<image", b"<foreignObject", b"<a ", b"href=", b"url(",
        b"@import", b"<?xml-stylesheet", b"file:",
    )
    lowered = output.lower()
    if any(token.lower() in lowered for token in forbidden):
        raise RenderError("SVG_ACTIVE_OR_EXTERNAL_CONTENT")
    return output


def validate_write_targets(source: Path, output: Path, replace: bool) -> Path:
    source_parent = source.parent.absolute()
    output_parent = output.parent.absolute()
    if output.name != OUTPUT_NAME or output_parent != source_parent:
        raise RenderError("OUTPUT_NOT_ALLOWLISTED")
    sidecar = output.with_name(output.name + ".sha256")
    for target in (output, sidecar):
        reject_link_chain(target)
        if not target.parent.is_dir() or is_link_like(target.parent):
            raise RenderError("OUTPUT_PARENT_INVALID")
        if target.exists():
            if not stat.S_ISREG(target.lstat().st_mode):
                raise RenderError("OUTPUT_NOT_REGULAR")
            if not replace:
                raise RenderError("OUTPUT_EXISTS")
    return sidecar


def stage_file(path: Path, data: bytes) -> Path:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{path.name}.pending-", suffix=".tmp",
            dir=path.parent, delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if temporary.read_bytes() != data:
            raise RenderError("STAGED_WRITE_MISMATCH")
        return temporary
    except Exception:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        raise


def write_pair(source: Path, output: Path, svg: bytes, replace: bool) -> str:
    sidecar = validate_write_targets(source, output, replace)
    digest = sha256(svg)
    sidecar_bytes = f"{digest}  {output.name}\n".encode("ascii")
    staged: list[Path] = []
    try:
        staged_svg = stage_file(output, svg)
        staged.append(staged_svg)
        staged_sidecar = stage_file(sidecar, sidecar_bytes)
        staged.append(staged_sidecar)
        validate_write_targets(source, output, replace)
        os.replace(staged_svg, output)
        staged.remove(staged_svg)
        os.replace(staged_sidecar, sidecar)
        staged.remove(staged_sidecar)
    finally:
        for temporary in staged:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    reject_link_chain(output)
    reject_link_chain(sidecar)
    if (
        not stat.S_ISREG(output.lstat().st_mode)
        or not stat.S_ISREG(sidecar.lstat().st_mode)
        or output.read_bytes() != svg
        or sidecar.read_bytes() != sidecar_bytes
    ):
        raise RenderError("FINAL_WRITE_MISMATCH")
    return digest


def render_file(source: Path, output: Path, *, replace: bool = False) -> str:
    source = source.absolute()
    output = output.absolute()
    data, source_digest = read_verified_projection(source)
    svg = render_svg(data, source_digest)
    return write_pair(source, output, svg, replace)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("projection", nargs="?", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("output", nargs="?", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--replace", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = render_file(args.projection, args.output, replace=args.replace)
    except (OSError, UnicodeError, RenderError) as error:
        code = error.code if isinstance(error, RenderError) else "FILESYSTEM"
        print(f"PUBLIC_SPHERICAL_SVG|PASS=0|error={code}|json=0")
        return 1
    print(
        f"PUBLIC_SPHERICAL_SVG|PASS=1|file={OUTPUT_NAME}|sha256={result}"
        "|script=0|external_refs=0|raw_contents=0|json=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
