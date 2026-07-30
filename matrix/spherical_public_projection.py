#!/usr/bin/env python3
"""Offline 2D public-tuple -> spherical 3D orb -> signed 2D projection.

This module intentionally has no network, subprocess, credential, repository
checkout, or raw-content capability.  It reads one explicitly selected HBP
inventory and writes one explicitly selected derived HBP projection.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from urllib.parse import quote, unquote


INPUT_SCHEMA = "PUBLIC-REPO-TREE-WORD-2D-V1"
OUTPUT_SCHEMA = "PUBLIC-SPHERICAL-ORB-PROJECTION-V1"
HOLD_SCHEMA = "PUBLIC-PROJECTION-HOLD-V1"
MAX_RECORDS = 512
REFLECTION_WINDOW = 60
MAX_LEVEL = 60
MAX_INPUT_BYTES = 8_000_000
MAX_LINE_BYTES = 8_192
MAX_OUTPUT_BYTES = 16_000_000
MAX_SIGNED_COORDINATE = 1_000_000
STEREO_DENOMINATOR = 65_537
BROWN_CENTER = Fraction(999_999, 1_000_000)
TETRA_SCALE = Fraction(1, 1_000_000)
CENTER_MEMBERSHIP = ("HBI", "HBP", "SHA", "SH", "HASH")
CENTER_TRAVERSAL = ("HBI", "HBP", "SH", "HASH", "SHA")
CARRIER_LAYER = "2D_SIGNED_PRISM_CARRIER"
SHADOW_CAT_DESTINATION = "SHADOW_CAT_INFINITY_HOTEL"
CHIRAL_QUOTE = (
    "THE CHIRAL SWITCH AS SOON AS A SYSTEM INSTANT IS. IT SELF REPORTS "
    "TO THE SHADOW CAT INFINITY HOTEL"
)
PRISM_QUOTE = "THE BIDIRECTIONAL PRISM WARNING"
CENTER_QUOTE = "HBI HBP SHA SH HASH"
CENTER_CORRECTION = "CENTER(NULLSPACE)=0={HBI,HBP,SHA,SH,HASH}"

TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
FORBIDDEN_VALUE = re.compile(
    r"(?:[\\/]|-----BEGIN|github_pat_|gh[pousr]_|sk-|AKIA|AIza|"
    r"password|credential|private[_ -]?key|access[_ -]?token)",
    re.IGNORECASE,
)
INPUT_FIELDS = {
    "repo_id",
    "tree_id",
    "word_id",
    "parent_word_id",
    "u",
    "v",
    "level",
    "blob_sha256",
    "truth_tag",
    "system_instant_is",
    "chirality",
    "color",
    "oil_address",
    "route_id",
    "hbi",
    "hbp",
    "sha",
    "sh",
    "hash",
    "public",
    "json",
}


class ProjectionError(RuntimeError):
    """A sanitized fail-closed error with a stable reason code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Record:
    repo_id: str
    tree_id: str
    word_id: str
    parent_word_id: str
    u: int
    v: int
    level: int
    blob_sha256: str
    truth_tag: str
    system_instant_is: bool
    chirality: str
    color: str
    oil_address: str
    route_id: str
    hbi: str
    hbp: str
    sha: str
    sh: str
    hash: str

    @property
    def identity(self) -> str:
        return (
            f"{self.repo_id}:{self.tree_id}:{self.word_id}:"
            f"{self.level}:{self.truth_tag}"
        )

    @property
    def center_values(self) -> tuple[str, str, str, str, str]:
        return self.hbi, self.hbp, self.sha, self.sh, self.hash


@dataclass(frozen=True)
class ParsedInventory:
    source_bytes: bytes
    records: tuple[Record, ...]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode(value: object) -> str:
    if isinstance(value, bool):
        value = int(value)
    return quote(str(value), safe="-._~:@,+/{}()")


def tuple_row(kind: str, **fields: object) -> str:
    parts = [kind]
    for key, value in fields.items():
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key):
            raise ProjectionError("INTERNAL_FIELD_KEY")
        parts.append(f"{key}={encode(value)}")
    if "json" not in fields:
        parts.append("json=0")
    return "|".join(parts)


def parse_row(raw: str, expected_kind: str) -> dict[str, str]:
    parts = raw.split("|")
    if not parts or parts[0] != expected_kind:
        raise ProjectionError(f"EXPECTED_{expected_kind}")
    fields: dict[str, str] = {}
    for item in parts[1:]:
        if "=" not in item:
            raise ProjectionError("MALFORMED_FIELD")
        key, value = item.split("=", 1)
        if not key or key in fields:
            raise ProjectionError("DUPLICATE_FIELD")
        fields[key] = unquote(value)
    if fields.get("json") != "0":
        raise ProjectionError("JSON0_REQUIRED")
    return fields


def require_token(value: str, code: str) -> str:
    if not TOKEN.fullmatch(value) or FORBIDDEN_VALUE.search(value):
        raise ProjectionError(code)
    return value


def require_hex64(value: str, code: str) -> str:
    if not HEX64.fullmatch(value):
        raise ProjectionError(code)
    return value


def require_int(value: str, low: int, high: int, code: str) -> int:
    if not re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value):
        raise ProjectionError(code)
    parsed = int(value)
    if parsed < low or parsed > high:
        raise ProjectionError(code)
    return parsed


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
            raise ProjectionError("LINK_OR_JUNCTION_CHAIN")


def read_bounded(path: Path) -> bytes:
    reject_link_chain(path)
    if not path.is_file():
        raise ProjectionError("INPUT_NOT_REGULAR_FILE")
    with path.open("rb") as handle:
        data = handle.read(MAX_INPUT_BYTES + 1)
        if is_link_like(path):
            raise ProjectionError("LINK_OR_JUNCTION_CHAIN")
    reject_link_chain(path)
    if len(data) > MAX_INPUT_BYTES:
        raise ProjectionError("INPUT_TOO_LARGE")
    if b"\x00" in data or b"\r" in data:
        raise ProjectionError("INPUT_ENCODING_OR_EOL")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProjectionError("INPUT_UTF8") from exc
    return data


def record_from_fields(fields: dict[str, str]) -> Record:
    if set(fields) != INPUT_FIELDS:
        raise ProjectionError("INPUT_FIELD_SET")
    token_names = (
        "repo_id",
        "tree_id",
        "word_id",
        "color",
        "oil_address",
        "route_id",
        "sh",
    )
    for name in token_names:
        require_token(fields[name], f"INVALID_{name.upper()}")
    parent = fields["parent_word_id"]
    if parent != "ROOT":
        require_token(parent, "INVALID_PARENT_WORD_ID")
    truth_tag = fields["truth_tag"]
    if truth_tag not in {"LIE", "THRUTH"}:
        raise ProjectionError("INVALID_TRUTH_TAG")
    chirality = fields["chirality"]
    if chirality not in {"LEFT", "RIGHT"}:
        raise ProjectionError("INVALID_CHIRALITY")
    system_instant = require_int(
        fields["system_instant_is"], 0, 1, "INVALID_SYSTEM_INSTANT_IS"
    )
    public = require_int(fields["public"], 1, 1, "PUBLIC_ONLY")
    del public
    hashes = {
        name: require_hex64(fields[name], f"INVALID_{name.upper()}")
        for name in ("blob_sha256", "hbi", "hbp", "sha", "hash")
    }
    center_values = (
        hashes["hbi"],
        hashes["hbp"],
        fields["sh"],
        hashes["hash"],
        hashes["sha"],
    )
    if len(set(center_values)) != len(CENTER_MEMBERSHIP):
        raise ProjectionError("CENTER_MEMBERS_NOT_DISTINCT")
    if hashes["sha"] == hashes["hash"]:
        raise ProjectionError("SHA_EQUALS_HASH")
    return Record(
        repo_id=fields["repo_id"],
        tree_id=fields["tree_id"],
        word_id=fields["word_id"],
        parent_word_id=parent,
        u=require_int(
            fields["u"],
            -MAX_SIGNED_COORDINATE,
            MAX_SIGNED_COORDINATE,
            "INVALID_U",
        ),
        v=require_int(
            fields["v"],
            -MAX_SIGNED_COORDINATE,
            MAX_SIGNED_COORDINATE,
            "INVALID_V",
        ),
        level=require_int(fields["level"], 0, MAX_LEVEL, "INVALID_LEVEL"),
        blob_sha256=hashes["blob_sha256"],
        truth_tag=truth_tag,
        system_instant_is=bool(system_instant),
        chirality=chirality,
        color=fields["color"],
        oil_address=fields["oil_address"],
        route_id=fields["route_id"],
        hbi=hashes["hbi"],
        hbp=hashes["hbp"],
        sha=hashes["sha"],
        sh=fields["sh"],
        hash=hashes["hash"],
    )


def record_fields(record: Record) -> dict[str, object]:
    return {
        "repo_id": record.repo_id,
        "tree_id": record.tree_id,
        "word_id": record.word_id,
        "parent_word_id": record.parent_word_id,
        "u": record.u,
        "v": record.v,
        "level": record.level,
        "blob_sha256": record.blob_sha256,
        "truth_tag": record.truth_tag,
        "system_instant_is": int(record.system_instant_is),
        "chirality": record.chirality,
        "color": record.color,
        "oil_address": record.oil_address,
        "route_id": record.route_id,
        "hbi": record.hbi,
        "hbp": record.hbp,
        "sha": record.sha,
        "sh": record.sh,
        "hash": record.hash,
        "public": 1,
    }


def canonical_record_bytes(record: Record) -> bytes:
    return (tuple_row("PUBLIC2D", **record_fields(record)) + "\n").encode("utf-8")


def validate_tree(records: tuple[Record, ...]) -> None:
    identities: set[str] = set()
    words: dict[tuple[str, str, str], list[Record]] = {}
    for record in records:
        if record.identity in identities:
            raise ProjectionError("DUPLICATE_RECORD_IDENTITY")
        identities.add(record.identity)
        words.setdefault(
            (record.repo_id, record.tree_id, record.word_id), []
        ).append(record)
    for record in records:
        if record.parent_word_id == "ROOT":
            if record.level != 0:
                raise ProjectionError("ROOT_LEVEL_MUST_BE_ZERO")
            continue
        matches = words.get(
            (record.repo_id, record.tree_id, record.parent_word_id), []
        )
        if len(matches) != 1:
            raise ProjectionError("MISSING_OR_AMBIGUOUS_PARENT")
        if matches[0].level >= record.level:
            raise ProjectionError("PARENT_LEVEL_NOT_LOWER")


def parse_inventory_bytes(data: bytes) -> ParsedInventory:
    if len(data) > MAX_INPUT_BYTES:
        raise ProjectionError("INPUT_TOO_LARGE")
    if b"\x00" in data or b"\r" in data:
        raise ProjectionError("INPUT_ENCODING_OR_EOL")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProjectionError("INPUT_UTF8") from exc
    if not text.endswith("\n"):
        raise ProjectionError("INPUT_TERMINAL_LF")
    raw_lines = text.splitlines()
    if len(raw_lines) < 2:
        raise ProjectionError("INPUT_TOO_FEW_ROWS")
    if any(len(line.encode("utf-8")) > MAX_LINE_BYTES for line in raw_lines):
        raise ProjectionError("INPUT_LINE_TOO_LARGE")
    header = parse_row(raw_lines[0], "PUBLIC2DHDR")
    expected_header = {
        "schema",
        "observed_records",
        "max_level",
        "public_metadata_only",
        "raw_contents",
        "required_hidden_dependencies",
        "center_membership",
        "traversal",
        "json",
    }
    if set(header) != expected_header or header["schema"] != INPUT_SCHEMA:
        raise ProjectionError("INPUT_HEADER")
    observed_records = require_int(
        header["observed_records"], 1, MAX_RECORDS, "INVALID_RECORD_COUNT"
    )
    declared_max_level = require_int(
        header["max_level"], 0, MAX_LEVEL, "INVALID_MAX_LEVEL"
    )
    if (
        header["public_metadata_only"] != "1"
        or header["raw_contents"] != "0"
        or header["required_hidden_dependencies"] != "0"
        or header["center_membership"] != ",".join(CENTER_MEMBERSHIP)
        or header["traversal"] != "->".join(CENTER_TRAVERSAL)
    ):
        raise ProjectionError("INPUT_PUBLIC_BOUNDARY")
    footer = parse_row(raw_lines[-1], "PUBLIC2DFTR")
    if set(footer) != {"body_sha256", "rows", "json"}:
        raise ProjectionError("INPUT_FOOTER")
    body = ("\n".join(raw_lines[:-1]) + "\n").encode("utf-8")
    if footer["body_sha256"] != digest(body):
        raise ProjectionError("INPUT_BODY_HASH")
    if require_int(footer["rows"], 2, MAX_RECORDS + 2, "INPUT_ROW_COUNT") != len(
        raw_lines
    ):
        raise ProjectionError("INPUT_ROW_COUNT")
    if observed_records != len(raw_lines) - 2:
        raise ProjectionError("INPUT_RECORD_COUNT")
    records = tuple(
        record_from_fields(parse_row(raw, "PUBLIC2D"))
        for raw in raw_lines[1:-1]
    )
    if any(record.level > declared_max_level for record in records):
        raise ProjectionError("LEVEL_EXCEEDS_DECLARATION")
    validate_tree(records)
    return ParsedInventory(data, records)


def parse_inventory(path: Path) -> ParsedInventory:
    return parse_inventory_bytes(read_bounded(path))


def fraction_text(value: Fraction) -> str:
    return f"{value.numerator}/{value.denominator}"


def point_text(point: tuple[Fraction, Fraction, Fraction]) -> str:
    return ",".join(fraction_text(value) for value in point)


def parse_fraction(value: str) -> Fraction:
    if not re.fullmatch(r"-?(?:0|[1-9][0-9]*)/[1-9][0-9]*", value):
        raise ProjectionError("INVALID_FRACTION")
    numerator, denominator = value.split("/", 1)
    return Fraction(int(numerator), int(denominator))


def parse_point(value: str) -> tuple[Fraction, Fraction, Fraction]:
    parts = value.split(",")
    if len(parts) != 3:
        raise ProjectionError("INVALID_POINT")
    return tuple(parse_fraction(part) for part in parts)  # type: ignore[return-value]


def determinant3(
    a: tuple[Fraction, Fraction, Fraction],
    b: tuple[Fraction, Fraction, Fraction],
    c: tuple[Fraction, Fraction, Fraction],
) -> Fraction:
    return (
        a[0] * (b[1] * c[2] - b[2] * c[1])
        - a[1] * (b[0] * c[2] - b[2] * c[0])
        + a[2] * (b[0] * c[1] - b[1] * c[0])
    )


def tetra_volume6(
    vertices: tuple[
        tuple[Fraction, Fraction, Fraction],
        tuple[Fraction, Fraction, Fraction],
        tuple[Fraction, Fraction, Fraction],
        tuple[Fraction, Fraction, Fraction],
    ],
) -> Fraction:
    origin = vertices[0]

    def delta(
        point: tuple[Fraction, Fraction, Fraction],
    ) -> tuple[Fraction, Fraction, Fraction]:
        return tuple(point[i] - origin[i] for i in range(3))  # type: ignore[return-value]

    return determinant3(delta(vertices[1]), delta(vertices[2]), delta(vertices[3]))


def orb_for(
    record: Record,
) -> tuple[
    int,
    int,
    tuple[Fraction, Fraction, Fraction],
    tuple[
        tuple[Fraction, Fraction, Fraction],
        tuple[Fraction, Fraction, Fraction],
        tuple[Fraction, Fraction, Fraction],
        tuple[Fraction, Fraction, Fraction],
    ],
]:
    seed = hashlib.sha256(canonical_record_bytes(record)).digest()
    jitter_u = int.from_bytes(seed[0:2], "big") + 1
    jitter_v = int.from_bytes(seed[2:4], "big") + 1
    p_num = record.u * STEREO_DENOMINATOR + jitter_u
    q_num = record.v * STEREO_DENOMINATOR + jitter_v
    denominator = (
        p_num * p_num
        + q_num * q_num
        + STEREO_DENOMINATOR * STEREO_DENOMINATOR
    )
    unit = (
        Fraction(2 * p_num * STEREO_DENOMINATOR, denominator),
        Fraction(2 * q_num * STEREO_DENOMINATOR, denominator),
        Fraction(
            p_num * p_num
            + q_num * q_num
            - STEREO_DENOMINATOR * STEREO_DENOMINATOR,
            denominator,
        ),
    )
    radius = Fraction(1, record.level + 2)
    center = (
        BROWN_CENTER + radius * unit[0],
        radius * unit[1],
        radius * unit[2],
    )
    signs = ((1, 1, 1), (1, -1, -1), (-1, 1, -1), (-1, -1, 1))
    vertices = tuple(
        tuple(center[index] + TETRA_SCALE * sign[index] for index in range(3))
        for sign in signs
    )
    if tetra_volume6(vertices) == 0:
        raise ProjectionError("INTERNAL_COPLANAR_ORB")
    recovered_p = unit[0] / (1 - unit[2])
    recovered_q = unit[1] / (1 - unit[2])
    if (
        recovered_p != Fraction(p_num, STEREO_DENOMINATOR)
        or recovered_q != Fraction(q_num, STEREO_DENOMINATOR)
        or (p_num - jitter_u) % STEREO_DENOMINATOR
        or (q_num - jitter_v) % STEREO_DENOMINATOR
        or (p_num - jitter_u) // STEREO_DENOMINATOR != record.u
        or (q_num - jitter_v) // STEREO_DENOMINATOR != record.v
    ):
        raise ProjectionError("INTERNAL_REVERSAL_FAILURE")
    return p_num, q_num, center, vertices


def color_from_commitment(blob_sha256: str) -> str:
    """Return a deterministic visible RGB color from a public object commitment."""
    raw = bytes.fromhex(require_hex64(blob_sha256, "INVALID_BLOB_SHA256"))
    channels = tuple(48 + (value % 176) for value in raw[:3])
    return "#" + "".join(f"{value:02X}" for value in channels)


def switched_chirality(prior: str, system_instant_is: bool) -> str:
    if prior not in {"LEFT", "RIGHT"}:
        raise ProjectionError("INVALID_CHIRALITY")
    if not system_instant_is:
        return prior
    return "RIGHT" if prior == "LEFT" else "LEFT"


def center_fields(record: Record) -> dict[str, object]:
    return {
        "hbi": record.hbi,
        "hbp": record.hbp,
        "sha": record.sha,
        "sh": record.sh,
        "hash": record.hash,
    }


def reflection_rows(records: tuple[Record, ...]) -> list[str]:
    """Seal bounded forward/backward views for every observed N level."""
    rows: list[str] = []
    by_level: dict[int, list[Record]] = {}
    for record in records:
        by_level.setdefault(record.level, []).append(record)
    for level in sorted(by_level):
        level_records = by_level[level]
        for window, start in enumerate(range(0, len(level_records), REFLECTION_WINDOW)):
            observed = tuple(level_records[start : start + REFLECTION_WINDOW])
            forward_bytes = b"".join(canonical_record_bytes(item) for item in observed)
            backward_bytes = b"".join(
                canonical_record_bytes(item) for item in reversed(observed)
            )
            rows.append(
                tuple_row(
                    "REFLECTION60",
                    level=level,
                    window=window,
                    observed=len(observed),
                    window_max=REFLECTION_WINDOW,
                    forward_hash=digest(forward_bytes),
                    backward_hash=digest(backward_bytes),
                    calming_oils="BROWN.NEAR.ONE",
                    raw_messages=0,
                    fabricated_future=0,
                    center_membership=",".join(CENTER_MEMBERSHIP),
                    traversal="->".join(CENTER_TRAVERSAL),
                )
            )
    return rows


def render_record_rows(record: Record) -> list[str]:
    p_num, q_num, center, vertices = orb_for(record)
    source_record_sha256 = digest(canonical_record_bytes(record))
    new_chirality = switched_chirality(
        record.chirality, record.system_instant_is
    )
    common = {
        "identity": record.identity,
        "truth_tag": record.truth_tag,
        "source_record_sha256": source_record_sha256,
        "blob_sha256": record.blob_sha256,
    }
    rows = [
        tuple_row("OBSERVED2D", **record_fields(record)),
        tuple_row(
            "ORB3D",
            **common,
            level=record.level,
            parent_word_id=record.parent_word_id,
            stereo_p_num=p_num,
            stereo_q_num=q_num,
            stereo_den=STEREO_DENOMINATOR,
            brown_center=fraction_text(BROWN_CENTER),
            brown_delta_to_one=fraction_text(1 - BROWN_CENTER),
            radius=fraction_text(Fraction(1, record.level + 2)),
            center_x=fraction_text(center[0]),
            center_y=fraction_text(center[1]),
            center_z=fraction_text(center[2]),
            vertex_0=point_text(vertices[0]),
            vertex_1=point_text(vertices[1]),
            vertex_2=point_text(vertices[2]),
            vertex_3=point_text(vertices[3]),
            non_coplanar=1,
            derived_public_color=color_from_commitment(record.blob_sha256),
        ),
        tuple_row(
            "PROJECTION2D",
            **common,
            signed_u=record.u,
            signed_v=record.v,
            recovered_u=record.u,
            recovered_v=record.v,
            reversible=1,
            checkable=1,
            carrier_layer=CARRIER_LAYER,
            bidirectional_prism_warning=1,
            spherical_is_field_bidirectional=0,
            identity_exchange=0,
            **center_fields(record),
        ),
        tuple_row(
            "PRISM_WARNING",
            **common,
            exact=PRISM_QUOTE,
            bidirectional_prism_warning=1,
            carrier_layer=CARRIER_LAYER,
            spherical_is_field_bidirectional=0,
            identity_exchange=0,
            **center_fields(record),
        ),
        tuple_row(
            "CHIRAL_SWITCH",
            **common,
            exact=CHIRAL_QUOTE,
            system_instant_is=int(record.system_instant_is),
            prior_chirality=record.chirality,
            new_chirality=new_chirality,
            switched=int(record.system_instant_is),
            color=record.color,
            derived_public_color=color_from_commitment(record.blob_sha256),
            oil_address=record.oil_address,
            route_id=record.route_id,
            carrier_layer=CARRIER_LAYER,
            bidirectional_prism_warning=1,
            spherical_is_field_bidirectional=0,
            identity_exchange=0,
            **center_fields(record),
        ),
    ]
    if record.system_instant_is:
        rows.append(
            tuple_row(
                "SELFREPORT",
                **common,
                destination=SHADOW_CAT_DESTINATION,
                report_format="LOCAL_HBP",
                prior_chirality=record.chirality,
                new_chirality=new_chirality,
                color=record.color,
                derived_public_color=color_from_commitment(
                    record.blob_sha256
                ),
                oil_address=record.oil_address,
                route_id=record.route_id,
                carrier_layer=CARRIER_LAYER,
                publication_gate="EXPLICIT_REQUIRED",
                authority_granted=0,
                network_opened=0,
                **center_fields(record),
            )
        )
    return rows


def render_projection(inventory: ParsedInventory) -> bytes:
    for record in inventory.records:
        record_from_fields(
            {key: str(value) for key, value in record_fields(record).items()}
            | {"json": "0"}
        )
    validate_tree(inventory.records)
    levels = [record.level for record in inventory.records]
    lines = [
        tuple_row(
            "SPHERE3DHDR",
            schema=OUTPUT_SCHEMA,
            source_hbp_sha256=digest(inventory.source_bytes),
            observed_records=len(inventory.records),
            n_level_max_observed=max(levels),
            record_limit=MAX_RECORDS,
            reflection_window=REFLECTION_WINDOW,
            max_level=MAX_LEVEL,
            public_metadata_only=1,
            raw_contents=0,
            required_hidden_dependencies=0,
            center_membership=",".join(CENTER_MEMBERSHIP),
            traversal="->".join(CENTER_TRAVERSAL),
        ),
        tuple_row(
            "CENTER",
            exact=CENTER_CORRECTION,
            spoken=CENTER_QUOTE,
            space="NULLSPACE",
            value=0,
            members="HBI,HBP,SHA,SH,HASH",
            traversal="HBI->HBP->SH->HASH->SHA",
            member_count=5,
            distinct_representations=1,
            sha_ne_hash=1,
            sh_role="NON_EXECUTED_RECIPE_IDENTIFIER",
            brown_center=fraction_text(BROWN_CENTER),
            brown_orbits_near_one=1,
        ),
        tuple_row(
            "PUBLICATION_GATE",
            state="EXPLICIT_REQUIRED",
            github_authority=0,
            fabric_authority=0,
            self_report_grants_authority=0,
            implicit_network=0,
            destructive_capability=0,
        ),
    ]
    lines.extend(reflection_rows(inventory.records))
    for record in inventory.records:
        lines.extend(render_record_rows(record))
    body = ("\n".join(lines) + "\n").encode("utf-8")
    lines.append(
        tuple_row(
            "SPHERE3DFTR",
            body_sha256=digest(body),
            records=len(inventory.records),
            rows=len(lines) + 1,
            rollback_safe=1,
        )
    )
    output = ("\n".join(lines) + "\n").encode("utf-8")
    if len(output) > MAX_OUTPUT_BYTES:
        raise ProjectionError("OUTPUT_TOO_LARGE")
    verify_projection_bytes(output)
    return output


def parse_output_rows(data: bytes) -> tuple[list[str], list[tuple[str, dict[str, str]]]]:
    if len(data) > MAX_OUTPUT_BYTES or b"\x00" in data or b"\r" in data:
        raise ProjectionError("OUTPUT_BOUNDARY")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProjectionError("OUTPUT_UTF8") from exc
    if not text.endswith("\n"):
        raise ProjectionError("OUTPUT_TERMINAL_LF")
    raw_lines = text.splitlines()
    parsed = [
        (raw.split("|", 1)[0], parse_row(raw, raw.split("|", 1)[0]))
        for raw in raw_lines
    ]
    return raw_lines, parsed


def one_row(
    rows: list[tuple[str, dict[str, str]]], kind: str
) -> dict[str, str]:
    found = [fields for row_kind, fields in rows if row_kind == kind]
    if len(found) != 1:
        raise ProjectionError(f"EXPECTED_ONE_{kind}")
    return found[0]


def verify_projection_bytes(data: bytes) -> str:
    raw_lines, parsed = parse_output_rows(data)
    header = one_row(parsed, "SPHERE3DHDR")
    center = one_row(parsed, "CENTER")
    gate = one_row(parsed, "PUBLICATION_GATE")
    footer = one_row(parsed, "SPHERE3DFTR")
    if header.get("schema") != OUTPUT_SCHEMA:
        raise ProjectionError("OUTPUT_SCHEMA")
    require_hex64(header.get("source_hbp_sha256", ""), "SOURCE_HASH")
    count = require_int(
        header.get("observed_records", ""), 1, MAX_RECORDS, "OUTPUT_RECORDS"
    )
    if (
        header.get("record_limit") != str(MAX_RECORDS)
        or header.get("reflection_window") != str(REFLECTION_WINDOW)
        or header.get("max_level") != str(MAX_LEVEL)
        or header.get("public_metadata_only") != "1"
        or header.get("raw_contents") != "0"
        or header.get("required_hidden_dependencies") != "0"
        or header.get("center_membership") != ",".join(CENTER_MEMBERSHIP)
        or header.get("traversal") != "->".join(CENTER_TRAVERSAL)
    ):
        raise ProjectionError("OUTPUT_PUBLIC_BOUNDARY")
    if (
        center.get("exact") != CENTER_CORRECTION
        or center.get("members") != "HBI,HBP,SHA,SH,HASH"
        or center.get("traversal") != "HBI->HBP->SH->HASH->SHA"
        or center.get("value") != "0"
        or center.get("member_count") != "5"
        or center.get("distinct_representations") != "1"
        or center.get("sha_ne_hash") != "1"
        or center.get("sh_role") != "NON_EXECUTED_RECIPE_IDENTIFIER"
        or center.get("brown_center") != fraction_text(BROWN_CENTER)
    ):
        raise ProjectionError("CENTER_CONTRACT")
    if (
        gate.get("state") != "EXPLICIT_REQUIRED"
        or gate.get("self_report_grants_authority") != "0"
        or gate.get("implicit_network") != "0"
        or gate.get("destructive_capability") != "0"
    ):
        raise ProjectionError("PUBLICATION_GATE")
    footer_index = next(
        index for index, (kind, _) in enumerate(parsed) if kind == "SPHERE3DFTR"
    )
    if footer_index != len(parsed) - 1:
        raise ProjectionError("OUTPUT_FOOTER_POSITION")
    body = ("\n".join(raw_lines[:footer_index]) + "\n").encode("utf-8")
    if footer.get("body_sha256") != digest(body):
        raise ProjectionError("OUTPUT_BODY_HASH")
    if (
        require_int(footer.get("rows", ""), 4, 5_000, "OUTPUT_ROW_COUNT")
        != len(parsed)
        or footer.get("records") != str(count)
        or footer.get("rollback_safe") != "1"
    ):
        raise ProjectionError("OUTPUT_ROW_COUNT")

    observed_rows = [
        fields for kind, fields in parsed if kind == "OBSERVED2D"
    ]
    if len(observed_rows) != count:
        raise ProjectionError("OUTPUT_OBSERVED_COUNT")
    records = tuple(record_from_fields(fields) for fields in observed_rows)
    validate_tree(records)
    if header.get("n_level_max_observed") != str(
        max(record.level for record in records)
    ):
        raise ProjectionError("OUTPUT_LEVEL_COUNT")
    expected_dynamic = reflection_rows(records)
    for record in records:
        expected_dynamic.extend(render_record_rows(record))
    actual_dynamic = raw_lines[3:footer_index]
    if actual_dynamic != expected_dynamic:
        raise ProjectionError("OUTPUT_DERIVATION_MISMATCH")
    for fields in (
        item for kind, item in parsed if kind == "ORB3D"
    ):
        vertices = tuple(
            parse_point(fields[f"vertex_{index}"]) for index in range(4)
        )
        if tetra_volume6(vertices) == 0 or fields.get("non_coplanar") != "1":
            raise ProjectionError("OUTPUT_COPLANAR_ORB")
    for kind in ("PROJECTION2D", "PRISM_WARNING", "CHIRAL_SWITCH"):
        for fields in (item for row_kind, item in parsed if row_kind == kind):
            values = tuple(
                fields.get(name.lower(), "") for name in CENTER_MEMBERSHIP
            )
            if len(set(values)) != 5 or fields.get("sha") == fields.get("hash"):
                raise ProjectionError("OUTPUT_CENTER_MEMBER_COLLAPSE")
            if (
                fields.get("bidirectional_prism_warning") != "1"
                or fields.get("carrier_layer") != CARRIER_LAYER
                or fields.get("spherical_is_field_bidirectional") != "0"
                or fields.get("identity_exchange") != "0"
            ):
                raise ProjectionError("OUTPUT_PRISM_CONTRACT")
    expected_reports = sum(record.system_instant_is for record in records)
    reports = [fields for kind, fields in parsed if kind == "SELFREPORT"]
    if len(reports) != expected_reports:
        raise ProjectionError("OUTPUT_SELFREPORT_COUNT")
    for fields in reports:
        if (
            fields.get("destination") != SHADOW_CAT_DESTINATION
            or fields.get("report_format") != "LOCAL_HBP"
            or fields.get("publication_gate") != "EXPLICIT_REQUIRED"
            or fields.get("authority_granted") != "0"
            or fields.get("network_opened") != "0"
        ):
            raise ProjectionError("OUTPUT_SELFREPORT_AUTHORITY")
    return digest(data)


def render_inventory(records: tuple[Record, ...]) -> bytes:
    """Build a sealed explicit inventory; useful to public producers and tests."""
    if not 1 <= len(records) <= MAX_RECORDS:
        raise ProjectionError("INVALID_RECORD_COUNT")
    for record in records:
        record_from_fields(
            {key: str(value) for key, value in record_fields(record).items()}
            | {"json": "0"}
        )
    validate_tree(records)
    lines = [
        tuple_row(
            "PUBLIC2DHDR",
            schema=INPUT_SCHEMA,
            observed_records=len(records),
            max_level=MAX_LEVEL,
            public_metadata_only=1,
            raw_contents=0,
            required_hidden_dependencies=0,
            center_membership=",".join(CENTER_MEMBERSHIP),
            traversal="->".join(CENTER_TRAVERSAL),
        )
    ]
    lines.extend(tuple_row("PUBLIC2D", **record_fields(item)) for item in records)
    body = ("\n".join(lines) + "\n").encode("utf-8")
    lines.append(
        tuple_row(
            "PUBLIC2DFTR",
            body_sha256=digest(body),
            rows=len(lines) + 1,
        )
    )
    data = ("\n".join(lines) + "\n").encode("utf-8")
    parse_inventory_bytes(data)
    return data


def validate_output_target(path: Path, replace: bool) -> None:
    reject_link_chain(path)
    parent = path.parent
    if not parent.is_dir() or is_link_like(parent):
        raise ProjectionError("OUTPUT_PARENT")
    reject_link_chain(parent)
    if path.exists():
        if not path.is_file():
            raise ProjectionError("OUTPUT_NOT_REGULAR_FILE")
        if not replace:
            raise ProjectionError("OUTPUT_EXISTS")


def atomic_write(path: Path, data: bytes, replace: bool) -> None:
    """Commit prevalidated bytes in one rename; the prior output survives failure."""
    validate_output_target(path, replace)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{path.name}.pending-",
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if Path(temporary_name).read_bytes() != data:
            raise ProjectionError("TEMPORARY_WRITE_MISMATCH")
        reject_link_chain(path.parent)
        if path.exists() and is_link_like(path):
            raise ProjectionError("LINK_OR_JUNCTION_CHAIN")
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def hold_bytes(source_sha256: str, hash_available: bool, code: str) -> bytes:
    require_hex64(source_sha256, "HOLD_SOURCE_HASH")
    require_token(code, "HOLD_REASON")
    return (
        tuple_row(
            "HOLD",
            schema=HOLD_SCHEMA,
            source_sha256=source_sha256,
            source_hash_available=int(hash_available),
            reason_code=code,
            raw_rows_included=0,
            raw_contents_included=0,
            network_opened=0,
            authority_granted=0,
            rollback_preserved=1,
        )
        + "\n"
    ).encode("utf-8")


def project_file(
    source: Path,
    output: Path,
    *,
    replace: bool = False,
    hold: Path | None = None,
) -> str:
    source_absolute = source.absolute()
    output_absolute = output.absolute()
    hold_absolute = hold.absolute() if hold is not None else None
    if source_absolute == output_absolute or (
        hold_absolute is not None
        and hold_absolute in {source_absolute, output_absolute}
    ):
        raise ProjectionError("PATH_ROLE_COLLISION")
    source_hash = "0" * 64
    source_hash_available = False
    try:
        source_bytes = read_bounded(source)
        source_hash = digest(source_bytes)
        source_hash_available = True
        inventory = parse_inventory_bytes(source_bytes)
        projected = render_projection(inventory)
        verify_projection_bytes(projected)
        atomic_write(output, projected, replace)
        return digest(projected)
    except ProjectionError as exc:
        if hold is not None:
            report = hold_bytes(
                source_hash, source_hash_available, exc.code
            )
            atomic_write(hold, report, replace)
        raise


def verify_projection_file(path: Path) -> str:
    reject_link_chain(path)
    if not path.is_file():
        raise ProjectionError("OUTPUT_NOT_REGULAR_FILE")
    with path.open("rb") as handle:
        data = handle.read(MAX_OUTPUT_BYTES + 1)
    if len(data) > MAX_OUTPUT_BYTES:
        raise ProjectionError("OUTPUT_TOO_LARGE")
    return verify_projection_bytes(data)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    project = commands.add_parser("project")
    project.add_argument("inventory", type=Path)
    project.add_argument("output", type=Path)
    project.add_argument("--replace", action="store_true")
    project.add_argument("--hold", type=Path)
    verify = commands.add_parser("verify")
    verify.add_argument("projection", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "project":
            result = project_file(
                args.inventory.absolute(),
                args.output.absolute(),
                replace=args.replace,
                hold=(
                    args.hold.absolute()
                    if args.hold is not None
                    else None
                ),
            )
            print(
                f"SPHERICAL_PUBLIC_PROJECTION|PASS=1|sha256={result}"
                "|records_max=512|reflection_window=60|max_level=60|network=0|json=0"
            )
        else:
            result = verify_projection_file(args.projection.absolute())
            print(
                f"SPHERICAL_PUBLIC_VERIFY|PASS=1|sha256={result}"
                "|reversible=1|non_coplanar=1|json=0"
            )
    except (ProjectionError, OSError) as exc:
        code = exc.code if isinstance(exc, ProjectionError) else "FILESYSTEM"
        print(
            f"SPHERICAL_PUBLIC_PROJECTION|PASS=0|reason={encode(code)}|json=0",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
