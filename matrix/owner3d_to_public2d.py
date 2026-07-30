#!/usr/bin/env python3
"""Verify a public OWNER3D seal and derive one PUBLIC2D root per repository.

The adapter is offline. It reads the selected HBI, its sibling HBP, and their
SHA-256 sidecars; it carries no GitHub, subprocess, JSON, credential, blob-body,
or private-repository acquisition capability.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

try:
    from . import spherical_public_projection as projection
except ImportError:  # Direct script execution from matrix/.
    import spherical_public_projection as projection


OWNER_SCHEMA_V1 = "ASOLARIA-PUBLIC-OWNER-3D-TREE-V1"
OWNER_SCHEMA_V2 = "ASOLARIA-PUBLIC-OWNER-3D-TREE-V2"
OWNER_SCHEMAS = {OWNER_SCHEMA_V1, OWNER_SCHEMA_V2}
CENTER_MEMBERS = "HBI,HBP,SHA,SH,HASH"
CENTER_TRAVERSAL = "HBI,HBP,SH,HASH,SHA"
OWNER_RECIPE = "GH_PUBLIC_OWNER_TREE_V1"
PUBLIC_SH = "GH.PUBLIC.OWNER.TREE.V1"
MAX_REPOS = projection.MAX_RECORDS
MAX_HBI_BYTES = 64 * 1024
MAX_HBP_BYTES = projection.MAX_INPUT_BYTES
MAX_LINE_BYTES = projection.MAX_LINE_BYTES
MAX_MEDIA_DECLARED_BYTES = 1_000_000_000_000_000
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
OWNER = re.compile(r"[A-Za-z0-9-]{1,39}\Z")
REPO_NAME = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
UTC_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z\Z")
COLOR = re.compile(r"#[0-9A-F]{6}\Z")
PERCENT_VALUE = re.compile(r"(?:[^%]|%[0-9A-Fa-f]{2})*\Z")
ZERO_SHA1 = "0" * 40
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class AdapterError(RuntimeError):
    """A stable, non-sensitive verification or conversion failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class OwnerRepo:
    index: int
    name: str
    state: str
    object_root: str
    tree: str
    color: str
    image_entries: int
    video_entries: int
    media_declared_bytes: int
    media_size_unknown_entries: int
    media_root: str
    source_row: bytes


@dataclass(frozen=True)
class OwnerSeal:
    schema: str
    hbi_sha256: str
    hbp_sha256: str
    hbp_filename: str
    object_commitment: str
    repositories: tuple[OwnerRepo, ...]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_row(raw: str, expected_kind: str) -> dict[str, str]:
    parts = raw.split("|")
    if not parts or parts[0] != expected_kind:
        raise AdapterError(f"EXPECTED_{expected_kind}")
    fields: dict[str, str] = {}
    for item in parts[1:]:
        if "=" not in item:
            raise AdapterError("MALFORMED_FIELD")
        key, encoded = item.split("=", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or key in fields:
            raise AdapterError("FIELD_KEY")
        if PERCENT_VALUE.fullmatch(encoded) is None:
            raise AdapterError("FIELD_PERCENT_ENCODING")
        value = unquote(encoded)
        if any(ord(character) < 32 for character in value):
            raise AdapterError("FIELD_CONTROL_CHARACTER")
        fields[key] = value
    if fields.get("json") != "0":
        raise AdapterError("JSON0_REQUIRED")
    return fields


def exact_fields(fields: dict[str, str], names: set[str], code: str) -> None:
    if set(fields) != names:
        raise AdapterError(code)


def integer(value: str, low: int, high: int, code: str) -> int:
    if re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        raise AdapterError(code)
    result = int(value)
    if not low <= result <= high:
        raise AdapterError(code)
    return result


def hex_value(value: str, expression: re.Pattern[str], code: str) -> str:
    if expression.fullmatch(value) is None:
        raise AdapterError(code)
    return value


def read_file(path: Path, limit: int, code: str) -> bytes:
    try:
        projection.reject_link_chain(path)
    except projection.ProjectionError as exc:
        raise AdapterError("LINK_OR_JUNCTION_CHAIN") from exc
    if not path.is_file():
        raise AdapterError(code)
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    try:
        projection.reject_link_chain(path)
    except projection.ProjectionError as exc:
        raise AdapterError("LINK_OR_JUNCTION_CHAIN") from exc
    if len(data) > limit:
        raise AdapterError(f"{code}_TOO_LARGE")
    if b"\x00" in data or b"\r" in data:
        raise AdapterError(f"{code}_ENCODING_OR_EOL")
    return data


def text_lines(data: bytes, code: str) -> list[str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AdapterError(f"{code}_UTF8") from exc
    if not text.endswith("\n"):
        raise AdapterError(f"{code}_TERMINAL_LF")
    lines = text.splitlines()
    if any(len(line.encode("utf-8")) > MAX_LINE_BYTES for line in lines):
        raise AdapterError(f"{code}_LINE_TOO_LARGE")
    return lines


def verify_sidecar(path: Path, data: bytes) -> str:
    sidecar = path.with_name(path.name + ".sha256")
    sidecar_data = read_file(sidecar, 512, "SIDECAR")
    expected_digest = digest(data)
    expected = f"{expected_digest}  {path.name}\n".encode("ascii")
    if sidecar_data != expected:
        raise AdapterError("SIDECAR_MISMATCH")
    return expected_digest


def verify_center(fields: dict[str, str], *, hbp: bool) -> None:
    expected = {
        "nullspace",
        "center_members",
        "traversal",
        "sha_equals_hash",
        "json",
    }
    if hbp:
        expected |= {"brown_center", "close_to"}
    exact_fields(fields, expected, "CENTER_FIELDS")
    if (
        fields["nullspace"] != "0"
        or fields["center_members"] != CENTER_MEMBERS
        or fields["traversal"] != CENTER_TRAVERSAL
        or fields["sha_equals_hash"] != "0"
        or (hbp and fields["brown_center"] != "#8B5A2B")
        or (hbp and fields["close_to"] != "1")
    ):
        raise AdapterError("CENTER_CONTRACT")


def parse_hbi(index_path: Path) -> tuple[str, str, str, int, str, str]:
    data = read_file(index_path, MAX_HBI_BYTES, "HBI")
    hbi_sha = verify_sidecar(index_path, data)
    lines = text_lines(data, "HBI")
    if len(lines) != 6:
        raise AdapterError("HBI_ROW_COUNT")
    header = parse_row(lines[0], "OWNER3DHBI")
    exact_fields(header, {"schema", "version", "json"}, "HBI_HEADER_FIELDS")
    schema = header["schema"]
    if schema not in OWNER_SCHEMAS or header["version"] != "1":
        raise AdapterError("HBI_HEADER")
    verify_center(parse_row(lines[1], "CENTER"), hbp=False)
    hbp_ref = parse_row(lines[2], "HBP")
    exact_fields(
        hbp_ref,
        {"path", "sha256", "repos", "raw_blob_bodies", "json"},
        "HBI_HBP_FIELDS",
    )
    filename = hbp_ref["path"]
    if (
        not filename
        or filename in {".", ".."}
        or Path(filename).name != filename
        or "/" in filename
        or "\\" in filename
    ):
        raise AdapterError("HBI_HBP_PATH")
    hbp_sha = hex_value(hbp_ref["sha256"], HEX64, "HBI_HBP_SHA")
    repos = integer(hbp_ref["repos"], 1, MAX_REPOS, "HBI_REPOS")
    if hbp_ref["raw_blob_bodies"] != "0":
        raise AdapterError("HBI_RAW_BLOB_BOUNDARY")
    object_hash = parse_row(lines[3], "HASH")
    exact_fields(object_hash, {"role", "value", "json"}, "HBI_HASH_FIELDS")
    if object_hash["role"] != "SPHERICAL_OBJECT_COMMITMENT":
        raise AdapterError("HBI_HASH_ROLE")
    root = hex_value(object_hash["value"], HEX64, "HBI_HASH")
    recipe = parse_row(lines[4], "SH")
    exact_fields(recipe, {"recipe", "executed_authority", "json"}, "HBI_SH_FIELDS")
    if recipe["recipe"] != OWNER_RECIPE or recipe["executed_authority"] != "0":
        raise AdapterError("HBI_SH")
    footer = parse_row(lines[5], "OWNER3DHBIFTR")
    exact_fields(footer, {"body_sha256", "rows", "json"}, "HBI_FOOTER_FIELDS")
    body = ("\n".join(lines[:-1]) + "\n").encode("utf-8")
    if footer["body_sha256"] != digest(body) or footer["rows"] != "6":
        raise AdapterError("HBI_FOOTER")
    return schema, hbi_sha, filename, repos, hbp_sha, root


def parse_repo(
    raw: str, expected_index: int, schema: str
) -> tuple[OwnerRepo, dict[str, int]]:
    fields = parse_row(raw, "REPO")
    expected = {
        "i", "name", "branch", "state", "commit", "tree", "entries",
        "blobs", "trees", "commits", "symlinks", "object_root_sha256",
        "word_rime_root_sha256", "word_count", "color", "json",
    }
    if schema == OWNER_SCHEMA_V2:
        expected |= {
            "image_entries", "video_entries", "media_declared_bytes",
            "media_size_unknown_entries", "media_root_sha256",
        }
    exact_fields(fields, expected, "REPO_FIELDS")
    if integer(fields["i"], expected_index, expected_index, "REPO_INDEX") != expected_index:
        raise AdapterError("REPO_INDEX")
    if REPO_NAME.fullmatch(fields["name"]) is None:
        raise AdapterError("REPO_NAME")
    if not fields["branch"] or len(fields["branch"].encode("utf-8")) > 256:
        raise AdapterError("REPO_BRANCH")
    state = fields["state"]
    if state not in {"PUBLIC_TREE_COMPLETE", "EMPTY_UNBORN"}:
        raise AdapterError("REPO_STATE")
    commit = hex_value(fields["commit"], HEX40, "REPO_COMMIT")
    tree = hex_value(fields["tree"], HEX40, "REPO_TREE")
    counts = {
        key: integer(fields[key], 0, 1_000_000, f"REPO_{key.upper()}")
        for key in ("entries", "blobs", "trees", "commits", "symlinks")
    }
    if counts["entries"] != counts["blobs"] + counts["trees"] + counts["commits"]:
        raise AdapterError("REPO_ENTRY_SUM")
    if counts["symlinks"] > counts["blobs"]:
        raise AdapterError("REPO_SYMLINK_COUNT")
    image_entries = integer(fields.get("image_entries", "0"), 0, 1_000_000, "REPO_IMAGE_ENTRIES")
    video_entries = integer(fields.get("video_entries", "0"), 0, 1_000_000, "REPO_VIDEO_ENTRIES")
    media_declared_bytes = integer(
        fields.get("media_declared_bytes", "0"),
        0,
        MAX_MEDIA_DECLARED_BYTES,
        "REPO_MEDIA_DECLARED_BYTES",
    )
    media_size_unknown_entries = integer(
        fields.get("media_size_unknown_entries", "0"),
        0,
        1_000_000,
        "REPO_MEDIA_SIZE_UNKNOWN",
    )
    if image_entries + video_entries > counts["blobs"]:
        raise AdapterError("REPO_MEDIA_COUNT")
    media_root = hex_value(
        fields.get("media_root_sha256", EMPTY_SHA256), HEX64, "REPO_MEDIA_ROOT"
    )
    object_root = hex_value(fields["object_root_sha256"], HEX64, "REPO_OBJECT_ROOT")
    hex_value(fields["word_rime_root_sha256"], HEX64, "REPO_WORD_ROOT")
    integer(fields["word_count"], 1, 100_000_000, "REPO_WORD_COUNT")
    if COLOR.fullmatch(fields["color"]) is None:
        raise AdapterError("REPO_COLOR")
    if state == "EMPTY_UNBORN":
        if commit != ZERO_SHA1 or tree != ZERO_SHA1 or any(counts.values()):
            raise AdapterError("REPO_UNBORN_SHAPE")
        if object_root != EMPTY_SHA256:
            raise AdapterError("REPO_UNBORN_ROOT")
        if (
            image_entries
            or video_entries
            or media_declared_bytes
            or media_size_unknown_entries
            or media_root != EMPTY_SHA256
        ):
            raise AdapterError("REPO_UNBORN_MEDIA")
    elif commit == ZERO_SHA1 or tree == ZERO_SHA1:
        raise AdapterError("REPO_COMPLETE_SHAPE")
    return (
        OwnerRepo(
            expected_index,
            fields["name"],
            state,
            object_root,
            tree,
            fields["color"],
            image_entries,
            video_entries,
            media_declared_bytes,
            media_size_unknown_entries,
            media_root,
            (raw + "\n").encode("utf-8"),
        ),
        counts,
    )


def parse_hbp(
    hbp_path: Path,
    expected_sha: str,
    expected_repos: int,
    expected_root: str,
    expected_schema: str,
) -> tuple[str, tuple[OwnerRepo, ...]]:
    data = read_file(hbp_path, MAX_HBP_BYTES, "HBP")
    hbp_sha = verify_sidecar(hbp_path, data)
    if hbp_sha != expected_sha:
        raise AdapterError("HBI_HBP_SHA_MISMATCH")
    lines = text_lines(data, "HBP")
    if len(lines) != expected_repos + 6:
        raise AdapterError("HBP_ROW_COUNT")
    header = parse_row(lines[0], "OWNER3DRUN")
    exact_fields(
        header,
        {"schema", "owner", "captured_at", "surface", "repos", "json"},
        "HBP_HEADER_FIELDS",
    )
    if (
        header["schema"] != expected_schema
        or OWNER.fullmatch(header["owner"]) is None
        or UTC_TIME.fullmatch(header["captured_at"]) is None
        or header["surface"] != "PUBLIC_API_SUBSET"
        or integer(header["repos"], 1, MAX_REPOS, "HBP_REPOS") != expected_repos
    ):
        raise AdapterError("HBP_HEADER")
    verify_center(parse_row(lines[1], "CENTER"), hbp=True)
    recipe = parse_row(lines[2], "RECIPE")
    expected_recipe = {
        "sh": OWNER_RECIPE,
        "transport": "GH_CLI_PUBLIC_REST",
        "recursive_git_tree": "1",
        "paths_published": "0",
        "blob_bodies_read": "0",
        "json": "0",
    }
    if expected_schema == OWNER_SCHEMA_V2:
        expected_recipe |= {
            "media_extensions_classified": "1",
            "media_paths_published": "0",
            "media_bodies_read": "0",
            "media_classification": "PATH_EXTENSION_METADATA_ONLY",
        }
    exact_fields(recipe, set(expected_recipe), "HBP_RECIPE_FIELDS")
    if recipe != expected_recipe:
        raise AdapterError("HBP_RECIPE")
    boundary = parse_row(lines[3], "BOUNDARY")
    boundary_fields = {
        "private_repo_endpoint_calls", "private_repo_rows", "private_keys",
        "credentials_in_output", "catalog_grants_authority", "system_affirmed",
        "json",
    }
    if expected_schema == OWNER_SCHEMA_V2:
        boundary_fields |= {"media_bytes_embedded", "media_decoder_claim"}
    exact_fields(boundary, boundary_fields, "HBP_BOUNDARY_FIELDS")
    if any(boundary[key] != "0" for key in boundary if key != "json"):
        raise AdapterError("HBP_PUBLIC_BOUNDARY")
    repositories: list[OwnerRepo] = []
    totals = {key: 0 for key in ("entries", "blobs", "trees", "commits", "symlinks")}
    media_totals = {
        "image_entries": 0,
        "video_entries": 0,
        "media_declared_bytes": 0,
        "media_size_unknown_entries": 0,
    }
    for index, raw in enumerate(lines[4 : 4 + expected_repos]):
        repository, counts = parse_repo(raw, index, expected_schema)
        repositories.append(repository)
        for key, value in counts.items():
            totals[key] += value
        media_totals["image_entries"] += repository.image_entries
        media_totals["video_entries"] += repository.video_entries
        media_totals["media_declared_bytes"] += repository.media_declared_bytes
        media_totals["media_size_unknown_entries"] += repository.media_size_unknown_entries
    if len({repository.name.casefold() for repository in repositories}) != len(repositories):
        raise AdapterError("REPO_NAME_DUPLICATE")
    calculated = hashlib.sha256()
    for repository in repositories:
        row = repository.source_row[:-1]
        calculated.update(len(row).to_bytes(8, "big"))
        calculated.update(row)
    object_hash = parse_row(lines[-2], "HASH")
    exact_fields(
        object_hash,
        {"role", "algorithm", "value", "distinct_from_hbp_byte_sha", "json"},
        "HBP_HASH_FIELDS",
    )
    if (
        object_hash["role"] != "SPHERICAL_OBJECT_COMMITMENT"
        or object_hash["algorithm"] != "SHA256"
        or object_hash["distinct_from_hbp_byte_sha"] != "1"
        or object_hash["value"] != calculated.hexdigest()
        or object_hash["value"] != expected_root
        or object_hash["value"] == hbp_sha
    ):
        raise AdapterError("HBP_OBJECT_COMMITMENT")
    summary = parse_row(lines[-1], "SUMMARY")
    expected_summary_fields = {
        "repos", "branched", "unborn", "entries", "blobs", "trees",
        "commits", "symlinks", "json",
    }
    if expected_schema == OWNER_SCHEMA_V2:
        expected_summary_fields |= set(media_totals)
    exact_fields(summary, expected_summary_fields, "HBP_SUMMARY_FIELDS")
    branched = sum(repository.state == "PUBLIC_TREE_COMPLETE" for repository in repositories)
    unborn = expected_repos - branched
    expected_summary = {
        "repos": expected_repos,
        "branched": branched,
        "unborn": unborn,
        **totals,
    }
    if expected_schema == OWNER_SCHEMA_V2:
        expected_summary |= media_totals
    for key, value in expected_summary.items():
        high = MAX_MEDIA_DECLARED_BYTES if key == "media_declared_bytes" else 1_000_000_000
        if integer(summary[key], 0, high, "HBP_SUMMARY") != value:
            raise AdapterError("HBP_SUMMARY")
    return hbp_sha, tuple(repositories)


def verify_owner_seal(index_path: Path) -> OwnerSeal:
    schema, hbi_sha, filename, repos, expected_hbp_sha, expected_root = parse_hbi(index_path)
    hbp_path = index_path.with_name(filename)
    hbp_sha, repositories = parse_hbp(
        hbp_path, expected_hbp_sha, repos, expected_root, schema
    )
    return OwnerSeal(schema, hbi_sha, hbp_sha, filename, expected_root, repositories)


def signed_coordinate(material: bytes, offset: int) -> int:
    span = 2 * projection.MAX_SIGNED_COORDINATE + 1
    return int.from_bytes(material[offset : offset + 8], "big") % span - projection.MAX_SIGNED_COORDINATE


def public_record(repository: OwnerRepo, seal: OwnerSeal) -> projection.Record:
    material = (
        b"OWNER3D-TO-PUBLIC2D\0"
        + bytes.fromhex(seal.hbi_sha256)
        + bytes.fromhex(seal.hbp_sha256)
        + repository.source_row
    )
    position = hashlib.sha256(b"POSITION\0" + material).digest()
    values = {
        label: digest(label.encode("ascii") + b"\0" + material)
        for label in ("HBI", "HBP", "SHA", "HASH")
    }
    center = (
        values["HBI"],
        values["HBP"],
        values["SHA"],
        PUBLIC_SH,
        values["HASH"],
    )
    if len(set(center)) != 5 or values["SHA"] == values["HASH"]:
        raise AdapterError("DERIVED_CENTER_COLLISION")
    return projection.Record(
        repo_id=f"gh.public.r{repository.index}.{repository.object_root[:16]}",
        tree_id=f"tree.{repository.tree[:16]}",
        word_id="repo.root",
        parent_word_id="ROOT",
        u=signed_coordinate(position, 0),
        v=signed_coordinate(position, 8),
        level=0,
        blob_sha256=repository.object_root,
        truth_tag="THRUTH",
        system_instant_is=repository.state == "PUBLIC_TREE_COMPLETE",
        chirality="RIGHT" if position[16] & 1 else "LEFT",
        color="RGB." + repository.color[1:],
        oil_address="OIL.CALM.BROWN",
        route_id=f"shadow.cat.r{repository.index}",
        hbi=values["HBI"],
        hbp=values["HBP"],
        sha=values["SHA"],
        sh=PUBLIC_SH,
        hash=values["HASH"],
    )


def render_public2d(seal: OwnerSeal) -> bytes:
    records = tuple(public_record(repository, seal) for repository in seal.repositories)
    return projection.render_inventory(records)


def convert_file(index_path: Path, output_path: Path, *, replace: bool = False) -> str:
    index_path = index_path.absolute()
    output_path = output_path.absolute()
    seal = verify_owner_seal(index_path)
    hbp_path = index_path.with_name(seal.hbp_filename)
    protected = {
        index_path,
        hbp_path,
        index_path.with_name(index_path.name + ".sha256"),
        hbp_path.with_name(hbp_path.name + ".sha256"),
    }
    output_sidecar = output_path.with_name(output_path.name + ".sha256")
    if output_path in protected or output_sidecar in protected or output_path == output_sidecar:
        raise AdapterError("PATH_ROLE_COLLISION")
    data = render_public2d(seal)
    result = digest(data)
    try:
        projection.validate_output_target(output_path, replace)
        projection.validate_output_target(output_sidecar, replace)
        projection.atomic_write(output_path, data, replace)
        projection.atomic_write(
            output_sidecar,
            f"{result}  {output_path.name}\n".encode("ascii"),
            replace,
        )
    except projection.ProjectionError as exc:
        raise AdapterError(exc.code) from exc
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("index", type=Path, help="sealed OWNER3D .hbi index")
    parser.add_argument("output", type=Path, help="derived PUBLIC2D .hbp")
    parser.add_argument("--replace", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = convert_file(args.index.absolute(), args.output.absolute(), replace=args.replace)
        record_count = len(projection.parse_inventory(args.output.absolute()).records)
        print(
            f"OWNER3D_TO_PUBLIC2D|PASS=1|repos={record_count}"
            f"|sha256={result}|raw_contents=0|private_metadata=0|json=0"
        )
    except (AdapterError, projection.ProjectionError, OSError) as exc:
        code = (
            exc.code
            if isinstance(exc, (AdapterError, projection.ProjectionError))
            else "FILESYSTEM"
        )
        print(f"OWNER3D_TO_PUBLIC2D|PASS=0|reason={code}|json=0", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
