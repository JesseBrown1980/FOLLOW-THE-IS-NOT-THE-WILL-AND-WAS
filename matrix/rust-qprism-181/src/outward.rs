//! Exact-integer outward truth-wave projection over a verified OWNER3D V2 capture.
//!
//! This module is additive to the existing QPRISM renderer. It consumes public
//! repository metadata, emits no repository or media bodies, and grants no MCP,
//! network, quarantine, or execution authority.

use super::{
    atomic_write_set, ensure_distinct_paths, exact_orb, fields, file_name, hex, parse_hex32,
    read_verified_input, required, sha256, sidecar_path, signed_projection, InputRecord,
    QprismError,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const INPUT_SCHEMA: &str = "ASOLARIA-PUBLIC-OWNER-3D-TREE-V2";
const OUTPUT_SCHEMA: &str = "ASOLARIA-PUBLIC-OUTWARD-TRUTH-WAVES-RUST-181-V1";
const GGUF_ARCHITECTURE: &str = "asolaria-public-outward-truth-wave";
const GGUF_NAME_VALUE: &str = "PUBLIC-OUTWARD-TRUTH-WAVES";
const GGUF_PAYLOAD_KIND: &str = "DERIVED_PUBLIC_OUTWARD_TRUTH_WAVES";
const CENTER_MEMBERS: &str = "HBI,HBP,SHA,SH,HASH";
const CENTER_TRAVERSAL: &str = "HBI->HBP->SH->HASH->SHA";
const RECIPE: &str = "OUTWARD_TRUTH_WAVE_RUST_181_V1";
const MEDIA_CLASSIFICATION: &str = "PATH_EXTENSION_METADATA_ONLY";
const MAX_MEDIA_DECLARED_BYTES: u64 = 1_000_000_000_000_000;
const MAX_REPOS: usize = 512;
const MAX_LINE_BYTES: usize = 16_384;
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ZERO_SHA1: &str = "0000000000000000000000000000000000000000";
const WAVE_DESCRIPTOR_WIDTH: usize = 32;
const DETECTOR_COUNT: usize = 4;
const DIRECTION_COUNT: usize = 3;
const WAVE_COUNT_PER_REPO: usize = DETECTOR_COUNT * DIRECTION_COUNT;
const VIEW_CENTER: i64 = 1_000;
const RADIAL_BASE: i64 = 180_000;
const RADIAL_STEP: i64 = 30_000;
const TANGENT_STEP: i64 = 60_000;
const DEPTH_DIVISOR: i128 = 1_000_000_000;
const DEPTH_DETECTOR_STEP: i64 = 20_000;
const DEPTH_DIRECTION_STEP: i64 = 5_000;
const GGUF_MAGIC: u32 = 0x4655_4747;
const GGUF_VERSION: u32 = 3;
const GGUF_TYPE_UINT32: u32 = 4;
const GGUF_TYPE_STRING: u32 = 8;
const GGUF_TYPE_UINT64: u32 = 10;
const GGML_TYPE_I8: u32 = 24;
const GGUF_ALIGNMENT: usize = 32;

pub const HBP_NAME: &str = "PUBLIC-OUTWARD-TRUTH-WAVES.hbp";
pub const HBI_NAME: &str = "PUBLIC-OUTWARD-TRUTH-WAVES.hbi";
pub const SVG_NAME: &str = "PUBLIC-OUTWARD-TRUTH-WAVES.svg";
pub const GGUF_NAME: &str = "PUBLIC-OUTWARD-TRUTH-WAVES.gguf";

type Result<T> = std::result::Result<T, QprismError>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct OwnerRepo {
    index: usize,
    tree_complete: bool,
    tree: String,
    object_root: [u8; 32],
    image_entries: u64,
    video_entries: u64,
    media_declared_bytes: u64,
    media_size_unknown_entries: u64,
    media_root: [u8; 32],
    color: [u8; 3],
    source_row: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OwnerCapture {
    source_bytes: Vec<u8>,
    repositories: Vec<OwnerRepo>,
    object_commitment: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Detector {
    ByteCommitment,
    ClaimEvidence,
    MediaBinding,
    RuntimeAuthority,
}

impl Detector {
    const ALL: [Self; DETECTOR_COUNT] = [
        Self::ByteCommitment,
        Self::ClaimEvidence,
        Self::MediaBinding,
        Self::RuntimeAuthority,
    ];

    const fn index(self) -> usize {
        match self {
            Self::ByteCommitment => 0,
            Self::ClaimEvidence => 1,
            Self::MediaBinding => 2,
            Self::RuntimeAuthority => 3,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::ByteCommitment => "BYTE_COMMITMENT",
            Self::ClaimEvidence => "CLAIM_EVIDENCE",
            Self::MediaBinding => "MEDIA_BINDING",
            Self::RuntimeAuthority => "RUNTIME_AUTHORITY",
        }
    }

    const fn electron_id(self) -> &'static str {
        match self {
            Self::ByteCommitment => "electron.byte.commitment",
            Self::ClaimEvidence => "electron.claim.evidence",
            Self::MediaBinding => "electron.media.binding",
            Self::RuntimeAuthority => "electron.runtime.authority",
        }
    }

    const fn radial(self) -> (i64, i64) {
        match self {
            Self::ByteCommitment => (1, 0),
            Self::ClaimEvidence => (0, 1),
            Self::MediaBinding => (-1, 0),
            Self::RuntimeAuthority => (0, -1),
        }
    }

    const fn palette(self) -> [u8; 3] {
        match self {
            Self::ByteCommitment => [58, 188, 255],
            Self::ClaimEvidence => [255, 190, 64],
            Self::MediaBinding => [190, 92, 255],
            Self::RuntimeAuthority => [76, 224, 158],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Direction {
    Negative,
    Centre,
    Positive,
}

impl Direction {
    const ALL: [Self; DIRECTION_COUNT] = [Self::Negative, Self::Centre, Self::Positive];

    const fn index(self) -> usize {
        match self {
            Self::Negative => 0,
            Self::Centre => 1,
            Self::Positive => 2,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Negative => "NEGATIVE",
            Self::Centre => "CENTRE",
            Self::Positive => "POSITIVE",
        }
    }

    const fn sign(self) -> i64 {
        match self {
            Self::Negative => -1,
            Self::Centre => 0,
            Self::Positive => 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Wave {
    order: usize,
    wave_id: String,
    source_identity_sha256: String,
    repo_id: String,
    detector: Detector,
    direction: Direction,
    center: [i64; 3],
    endpoint: [i64; 3],
    projected_center: [i64; 2],
    projected_endpoint: [i64; 2],
    color: [u8; 3],
    evidence_status: &'static str,
    tree_complete: bool,
    image_entries: u64,
    video_entries: u64,
    media_declared_bytes: u64,
    media_size_unknown_entries: u64,
    media_root: String,
    hbi: String,
    hbp: String,
    sha: String,
    sh: String,
    hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutwardResult {
    pub repositories: usize,
    pub waves: usize,
    pub hbp_sha256: String,
    pub hbi_sha256: String,
    pub svg_sha256: String,
    pub gguf_sha256: String,
}

#[derive(Default)]
struct Totals {
    branched: u64,
    unborn: u64,
    entries: u64,
    blobs: u64,
    trees: u64,
    commits: u64,
    symlinks: u64,
    image_entries: u64,
    video_entries: u64,
    media_declared_bytes: u64,
    media_size_unknown_entries: u64,
}

fn error(code: &'static str) -> QprismError {
    QprismError::new(code)
}

fn exact_keys(map: &BTreeMap<&str, &str>, expected: &[&str]) -> Result<()> {
    if map.len() != expected.len() || expected.iter().any(|key| !map.contains_key(key)) {
        return Err(error("OUTWARD_FIELD_SET"));
    }
    Ok(())
}

fn decimal_u64(value: &str, maximum: u64) -> Result<u64> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(error("OUTWARD_UNSIGNED_INTEGER"));
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| error("OUTWARD_UNSIGNED_INTEGER"))?;
    if parsed > maximum {
        return Err(error("OUTWARD_UNSIGNED_RANGE"));
    }
    Ok(parsed)
}

fn hex40(value: &str) -> Result<String> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(error("OUTWARD_HEX40"));
    }
    Ok(value.to_owned())
}

fn owner_rgb(value: &str) -> Result<[u8; 3]> {
    let digits = value
        .strip_prefix('#')
        .ok_or_else(|| error("OUTWARD_RGB"))?;
    if digits.len() != 6
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
    {
        return Err(error("OUTWARD_RGB"));
    }
    let packed = u32::from_str_radix(digits, 16).map_err(|_| error("OUTWARD_RGB"))?;
    Ok([
        u8::try_from((packed >> 16) & 255).expect("masked red channel"),
        u8::try_from((packed >> 8) & 255).expect("masked green channel"),
        u8::try_from(packed & 255).expect("masked blue channel"),
    ])
}

fn add_total(total: &mut u64, value: u64) -> Result<()> {
    *total = total
        .checked_add(value)
        .ok_or_else(|| error("OUTWARD_TOTAL_OVERFLOW"))?;
    Ok(())
}

fn parse_owner_repo(raw: &str, expected_index: usize, totals: &mut Totals) -> Result<OwnerRepo> {
    let map = fields(raw, "REPO")?;
    exact_keys(
        &map,
        &[
            "i",
            "name",
            "branch",
            "state",
            "commit",
            "tree",
            "entries",
            "blobs",
            "trees",
            "commits",
            "symlinks",
            "image_entries",
            "video_entries",
            "media_declared_bytes",
            "media_size_unknown_entries",
            "media_root_sha256",
            "object_root_sha256",
            "word_rime_root_sha256",
            "word_count",
            "color",
            "json",
        ],
    )?;
    if decimal_u64(
        required(&map, "i")?,
        u64::try_from(MAX_REPOS).map_err(|_| error("OUTWARD_REPOSITORY_COUNT"))?,
    )? != u64::try_from(expected_index).map_err(|_| error("OUTWARD_REPOSITORY_COUNT"))?
        || required(&map, "json")? != "0"
        || required(&map, "name")?.len() > 512
        || required(&map, "branch")?.len() > 512
    {
        return Err(error("OUTWARD_REPO_IDENTITY"));
    }
    let state = required(&map, "state")?;
    let tree_complete = match state {
        "PUBLIC_TREE_COMPLETE" => true,
        "EMPTY_UNBORN" => false,
        _ => return Err(error("OUTWARD_REPO_STATE")),
    };
    let commit = hex40(required(&map, "commit")?)?;
    let tree = hex40(required(&map, "tree")?)?;
    let entries = decimal_u64(required(&map, "entries")?, 1_000_000)?;
    let blobs = decimal_u64(required(&map, "blobs")?, 1_000_000)?;
    let trees = decimal_u64(required(&map, "trees")?, 1_000_000)?;
    let commits = decimal_u64(required(&map, "commits")?, 1_000_000)?;
    let symlinks = decimal_u64(required(&map, "symlinks")?, 1_000_000)?;
    let image_entries = decimal_u64(required(&map, "image_entries")?, 1_000_000)?;
    let video_entries = decimal_u64(required(&map, "video_entries")?, 1_000_000)?;
    let media_declared_bytes = decimal_u64(
        required(&map, "media_declared_bytes")?,
        MAX_MEDIA_DECLARED_BYTES,
    )?;
    let media_size_unknown_entries =
        decimal_u64(required(&map, "media_size_unknown_entries")?, 1_000_000)?;
    let media_root = parse_hex32(required(&map, "media_root_sha256")?)?;
    let object_root = parse_hex32(required(&map, "object_root_sha256")?)?;
    parse_hex32(required(&map, "word_rime_root_sha256")?)?;
    decimal_u64(required(&map, "word_count")?, 100_000_000)?;
    let color = owner_rgb(required(&map, "color")?)?;
    let counted_entries = blobs
        .checked_add(trees)
        .and_then(|value| value.checked_add(commits))
        .ok_or_else(|| error("OUTWARD_ENTRY_OVERFLOW"))?;
    let media_entries = image_entries
        .checked_add(video_entries)
        .ok_or_else(|| error("OUTWARD_MEDIA_OVERFLOW"))?;
    if entries != counted_entries
        || symlinks > blobs
        || media_entries > blobs
        || media_size_unknown_entries > media_entries
    {
        return Err(error("OUTWARD_REPO_COUNTS"));
    }
    let media_root_hex = hex(&media_root);
    let object_root_hex = hex(&object_root);
    if tree_complete {
        if commit == ZERO_SHA1 || tree == ZERO_SHA1 {
            return Err(error("OUTWARD_COMPLETE_SHAPE"));
        }
        if media_entries == 0 && media_root_hex != EMPTY_SHA256 {
            return Err(error("OUTWARD_EMPTY_MEDIA_ROOT"));
        }
        if media_entries > 0 && media_root_hex == EMPTY_SHA256 {
            return Err(error("OUTWARD_PRESENT_MEDIA_ROOT"));
        }
        add_total(&mut totals.branched, 1)?;
    } else {
        if commit != ZERO_SHA1
            || tree != ZERO_SHA1
            || entries != 0
            || blobs != 0
            || trees != 0
            || commits != 0
            || symlinks != 0
            || image_entries != 0
            || video_entries != 0
            || media_declared_bytes != 0
            || media_size_unknown_entries != 0
            || media_root_hex != EMPTY_SHA256
            || object_root_hex != EMPTY_SHA256
        {
            return Err(error("OUTWARD_UNBORN_SHAPE"));
        }
        add_total(&mut totals.unborn, 1)?;
    }
    add_total(&mut totals.entries, entries)?;
    add_total(&mut totals.blobs, blobs)?;
    add_total(&mut totals.trees, trees)?;
    add_total(&mut totals.commits, commits)?;
    add_total(&mut totals.symlinks, symlinks)?;
    add_total(&mut totals.image_entries, image_entries)?;
    add_total(&mut totals.video_entries, video_entries)?;
    add_total(&mut totals.media_declared_bytes, media_declared_bytes)?;
    add_total(
        &mut totals.media_size_unknown_entries,
        media_size_unknown_entries,
    )?;
    Ok(OwnerRepo {
        index: expected_index,
        tree_complete,
        tree,
        object_root,
        image_entries,
        video_entries,
        media_declared_bytes,
        media_size_unknown_entries,
        media_root,
        color,
        source_row: raw.as_bytes().to_vec(),
    })
}

fn require_summary(map: &BTreeMap<&str, &str>, key: &str, expected: u64) -> Result<()> {
    if decimal_u64(required(map, key)?, MAX_MEDIA_DECLARED_BYTES)? != expected {
        return Err(error("OUTWARD_SUMMARY_VALUE"));
    }
    Ok(())
}

fn parse_owner_capture(source_bytes: &[u8]) -> Result<OwnerCapture> {
    if source_bytes.is_empty()
        || source_bytes.last() != Some(&b'\n')
        || source_bytes.contains(&b'\r')
        || source_bytes.contains(&0)
    {
        return Err(error("OUTWARD_INPUT_TEXT"));
    }
    let text = std::str::from_utf8(source_bytes).map_err(|_| error("OUTWARD_INPUT_UTF8"))?;
    let lines: Vec<&str> = text[..text.len() - 1].split('\n').collect();
    if lines.len() < 7
        || lines
            .iter()
            .any(|line| line.as_bytes().len() > MAX_LINE_BYTES)
    {
        return Err(error("OUTWARD_INPUT_ROWS"));
    }

    let header = fields(lines[0], "OWNER3DRUN")?;
    exact_keys(
        &header,
        &["schema", "owner", "captured_at", "surface", "repos", "json"],
    )?;
    if required(&header, "schema")? != INPUT_SCHEMA
        || required(&header, "surface")? != "PUBLIC_API_SUBSET"
        || required(&header, "json")? != "0"
    {
        return Err(error("OUTWARD_INPUT_HEADER"));
    }
    let repo_count = usize::try_from(decimal_u64(
        required(&header, "repos")?,
        u64::try_from(MAX_REPOS).map_err(|_| error("OUTWARD_REPOSITORY_COUNT"))?,
    )?)
    .map_err(|_| error("OUTWARD_REPOSITORY_COUNT"))?;
    if repo_count == 0 || lines.len() != repo_count + 6 {
        return Err(error("OUTWARD_REPO_COUNT"));
    }

    let center = fields(lines[1], "CENTER")?;
    exact_keys(
        &center,
        &[
            "nullspace",
            "center_members",
            "traversal",
            "sha_equals_hash",
            "brown_center",
            "close_to",
            "json",
        ],
    )?;
    if required(&center, "nullspace")? != "0"
        || required(&center, "center_members")? != CENTER_MEMBERS
        || required(&center, "traversal")? != "HBI,HBP,SH,HASH,SHA"
        || required(&center, "sha_equals_hash")? != "0"
        || required(&center, "brown_center")? != "#8B5A2B"
        || required(&center, "close_to")? != "1"
        || required(&center, "json")? != "0"
    {
        return Err(error("OUTWARD_INPUT_CENTER"));
    }

    let recipe = fields(lines[2], "RECIPE")?;
    exact_keys(
        &recipe,
        &[
            "sh",
            "transport",
            "recursive_git_tree",
            "paths_published",
            "blob_bodies_read",
            "media_extensions_classified",
            "media_paths_published",
            "media_bodies_read",
            "media_classification",
            "json",
        ],
    )?;
    if required(&recipe, "sh")? != "GH_PUBLIC_OWNER_TREE_V1"
        || required(&recipe, "transport")? != "GH_CLI_PUBLIC_REST"
        || required(&recipe, "recursive_git_tree")? != "1"
        || required(&recipe, "paths_published")? != "0"
        || required(&recipe, "blob_bodies_read")? != "0"
        || required(&recipe, "media_extensions_classified")? != "1"
        || required(&recipe, "media_paths_published")? != "0"
        || required(&recipe, "media_bodies_read")? != "0"
        || required(&recipe, "media_classification")? != MEDIA_CLASSIFICATION
        || required(&recipe, "json")? != "0"
    {
        return Err(error("OUTWARD_INPUT_RECIPE"));
    }

    let boundary = fields(lines[3], "BOUNDARY")?;
    exact_keys(
        &boundary,
        &[
            "private_repo_endpoint_calls",
            "private_repo_rows",
            "private_keys",
            "credentials_in_output",
            "catalog_grants_authority",
            "system_affirmed",
            "media_bytes_embedded",
            "media_decoder_claim",
            "json",
        ],
    )?;
    for key in [
        "private_repo_endpoint_calls",
        "private_repo_rows",
        "private_keys",
        "credentials_in_output",
        "catalog_grants_authority",
        "system_affirmed",
        "media_bytes_embedded",
        "media_decoder_claim",
        "json",
    ] {
        if required(&boundary, key)? != "0" {
            return Err(error("OUTWARD_INPUT_BOUNDARY"));
        }
    }

    let mut totals = Totals::default();
    let mut repositories = Vec::with_capacity(repo_count);
    let mut root_material = Vec::new();
    for (index, raw) in lines[4..4 + repo_count].iter().enumerate() {
        let repository = parse_owner_repo(raw, index, &mut totals)?;
        let length = u64::try_from(raw.len()).map_err(|_| error("OUTWARD_ROW_LENGTH"))?;
        root_material.extend_from_slice(&length.to_be_bytes());
        root_material.extend_from_slice(raw.as_bytes());
        repositories.push(repository);
    }
    let calculated_root = hex(&sha256(&root_material));
    let hash_row = fields(lines[4 + repo_count], "HASH")?;
    exact_keys(
        &hash_row,
        &[
            "role",
            "algorithm",
            "value",
            "distinct_from_hbp_byte_sha",
            "json",
        ],
    )?;
    if required(&hash_row, "role")? != "SPHERICAL_OBJECT_COMMITMENT"
        || required(&hash_row, "algorithm")? != "SHA256"
        || required(&hash_row, "value")? != calculated_root
        || required(&hash_row, "distinct_from_hbp_byte_sha")? != "1"
        || required(&hash_row, "json")? != "0"
    {
        return Err(error("OUTWARD_INPUT_OBJECT_HASH"));
    }

    let summary = fields(lines[5 + repo_count], "SUMMARY")?;
    exact_keys(
        &summary,
        &[
            "repos",
            "branched",
            "unborn",
            "entries",
            "blobs",
            "trees",
            "commits",
            "symlinks",
            "image_entries",
            "video_entries",
            "media_declared_bytes",
            "media_size_unknown_entries",
            "json",
        ],
    )?;
    require_summary(
        &summary,
        "repos",
        u64::try_from(repo_count).map_err(|_| error("OUTWARD_REPOSITORY_COUNT"))?,
    )?;
    require_summary(&summary, "branched", totals.branched)?;
    require_summary(&summary, "unborn", totals.unborn)?;
    require_summary(&summary, "entries", totals.entries)?;
    require_summary(&summary, "blobs", totals.blobs)?;
    require_summary(&summary, "trees", totals.trees)?;
    require_summary(&summary, "commits", totals.commits)?;
    require_summary(&summary, "symlinks", totals.symlinks)?;
    require_summary(&summary, "image_entries", totals.image_entries)?;
    require_summary(&summary, "video_entries", totals.video_entries)?;
    require_summary(
        &summary,
        "media_declared_bytes",
        totals.media_declared_bytes,
    )?;
    require_summary(
        &summary,
        "media_size_unknown_entries",
        totals.media_size_unknown_entries,
    )?;
    if required(&summary, "json")? != "0" {
        return Err(error("OUTWARD_SUMMARY_JSON"));
    }
    if calculated_root == hex(&sha256(source_bytes)) {
        return Err(error("OUTWARD_HASH_EQUALS_SHA"));
    }
    Ok(OwnerCapture {
        source_bytes: source_bytes.to_vec(),
        repositories,
        object_commitment: calculated_root,
    })
}

fn hash_with_label(label: &str, value: &[u8]) -> String {
    let mut material = Vec::with_capacity(label.len() + value.len() + 1);
    material.extend_from_slice(label.as_bytes());
    material.push(0);
    material.extend_from_slice(value);
    hex(&sha256(&material))
}

fn coordinate(seed: &[u8], offset: usize) -> i64 {
    let raw = u64::from_be_bytes(
        seed[offset..offset + 8]
            .try_into()
            .expect("fixed digest window"),
    );
    i64::try_from(raw % 2_000_001).expect("bounded coordinate") - 1_000_000
}

fn derive_records(capture: &OwnerCapture) -> Vec<InputRecord> {
    let source_sha256 = sha256(&capture.source_bytes);
    capture
        .repositories
        .iter()
        .map(|repo| {
            let mut seed_material = b"OWNER3D-V2-INPUT-RECORD\0".to_vec();
            seed_material.extend_from_slice(&source_sha256);
            seed_material.extend_from_slice(&repo.source_row);
            let seed = sha256(&seed_material);
            let repo_id = format!(
                "gh.public.r{}.{}",
                repo.index,
                &hex(&repo.object_root)[..16]
            );
            let tree_id = format!("tree.{}", &repo.tree[..16]);
            let u = coordinate(&seed, 0);
            let v = coordinate(&seed, 8);
            let canonical_row = format!(
                "INPUT|repo={repo_id}|tree={tree_id}|word=repo.root|parent=ROOT|u={u}|v={v}|level=0|blob_sha256={}|color=#{:02X}{:02X}{:02X}|truth=THRUTH|json=0",
                hex(&repo.object_root),
                repo.color[0],
                repo.color[1],
                repo.color[2]
            )
            .into_bytes();
            InputRecord {
                repo_id,
                tree_id,
                word_id: "repo.root".to_owned(),
                parent_word_id: "ROOT".to_owned(),
                u,
                v,
                level: 0,
                blob_sha256: repo.object_root,
                input_rgb: repo.color,
                truth_tag: "THRUTH".to_owned(),
                canonical_row,
            }
        })
        .collect()
}

fn checked_i64(value: i128) -> Result<i64> {
    i64::try_from(value).map_err(|_| error("OUTWARD_I64_RANGE"))
}

fn checked_sum(left: i64, right: i64) -> Result<i64> {
    checked_i64(
        i128::from(left)
            .checked_add(i128::from(right))
            .ok_or_else(|| error("OUTWARD_INTEGER_OVERFLOW"))?,
    )
}

fn wave_color(input: [u8; 3], detector: Detector, direction: Direction) -> [u8; 3] {
    let palette = detector.palette();
    let mut output = [0_u8; 3];
    for index in 0..3 {
        let blended = (2 * u16::from(input[index]) + u16::from(palette[index])) / 3;
        let directed = match direction {
            Direction::Negative => blended / 2,
            Direction::Centre => blended,
            Direction::Positive => (blended + 255) / 2,
        };
        output[index] = u8::try_from(directed).expect("bounded RGB transform");
    }
    output
}

fn detector_evidence(repo: &OwnerRepo, detector: Detector) -> &'static str {
    match detector {
        Detector::ByteCommitment => "MEASURED_MATCH",
        Detector::ClaimEvidence => "OPERATOR_TAG_PRESERVED",
        Detector::MediaBinding => {
            if repo.image_entries > 0 || repo.video_entries > 0 {
                "EXTENSION_METADATA_PRESENT"
            } else {
                "NO_EXTENSION_MATCH_IN_CAPTURE"
            }
        }
        Detector::RuntimeAuthority => "SYSTEM_AFFIRMED_0",
    }
}

fn derive_waves(capture: &OwnerCapture, records: &[InputRecord]) -> Result<Vec<Wave>> {
    if records.len() != capture.repositories.len() {
        return Err(error("OUTWARD_RECORD_COUNT"));
    }
    let source_sha256 = sha256(&capture.source_bytes);
    let mut identifiers = BTreeSet::new();
    let mut waves = Vec::with_capacity(records.len() * WAVE_COUNT_PER_REPO);
    for (repo, record) in capture.repositories.iter().zip(records) {
        let orb = exact_orb(record)?;
        let center_z = checked_i64(orb.depth_scaled / DEPTH_DIVISOR)?;
        let center = [record.u, record.v, center_z];
        let projected_center_pair = signed_projection(center[0], center[1], center[2])?;
        let projected_center = [projected_center_pair.0, projected_center_pair.1];
        let mut identity_material = b"OWNER3D-V2-SOURCE-IDENTITY\0".to_vec();
        identity_material.extend_from_slice(&source_sha256);
        identity_material.extend_from_slice(&record.canonical_row);
        let source_identity_sha256 = hex(&sha256(&identity_material));
        for detector in Detector::ALL {
            let detector_index =
                i64::try_from(detector.index()).map_err(|_| error("OUTWARD_DETECTOR_INDEX"))?;
            let radius = RADIAL_BASE
                .checked_add(
                    RADIAL_STEP
                        .checked_mul(detector_index)
                        .ok_or_else(|| error("OUTWARD_INTEGER_OVERFLOW"))?,
                )
                .ok_or_else(|| error("OUTWARD_INTEGER_OVERFLOW"))?;
            let (radial_x, radial_y) = detector.radial();
            let tangent_x = radial_y
                .checked_neg()
                .ok_or_else(|| error("OUTWARD_INTEGER_OVERFLOW"))?;
            let tangent_y = radial_x;
            for direction in Direction::ALL {
                let sign = direction.sign();
                let x_offset = i128::from(radial_x)
                    .checked_mul(i128::from(radius))
                    .and_then(|value| {
                        i128::from(tangent_x)
                            .checked_mul(i128::from(sign))
                            .and_then(|tangent| tangent.checked_mul(i128::from(TANGENT_STEP)))
                            .and_then(|tangent| value.checked_add(tangent))
                    })
                    .ok_or_else(|| error("OUTWARD_INTEGER_OVERFLOW"))?;
                let y_offset = i128::from(radial_y)
                    .checked_mul(i128::from(radius))
                    .and_then(|value| {
                        i128::from(tangent_y)
                            .checked_mul(i128::from(sign))
                            .and_then(|tangent| tangent.checked_mul(i128::from(TANGENT_STEP)))
                            .and_then(|tangent| value.checked_add(tangent))
                    })
                    .ok_or_else(|| error("OUTWARD_INTEGER_OVERFLOW"))?;
                let detector_depth = detector_index
                    .checked_mul(DEPTH_DETECTOR_STEP)
                    .ok_or_else(|| error("OUTWARD_INTEGER_OVERFLOW"))?;
                let direction_depth = sign
                    .checked_mul(DEPTH_DIRECTION_STEP)
                    .ok_or_else(|| error("OUTWARD_INTEGER_OVERFLOW"))?;
                let endpoint = [
                    checked_sum(center[0], checked_i64(x_offset)?)?,
                    checked_sum(center[1], checked_i64(y_offset)?)?,
                    checked_sum(checked_sum(center[2], detector_depth)?, direction_depth)?,
                ];
                let projected_endpoint_pair =
                    signed_projection(endpoint[0], endpoint[1], endpoint[2])?;
                let projected_endpoint = [projected_endpoint_pair.0, projected_endpoint_pair.1];
                let mut wave_material = b"OUTWARD-TRUTH-WAVE-RUST-181\0".to_vec();
                wave_material.extend_from_slice(&source_sha256);
                wave_material.extend_from_slice(&repo.source_row);
                wave_material.extend_from_slice(detector.name().as_bytes());
                wave_material.push(0);
                wave_material.extend_from_slice(direction.name().as_bytes());
                let wave_id = hex(&sha256(&wave_material));
                if !identifiers.insert(wave_id.clone()) {
                    return Err(error("OUTWARD_WAVE_ID_COLLISION"));
                }
                let hbi = hash_with_label("HBI", wave_id.as_bytes());
                let hbp = hash_with_label("HBP", wave_id.as_bytes());
                let sha = hash_with_label("SHA", wave_id.as_bytes());
                let sh = hash_with_label("SH", wave_id.as_bytes());
                let hash = hash_with_label("HASH", wave_id.as_bytes());
                let address_count = [
                    hbi.as_str(),
                    hbp.as_str(),
                    sha.as_str(),
                    sh.as_str(),
                    hash.as_str(),
                ]
                .into_iter()
                .collect::<BTreeSet<_>>()
                .len();
                if address_count != 5 {
                    return Err(error("OUTWARD_ADDRESS_COLLISION"));
                }
                waves.push(Wave {
                    order: waves.len(),
                    wave_id,
                    source_identity_sha256: source_identity_sha256.clone(),
                    repo_id: record.repo_id.clone(),
                    detector,
                    direction,
                    center,
                    endpoint,
                    projected_center,
                    projected_endpoint,
                    color: wave_color(record.input_rgb, detector, direction),
                    evidence_status: detector_evidence(repo, detector),
                    tree_complete: repo.tree_complete,
                    image_entries: repo.image_entries,
                    video_entries: repo.video_entries,
                    media_declared_bytes: repo.media_declared_bytes,
                    media_size_unknown_entries: repo.media_size_unknown_entries,
                    media_root: hex(&repo.media_root),
                    hbi,
                    hbp,
                    sha,
                    sh,
                    hash,
                });
            }
        }
    }
    if waves.len() != records.len() * WAVE_COUNT_PER_REPO {
        return Err(error("OUTWARD_WAVE_COUNT"));
    }
    Ok(waves)
}

fn wave_row(wave: &Wave) -> String {
    format!(
        "WAVE|i={}|repo={}|detector={}|direction={}|source_identity_sha256={}|wave_id={}|center_x={}|center_y={}|center_z={}|endpoint_x={}|endpoint_y={}|endpoint_z={}|projected_center_u={}|projected_center_v={}|projected_endpoint_u={}|projected_endpoint_v={}|color=#{:02X}{:02X}{:02X}|claim_label=LIE|correction_label=THRUTH|evidence_status={}|tree_complete={}|image_entries={}|video_entries={}|media_declared_bytes={}|media_size_unknown_entries={}|media_root_sha256={}|hbi={}|hbp={}|sha={}|sh={}|hash={}|electron={}|catalog_only=1|function_call_authority=0|network=0|execution=0|physical_energy=0|identity_accusation=0|quarantine_applied=0|json=0",
        wave.order,
        wave.repo_id,
        wave.detector.name(),
        wave.direction.name(),
        wave.source_identity_sha256,
        wave.wave_id,
        wave.center[0],
        wave.center[1],
        wave.center[2],
        wave.endpoint[0],
        wave.endpoint[1],
        wave.endpoint[2],
        wave.projected_center[0],
        wave.projected_center[1],
        wave.projected_endpoint[0],
        wave.projected_endpoint[1],
        wave.color[0],
        wave.color[1],
        wave.color[2],
        wave.evidence_status,
        u8::from(wave.tree_complete),
        wave.image_entries,
        wave.video_entries,
        wave.media_declared_bytes,
        wave.media_size_unknown_entries,
        wave.media_root,
        wave.hbi,
        wave.hbp,
        wave.sha,
        wave.sh,
        wave.hash,
        wave.detector.electron_id(),
    )
}

fn joined_rows(rows: &[String]) -> Vec<u8> {
    let mut output = rows.join("\n").into_bytes();
    output.push(b'\n');
    output
}

fn build_hbp(capture: &OwnerCapture, waves: &[Wave]) -> Result<(Vec<u8>, String)> {
    let source_sha256 = hex(&sha256(&capture.source_bytes));
    let mut rows = vec![
        format!(
            "OUTWARDRUN|schema={OUTPUT_SCHEMA}|source_schema={INPUT_SCHEMA}|repositories={}|waves={}|detectors={DETECTOR_COUNT}|directions={DIRECTION_COUNT}|descriptor_width={WAVE_DESCRIPTOR_WIDTH}|json=0",
            capture.repositories.len(),
            waves.len()
        ),
        format!(
            "SOURCE|sha256={source_sha256}|object_hash={}|sidecar_verified=1|media_classification={MEDIA_CLASSIFICATION}|repo_bodies_read=0|media_bodies_read=0|json=0",
            capture.object_commitment
        ),
        format!(
            "CENTER|nullspace=0|center_members={CENTER_MEMBERS}|traversal={CENTER_TRAVERSAL}|sha_equals_hash=0|brown_center=#8B5A2B|close_to=1|json=0"
        ),
        "STAGE|i=0|name=OWNER3D_TO_EXACT_INPUT_RECORD|integer_only=1|float=0|execution=0|json=0".to_owned(),
        "STAGE|i=1|name=FOUR_DETECTORS_THREE_DIRECTIONS|detectors=4|directions=3|waves_per_repo=12|integer_only=1|float=0|execution=0|json=0".to_owned(),
        "STAGE|i=2|name=STATIC_OUTPUT_SEAL|formats=HBP,HBI,SVG,GGUF|network=0|execution=0|json=0".to_owned(),
        "QUARANTINE|name=BLACK_HEAT|mode=REVERSIBLE_VISUALIZATION_ONLY|bytes_preserved=1|reversible=1|deletion=0|execution=0|physical_energy=0|identity_accusation=0|quarantine_applied=0|json=0".to_owned(),
    ];
    for detector in Detector::ALL {
        rows.push(format!(
            "DETECTOR|i={}|name={}|electron={}|catalog_only=1|function_call_authority=0|network=0|execution=0|json=0",
            detector.index(),
            detector.name(),
            detector.electron_id()
        ));
    }

    let mut object_material = Vec::new();
    for wave in waves {
        let row = wave_row(wave);
        let length = u64::try_from(row.len()).map_err(|_| error("OUTWARD_ROW_LENGTH"))?;
        object_material.extend_from_slice(&length.to_be_bytes());
        object_material.extend_from_slice(row.as_bytes());
        rows.push(row);
    }
    let object_hash = hex(&sha256(&object_material));
    rows.push(format!(
        "HASH|role=SPHERICAL_WAVE_OBJECT_COMMITMENT|algorithm=SHA256|value={object_hash}|distinct_from_hbp_byte_sha=1|json=0"
    ));
    rows.push(format!(
        "SUMMARY|repositories={}|waves={}|detectors={DETECTOR_COUNT}|directions={DIRECTION_COUNT}|catalog_electrons={DETECTOR_COUNT}|media_bytes_embedded=0|repo_bytes_embedded=0|network=0|execution=0|physical_energy=0|authority=0|json=0",
        capture.repositories.len(),
        waves.len()
    ));
    let body = joined_rows(&rows);
    let footer = format!(
        "OUTWARDFTR|body_sha256={}|rows={}|json=0",
        hex(&sha256(&body)),
        rows.len() + 1
    );
    rows.push(footer);
    let output = joined_rows(&rows);
    if hex(&sha256(&output)) == object_hash {
        return Err(error("OUTWARD_HASH_EQUALS_SHA"));
    }
    Ok((output, object_hash))
}

fn svg_coordinate(value: i64) -> Result<i64> {
    let projected = checked_sum(VIEW_CENTER, value)?;
    if !(0..=2_000).contains(&projected) {
        return Err(error("OUTWARD_SVG_RANGE"));
    }
    Ok(projected)
}

fn build_svg(capture: &OwnerCapture, waves: &[Wave], object_hash: &str) -> Result<Vec<u8>> {
    let mut output = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"2000\" height=\"2000\" viewBox=\"0 0 2000 2000\" role=\"img\" aria-labelledby=\"title description\" data-script=\"0\" data-network=\"0\" data-execution=\"0\">\n<title id=\"title\">Public outward truth waves</title>\n<desc id=\"description\">Four catalog-only detectors emit three exact-integer directions from each public repository center. LIE and THRUTH are labels; BLACK_HEAT is a hidden reversible visualization and applies no quarantine.</desc>\n<rect x=\"0\" y=\"0\" width=\"2000\" height=\"2000\" fill=\"#120F18\"/>\n",
    );
    output.push_str(&format!(
        "<g id=\"OUTWARD_TRUTH_WAVES\" data-schema=\"{OUTPUT_SCHEMA}\" data-repositories=\"{}\" data-waves=\"{}\" data-object-hash=\"{object_hash}\">\n",
        capture.repositories.len(),
        waves.len()
    ));
    for (repo_index, repo_waves) in waves.chunks_exact(WAVE_COUNT_PER_REPO).enumerate() {
        let center_u = svg_coordinate(repo_waves[0].projected_center[0])?;
        let center_v = svg_coordinate(repo_waves[0].projected_center[1])?;
        output.push_str(&format!(
            "<g id=\"repo-{repo_index}\" data-repo=\"{}\">\n<path d=\"M {} {} l 5 -5 l 5 5 l -5 5 Z\" fill=\"#{:02X}{:02X}{:02X}\" stroke=\"#F5E9D0\" stroke-width=\"1\"/>\n",
            repo_waves[0].repo_id,
            center_u,
            center_v,
            capture.repositories[repo_index].color[0],
            capture.repositories[repo_index].color[1],
            capture.repositories[repo_index].color[2]
        ));
        for wave in repo_waves {
            let end_u = svg_coordinate(wave.projected_endpoint[0])?;
            let end_v = svg_coordinate(wave.projected_endpoint[1])?;
            output.push_str(&format!(
                "<g id=\"wave-{}\" data-detector=\"{}\" data-direction=\"{}\" data-electron=\"{}\" data-catalog-only=\"1\" data-authority=\"0\">\n<path data-label=\"LIE\" d=\"M {end_u} {end_v} L {center_u} {center_v}\" fill=\"none\" stroke=\"#4B3429\" stroke-width=\"1\" stroke-dasharray=\"3 3\"/>\n<path data-label=\"THRUTH\" d=\"M {center_u} {center_v} L {end_u} {end_v}\" fill=\"none\" stroke=\"#{:02X}{:02X}{:02X}\" stroke-width=\"2\"/>\n</g>\n",
                &wave.wave_id[..16],
                wave.detector.name(),
                wave.direction.name(),
                wave.detector.electron_id(),
                wave.color[0],
                wave.color[1],
                wave.color[2]
            ));
        }
        output.push_str("</g>\n");
    }
    output.push_str("</g>\n<g id=\"BLACK_HEAT_REVERSIBLE_VISUALIZATION\" visibility=\"hidden\" data-bytes-preserved=\"1\" data-reversible=\"1\" data-deletion=\"0\" data-execution=\"0\" data-physical-energy=\"0\" data-identity-accusation=\"0\" data-quarantine-applied=\"0\"><path d=\"M 0 0 H 2000 V 2000 H 0 Z\" fill=\"#000000\"/></g>\n</svg>\n");
    let bytes = output.into_bytes();
    let lower = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
    for forbidden in ["<script", "<image", "<foreignobject", " href=", "url("] {
        if lower.contains(forbidden) {
            return Err(error("OUTWARD_SVG_ACTIVE_CONTENT"));
        }
    }
    Ok(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum GgufValue {
    U32(u32),
    U64(u64),
    Text(String),
}

fn gguf_string(value: &str) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(
        &u64::try_from(value.len())
            .map_err(|_| error("OUTWARD_GGUF_STRING_LENGTH"))?
            .to_le_bytes(),
    );
    output.extend_from_slice(value.as_bytes());
    Ok(output)
}

fn metadata_text(key: &str, value: &str) -> Result<Vec<u8>> {
    let mut output = gguf_string(key)?;
    output.extend_from_slice(&GGUF_TYPE_STRING.to_le_bytes());
    output.extend_from_slice(&gguf_string(value)?);
    Ok(output)
}

fn metadata_u32(key: &str, value: u32) -> Result<Vec<u8>> {
    let mut output = gguf_string(key)?;
    output.extend_from_slice(&GGUF_TYPE_UINT32.to_le_bytes());
    output.extend_from_slice(&value.to_le_bytes());
    Ok(output)
}

fn metadata_u64(key: &str, value: u64) -> Result<Vec<u8>> {
    let mut output = gguf_string(key)?;
    output.extend_from_slice(&GGUF_TYPE_UINT64.to_le_bytes());
    output.extend_from_slice(&value.to_le_bytes());
    Ok(output)
}

fn descriptor_bytes(waves: &[Wave]) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(waves.len() * WAVE_DESCRIPTOR_WIDTH);
    for wave in waves {
        output
            .push(u8::try_from(wave.detector.index()).map_err(|_| error("OUTWARD_GGUF_DETECTOR"))?);
        output.push(
            u8::try_from(wave.direction.index()).map_err(|_| error("OUTWARD_GGUF_DIRECTION"))?,
        );
        output.extend_from_slice(&wave.color);
        output.push(0); // quarantine_applied
        output.push(u8::from(wave.image_entries > 0 || wave.video_entries > 0));
        output.push(u8::from(wave.tree_complete));
        let projected_u = i32::try_from(wave.projected_endpoint[0])
            .map_err(|_| error("OUTWARD_GGUF_COORDINATE"))?;
        let projected_v = i32::try_from(wave.projected_endpoint[1])
            .map_err(|_| error("OUTWARD_GGUF_COORDINATE"))?;
        output.extend_from_slice(&projected_u.to_le_bytes());
        output.extend_from_slice(&projected_v.to_le_bytes());
        let media_root = parse_hex32(&wave.media_root)?;
        output.extend_from_slice(&media_root[..8]);
        let wave_id = parse_hex32(&wave.wave_id)?;
        output.extend_from_slice(&wave_id[..8]);
    }
    if output.len() != waves.len() * WAVE_DESCRIPTOR_WIDTH {
        return Err(error("OUTWARD_GGUF_DESCRIPTOR_LENGTH"));
    }
    Ok(output)
}

fn gguf_metadata(
    capture: &OwnerCapture,
    descriptor_sha256: &str,
) -> Result<Vec<(String, GgufValue)>> {
    let source_sha256 = hex(&sha256(&capture.source_bytes));
    let repositories =
        u64::try_from(capture.repositories.len()).map_err(|_| error("OUTWARD_REPOSITORY_COUNT"))?;
    Ok(vec![
        (
            "general.architecture".to_owned(),
            GgufValue::Text(GGUF_ARCHITECTURE.to_owned()),
        ),
        (
            "general.name".to_owned(),
            GgufValue::Text(GGUF_NAME_VALUE.to_owned()),
        ),
        (
            "general.alignment".to_owned(),
            GgufValue::U32(
                u32::try_from(GGUF_ALIGNMENT).map_err(|_| error("OUTWARD_GGUF_ALIGNMENT"))?,
            ),
        ),
        (
            "asolaria.schema".to_owned(),
            GgufValue::Text(OUTPUT_SCHEMA.to_owned()),
        ),
        (
            "asolaria.payload.kind".to_owned(),
            GgufValue::Text(GGUF_PAYLOAD_KIND.to_owned()),
        ),
        (
            "asolaria.source.schema".to_owned(),
            GgufValue::Text(INPUT_SCHEMA.to_owned()),
        ),
        (
            "asolaria.source.sha256".to_owned(),
            GgufValue::Text(source_sha256),
        ),
        (
            "asolaria.source.object_hash".to_owned(),
            GgufValue::Text(capture.object_commitment.clone()),
        ),
        (
            "asolaria.repositories".to_owned(),
            GgufValue::U64(repositories),
        ),
        (
            "asolaria.detectors".to_owned(),
            GgufValue::U32(
                u32::try_from(DETECTOR_COUNT).map_err(|_| error("OUTWARD_GGUF_DETECTOR"))?,
            ),
        ),
        (
            "asolaria.directions".to_owned(),
            GgufValue::U32(
                u32::try_from(DIRECTION_COUNT).map_err(|_| error("OUTWARD_GGUF_DIRECTION"))?,
            ),
        ),
        (
            "asolaria.descriptor.width".to_owned(),
            GgufValue::U32(
                u32::try_from(WAVE_DESCRIPTOR_WIDTH)
                    .map_err(|_| error("OUTWARD_GGUF_DESCRIPTOR_LENGTH"))?,
            ),
        ),
        (
            "asolaria.descriptor.shape".to_owned(),
            GgufValue::Text(format!("[32,3,4,{}]", capture.repositories.len())),
        ),
        (
            "asolaria.descriptor.order".to_owned(),
            GgufValue::Text("repo,detector,direction,feature".to_owned()),
        ),
        (
            "asolaria.descriptor.sha256".to_owned(),
            GgufValue::Text(descriptor_sha256.to_owned()),
        ),
        (
            "asolaria.media.classification".to_owned(),
            GgufValue::Text(MEDIA_CLASSIFICATION.to_owned()),
        ),
        (
            "asolaria.media.bytes_embedded".to_owned(),
            GgufValue::U64(0),
        ),
        (
            "asolaria.image.bytes_embedded".to_owned(),
            GgufValue::U64(0),
        ),
        (
            "asolaria.video.bytes_embedded".to_owned(),
            GgufValue::U64(0),
        ),
        (
            "asolaria.repository.bytes_embedded".to_owned(),
            GgufValue::U64(0),
        ),
        (
            "asolaria.mcp.electrons".to_owned(),
            GgufValue::Text(
                "BYTE_COMMITMENT,CLAIM_EVIDENCE,MEDIA_BINDING,RUNTIME_AUTHORITY".to_owned(),
            ),
        ),
        ("asolaria.mcp.catalog_only".to_owned(), GgufValue::U32(1)),
        (
            "asolaria.function_call_authority".to_owned(),
            GgufValue::U32(0),
        ),
        ("asolaria.network".to_owned(), GgufValue::U32(0)),
        ("asolaria.execution".to_owned(), GgufValue::U32(0)),
        (
            "asolaria.quarantine.name".to_owned(),
            GgufValue::Text("BLACK_HEAT".to_owned()),
        ),
        (
            "asolaria.quarantine.mode".to_owned(),
            GgufValue::Text("REVERSIBLE_VISUALIZATION_ONLY".to_owned()),
        ),
        (
            "asolaria.quarantine.bytes_preserved".to_owned(),
            GgufValue::U32(1),
        ),
        (
            "asolaria.quarantine.reversible".to_owned(),
            GgufValue::U32(1),
        ),
        ("asolaria.quarantine.deletion".to_owned(), GgufValue::U32(0)),
        (
            "asolaria.quarantine.execution".to_owned(),
            GgufValue::U32(0),
        ),
        (
            "asolaria.quarantine.physical_energy".to_owned(),
            GgufValue::U32(0),
        ),
        (
            "asolaria.quarantine.identity_accusation".to_owned(),
            GgufValue::U32(0),
        ),
        ("asolaria.quarantine.applied".to_owned(), GgufValue::U32(0)),
    ])
}

fn align_up(value: usize, alignment: usize) -> Result<usize> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(error("OUTWARD_GGUF_ALIGNMENT"));
    }
    value
        .checked_add(alignment - 1)
        .map(|sum| sum / alignment * alignment)
        .ok_or_else(|| error("OUTWARD_GGUF_SIZE"))
}

fn build_gguf(capture: &OwnerCapture, waves: &[Wave]) -> Result<(Vec<u8>, Vec<u8>)> {
    let descriptor = descriptor_bytes(waves)?;
    let descriptor_sha256 = hex(&sha256(&descriptor));
    let metadata = gguf_metadata(capture, &descriptor_sha256)?;
    let mut metadata_bytes = Vec::new();
    for (key, value) in &metadata {
        metadata_bytes.extend_from_slice(&match value {
            GgufValue::U32(value) => metadata_u32(key, *value)?,
            GgufValue::U64(value) => metadata_u64(key, *value)?,
            GgufValue::Text(value) => metadata_text(key, value)?,
        });
    }
    let mut tensor_info = gguf_string("outward_wave")?;
    tensor_info.extend_from_slice(&4_u32.to_le_bytes());
    for dimension in [
        u64::try_from(WAVE_DESCRIPTOR_WIDTH)
            .map_err(|_| error("OUTWARD_GGUF_DESCRIPTOR_LENGTH"))?,
        u64::try_from(DIRECTION_COUNT).map_err(|_| error("OUTWARD_GGUF_DIRECTION"))?,
        u64::try_from(DETECTOR_COUNT).map_err(|_| error("OUTWARD_GGUF_DETECTOR"))?,
        u64::try_from(capture.repositories.len()).map_err(|_| error("OUTWARD_REPOSITORY_COUNT"))?,
    ] {
        tensor_info.extend_from_slice(&dimension.to_le_bytes());
    }
    tensor_info.extend_from_slice(&GGML_TYPE_I8.to_le_bytes());
    tensor_info.extend_from_slice(&0_u64.to_le_bytes());

    let mut header = Vec::new();
    header.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
    header.extend_from_slice(&GGUF_VERSION.to_le_bytes());
    header.extend_from_slice(&1_u64.to_le_bytes());
    header.extend_from_slice(
        &u64::try_from(metadata.len())
            .map_err(|_| error("OUTWARD_GGUF_METADATA_COUNT"))?
            .to_le_bytes(),
    );
    header.extend_from_slice(&metadata_bytes);
    header.extend_from_slice(&tensor_info);
    let data_start = align_up(header.len(), GGUF_ALIGNMENT)?;
    let mut output = header;
    output.resize(data_start, 0);
    output.extend_from_slice(&descriptor);
    verify_gguf(&output, capture, &descriptor)?;
    Ok((output, descriptor))
}

struct GgufReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> GgufReader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| error("OUTWARD_GGUF_BOUNDS"))?;
        if end > self.bytes.len() {
            return Err(error("OUTWARD_GGUF_BOUNDS"));
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("four-byte reader window"),
        ))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("eight-byte reader window"),
        ))
    }

    fn string(&mut self) -> Result<String> {
        let length =
            usize::try_from(self.u64()?).map_err(|_| error("OUTWARD_GGUF_STRING_LENGTH"))?;
        let bytes = self.take(length)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| error("OUTWARD_GGUF_UTF8"))
    }
}

fn metadata_value<'a>(
    metadata: &'a BTreeMap<String, GgufValue>,
    key: &str,
) -> Result<&'a GgufValue> {
    metadata
        .get(key)
        .ok_or_else(|| error("OUTWARD_GGUF_METADATA_KEY"))
}

fn verify_gguf(bytes: &[u8], capture: &OwnerCapture, descriptor: &[u8]) -> Result<()> {
    let mut reader = GgufReader { bytes, position: 0 };
    if reader.u32()? != GGUF_MAGIC || reader.u32()? != GGUF_VERSION || reader.u64()? != 1 {
        return Err(error("OUTWARD_GGUF_HEADER"));
    }
    let metadata_count =
        usize::try_from(reader.u64()?).map_err(|_| error("OUTWARD_GGUF_METADATA_COUNT"))?;
    let expected_metadata = gguf_metadata(capture, &hex(&sha256(descriptor)))?;
    if metadata_count != expected_metadata.len() {
        return Err(error("OUTWARD_GGUF_METADATA_COUNT"));
    }
    let mut metadata = BTreeMap::new();
    for _ in 0..metadata_count {
        let key = reader.string()?;
        let value_type = reader.u32()?;
        let value = match value_type {
            GGUF_TYPE_UINT32 => GgufValue::U32(reader.u32()?),
            GGUF_TYPE_UINT64 => GgufValue::U64(reader.u64()?),
            GGUF_TYPE_STRING => GgufValue::Text(reader.string()?),
            _ => return Err(error("OUTWARD_GGUF_METADATA_TYPE")),
        };
        if metadata.insert(key, value).is_some() {
            return Err(error("OUTWARD_GGUF_METADATA_DUPLICATE"));
        }
    }
    let expected_map: BTreeMap<String, GgufValue> = expected_metadata.into_iter().collect();
    if metadata != expected_map {
        return Err(error("OUTWARD_GGUF_METADATA_VALUE"));
    }
    if metadata_value(&metadata, "asolaria.media.bytes_embedded")? != &GgufValue::U64(0)
        || metadata_value(&metadata, "asolaria.repository.bytes_embedded")? != &GgufValue::U64(0)
        || metadata_value(&metadata, "asolaria.function_call_authority")? != &GgufValue::U32(0)
        || metadata_value(&metadata, "asolaria.network")? != &GgufValue::U32(0)
        || metadata_value(&metadata, "asolaria.execution")? != &GgufValue::U32(0)
        || metadata_value(&metadata, "asolaria.quarantine.physical_energy")? != &GgufValue::U32(0)
        || metadata_value(&metadata, "asolaria.quarantine.applied")? != &GgufValue::U32(0)
    {
        return Err(error("OUTWARD_GGUF_BOUNDARY"));
    }

    if reader.string()? != "outward_wave" || reader.u32()? != 4 {
        return Err(error("OUTWARD_GGUF_TENSOR"));
    }
    let dimensions = [reader.u64()?, reader.u64()?, reader.u64()?, reader.u64()?];
    let expected_dimensions = [
        u64::try_from(WAVE_DESCRIPTOR_WIDTH)
            .map_err(|_| error("OUTWARD_GGUF_DESCRIPTOR_LENGTH"))?,
        u64::try_from(DIRECTION_COUNT).map_err(|_| error("OUTWARD_GGUF_DIRECTION"))?,
        u64::try_from(DETECTOR_COUNT).map_err(|_| error("OUTWARD_GGUF_DETECTOR"))?,
        u64::try_from(capture.repositories.len()).map_err(|_| error("OUTWARD_REPOSITORY_COUNT"))?,
    ];
    if dimensions != expected_dimensions || reader.u32()? != GGML_TYPE_I8 || reader.u64()? != 0 {
        return Err(error("OUTWARD_GGUF_TENSOR"));
    }
    let data_start = align_up(reader.position, GGUF_ALIGNMENT)?;
    if data_start > bytes.len()
        || bytes[reader.position..data_start]
            .iter()
            .any(|byte| *byte != 0)
        || bytes.len() != data_start + descriptor.len()
        || &bytes[data_start..] != descriptor
    {
        return Err(error("OUTWARD_GGUF_DATA"));
    }
    Ok(())
}

fn build_hbi(
    capture: &OwnerCapture,
    waves: &[Wave],
    object_hash: &str,
    hbp_sha256: &str,
    svg_sha256: &str,
    gguf_sha256: &str,
    descriptor_sha256: &str,
) -> Vec<u8> {
    let mut rows = vec![
        format!(
            "OUTWARDIDX|schema={OUTPUT_SCHEMA}|repositories={}|waves={}|detectors={DETECTOR_COUNT}|directions={DIRECTION_COUNT}|json=0",
            capture.repositories.len(),
            waves.len()
        ),
        format!(
            "SOURCE|schema={INPUT_SCHEMA}|sha256={}|object_hash={}|sidecar_verified=1|json=0",
            hex(&sha256(&capture.source_bytes)),
            capture.object_commitment
        ),
        format!(
            "ARTIFACT|kind=HBP|file={HBP_NAME}|sha256={hbp_sha256}|json=0"
        ),
        format!(
            "ARTIFACT|kind=SVG|file={SVG_NAME}|sha256={svg_sha256}|static=1|script=0|network=0|json=0"
        ),
        format!(
            "ARTIFACT|kind=GGUF|file={GGUF_NAME}|sha256={gguf_sha256}|tensor=outward_wave|shape=32,3,4,{}|order=repo,detector,direction,feature|descriptor_sha256={descriptor_sha256}|media_bytes_embedded=0|repo_bytes_embedded=0|json=0",
            capture.repositories.len()
        ),
        format!(
            "CENTER|nullspace=0|center_members={CENTER_MEMBERS}|traversal={CENTER_TRAVERSAL}|sha_equals_hash=0|object_hash={object_hash}|json=0"
        ),
        "ELECTRONS|members=BYTE_COMMITMENT,CLAIM_EVIDENCE,MEDIA_BINDING,RUNTIME_AUTHORITY|catalog_only=1|function_call_authority=0|network=0|execution=0|json=0".to_owned(),
        "QUARANTINE|name=BLACK_HEAT|mode=REVERSIBLE_VISUALIZATION_ONLY|bytes_preserved=1|reversible=1|deletion=0|execution=0|physical_energy=0|identity_accusation=0|quarantine_applied=0|json=0".to_owned(),
        format!(
            "BOUNDARY|media_classification={MEDIA_CLASSIFICATION}|media_bodies_read=0|media_bytes_embedded=0|repository_bodies_read=0|repository_bytes_embedded=0|private_repo_rows=0|private_keys=0|credentials=0|system_affirmed=0|json=0"
        ),
        format!(
            "RECIPE|sh={RECIPE}|integer_only=1|float=0|unsafe=0|dependencies=0|rust=1.81.0|json=0"
        ),
    ];
    let body = joined_rows(&rows);
    rows.push(format!(
        "OUTWARDIDXFTR|body_sha256={}|rows={}|json=0",
        hex(&sha256(&body)),
        rows.len() + 1
    ));
    joined_rows(&rows)
}

fn sidecar_bytes(path: &Path, bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(format!("{}  {}\n", hex(&sha256(bytes)), file_name(path)?).into_bytes())
}

pub fn run_outward(input: &Path, output_dir: &Path, replace: bool) -> Result<OutwardResult> {
    let metadata = fs::metadata(output_dir).map_err(|_| error("OUTWARD_OUTPUT_DIRECTORY"))?;
    if !metadata.is_dir() {
        return Err(error("OUTWARD_OUTPUT_DIRECTORY"));
    }
    let source_bytes = read_verified_input(input)?;
    let capture = parse_owner_capture(&source_bytes)?;
    let records = derive_records(&capture);
    let waves = derive_waves(&capture, &records)?;
    let (hbp, object_hash) = build_hbp(&capture, &waves)?;
    let svg = build_svg(&capture, &waves, &object_hash)?;
    let (gguf, descriptor) = build_gguf(&capture, &waves)?;
    let hbp_sha256 = hex(&sha256(&hbp));
    let svg_sha256 = hex(&sha256(&svg));
    let gguf_sha256 = hex(&sha256(&gguf));
    let descriptor_sha256 = hex(&sha256(&descriptor));
    let hbi = build_hbi(
        &capture,
        &waves,
        &object_hash,
        &hbp_sha256,
        &svg_sha256,
        &gguf_sha256,
        &descriptor_sha256,
    );
    let hbi_sha256 = hex(&sha256(&hbi));

    let hbp_path = output_dir.join(HBP_NAME);
    let hbi_path = output_dir.join(HBI_NAME);
    let svg_path = output_dir.join(SVG_NAME);
    let gguf_path = output_dir.join(GGUF_NAME);
    let hbp_sidecar_path = sidecar_path(&hbp_path)?;
    let hbi_sidecar_path = sidecar_path(&hbi_path)?;
    let svg_sidecar_path = sidecar_path(&svg_path)?;
    let gguf_sidecar_path = sidecar_path(&gguf_path)?;
    let input_sidecar_path = sidecar_path(input)?;
    ensure_distinct_paths(&[
        input,
        &input_sidecar_path,
        &hbp_path,
        &hbp_sidecar_path,
        &hbi_path,
        &hbi_sidecar_path,
        &svg_path,
        &svg_sidecar_path,
        &gguf_path,
        &gguf_sidecar_path,
    ])?;
    let hbp_sidecar = sidecar_bytes(&hbp_path, &hbp)?;
    let hbi_sidecar = sidecar_bytes(&hbi_path, &hbi)?;
    let svg_sidecar = sidecar_bytes(&svg_path, &svg)?;
    let gguf_sidecar = sidecar_bytes(&gguf_path, &gguf)?;
    atomic_write_set(
        &[
            (&hbp_path, hbp.as_slice()),
            (&hbp_sidecar_path, hbp_sidecar.as_slice()),
            (&hbi_path, hbi.as_slice()),
            (&hbi_sidecar_path, hbi_sidecar.as_slice()),
            (&svg_path, svg.as_slice()),
            (&svg_sidecar_path, svg_sidecar.as_slice()),
            (&gguf_path, gguf.as_slice()),
            (&gguf_sidecar_path, gguf_sidecar.as_slice()),
        ],
        replace,
    )?;
    Ok(OutwardResult {
        repositories: capture.repositories.len(),
        waves: waves.len(),
        hbp_sha256,
        hbi_sha256,
        svg_sha256,
        gguf_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_source() -> Vec<u8> {
        let media_root = hex(&sha256(b"synthetic-media-root"));
        let object_root = hex(&sha256(b"synthetic-object-root"));
        let word_root_zero = hex(&sha256(b"synthetic-word-zero"));
        let word_root_one = hex(&sha256(b"synthetic-word-one"));
        let repository_rows = vec![
            format!(
                "REPO|i=0|name=alpha|branch=main|state=PUBLIC_TREE_COMPLETE|commit={}|tree={}|entries=3|blobs=2|trees=1|commits=0|symlinks=0|image_entries=1|video_entries=0|media_declared_bytes=123|media_size_unknown_entries=0|media_root_sha256={media_root}|object_root_sha256={object_root}|word_rime_root_sha256={word_root_zero}|word_count=3|color=#123ABC|json=0",
                "1".repeat(40),
                "2".repeat(40)
            ),
            format!(
                "REPO|i=1|name=omega|branch=main|state=EMPTY_UNBORN|commit={ZERO_SHA1}|tree={ZERO_SHA1}|entries=0|blobs=0|trees=0|commits=0|symlinks=0|image_entries=0|video_entries=0|media_declared_bytes=0|media_size_unknown_entries=0|media_root_sha256={EMPTY_SHA256}|object_root_sha256={EMPTY_SHA256}|word_rime_root_sha256={word_root_one}|word_count=2|color=#8B5A2B|json=0"
            ),
        ];
        let mut root_material = Vec::new();
        for row in &repository_rows {
            root_material.extend_from_slice(
                &u64::try_from(row.len())
                    .expect("synthetic row length fits u64")
                    .to_be_bytes(),
            );
            root_material.extend_from_slice(row.as_bytes());
        }
        let object_hash = hex(&sha256(&root_material));
        let mut rows = vec![
            format!(
                "OWNER3DRUN|schema={INPUT_SCHEMA}|owner=fixture|captured_at=2026-07-30T00:00:00.000Z|surface=PUBLIC_API_SUBSET|repos=2|json=0"
            ),
            format!(
                "CENTER|nullspace=0|center_members={CENTER_MEMBERS}|traversal=HBI,HBP,SH,HASH,SHA|sha_equals_hash=0|brown_center=#8B5A2B|close_to=1|json=0"
            ),
            format!(
                "RECIPE|sh=GH_PUBLIC_OWNER_TREE_V1|transport=GH_CLI_PUBLIC_REST|recursive_git_tree=1|paths_published=0|blob_bodies_read=0|media_extensions_classified=1|media_paths_published=0|media_bodies_read=0|media_classification={MEDIA_CLASSIFICATION}|json=0"
            ),
            "BOUNDARY|private_repo_endpoint_calls=0|private_repo_rows=0|private_keys=0|credentials_in_output=0|catalog_grants_authority=0|system_affirmed=0|media_bytes_embedded=0|media_decoder_claim=0|json=0".to_owned(),
        ];
        rows.extend(repository_rows);
        rows.push(format!(
            "HASH|role=SPHERICAL_OBJECT_COMMITMENT|algorithm=SHA256|value={object_hash}|distinct_from_hbp_byte_sha=1|json=0"
        ));
        rows.push("SUMMARY|repos=2|branched=1|unborn=1|entries=3|blobs=2|trees=1|commits=0|symlinks=0|image_entries=1|video_entries=0|media_declared_bytes=123|media_size_unknown_entries=0|json=0".to_owned());
        joined_rows(&rows)
    }

    fn synthetic_projection() -> (OwnerCapture, Vec<InputRecord>, Vec<Wave>) {
        let source = synthetic_source();
        let capture = parse_owner_capture(&source).expect("synthetic OWNER3D V2 parses");
        let records = derive_records(&capture);
        let waves = derive_waves(&capture, &records).expect("exact integer waves derive");
        (capture, records, waves)
    }

    #[test]
    fn population_is_four_by_three_per_repository() {
        let (capture, records, waves) = synthetic_projection();
        assert_eq!(capture.repositories.len(), 2);
        assert_eq!(records.len(), 2);
        assert_eq!(waves.len(), 24);
        assert_eq!(
            waves
                .iter()
                .map(|wave| wave.wave_id.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            24
        );
        for repository_waves in waves.chunks_exact(WAVE_COUNT_PER_REPO) {
            let addresses = repository_waves
                .iter()
                .map(|wave| (wave.detector, wave.direction))
                .collect::<BTreeSet<_>>();
            assert_eq!(addresses.len(), WAVE_COUNT_PER_REPO);
        }
        for wave in &waves {
            assert_eq!(
                [
                    wave.hbi.as_str(),
                    wave.hbp.as_str(),
                    wave.sha.as_str(),
                    wave.sh.as_str(),
                    wave.hash.as_str()
                ]
                .into_iter()
                .collect::<BTreeSet<_>>()
                .len(),
                5
            );
        }
    }

    #[test]
    fn gguf_shape_payload_and_boundaries_are_exact() {
        let (capture, _, waves) = synthetic_projection();
        let (gguf, descriptor) = build_gguf(&capture, &waves).expect("GGUF builds");
        assert_eq!(descriptor.len(), 32 * 3 * 4 * 2);
        verify_gguf(&gguf, &capture, &descriptor).expect("GGUF self-verifies");
        let mut corrupted = gguf;
        let final_index = corrupted.len() - 1;
        corrupted[final_index] ^= 1;
        assert!(verify_gguf(&corrupted, &capture, &descriptor).is_err());
    }

    #[test]
    fn receipts_and_static_svg_keep_reversible_boundary() {
        let (capture, _, waves) = synthetic_projection();
        let (hbp, object_hash) = build_hbp(&capture, &waves).expect("HBP builds");
        let hbp_text = std::str::from_utf8(&hbp).expect("HBP UTF-8");
        assert_eq!(
            hbp_text
                .lines()
                .filter(|line| line.starts_with("WAVE|"))
                .count(),
            24
        );
        assert!(hbp_text.contains("bytes_preserved=1|reversible=1|deletion=0|execution=0|physical_energy=0|identity_accusation=0|quarantine_applied=0"));
        let svg = build_svg(&capture, &waves, &object_hash).expect("SVG builds");
        let svg_text = std::str::from_utf8(&svg).expect("SVG UTF-8");
        assert!(svg_text.contains("BLACK_HEAT_REVERSIBLE_VISUALIZATION"));
        assert!(svg_text.contains("visibility=\"hidden\""));
        assert!(!svg_text.contains("<script"));
        assert!(!svg_text.contains("<image"));
        assert!(!svg_text.contains(" href="));
    }
}
