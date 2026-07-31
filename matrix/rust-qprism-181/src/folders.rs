//! Exact-integer calming-OIL projection over a sealed public Git folder tree.
//!
//! The renderer consumes identity and aggregate-count rows only. It emits no
//! repository bodies, paths, media bodies, credentials, network operations,
//! execution authority, or physical-energy effects.

use super::{
    atomic_write_set, ensure_distinct_paths, fields, file_name, hex, parse_hex32,
    read_verified_input, required, sha256, sidecar_path, signed_projection, QprismError,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const INPUT_SCHEMA: &str = "ASOLARIA-PUBLIC-FOLDER-3D-TREE-V1";
const OUTPUT_SCHEMA: &str = "ASOLARIA-PUBLIC-FOLDER-CALMING-OILS-RUST-181-V1";
const GGUF_ARCHITECTURE: &str = "asolaria-public-folder-calming-oils";
const GGUF_NAME_VALUE: &str = "PUBLIC-FOLDER-CALMING-OILS";
const GGUF_PAYLOAD_KIND: &str = "DERIVED_PUBLIC_FOLDER_CALMING_OIL_DESCRIPTOR";
const CENTER_MEMBERS: &str = "HBI,HBP,SHA,SH,HASH";
const CENTER_TRAVERSAL: &str = "HBI->HBP->SH->HASH->SHA";
const RECIPE: &str = "FOLDER_CALMING_OILS_RUST_181_V1";
const MAX_REPOSITORIES: usize = 512;
// The shared verified-input reader is capped at 8,000,000 bytes. These two
// bounds remain jointly reachable even when every accepted row is maximal.
const MAX_FOLDERS: usize = 7_600;
const MAX_LINE_BYTES: usize = 1_024;
const MAX_LEVEL: u16 = 4_096;
const MAX_COORDINATE: i64 = 1_000_000;
const MAX_DIRECT_OBJECTS: u32 = 100_000_000;
const FAMILY_COUNT: usize = 3;
const DESCRIPTOR_WIDTH: usize = 64;
const VIEW_CENTER: i64 = 1_000;
const GGUF_MAGIC: u32 = 0x4655_4747;
const GGUF_VERSION: u32 = 3;
const GGUF_TYPE_UINT32: u32 = 4;
const GGUF_TYPE_STRING: u32 = 8;
const GGUF_TYPE_UINT64: u32 = 10;
const GGML_TYPE_I8: u32 = 24;
const GGUF_ALIGNMENT: usize = 32;
const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub const HBP_NAME: &str = "PUBLIC-FOLDER-CALMING-OILS.hbp";
pub const HBI_NAME: &str = "PUBLIC-FOLDER-CALMING-OILS.hbi";
pub const SVG_NAME: &str = "PUBLIC-FOLDER-CALMING-OILS.svg";
pub const GGUF_NAME: &str = "PUBLIC-FOLDER-CALMING-OILS.gguf";

type Result<T> = std::result::Result<T, QprismError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceKind {
    RepositoryRoot,
    GitTree,
}

impl SourceKind {
    const fn name(self) -> &'static str {
        match self {
            Self::RepositoryRoot => "REPOSITORY_ROOT",
            Self::GitTree => "GIT_TREE",
        }
    }

    const fn index(self) -> u8 {
        match self {
            Self::RepositoryRoot => 0,
            Self::GitTree => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Family {
    Brown,
    AntiBrown,
    AntiAntiBrown,
}

impl Family {
    const ALL: [Self; FAMILY_COUNT] = [Self::Brown, Self::AntiBrown, Self::AntiAntiBrown];

    const fn index(self) -> usize {
        match self {
            Self::Brown => 0,
            Self::AntiBrown => 1,
            Self::AntiAntiBrown => 2,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Brown => "BROWN",
            Self::AntiBrown => "ANTI_BROWN",
            Self::AntiAntiBrown => "ANTI_ANTI_BROWN",
        }
    }

    const fn offset(self) -> [i64; 3] {
        match self {
            Self::Brown => [-30_000, 0, -10_000],
            Self::AntiBrown => [0, 30_000, 0],
            Self::AntiAntiBrown => [30_000, 0, 10_000],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Folder {
    index: usize,
    repo_id: String,
    folder_id: String,
    parent_folder_id: String,
    sibling_ordinal: u32,
    level: u16,
    tree_commitment_sha256: [u8; 32],
    source_kind: SourceKind,
    direct_blobs: u32,
    direct_trees: u32,
    direct_commits: u32,
    direct_symlinks: u32,
    object_sha256: [u8; 32],
    position: [i64; 3],
    color: [u8; 3],
    canonical_row: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FolderCapture {
    source_bytes: Vec<u8>,
    source_capture_sha256: [u8; 32],
    public_set_sha256: [u8; 32],
    repositories: usize,
    folders: Vec<Folder>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Leaf {
    order: usize,
    folder_index: usize,
    repo_id: String,
    folder_id: String,
    parent_folder_id: String,
    sibling_ordinal: u32,
    level: u16,
    tree_commitment_sha256: [u8; 32],
    source_kind: SourceKind,
    direct_blobs: u32,
    direct_trees: u32,
    direct_commits: u32,
    direct_symlinks: u32,
    object_sha256: [u8; 32],
    family: Family,
    source_identity_sha256: String,
    parent_identity_sha256: String,
    leaf_id: String,
    view: [i64; 3],
    projected: [i64; 2],
    color: [u8; 3],
    hbi: String,
    hbp: String,
    sh: String,
    hash: String,
    sha: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderResult {
    pub repositories: usize,
    pub folders: usize,
    pub leaves: usize,
    pub hbp_sha256: String,
    pub hbi_sha256: String,
    pub svg_sha256: String,
    pub gguf_sha256: String,
}

fn error(code: &'static str) -> QprismError {
    QprismError::new(code)
}

fn exact_keys(map: &BTreeMap<&str, &str>, expected: &[&str]) -> Result<()> {
    if map.len() != expected.len() || expected.iter().any(|key| !map.contains_key(key)) {
        return Err(error("FOLDER_FIELD_SET"));
    }
    Ok(())
}

fn decimal_u64(value: &str, maximum: u64) -> Result<u64> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(error("FOLDER_UNSIGNED_INTEGER"));
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| error("FOLDER_UNSIGNED_INTEGER"))?;
    if parsed > maximum {
        return Err(error("FOLDER_UNSIGNED_RANGE"));
    }
    Ok(parsed)
}

fn usize_u64(value: usize) -> Result<u64> {
    u64::try_from(value).map_err(|_| error("FOLDER_USIZE_RANGE"))
}

fn decimal_i64(value: &str, maximum_absolute: i64) -> Result<i64> {
    if value.is_empty()
        || value.starts_with('+')
        || value == "-0"
        || (value.starts_with('0') && value.len() > 1)
        || (value.starts_with('-') && value.as_bytes().get(1) == Some(&b'0'))
        || !value
            .bytes()
            .enumerate()
            .all(|(index, byte)| byte.is_ascii_digit() || (index == 0 && byte == b'-'))
    {
        return Err(error("FOLDER_SIGNED_INTEGER"));
    }
    let parsed = value
        .parse::<i64>()
        .map_err(|_| error("FOLDER_SIGNED_INTEGER"))?;
    if parsed < -maximum_absolute || parsed > maximum_absolute {
        return Err(error("FOLDER_COORDINATE_RANGE"));
    }
    Ok(parsed)
}

fn rgb(value: &str) -> Result<[u8; 3]> {
    let digits = value
        .strip_prefix("RGB.")
        .ok_or_else(|| error("FOLDER_RGB"))?;
    if digits.len() != 6
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
    {
        return Err(error("FOLDER_RGB"));
    }
    let packed = u32::from_str_radix(digits, 16).map_err(|_| error("FOLDER_RGB"))?;
    Ok([
        u8::try_from((packed >> 16) & 255).expect("masked red channel"),
        u8::try_from((packed >> 8) & 255).expect("masked green channel"),
        u8::try_from(packed & 255).expect("masked blue channel"),
    ])
}

fn source_kind(value: &str) -> Result<SourceKind> {
    match value {
        "REPOSITORY_ROOT" => Ok(SourceKind::RepositoryRoot),
        "GIT_TREE" => Ok(SourceKind::GitTree),
        _ => Err(error("FOLDER_SOURCE_KIND")),
    }
}

fn domain_prefix(label: &[u8]) -> Vec<u8> {
    let mut output = INPUT_SCHEMA.as_bytes().to_vec();
    output.push(0);
    output.extend_from_slice(label);
    output.push(0);
    output
}

fn derive_folder_id(
    source_capture_sha256: &[u8; 32],
    repo_id: &[u8; 32],
    parent_folder_id: &[u8; 32],
    sibling_ordinal: u32,
    tree_commitment_sha256: &[u8; 32],
) -> [u8; 32] {
    let mut material = domain_prefix(b"FOLDER-ID");
    material.extend_from_slice(source_capture_sha256);
    material.extend_from_slice(repo_id);
    material.extend_from_slice(parent_folder_id);
    material.extend_from_slice(&sibling_ordinal.to_be_bytes());
    material.extend_from_slice(tree_commitment_sha256);
    sha256(&material)
}

struct ObjectFields<'a> {
    index: usize,
    repo_id: &'a [u8; 32],
    folder_id: &'a [u8; 32],
    parent_folder_id: &'a [u8; 32],
    sibling_ordinal: u32,
    level: u16,
    tree_commitment_sha256: &'a [u8; 32],
    source_kind: SourceKind,
    direct_blobs: u32,
    direct_trees: u32,
    direct_commits: u32,
    direct_symlinks: u32,
}

fn derive_object(fields: &ObjectFields<'_>) -> Result<[u8; 32]> {
    let mut material = domain_prefix(b"FOLDER-OBJECT");
    material.extend_from_slice(
        &u64::try_from(fields.index)
            .map_err(|_| error("FOLDER_INDEX"))?
            .to_be_bytes(),
    );
    material.extend_from_slice(fields.repo_id);
    material.extend_from_slice(fields.folder_id);
    material.extend_from_slice(fields.parent_folder_id);
    material.extend_from_slice(&fields.sibling_ordinal.to_be_bytes());
    material.extend_from_slice(&u32::from(fields.level).to_be_bytes());
    material.extend_from_slice(fields.tree_commitment_sha256);
    material.push(match fields.source_kind {
        SourceKind::RepositoryRoot => 1,
        SourceKind::GitTree => 2,
    });
    for value in [
        fields.direct_blobs,
        fields.direct_trees,
        fields.direct_commits,
        fields.direct_symlinks,
    ] {
        material.extend_from_slice(&u64::from(value).to_be_bytes());
    }
    Ok(sha256(&material))
}

fn coordinate_from_object(object: &[u8; 32], offset: usize) -> i64 {
    let raw = u32::from_be_bytes(
        object[offset..offset + 4]
            .try_into()
            .expect("fixed four-byte object window"),
    );
    i64::from(raw % 2_000_001) - MAX_COORDINATE
}

fn color_from_object(object: &[u8; 32]) -> [u8; 3] {
    [
        48 + (object[12] % 160),
        48 + (object[13] % 160),
        48 + (object[14] % 160),
    ]
}

fn parse_folder(
    raw: &str,
    expected_index: usize,
    source_capture_sha256: &[u8; 32],
) -> Result<Folder> {
    let map = fields(raw, "FOLDER")?;
    exact_keys(
        &map,
        &[
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
        ],
    )?;
    if decimal_u64(required(&map, "i")?, usize_u64(MAX_FOLDERS)?)?
        != u64::try_from(expected_index).map_err(|_| error("FOLDER_INDEX"))?
        || required(&map, "json")? != "0"
    {
        return Err(error("FOLDER_INDEX"));
    }
    let repo_id_text = required(&map, "repo_id")?;
    let repo_id = parse_hex32(repo_id_text)?;
    let folder_id_text = required(&map, "folder_id")?;
    let folder_id = parse_hex32(folder_id_text)?;
    let parent_folder_id_text = required(&map, "parent_folder_id")?;
    let parent_folder_id = parse_hex32(parent_folder_id_text)?;
    let sibling_ordinal = u32::try_from(decimal_u64(
        required(&map, "sibling_ordinal")?,
        u64::from(MAX_DIRECT_OBJECTS),
    )?)
    .map_err(|_| error("FOLDER_SIBLING_ORDINAL"))?;
    let level = u16::try_from(decimal_u64(required(&map, "level")?, u64::from(MAX_LEVEL))?)
        .map_err(|_| error("FOLDER_LEVEL"))?;
    let tree_commitment_sha256 = parse_hex32(required(&map, "tree_commitment_sha256")?)?;
    let source_kind = source_kind(required(&map, "source_kind")?)?;
    let direct_limit = u64::from(MAX_DIRECT_OBJECTS);
    let direct_blobs = u32::try_from(decimal_u64(required(&map, "direct_blobs")?, direct_limit)?)
        .map_err(|_| error("FOLDER_DIRECT_COUNT"))?;
    let direct_symlinks = u32::try_from(decimal_u64(
        required(&map, "direct_symlinks")?,
        direct_limit,
    )?)
    .map_err(|_| error("FOLDER_DIRECT_COUNT"))?;
    if direct_symlinks > direct_blobs {
        return Err(error("FOLDER_SYMLINK_COUNT"));
    }
    let direct_trees = u32::try_from(decimal_u64(required(&map, "direct_trees")?, direct_limit)?)
        .map_err(|_| error("FOLDER_DIRECT_COUNT"))?;
    let direct_commits = u32::try_from(decimal_u64(
        required(&map, "direct_commits")?,
        direct_limit,
    )?)
    .map_err(|_| error("FOLDER_DIRECT_COUNT"))?;
    let expected_folder_id = derive_folder_id(
        source_capture_sha256,
        &repo_id,
        &parent_folder_id,
        sibling_ordinal,
        &tree_commitment_sha256,
    );
    if folder_id != expected_folder_id {
        return Err(error("FOLDER_ID_DERIVATION"));
    }
    let object_fields = ObjectFields {
        index: expected_index,
        repo_id: &repo_id,
        folder_id: &folder_id,
        parent_folder_id: &parent_folder_id,
        sibling_ordinal,
        level,
        tree_commitment_sha256: &tree_commitment_sha256,
        source_kind,
        direct_blobs,
        direct_trees,
        direct_commits,
        direct_symlinks,
    };
    let object_sha256 = derive_object(&object_fields)?;
    if parse_hex32(required(&map, "object_sha256")?)? != object_sha256 {
        return Err(error("FOLDER_OBJECT_DERIVATION"));
    }
    let position = [
        coordinate_from_object(&object_sha256, 0),
        coordinate_from_object(&object_sha256, 4),
        coordinate_from_object(&object_sha256, 8),
    ];
    for (key, expected) in [("x", position[0]), ("y", position[1]), ("z", position[2])] {
        if decimal_i64(required(&map, key)?, MAX_COORDINATE)? != expected {
            return Err(error("FOLDER_COORDINATE_DERIVATION"));
        }
    }
    let color = color_from_object(&object_sha256);
    if rgb(required(&map, "color")?)? != color {
        return Err(error("FOLDER_COLOR_DERIVATION"));
    }
    Ok(Folder {
        index: expected_index,
        repo_id: repo_id_text.to_owned(),
        folder_id: folder_id_text.to_owned(),
        parent_folder_id: parent_folder_id_text.to_owned(),
        sibling_ordinal,
        level,
        tree_commitment_sha256,
        source_kind,
        direct_blobs,
        direct_trees,
        direct_commits,
        direct_symlinks,
        object_sha256,
        position,
        color,
        canonical_row: raw.as_bytes().to_vec(),
    })
}

fn validate_input_text(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty()
        || bytes.last() != Some(&b'\n')
        || bytes.contains(&b'\r')
        || bytes.contains(&0)
    {
        return Err(error("FOLDER_INPUT_TEXT"));
    }
    if bytes
        .split(|byte| *byte == b'\n')
        .any(|line| line.len() > MAX_LINE_BYTES)
    {
        return Err(error("FOLDER_LINE_SIZE"));
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() != 24
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[23] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19 | 23) && !byte.is_ascii_digit()
        })
    {
        return Err(error("FOLDER_CAPTURED_AT"));
    }
    let number = |start: usize, end: usize| -> Result<u32> {
        value[start..end]
            .parse::<u32>()
            .map_err(|_| error("FOLDER_CAPTURED_AT"))
    };
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    number(20, 23)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(error("FOLDER_CAPTURED_AT")),
    };
    if day == 0 || day > max_day || hour > 23 || minute > 59 || second > 59 {
        return Err(error("FOLDER_CAPTURED_AT"));
    }
    Ok(())
}

fn validate_hierarchy(folders: &[Folder], root_nodes: usize) -> Result<()> {
    let mut by_identity = BTreeMap::<(&str, &str), &Folder>::new();
    let mut global_folder_ids = BTreeSet::new();
    let mut roots = BTreeMap::<&str, usize>::new();
    let mut sibling_keys = BTreeSet::new();
    for folder in folders {
        if !global_folder_ids.insert(folder.folder_id.as_str())
            || by_identity
                .insert((folder.repo_id.as_str(), folder.folder_id.as_str()), folder)
                .is_some()
        {
            return Err(error("FOLDER_DUPLICATE_IDENTITY"));
        }
        if folder.level == 0 {
            if folder.parent_folder_id != ZERO_SHA256
                || folder.source_kind != SourceKind::RepositoryRoot
                || folder.sibling_ordinal != 0
            {
                return Err(error("FOLDER_ROOT_SHAPE"));
            }
            let count = roots.entry(folder.repo_id.as_str()).or_insert(0);
            *count = count
                .checked_add(1)
                .ok_or_else(|| error("FOLDER_ROOT_COUNT"))?;
        } else if folder.parent_folder_id == ZERO_SHA256
            || folder.source_kind != SourceKind::GitTree
        {
            return Err(error("FOLDER_CHILD_SHAPE"));
        }
    }
    if roots.len() != root_nodes || roots.values().any(|count| *count != 1) {
        return Err(error("FOLDER_REPOSITORY_ROOTS"));
    }

    let mut child_counts = BTreeMap::<(&str, &str), u32>::new();
    for folder in folders.iter().filter(|folder| folder.level > 0) {
        let parent = by_identity
            .get(&(folder.repo_id.as_str(), folder.parent_folder_id.as_str()))
            .ok_or_else(|| error("FOLDER_PARENT_MISSING"))?;
        let expected_level = parent
            .level
            .checked_add(1)
            .ok_or_else(|| error("FOLDER_LEVEL_OVERFLOW"))?;
        if folder.level != expected_level {
            return Err(error("FOLDER_PARENT_LEVEL"));
        }
        let key = (
            folder.repo_id.as_str(),
            folder.parent_folder_id.as_str(),
            folder.sibling_ordinal,
        );
        if !sibling_keys.insert(key) || folder.sibling_ordinal >= parent.direct_trees {
            return Err(error("FOLDER_SIBLING_ORDINAL"));
        }
        let count = child_counts
            .entry((folder.repo_id.as_str(), folder.parent_folder_id.as_str()))
            .or_insert(0);
        *count = count
            .checked_add(1)
            .ok_or_else(|| error("FOLDER_CHILD_COUNT"))?;
    }
    for folder in folders {
        let child_count = child_counts
            .get(&(folder.repo_id.as_str(), folder.folder_id.as_str()))
            .copied()
            .unwrap_or(0);
        if child_count != folder.direct_trees {
            return Err(error("FOLDER_DIRECT_TREE_COUNT"));
        }
    }
    Ok(())
}

fn parse_capture(source_bytes: &[u8]) -> Result<FolderCapture> {
    validate_input_text(source_bytes)?;
    let text = std::str::from_utf8(source_bytes).map_err(|_| error("FOLDER_INPUT_UTF8"))?;
    let lines: Vec<&str> = text[..text.len() - 1].split('\n').collect();
    if lines.len() < 8 {
        return Err(error("FOLDER_INPUT_ROWS"));
    }

    let header = fields(lines[0], "FOLDER3DRUN")?;
    exact_keys(
        &header,
        &[
            "schema",
            "owner",
            "captured_at",
            "surface",
            "source_capture_sha256",
            "public_set_sha256",
            "repositories",
            "branched",
            "unborn",
            "root_nodes",
            "tree_nodes",
            "folders",
            "public_metadata_only",
            "json",
        ],
    )?;
    if required(&header, "schema")? != INPUT_SCHEMA
        || required(&header, "owner")? != "JesseBrown1980"
        || required(&header, "surface")? != "MEASURED_GITHUB_PUBLIC"
        || required(&header, "public_metadata_only")? != "1"
        || required(&header, "json")? != "0"
    {
        return Err(error("FOLDER_INPUT_HEADER"));
    }
    validate_timestamp(required(&header, "captured_at")?)?;
    let source_capture_sha256 = parse_hex32(required(&header, "source_capture_sha256")?)?;
    let public_set_sha256 = parse_hex32(required(&header, "public_set_sha256")?)?;
    let repositories = usize::try_from(decimal_u64(
        required(&header, "repositories")?,
        usize_u64(MAX_REPOSITORIES)?,
    )?)
    .map_err(|_| error("FOLDER_REPOSITORY_COUNT"))?;
    let branched = usize::try_from(decimal_u64(
        required(&header, "branched")?,
        usize_u64(MAX_REPOSITORIES)?,
    )?)
    .map_err(|_| error("FOLDER_BRANCHED_COUNT"))?;
    let unborn = usize::try_from(decimal_u64(
        required(&header, "unborn")?,
        usize_u64(MAX_REPOSITORIES)?,
    )?)
    .map_err(|_| error("FOLDER_UNBORN_COUNT"))?;
    let root_nodes = usize::try_from(decimal_u64(
        required(&header, "root_nodes")?,
        usize_u64(MAX_REPOSITORIES)?,
    )?)
    .map_err(|_| error("FOLDER_ROOT_COUNT"))?;
    let tree_nodes = usize::try_from(decimal_u64(
        required(&header, "tree_nodes")?,
        usize_u64(MAX_FOLDERS)?,
    )?)
    .map_err(|_| error("FOLDER_TREE_COUNT"))?;
    let folder_count = usize::try_from(decimal_u64(
        required(&header, "folders")?,
        usize_u64(MAX_FOLDERS)?,
    )?)
    .map_err(|_| error("FOLDER_COUNT"))?;
    if repositories == 0
        || branched == 0
        || branched.checked_add(unborn) != Some(repositories)
        || root_nodes != branched
        || root_nodes.checked_add(tree_nodes) != Some(folder_count)
        || lines.len() != folder_count + 7
    {
        return Err(error("FOLDER_COUNT"));
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
        || required(&center, "brown_center")? != "RGB.8B5A2B"
        || required(&center, "close_to")? != "1"
        || required(&center, "json")? != "0"
    {
        return Err(error("FOLDER_INPUT_CENTER"));
    }

    let recipe = fields(lines[2], "RECIPE")?;
    exact_keys(
        &recipe,
        &[
            "transport",
            "recursive_git_tree",
            "complete_tree_required",
            "paths_published",
            "path_hashes_published",
            "tree_sha1_published",
            "git_tree_commitments",
            "path_dictionary_resistance_claim",
            "blob_bodies_read",
            "private_repo_endpoint_calls",
            "json",
        ],
    )?;
    if required(&recipe, "transport")? != "GH_CLI_AUTHENTICATED_PUBLIC"
        || required(&recipe, "recursive_git_tree")? != "1"
        || required(&recipe, "complete_tree_required")? != "1"
        || required(&recipe, "git_tree_commitments")? != "1"
        || [
            "paths_published",
            "path_hashes_published",
            "tree_sha1_published",
            "path_dictionary_resistance_claim",
            "blob_bodies_read",
            "private_repo_endpoint_calls",
            "json",
        ]
        .iter()
        .any(|key| required(&recipe, key).ok() != Some("0"))
    {
        return Err(error("FOLDER_INPUT_RECIPE"));
    }

    let boundary = fields(lines[3], "BOUNDARY")?;
    exact_keys(
        &boundary,
        &[
            "private_repo_rows",
            "private_repo_names",
            "credentials",
            "raw_paths",
            "raw_bodies",
            "network_in_renderer",
            "execution",
            "system_affirmed",
            "json",
        ],
    )?;
    if [
        "private_repo_rows",
        "private_repo_names",
        "credentials",
        "raw_paths",
        "raw_bodies",
        "network_in_renderer",
        "execution",
        "system_affirmed",
        "json",
    ]
    .iter()
    .any(|key| required(&boundary, key).ok() != Some("0"))
    {
        return Err(error("FOLDER_INPUT_BOUNDARY"));
    }

    let mut folders = Vec::with_capacity(folder_count);
    let mut object_material = Vec::new();
    for (index, raw) in lines[4..4 + folder_count].iter().enumerate() {
        folders.push(parse_folder(raw, index, &source_capture_sha256)?);
        object_material.extend_from_slice(
            &u64::try_from(raw.len())
                .map_err(|_| error("FOLDER_ROW_LENGTH"))?
                .to_be_bytes(),
        );
        object_material.extend_from_slice(raw.as_bytes());
    }
    validate_hierarchy(&folders, root_nodes)?;

    let object_hash = hex(&sha256(&object_material));
    let hash_row = fields(lines[4 + folder_count], "HASH")?;
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
        || required(&hash_row, "value")? != object_hash
        || required(&hash_row, "distinct_from_hbp_byte_sha")? != "1"
        || required(&hash_row, "json")? != "0"
    {
        return Err(error("FOLDER_INPUT_OBJECT_HASH"));
    }

    let roots_measured = folders
        .iter()
        .filter(|folder| folder.source_kind == SourceKind::RepositoryRoot)
        .count();
    let trees_measured = folders.len() - roots_measured;
    let max_level_measured = folders.iter().map(|folder| folder.level).max().unwrap_or(0);
    let unique_tree_objects = folders
        .iter()
        .map(|folder| folder.tree_commitment_sha256)
        .collect::<BTreeSet<_>>()
        .len();
    let mut direct_blobs = 0_u64;
    let mut direct_trees = 0_u64;
    let mut direct_commits = 0_u64;
    let mut direct_symlinks = 0_u64;
    for folder in &folders {
        direct_blobs = direct_blobs
            .checked_add(u64::from(folder.direct_blobs))
            .ok_or_else(|| error("FOLDER_TOTAL_OVERFLOW"))?;
        direct_trees = direct_trees
            .checked_add(u64::from(folder.direct_trees))
            .ok_or_else(|| error("FOLDER_TOTAL_OVERFLOW"))?;
        direct_commits = direct_commits
            .checked_add(u64::from(folder.direct_commits))
            .ok_or_else(|| error("FOLDER_TOTAL_OVERFLOW"))?;
        direct_symlinks = direct_symlinks
            .checked_add(u64::from(folder.direct_symlinks))
            .ok_or_else(|| error("FOLDER_TOTAL_OVERFLOW"))?;
    }
    let summary = fields(lines[5 + folder_count], "SUMMARY")?;
    exact_keys(
        &summary,
        &[
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
        ],
    )?;
    let expected_summary = [
        (
            "repositories",
            u64::try_from(repositories).map_err(|_| error("FOLDER_REPOSITORY_COUNT"))?,
        ),
        (
            "branched",
            u64::try_from(branched).map_err(|_| error("FOLDER_BRANCHED_COUNT"))?,
        ),
        (
            "unborn",
            u64::try_from(unborn).map_err(|_| error("FOLDER_UNBORN_COUNT"))?,
        ),
        (
            "repository_roots",
            u64::try_from(roots_measured).map_err(|_| error("FOLDER_ROOT_COUNT"))?,
        ),
        (
            "git_tree_folder_occurrences",
            u64::try_from(trees_measured).map_err(|_| error("FOLDER_TREE_COUNT"))?,
        ),
        (
            "folders",
            u64::try_from(folder_count).map_err(|_| error("FOLDER_COUNT"))?,
        ),
        ("max_level", u64::from(max_level_measured)),
        ("direct_blobs", direct_blobs),
        ("direct_trees", direct_trees),
        ("direct_commits", direct_commits),
        ("gitlinks", direct_commits),
        ("symlinks", direct_symlinks),
        (
            "unique_tree_objects",
            u64::try_from(unique_tree_objects).map_err(|_| error("FOLDER_UNIQUE_TREE_COUNT"))?,
        ),
    ];
    for (key, expected) in expected_summary {
        if decimal_u64(required(&summary, key)?, u64::MAX)? != expected {
            return Err(error("FOLDER_SUMMARY_VALUE"));
        }
    }
    if roots_measured != root_nodes
        || trees_measured != tree_nodes
        || direct_trees != u64::try_from(tree_nodes).map_err(|_| error("FOLDER_TREE_COUNT"))?
        || required(&summary, "json")? != "0"
    {
        return Err(error("FOLDER_SUMMARY_SHAPE"));
    }

    let footer = fields(lines[6 + folder_count], "FOLDER3DFTR")?;
    exact_keys(
        &footer,
        &["body_sha256", "rows", "repositories", "folders", "json"],
    )?;
    let body = format!("{}\n", lines[..lines.len() - 1].join("\n"));
    if required(&footer, "body_sha256")? != hex(&sha256(body.as_bytes()))
        || decimal_u64(required(&footer, "rows")?, usize_u64(MAX_FOLDERS + 7)?)?
            != u64::try_from(lines.len()).map_err(|_| error("FOLDER_ROW_COUNT"))?
        || decimal_u64(
            required(&footer, "repositories")?,
            usize_u64(MAX_REPOSITORIES)?,
        )? != u64::try_from(repositories).map_err(|_| error("FOLDER_REPOSITORY_COUNT"))?
        || decimal_u64(required(&footer, "folders")?, usize_u64(MAX_FOLDERS)?)?
            != u64::try_from(folder_count).map_err(|_| error("FOLDER_COUNT"))?
        || required(&footer, "json")? != "0"
    {
        return Err(error("FOLDER_INPUT_FOOTER"));
    }
    Ok(FolderCapture {
        source_bytes: source_bytes.to_vec(),
        source_capture_sha256,
        public_set_sha256,
        repositories,
        folders,
    })
}

fn checked_add_i64(left: i64, right: i64) -> Result<i64> {
    i64::try_from(
        i128::from(left)
            .checked_add(i128::from(right))
            .ok_or_else(|| error("FOLDER_INTEGER_OVERFLOW"))?,
    )
    .map_err(|_| error("FOLDER_I64_RANGE"))
}

fn hash_label(label: &str, value: &[u8]) -> String {
    let mut material = Vec::with_capacity(label.len() + value.len() + 1);
    material.extend_from_slice(label.as_bytes());
    material.push(0);
    material.extend_from_slice(value);
    hex(&sha256(&material))
}

fn family_color(input: [u8; 3], family: Family) -> [u8; 3] {
    let brown_base = [139_u16, 90_u16, 43_u16];
    let mut brown = [0_u8; 3];
    for index in 0..3 {
        brown[index] = u8::try_from(
            (u16::from(input[index])
                .checked_mul(2)
                .expect("bounded channel multiplication")
                + brown_base[index])
                / 3,
        )
        .expect("bounded Brown channel");
    }
    match family {
        Family::Brown => brown,
        Family::AntiBrown => brown.map(|value| 255 - value),
        Family::AntiAntiBrown => {
            let mut output = [0_u8; 3];
            for index in 0..3 {
                output[index] =
                    u8::try_from((u16::from(brown[index]) + u16::from(input[index])).div_ceil(2))
                        .expect("bounded anti-anti channel");
            }
            output
        }
    }
}

fn derive_leaves(capture: &FolderCapture) -> Result<Vec<Leaf>> {
    let source_sha256 = sha256(&capture.source_bytes);
    let mut identifiers = BTreeSet::new();
    let mut leaves = Vec::with_capacity(
        capture
            .folders
            .len()
            .checked_mul(FAMILY_COUNT)
            .ok_or_else(|| error("FOLDER_LEAF_COUNT"))?,
    );
    for folder in &capture.folders {
        let mut source_material = b"FOLDER-SOURCE-IDENTITY-RUST-181\0".to_vec();
        source_material.extend_from_slice(&source_sha256);
        source_material.extend_from_slice(&folder.canonical_row);
        let source_identity_sha256 = hex(&sha256(&source_material));
        let parent_identity_sha256 = hash_label(
            "FOLDER-PARENT-IDENTITY-RUST-181",
            format!("{}:{}", folder.repo_id, folder.parent_folder_id).as_bytes(),
        );
        for family in Family::ALL {
            let mut leaf_material = b"FOLDER-CALMING-OIL-LEAF-RUST-181\0".to_vec();
            leaf_material.extend_from_slice(&source_sha256);
            leaf_material.extend_from_slice(&folder.canonical_row);
            leaf_material.extend_from_slice(family.name().as_bytes());
            let leaf_id = hex(&sha256(&leaf_material));
            if !identifiers.insert(leaf_id.clone()) {
                return Err(error("FOLDER_LEAF_COLLISION"));
            }
            let offset = family.offset();
            let view = [
                checked_add_i64(folder.position[0], offset[0])?,
                checked_add_i64(folder.position[1], offset[1])?,
                checked_add_i64(folder.position[2], offset[2])?,
            ];
            let (projected_u, projected_v) = signed_projection(view[0], view[1], view[2])?;
            let hbi = hash_label("HBI", leaf_id.as_bytes());
            let hbp = hash_label("HBP", leaf_id.as_bytes());
            let sh = hash_label("SH", leaf_id.as_bytes());
            let hash = hash_label("HASH", leaf_id.as_bytes());
            let sha = hash_label("SHA", leaf_id.as_bytes());
            if [
                hbi.as_str(),
                hbp.as_str(),
                sh.as_str(),
                hash.as_str(),
                sha.as_str(),
            ]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .len()
                != 5
            {
                return Err(error("FOLDER_ADDRESS_COLLISION"));
            }
            leaves.push(Leaf {
                order: leaves.len(),
                folder_index: folder.index,
                repo_id: folder.repo_id.clone(),
                folder_id: folder.folder_id.clone(),
                parent_folder_id: folder.parent_folder_id.clone(),
                sibling_ordinal: folder.sibling_ordinal,
                level: folder.level,
                tree_commitment_sha256: folder.tree_commitment_sha256,
                source_kind: folder.source_kind,
                direct_blobs: folder.direct_blobs,
                direct_trees: folder.direct_trees,
                direct_commits: folder.direct_commits,
                direct_symlinks: folder.direct_symlinks,
                object_sha256: folder.object_sha256,
                family,
                source_identity_sha256: source_identity_sha256.clone(),
                parent_identity_sha256: parent_identity_sha256.clone(),
                leaf_id,
                view,
                projected: [projected_u, projected_v],
                color: family_color(folder.color, family),
                hbi,
                hbp,
                sh,
                hash,
                sha,
            });
        }
    }
    if leaves.len() != capture.folders.len() * FAMILY_COUNT {
        return Err(error("FOLDER_LEAF_COUNT"));
    }
    Ok(leaves)
}

fn joined_rows(rows: &[String]) -> Vec<u8> {
    let mut output = rows.join("\n").into_bytes();
    output.push(b'\n');
    output
}

fn rgb_text(color: [u8; 3]) -> String {
    format!("RGB.{:02X}{:02X}{:02X}", color[0], color[1], color[2])
}

fn leaf_row(leaf: &Leaf) -> String {
    format!(
        "OIL|i={}|folder_i={}|repo_id={}|folder_id={}|parent_folder_id={}|sibling_ordinal={}|level={}|source_kind={}|family={}|source_identity_sha256={}|parent_identity_sha256={}|leaf_id={}|tree_commitment_sha256={}|object_sha256={}|direct_blobs={}|direct_trees={}|direct_commits={}|direct_symlinks={}|view_x={}|view_y={}|view_z={}|projected_u={}|projected_v={}|color={}|hbi={}|hbp={}|sh={}|hash={}|sha={}|path_bytes_embedded=0|media_bytes_embedded=0|repository_bytes_embedded=0|credentials=0|network=0|execution=0|physical_energy=0|authority=0|json=0",
        leaf.order,
        leaf.folder_index,
        leaf.repo_id,
        leaf.folder_id,
        leaf.parent_folder_id,
        leaf.sibling_ordinal,
        leaf.level,
        leaf.source_kind.name(),
        leaf.family.name(),
        leaf.source_identity_sha256,
        leaf.parent_identity_sha256,
        leaf.leaf_id,
        hex(&leaf.tree_commitment_sha256),
        hex(&leaf.object_sha256),
        leaf.direct_blobs,
        leaf.direct_trees,
        leaf.direct_commits,
        leaf.direct_symlinks,
        leaf.view[0],
        leaf.view[1],
        leaf.view[2],
        leaf.projected[0],
        leaf.projected[1],
        rgb_text(leaf.color),
        leaf.hbi,
        leaf.hbp,
        leaf.sh,
        leaf.hash,
        leaf.sha,
    )
}

fn build_hbp(capture: &FolderCapture, leaves: &[Leaf]) -> Result<(Vec<u8>, String)> {
    let source_sha256 = hex(&sha256(&capture.source_bytes));
    let mut rows = vec![
        format!(
            "FOLDEROILRUN|schema={OUTPUT_SCHEMA}|source_schema={INPUT_SCHEMA}|repositories={}|folders={}|families={FAMILY_COUNT}|leaves={}|descriptor_width={DESCRIPTOR_WIDTH}|json=0",
            capture.repositories,
            capture.folders.len(),
            leaves.len()
        ),
        format!(
            "SOURCE|sha256={source_sha256}|source_capture_sha256={}|public_set_sha256={}|sidecar_verified=1|public_metadata_only=1|raw_paths=0|raw_bodies=0|git_tree_commitments=1|tree_sha1_recoverable=0|path_dictionary_resistance_claim=0|json=0",
            hex(&capture.source_capture_sha256),
            hex(&capture.public_set_sha256)
        ),
        format!(
            "CENTER|nullspace=0|center_members={CENTER_MEMBERS}|traversal={CENTER_TRAVERSAL}|sha_equals_hash=0|brown_center=RGB.8B5A2B|close_to=1|json=0"
        ),
        "STAGE|i=0|name=FOLDER_HBP_TO_EXACT_INTEGER_3D|integer_only=1|float=0|json=0"
            .to_owned(),
        "STAGE|i=1|name=THREE_INDEPENDENT_CALMING_OIL_FAMILIES|families=3|identity_exchange=0|json=0"
            .to_owned(),
        "STAGE|i=2|name=SIGNED_STATIC_PROJECTION_AND_DESCRIPTOR_SEAL|formats=HBP,HBI,SVG,GGUF|json=0"
            .to_owned(),
        "BOUNDARY|paths_published=0|direct_path_hashes=0|raw_tree_sha1_published=0|git_tree_commitments=1|path_dictionary_resistance_claim=0|media_bodies_read=0|media_bytes_embedded=0|repository_bodies_read=0|repository_bytes_embedded=0|private_repo_rows=0|private_repo_names=0|credentials=0|network=0|execution=0|physical_energy=0|authority=0|system_affirmed=0|json=0"
            .to_owned(),
    ];
    for family in Family::ALL {
        rows.push(format!(
            "FAMILY|i={}|name={}|independent_identity=1|calming_oil_label=1|physical_energy=0|authority=0|json=0",
            family.index(),
            family.name()
        ));
    }
    let mut object_material = Vec::new();
    for leaf in leaves {
        let row = leaf_row(leaf);
        object_material.extend_from_slice(
            &u64::try_from(row.len())
                .map_err(|_| error("FOLDER_OUTPUT_ROW_LENGTH"))?
                .to_be_bytes(),
        );
        object_material.extend_from_slice(row.as_bytes());
        rows.push(row);
    }
    let object_hash = hex(&sha256(&object_material));
    rows.push(format!(
        "HASH|role=SPHERICAL_FOLDER_OIL_OBJECT_COMMITMENT|algorithm=SHA256|value={object_hash}|distinct_from_hbp_byte_sha=1|json=0"
    ));
    rows.push(format!(
        "SUMMARY|repositories={}|folders={}|families={FAMILY_COUNT}|leaves={}|path_bytes_embedded=0|media_bytes_embedded=0|repository_bytes_embedded=0|credentials=0|network=0|execution=0|physical_energy=0|authority=0|json=0",
        capture.repositories,
        capture.folders.len(),
        leaves.len()
    ));
    let body = joined_rows(&rows);
    rows.push(format!(
        "FOLDEROILFTR|body_sha256={}|rows={}|json=0",
        hex(&sha256(&body)),
        rows.len() + 1
    ));
    let output = joined_rows(&rows);
    if hex(&sha256(&output)) == object_hash {
        return Err(error("FOLDER_HASH_EQUALS_SHA"));
    }
    Ok((output, object_hash))
}

fn screen_coordinate(value: i64) -> Result<i64> {
    let coordinate = checked_add_i64(VIEW_CENTER, value)?;
    if !(0..=2_000).contains(&coordinate) {
        return Err(error("FOLDER_SVG_RANGE"));
    }
    Ok(coordinate)
}

fn validate_static_svg(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes).map_err(|_| error("FOLDER_SVG_UTF8"))?;
    if !text.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg ")
        || !text.ends_with("</svg>\n")
    {
        return Err(error("FOLDER_SVG_SHAPE"));
    }
    let lower = text.to_ascii_lowercase();
    for forbidden in [
        "<script",
        "<image",
        "<foreignobject",
        "<iframe",
        "<object",
        "<embed",
        "<use",
        " href=",
        "xlink:",
        "url(",
        "javascript:",
        " onload=",
        " onclick=",
    ] {
        if lower.contains(forbidden) {
            return Err(error("FOLDER_SVG_ACTIVE_CONTENT"));
        }
    }
    Ok(())
}

fn build_svg(capture: &FolderCapture, leaves: &[Leaf], object_hash: &str) -> Result<Vec<u8>> {
    let mut output = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"2000\" height=\"2000\" viewBox=\"0 0 2000 2000\" role=\"img\" aria-labelledby=\"title description\" data-script=\"0\" data-network=\"0\" data-execution=\"0\">\n<title id=\"title\">Public folder calming-OIL canopy</title>\n<desc id=\"description\">A static signed projection of three independently addressed Brown-family descriptor leaves per public Git folder commitment.</desc>\n<rect x=\"0\" y=\"0\" width=\"2000\" height=\"2000\" fill=\"#100E14\"/>\n",
    );
    output.push_str(&format!(
        "<metadata>schema={OUTPUT_SCHEMA};source_schema={INPUT_SCHEMA};repositories={};folders={};families={FAMILY_COUNT};leaves={};object_hash={object_hash};integer_only=1;float=0;paths=0;media_bytes=0;repo_bytes=0;credentials=0;network=0;execution=0;physical_energy=0;authority=0;SYSTEM_AFFIRMED=0;json=0</metadata>\n",
        capture.repositories,
        capture.folders.len(),
        leaves.len()
    ));
    output.push_str("<g id=\"FOLDER_CALMING_OILS_3D_TO_2D\">\n");

    let mut centers = BTreeMap::<(&str, &str), [i64; 2]>::new();
    for folder in &capture.folders {
        let (projected_u, projected_v) =
            signed_projection(folder.position[0], folder.position[1], folder.position[2])?;
        centers.insert(
            (folder.repo_id.as_str(), folder.folder_id.as_str()),
            [
                screen_coordinate(projected_u)?,
                screen_coordinate(projected_v)?,
            ],
        );
    }
    for folder in capture.folders.iter().filter(|folder| folder.level > 0) {
        let child = centers
            .get(&(folder.repo_id.as_str(), folder.folder_id.as_str()))
            .ok_or_else(|| error("FOLDER_SVG_CHILD"))?;
        let parent = centers
            .get(&(folder.repo_id.as_str(), folder.parent_folder_id.as_str()))
            .ok_or_else(|| error("FOLDER_SVG_PARENT"))?;
        output.push_str(&format!(
            "<path class=\"folder-hierarchy\" d=\"M {} {} L {} {}\" fill=\"none\" stroke=\"#5B4636\" stroke-width=\"1\" data-child=\"{}\" data-parent=\"{}\"/>\n",
            parent[0], parent[1], child[0], child[1], folder.folder_id, folder.parent_folder_id
        ));
    }

    for folder_leaves in leaves.chunks_exact(FAMILY_COUNT) {
        output.push_str(&format!(
            "<g id=\"folder-{}\" data-folder-i=\"{}\" data-repo-id=\"{}\" data-level=\"{}\">\n",
            &folder_leaves[0].folder_id[..16],
            folder_leaves[0].folder_index,
            folder_leaves[0].repo_id,
            folder_leaves[0].level
        ));
        for leaf in folder_leaves {
            let x = screen_coordinate(leaf.projected[0])?;
            let y = screen_coordinate(leaf.projected[1])?;
            output.push_str(&format!(
                "<path id=\"oil-{}\" class=\"folder-calming-oil\" d=\"M {x} {} L {} {} L {} {} Z\" fill=\"#{}\" stroke=\"#F4F1E8\" stroke-width=\"1\" data-family=\"{}\" data-folder-id=\"{}\" data-source-identity-sha256=\"{}\" data-view-x=\"{}\" data-view-y=\"{}\" data-view-z=\"{}\" data-authority=\"0\"/>\n",
                &leaf.leaf_id[..16],
                y - 7,
                x + 7,
                y + 7,
                x - 7,
                y + 7,
                &rgb_text(leaf.color)[4..],
                leaf.family.name(),
                leaf.folder_id,
                leaf.source_identity_sha256,
                leaf.view[0],
                leaf.view[1],
                leaf.view[2]
            ));
        }
        output.push_str("</g>\n");
    }
    output.push_str("</g>\n</svg>\n");
    let bytes = output.into_bytes();
    validate_static_svg(&bytes)?;
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
            .map_err(|_| error("FOLDER_GGUF_STRING_LENGTH"))?
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

fn descriptor_bytes(capture: &FolderCapture, leaves: &[Leaf]) -> Result<Vec<u8>> {
    let expected = capture
        .folders
        .len()
        .checked_mul(FAMILY_COUNT)
        .and_then(|value| value.checked_mul(DESCRIPTOR_WIDTH))
        .ok_or_else(|| error("FOLDER_GGUF_DESCRIPTOR_LENGTH"))?;
    let mut output = Vec::with_capacity(expected);
    for leaf in leaves {
        if leaf.order != leaf.folder_index * FAMILY_COUNT + leaf.family.index() {
            return Err(error("FOLDER_GGUF_ITERATION_ORDER"));
        }
        output.push(u8::try_from(leaf.family.index()).map_err(|_| error("FOLDER_GGUF_FAMILY"))?);
        output.push(leaf.source_kind.index());
        output.extend_from_slice(&leaf.level.to_le_bytes());
        output.extend_from_slice(&leaf.color);
        output.push(0); // authority and active-effect sentinel
        output.extend_from_slice(
            &i32::try_from(leaf.projected[0])
                .map_err(|_| error("FOLDER_GGUF_COORDINATE"))?
                .to_le_bytes(),
        );
        output.extend_from_slice(
            &i32::try_from(leaf.projected[1])
                .map_err(|_| error("FOLDER_GGUF_COORDINATE"))?
                .to_le_bytes(),
        );
        output.extend_from_slice(&leaf.direct_blobs.to_le_bytes());
        output.extend_from_slice(&leaf.direct_trees.to_le_bytes());
        output.extend_from_slice(&leaf.direct_commits.to_le_bytes());
        output.extend_from_slice(&leaf.direct_symlinks.to_le_bytes());
        output.extend_from_slice(&leaf.tree_commitment_sha256[..8]);
        output.extend_from_slice(&leaf.object_sha256[..8]);
        output.extend_from_slice(&parse_hex32(&leaf.leaf_id)?[..8]);
        output.extend_from_slice(
            &u32::try_from(leaf.folder_index)
                .map_err(|_| error("FOLDER_GGUF_FOLDER_INDEX"))?
                .to_le_bytes(),
        );
        output.extend_from_slice(&leaf.sibling_ordinal.to_le_bytes());
    }
    if output.len() != expected {
        return Err(error("FOLDER_GGUF_DESCRIPTOR_LENGTH"));
    }
    Ok(output)
}

fn gguf_metadata(
    capture: &FolderCapture,
    descriptor_sha256: &str,
) -> Result<Vec<(String, GgufValue)>> {
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
                u32::try_from(GGUF_ALIGNMENT).map_err(|_| error("FOLDER_GGUF_ALIGNMENT"))?,
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
            GgufValue::Text(hex(&sha256(&capture.source_bytes))),
        ),
        (
            "asolaria.source.capture_sha256".to_owned(),
            GgufValue::Text(hex(&capture.source_capture_sha256)),
        ),
        (
            "asolaria.source.public_set_sha256".to_owned(),
            GgufValue::Text(hex(&capture.public_set_sha256)),
        ),
        (
            "asolaria.repositories".to_owned(),
            GgufValue::U64(
                u64::try_from(capture.repositories)
                    .map_err(|_| error("FOLDER_REPOSITORY_COUNT"))?,
            ),
        ),
        (
            "asolaria.folders".to_owned(),
            GgufValue::U64(
                u64::try_from(capture.folders.len()).map_err(|_| error("FOLDER_COUNT"))?,
            ),
        ),
        (
            "asolaria.families".to_owned(),
            GgufValue::U32(
                u32::try_from(FAMILY_COUNT).map_err(|_| error("FOLDER_GGUF_FAMILY"))?,
            ),
        ),
        (
            "asolaria.descriptor.width".to_owned(),
            GgufValue::U32(
                u32::try_from(DESCRIPTOR_WIDTH)
                    .map_err(|_| error("FOLDER_GGUF_DESCRIPTOR_LENGTH"))?,
            ),
        ),
        (
            "asolaria.tensor.dimensions".to_owned(),
            GgufValue::Text(format!(
                "[feature={DESCRIPTOR_WIDTH},family={FAMILY_COUNT},folder={}]",
                capture.folders.len()
            )),
        ),
        (
            "asolaria.descriptor.iteration_order".to_owned(),
            GgufValue::Text("folder,family,feature".to_owned()),
        ),
        (
            "asolaria.descriptor.encoding".to_owned(),
            GgufValue::Text("RAW_OCTETS_IN_GGML_I8".to_owned()),
        ),
        (
            "asolaria.descriptor.features".to_owned(),
            GgufValue::Text("0:family_u8,1:source_kind_u8,2:level_u16le,4:rgb_u8x3,7:active_zero,8:projected_u_i32le,12:projected_v_i32le,16:direct_blobs_u32le,20:direct_trees_u32le,24:direct_commits_u32le,28:direct_symlinks_u32le,32:tree_commitment_prefix8,40:object_prefix8,48:leaf_prefix8,56:folder_index_u32le,60:sibling_ordinal_u32le".to_owned()),
        ),
        (
            "asolaria.descriptor.sha256".to_owned(),
            GgufValue::Text(descriptor_sha256.to_owned()),
        ),
        (
            "asolaria.families.names".to_owned(),
            GgufValue::Text("BROWN,ANTI_BROWN,ANTI_ANTI_BROWN".to_owned()),
        ),
        (
            "asolaria.git_tree_commitments".to_owned(),
            GgufValue::U32(1),
        ),
        (
            "asolaria.path_dictionary_resistance_claim".to_owned(),
            GgufValue::U32(0),
        ),
        ("asolaria.path.bytes_embedded".to_owned(), GgufValue::U64(0)),
        (
            "asolaria.media.bytes_embedded".to_owned(),
            GgufValue::U64(0),
        ),
        (
            "asolaria.repository.bytes_embedded".to_owned(),
            GgufValue::U64(0),
        ),
        ("asolaria.credentials".to_owned(), GgufValue::U32(0)),
        ("asolaria.network".to_owned(), GgufValue::U32(0)),
        ("asolaria.execution".to_owned(), GgufValue::U32(0)),
        ("asolaria.physical_energy".to_owned(), GgufValue::U32(0)),
        ("asolaria.authority".to_owned(), GgufValue::U32(0)),
        (
            "asolaria.function_call_authority".to_owned(),
            GgufValue::U32(0),
        ),
        ("asolaria.system_affirmed".to_owned(), GgufValue::U32(0)),
    ])
}

fn align_up(value: usize, alignment: usize) -> Result<usize> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(error("FOLDER_GGUF_ALIGNMENT"));
    }
    value
        .checked_add(alignment - 1)
        .map(|sum| sum / alignment * alignment)
        .ok_or_else(|| error("FOLDER_GGUF_SIZE"))
}

fn build_gguf(capture: &FolderCapture, leaves: &[Leaf]) -> Result<(Vec<u8>, Vec<u8>)> {
    let descriptor = descriptor_bytes(capture, leaves)?;
    let metadata = gguf_metadata(capture, &hex(&sha256(&descriptor)))?;
    let mut metadata_bytes = Vec::new();
    for (key, value) in &metadata {
        metadata_bytes.extend_from_slice(&match value {
            GgufValue::U32(value) => metadata_u32(key, *value)?,
            GgufValue::U64(value) => metadata_u64(key, *value)?,
            GgufValue::Text(value) => metadata_text(key, value)?,
        });
    }
    let mut tensor_info = gguf_string("folder_calming_oil")?;
    tensor_info.extend_from_slice(&3_u32.to_le_bytes());
    for dimension in [
        u64::try_from(DESCRIPTOR_WIDTH).map_err(|_| error("FOLDER_GGUF_DESCRIPTOR_LENGTH"))?,
        u64::try_from(FAMILY_COUNT).map_err(|_| error("FOLDER_GGUF_FAMILY"))?,
        u64::try_from(capture.folders.len()).map_err(|_| error("FOLDER_COUNT"))?,
    ] {
        tensor_info.extend_from_slice(&dimension.to_le_bytes());
    }
    tensor_info.extend_from_slice(&GGML_TYPE_I8.to_le_bytes());
    tensor_info.extend_from_slice(&0_u64.to_le_bytes());

    let mut output = Vec::new();
    output.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
    output.extend_from_slice(&GGUF_VERSION.to_le_bytes());
    output.extend_from_slice(&1_u64.to_le_bytes());
    output.extend_from_slice(
        &u64::try_from(metadata.len())
            .map_err(|_| error("FOLDER_GGUF_METADATA_COUNT"))?
            .to_le_bytes(),
    );
    output.extend_from_slice(&metadata_bytes);
    output.extend_from_slice(&tensor_info);
    let data_start = align_up(output.len(), GGUF_ALIGNMENT)?;
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
            .ok_or_else(|| error("FOLDER_GGUF_BOUNDS"))?;
        if end > self.bytes.len() {
            return Err(error("FOLDER_GGUF_BOUNDS"));
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
            usize::try_from(self.u64()?).map_err(|_| error("FOLDER_GGUF_STRING_LENGTH"))?;
        String::from_utf8(self.take(length)?.to_vec()).map_err(|_| error("FOLDER_GGUF_UTF8"))
    }
}

fn verify_gguf(bytes: &[u8], capture: &FolderCapture, descriptor: &[u8]) -> Result<()> {
    let mut reader = GgufReader { bytes, position: 0 };
    if reader.u32()? != GGUF_MAGIC || reader.u32()? != GGUF_VERSION || reader.u64()? != 1 {
        return Err(error("FOLDER_GGUF_HEADER"));
    }
    let metadata_count =
        usize::try_from(reader.u64()?).map_err(|_| error("FOLDER_GGUF_METADATA_COUNT"))?;
    let expected_metadata = gguf_metadata(capture, &hex(&sha256(descriptor)))?;
    if metadata_count != expected_metadata.len() {
        return Err(error("FOLDER_GGUF_METADATA_COUNT"));
    }
    let mut metadata = BTreeMap::new();
    for _ in 0..metadata_count {
        let key = reader.string()?;
        let value_type = reader.u32()?;
        let value = match value_type {
            GGUF_TYPE_UINT32 => GgufValue::U32(reader.u32()?),
            GGUF_TYPE_UINT64 => GgufValue::U64(reader.u64()?),
            GGUF_TYPE_STRING => GgufValue::Text(reader.string()?),
            _ => return Err(error("FOLDER_GGUF_METADATA_TYPE")),
        };
        if metadata.insert(key, value).is_some() {
            return Err(error("FOLDER_GGUF_METADATA_DUPLICATE"));
        }
    }
    let expected_map: BTreeMap<String, GgufValue> = expected_metadata.into_iter().collect();
    if metadata != expected_map {
        return Err(error("FOLDER_GGUF_METADATA_VALUE"));
    }
    for key in [
        "asolaria.path.bytes_embedded",
        "asolaria.media.bytes_embedded",
        "asolaria.repository.bytes_embedded",
    ] {
        if metadata.get(key) != Some(&GgufValue::U64(0)) {
            return Err(error("FOLDER_GGUF_BOUNDARY"));
        }
    }
    for key in [
        "asolaria.path_dictionary_resistance_claim",
        "asolaria.credentials",
        "asolaria.network",
        "asolaria.execution",
        "asolaria.physical_energy",
        "asolaria.authority",
        "asolaria.function_call_authority",
        "asolaria.system_affirmed",
    ] {
        if metadata.get(key) != Some(&GgufValue::U32(0)) {
            return Err(error("FOLDER_GGUF_BOUNDARY"));
        }
    }
    if reader.string()? != "folder_calming_oil" || reader.u32()? != 3 {
        return Err(error("FOLDER_GGUF_TENSOR"));
    }
    let dimensions = [reader.u64()?, reader.u64()?, reader.u64()?];
    let expected_dimensions = [
        u64::try_from(DESCRIPTOR_WIDTH).map_err(|_| error("FOLDER_GGUF_DESCRIPTOR_LENGTH"))?,
        u64::try_from(FAMILY_COUNT).map_err(|_| error("FOLDER_GGUF_FAMILY"))?,
        u64::try_from(capture.folders.len()).map_err(|_| error("FOLDER_COUNT"))?,
    ];
    if dimensions != expected_dimensions || reader.u32()? != GGML_TYPE_I8 || reader.u64()? != 0 {
        return Err(error("FOLDER_GGUF_TENSOR"));
    }
    let data_start = align_up(reader.position, GGUF_ALIGNMENT)?;
    if data_start > bytes.len()
        || bytes[reader.position..data_start]
            .iter()
            .any(|byte| *byte != 0)
        || bytes.len() != data_start + descriptor.len()
        || &bytes[data_start..] != descriptor
    {
        return Err(error("FOLDER_GGUF_DATA"));
    }

    let expected_descriptor_length = capture
        .folders
        .len()
        .checked_mul(FAMILY_COUNT)
        .and_then(|value| value.checked_mul(DESCRIPTOR_WIDTH))
        .ok_or_else(|| error("FOLDER_GGUF_DESCRIPTOR_LENGTH"))?;
    if descriptor.len() != expected_descriptor_length || descriptor.is_empty() {
        return Err(error("FOLDER_GGUF_DESCRIPTOR_LENGTH"));
    }
    let final_offset = descriptor
        .len()
        .checked_sub(DESCRIPTOR_WIDTH)
        .ok_or_else(|| error("FOLDER_GGUF_DESCRIPTOR_LENGTH"))?;
    if descriptor[0] != 0
        || descriptor[1] != capture.folders[0].source_kind.index()
        || descriptor[final_offset] != 2
        || descriptor[final_offset + 1]
            != capture
                .folders
                .last()
                .ok_or_else(|| error("FOLDER_COUNT"))?
                .source_kind
                .index()
    {
        return Err(error("FOLDER_GGUF_SENTINEL"));
    }
    let first_folder = u32::from_le_bytes(
        descriptor[56..60]
            .try_into()
            .expect("first folder-index descriptor window"),
    );
    let last_folder = u32::from_le_bytes(
        descriptor[final_offset + 56..final_offset + 60]
            .try_into()
            .expect("last folder-index descriptor window"),
    );
    if first_folder != 0
        || last_folder
            != u32::try_from(capture.folders.len() - 1)
                .map_err(|_| error("FOLDER_GGUF_FOLDER_INDEX"))?
    {
        return Err(error("FOLDER_GGUF_SENTINEL"));
    }
    Ok(())
}

fn build_hbi(
    capture: &FolderCapture,
    leaves: &[Leaf],
    object_hash: &str,
    hbp_sha256: &str,
    svg_sha256: &str,
    gguf_sha256: &str,
    descriptor_sha256: &str,
) -> Vec<u8> {
    let mut rows = vec![
        format!(
            "FOLDEROILIDX|schema={OUTPUT_SCHEMA}|repositories={}|folders={}|families={FAMILY_COUNT}|leaves={}|json=0",
            capture.repositories,
            capture.folders.len(),
            leaves.len()
        ),
        format!(
            "SOURCE|schema={INPUT_SCHEMA}|sha256={}|source_capture_sha256={}|public_set_sha256={}|sidecar_verified=1|git_tree_commitments=1|tree_sha1_recoverable=0|path_dictionary_resistance_claim=0|json=0",
            hex(&sha256(&capture.source_bytes)),
            hex(&capture.source_capture_sha256),
            hex(&capture.public_set_sha256)
        ),
        format!("ARTIFACT|kind=HBP|file={HBP_NAME}|sha256={hbp_sha256}|json=0"),
        format!(
            "ARTIFACT|kind=SVG|file={SVG_NAME}|sha256={svg_sha256}|static=1|script=0|network=0|execution=0|json=0"
        ),
        format!(
            "ARTIFACT|kind=GGUF|file={GGUF_NAME}|sha256={gguf_sha256}|tensor=folder_calming_oil|dimensions=feature:{DESCRIPTOR_WIDTH},family:{FAMILY_COUNT},folder:{}|iteration_order=folder,family,feature|encoding=RAW_OCTETS_IN_GGML_I8|descriptor_sha256={descriptor_sha256}|json=0",
            capture.folders.len()
        ),
        format!(
            "CENTER|nullspace=0|center_members={CENTER_MEMBERS}|traversal={CENTER_TRAVERSAL}|sha_equals_hash=0|object_hash={object_hash}|json=0"
        ),
        "BOUNDARY|raw_paths=0|direct_path_hashes=0|raw_tree_sha1=0|git_tree_commitments=1|path_dictionary_resistance_claim=0|media_bytes_embedded=0|repository_bytes_embedded=0|credentials=0|network=0|execution=0|physical_energy=0|authority=0|system_affirmed=0|json=0".to_owned(),
        format!(
            "RECIPE|sh={RECIPE}|rust=1.81.0|integer_only=1|float=0|unsafe=0|dependencies=0|final_commit_marker=HBI_WITH_SIDECAR|json=0"
        ),
    ];
    let body = joined_rows(&rows);
    rows.push(format!(
        "FOLDEROILIDXFTR|body_sha256={}|rows={}|json=0",
        hex(&sha256(&body)),
        rows.len() + 1
    ));
    joined_rows(&rows)
}

fn sidecar_bytes(path: &Path, bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(format!("{}  {}\n", hex(&sha256(bytes)), file_name(path)?).into_bytes())
}

#[cfg(unix)]
fn ensure_single_hardlink(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if path.exists()
        && fs::metadata(path)
            .map_err(|_| error("FOLDER_LINK_METADATA"))?
            .nlink()
            != 1
    {
        return Err(error("FOLDER_HARDLINK"));
    }
    Ok(())
}

#[cfg(windows)]
fn ensure_single_hardlink(path: &Path) -> Result<()> {
    // This pinned Rust toolchain does not expose Windows link counts through a stable API. The
    // shared path gate still rejects reparse points and canonical path aliases;
    // the Unix lane additionally enforces nlink=1.
    if path.exists() {
        fs::metadata(path).map_err(|_| error("FOLDER_LINK_METADATA"))?;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_single_hardlink(path: &Path) -> Result<()> {
    if path.exists() {
        fs::metadata(path).map_err(|_| error("FOLDER_LINK_METADATA"))?;
    }
    Ok(())
}

pub fn run_folders(input: &Path, output_dir: &Path, replace: bool) -> Result<FolderResult> {
    if !fs::metadata(output_dir)
        .map_err(|_| error("FOLDER_OUTPUT_DIRECTORY"))?
        .is_dir()
    {
        return Err(error("FOLDER_OUTPUT_DIRECTORY"));
    }
    let input_sidecar = sidecar_path(input)?;
    ensure_single_hardlink(input)?;
    ensure_single_hardlink(&input_sidecar)?;
    let source_bytes = read_verified_input(input)?;
    let capture = parse_capture(&source_bytes)?;
    let leaves = derive_leaves(&capture)?;
    let (hbp, object_hash) = build_hbp(&capture, &leaves)?;
    let svg = build_svg(&capture, &leaves, &object_hash)?;
    let (gguf, descriptor) = build_gguf(&capture, &leaves)?;
    let hbp_sha256 = hex(&sha256(&hbp));
    let svg_sha256 = hex(&sha256(&svg));
    let gguf_sha256 = hex(&sha256(&gguf));
    let descriptor_sha256 = hex(&sha256(&descriptor));
    let hbi = build_hbi(
        &capture,
        &leaves,
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
    let hbp_sidecar = sidecar_path(&hbp_path)?;
    let hbi_sidecar = sidecar_path(&hbi_path)?;
    let svg_sidecar = sidecar_path(&svg_path)?;
    let gguf_sidecar = sidecar_path(&gguf_path)?;
    let paths = [
        input,
        input_sidecar.as_path(),
        hbp_path.as_path(),
        hbp_sidecar.as_path(),
        hbi_path.as_path(),
        hbi_sidecar.as_path(),
        svg_path.as_path(),
        svg_sidecar.as_path(),
        gguf_path.as_path(),
        gguf_sidecar.as_path(),
    ];
    ensure_distinct_paths(&paths)?;
    for path in paths {
        ensure_single_hardlink(path)?;
    }

    let hbp_sidecar_bytes = sidecar_bytes(&hbp_path, &hbp)?;
    let svg_sidecar_bytes = sidecar_bytes(&svg_path, &svg)?;
    let gguf_sidecar_bytes = sidecar_bytes(&gguf_path, &gguf)?;
    let hbi_sidecar_bytes = sidecar_bytes(&hbi_path, &hbi)?;
    // Primaries and their proofs publish first. The HBI proof is written before
    // the HBI itself, making the HBI bytes the final commit marker.
    atomic_write_set(
        &[
            (&hbp_path, hbp.as_slice()),
            (&hbp_sidecar, hbp_sidecar_bytes.as_slice()),
            (&svg_path, svg.as_slice()),
            (&svg_sidecar, svg_sidecar_bytes.as_slice()),
            (&gguf_path, gguf.as_slice()),
            (&gguf_sidecar, gguf_sidecar_bytes.as_slice()),
        ],
        replace,
    )?;
    atomic_write_set(
        &[
            (&hbi_sidecar, hbi_sidecar_bytes.as_slice()),
            (&hbi_path, hbi.as_slice()),
        ],
        replace,
    )?;
    Ok(FolderResult {
        repositories: capture.repositories,
        folders: capture.folders.len(),
        leaves: leaves.len(),
        hbp_sha256,
        hbi_sha256,
        svg_sha256,
        gguf_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn fixture_folder(
        index: usize,
        source_capture: &[u8; 32],
        repo_id: [u8; 32],
        parent_id: [u8; 32],
        sibling: u32,
        level: u16,
        tree: [u8; 32],
        kind: SourceKind,
        direct: [u32; 4],
    ) -> String {
        let folder_id = derive_folder_id(source_capture, &repo_id, &parent_id, sibling, &tree);
        let fields = ObjectFields {
            index,
            repo_id: &repo_id,
            folder_id: &folder_id,
            parent_folder_id: &parent_id,
            sibling_ordinal: sibling,
            level,
            tree_commitment_sha256: &tree,
            source_kind: kind,
            direct_blobs: direct[0],
            direct_trees: direct[1],
            direct_commits: direct[2],
            direct_symlinks: direct[3],
        };
        let object = derive_object(&fields).expect("fixture object derives");
        let position = [
            coordinate_from_object(&object, 0),
            coordinate_from_object(&object, 4),
            coordinate_from_object(&object, 8),
        ];
        format!(
            "FOLDER|i={index}|repo_id={}|folder_id={}|parent_folder_id={}|sibling_ordinal={sibling}|level={level}|tree_commitment_sha256={}|source_kind={}|direct_blobs={}|direct_trees={}|direct_commits={}|direct_symlinks={}|object_sha256={}|x={}|y={}|z={}|color={}|json=0",
            hex(&repo_id),
            hex(&folder_id),
            hex(&parent_id),
            hex(&tree),
            kind.name(),
            direct[0],
            direct[1],
            direct[2],
            direct[3],
            hex(&object),
            position[0],
            position[1],
            position[2],
            rgb_text(color_from_object(&object)),
        )
    }

    fn object_root(rows: &[String]) -> String {
        let mut material = Vec::new();
        for row in rows {
            material.extend_from_slice(
                &u64::try_from(row.len())
                    .expect("fixture row length fits u64")
                    .to_be_bytes(),
            );
            material.extend_from_slice(row.as_bytes());
        }
        hex(&sha256(&material))
    }

    fn source_rows(child_level: u16) -> Vec<String> {
        let source_capture = [0x11; 32];
        let public_set = [0x77; 32];
        let repo_alpha = [0x22; 32];
        let repo_beta = [0x44; 32];
        let zero = [0; 32];
        let root_alpha = fixture_folder(
            0,
            &source_capture,
            repo_alpha,
            zero,
            0,
            0,
            [0x33; 32],
            SourceKind::RepositoryRoot,
            [2, 1, 0, 1],
        );
        let root_alpha_id = parse_hex32(
            fields(&root_alpha, "FOLDER")
                .expect("fixture root fields")
                .get("folder_id")
                .expect("fixture root ID"),
        )
        .expect("fixture root ID parses");
        let child = fixture_folder(
            1,
            &source_capture,
            repo_alpha,
            root_alpha_id,
            0,
            child_level,
            [0x55; 32],
            SourceKind::GitTree,
            [1, 0, 1, 0],
        );
        let root_beta = fixture_folder(
            2,
            &source_capture,
            repo_beta,
            zero,
            0,
            0,
            [0x66; 32],
            SourceKind::RepositoryRoot,
            [0, 0, 0, 0],
        );
        let folder_rows = vec![root_alpha, child, root_beta];
        vec![
            format!(
                "FOLDER3DRUN|schema={INPUT_SCHEMA}|owner=JesseBrown1980|captured_at=2026-07-30T12:34:56.789Z|source_capture_sha256={}|public_set_sha256={}|surface=MEASURED_GITHUB_PUBLIC|repositories=3|branched=2|unborn=1|root_nodes=2|tree_nodes=1|folders=3|public_metadata_only=1|json=0",
                hex(&source_capture),
                hex(&public_set)
            ),
            format!(
                "CENTER|nullspace=0|center_members={CENTER_MEMBERS}|traversal=HBI,HBP,SH,HASH,SHA|sha_equals_hash=0|brown_center=RGB.8B5A2B|close_to=1|json=0"
            ),
            "RECIPE|transport=GH_CLI_AUTHENTICATED_PUBLIC|recursive_git_tree=1|complete_tree_required=1|paths_published=0|path_hashes_published=0|tree_sha1_published=0|git_tree_commitments=1|path_dictionary_resistance_claim=0|blob_bodies_read=0|private_repo_endpoint_calls=0|json=0".to_owned(),
            "BOUNDARY|private_repo_rows=0|private_repo_names=0|credentials=0|raw_paths=0|raw_bodies=0|network_in_renderer=0|execution=0|system_affirmed=0|json=0".to_owned(),
            folder_rows[0].clone(),
            folder_rows[1].clone(),
            folder_rows[2].clone(),
            format!(
                "HASH|role=SPHERICAL_OBJECT_COMMITMENT|algorithm=SHA256|value={}|distinct_from_hbp_byte_sha=1|json=0",
                object_root(&folder_rows)
            ),
            format!(
                "SUMMARY|repositories=3|branched=2|unborn=1|repository_roots=2|git_tree_folder_occurrences=1|folders=3|max_level={child_level}|direct_blobs=3|direct_trees=1|direct_commits=1|gitlinks=1|symlinks=1|unique_tree_objects=3|json=0"
            ),
        ]
    }

    fn seal(mut rows: Vec<String>) -> Vec<u8> {
        let body = joined_rows(&rows);
        rows.push(format!(
            "FOLDER3DFTR|body_sha256={}|rows={}|repositories=3|folders=3|json=0",
            hex(&sha256(&body)),
            rows.len() + 1
        ));
        joined_rows(&rows)
    }

    fn reseal_object_and_footer(mut rows: Vec<String>) -> Vec<u8> {
        let folder_rows = rows[4..7].to_vec();
        rows[7] = format!(
            "HASH|role=SPHERICAL_OBJECT_COMMITMENT|algorithm=SHA256|value={}|distinct_from_hbp_byte_sha=1|json=0",
            object_root(&folder_rows)
        );
        seal(rows)
    }

    fn replace_field(row: &str, key: &str, value: &str) -> String {
        row.split('|')
            .map(|piece| {
                if piece.starts_with(&format!("{key}=")) {
                    format!("{key}={value}")
                } else {
                    piece.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("|")
    }

    fn synthetic_capture() -> (FolderCapture, Vec<Leaf>) {
        let bytes = seal(source_rows(1));
        let capture = parse_capture(&bytes).expect("synthetic folder capture parses");
        let leaves = derive_leaves(&capture).expect("synthetic leaves derive");
        (capture, leaves)
    }

    #[test]
    fn cross_language_binary_fixture_is_exact() {
        let source = [0x11; 32];
        let repo = [0x22; 32];
        let parent = [0; 32];
        let tree = [0x33; 32];
        let folder = derive_folder_id(&source, &repo, &parent, 0, &tree);
        assert_eq!(
            hex(&folder),
            "da6ee33ff57efe847fb4dcae54b05501006665c88039f7667205fedf472dc716"
        );
        let object = derive_object(&ObjectFields {
            index: 0,
            repo_id: &repo,
            folder_id: &folder,
            parent_folder_id: &parent,
            sibling_ordinal: 0,
            level: 0,
            tree_commitment_sha256: &tree,
            source_kind: SourceKind::RepositoryRoot,
            direct_blobs: 2,
            direct_trees: 1,
            direct_commits: 0,
            direct_symlinks: 1,
        })
        .expect("known object derives");
        assert_eq!(
            hex(&object),
            "99127683f7fb3c0f9be8a1b8fe6e99d3a74735c0d176434b6217b033d0f5ad57"
        );
        assert_eq!(
            [
                coordinate_from_object(&object, 0),
                coordinate_from_object(&object, 4),
                coordinate_from_object(&object, 8)
            ],
            [-877_249, -564_817, 712_925]
        );
        assert_eq!(rgb_text(color_from_object(&object)), "RGB.8E9EC9");
    }

    #[test]
    fn population_and_family_identity_are_exact() {
        let (capture, leaves) = synthetic_capture();
        assert_eq!(capture.repositories, 3);
        assert_eq!(capture.folders.len(), 3);
        assert_eq!(leaves.len(), 9);
        assert_eq!(
            leaves
                .iter()
                .map(|leaf| leaf.leaf_id.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            9
        );
        for chunk in leaves.chunks_exact(FAMILY_COUNT) {
            assert_eq!(
                chunk
                    .iter()
                    .map(|leaf| leaf.family)
                    .collect::<BTreeSet<_>>(),
                Family::ALL.into_iter().collect()
            );
            assert!(chunk
                .iter()
                .all(|leaf| leaf.folder_id == chunk[0].folder_id));
        }
    }

    #[test]
    fn hierarchy_semantics_bounds_and_footer_are_fail_closed() {
        assert_eq!(
            parse_capture(&seal(source_rows(2)))
                .expect_err("level jump fails")
                .code(),
            "FOLDER_PARENT_LEVEL"
        );
        let mut coordinate_rows = source_rows(1);
        coordinate_rows[5] = replace_field(&coordinate_rows[5], "x", "1000001");
        assert_eq!(
            parse_capture(&reseal_object_and_footer(coordinate_rows))
                .expect_err("coordinate bound fails")
                .code(),
            "FOLDER_COORDINATE_RANGE"
        );
        let mut identity_rows = source_rows(1);
        identity_rows[5] = replace_field(&identity_rows[5], "folder_id", &"f".repeat(64));
        assert_eq!(
            parse_capture(&reseal_object_and_footer(identity_rows))
                .expect_err("resealed folder identity tamper fails")
                .code(),
            "FOLDER_ID_DERIVATION"
        );
        let mut bad_footer = seal(source_rows(1));
        let final_index = bad_footer.len() - 2;
        bad_footer[final_index] ^= 1;
        assert!(parse_capture(&bad_footer).is_err());
        assert!(validate_timestamp("2026-02-30T12:34:56.789Z").is_err());
    }

    #[test]
    fn gguf_dimensions_iteration_and_sentinels_verify() {
        let (capture, leaves) = synthetic_capture();
        let (gguf, descriptor) = build_gguf(&capture, &leaves).expect("GGUF builds");
        assert_eq!(descriptor.len(), 64 * 3 * 3);
        assert_eq!(descriptor[0], 0);
        assert_eq!(descriptor[64], 1);
        assert_eq!(descriptor[128], 2);
        assert_eq!(&descriptor[56..60], &0_u32.to_le_bytes());
        let final_offset = descriptor.len() - DESCRIPTOR_WIDTH;
        assert_eq!(descriptor[final_offset], 2);
        assert_eq!(
            &descriptor[final_offset + 56..final_offset + 60],
            &2_u32.to_le_bytes()
        );
        verify_gguf(&gguf, &capture, &descriptor).expect("GGUF self-verifies");
        let mut corrupted = gguf;
        let final_index = corrupted.len() - 1;
        corrupted[final_index] ^= 1;
        assert!(verify_gguf(&corrupted, &capture, &descriptor).is_err());
    }

    #[test]
    fn hbp_svg_boundaries_and_sidecars_are_exact() {
        let (capture, leaves) = synthetic_capture();
        let (hbp, object_hash) = build_hbp(&capture, &leaves).expect("HBP builds");
        let hbp_text = std::str::from_utf8(&hbp).expect("HBP UTF-8");
        assert_eq!(
            hbp_text
                .lines()
                .filter(|line| line.starts_with("OIL|"))
                .count(),
            9
        );
        assert!(hbp_text.contains("path_dictionary_resistance_claim=0"));
        assert!(hbp_text.contains("git_tree_commitments=1"));
        assert!(
            hbp_text.contains("credentials=0|network=0|execution=0|physical_energy=0|authority=0")
        );
        let svg = build_svg(&capture, &leaves, &object_hash).expect("SVG builds");
        let svg_text = std::str::from_utf8(&svg).expect("SVG UTF-8");
        assert_eq!(svg_text.matches("class=\"folder-calming-oil\"").count(), 9);
        assert_eq!(svg_text.matches("class=\"folder-hierarchy\"").count(), 1);
        let mut active = svg_text.trim_end_matches("</svg>\n").as_bytes().to_vec();
        active.extend_from_slice(b"<script>bad</script></svg>\n");
        assert_eq!(
            validate_static_svg(&active)
                .expect_err("active content fails")
                .code(),
            "FOLDER_SVG_ACTIVE_CONTENT"
        );
        let path = Path::new("PUBLIC-FOLDER-CALMING-OILS.hbp");
        assert_eq!(
            sidecar_bytes(path, &hbp).expect("sidecar builds"),
            format!("{}  {}\n", hex(&sha256(&hbp)), HBP_NAME).into_bytes()
        );
    }

    #[cfg(unix)]
    #[test]
    fn hardlinks_are_rejected_on_the_linux_lane() {
        let directory = std::env::temp_dir().join(format!(
            "folder-oil-hardlink-{}-{}",
            std::process::id(),
            hex(&sha256(b"folder-oil-hardlink-test"))[..12].to_owned()
        ));
        fs::create_dir(&directory).expect("temporary directory creates");
        let first = directory.join("first.hbp");
        let second = directory.join("second.hbp");
        fs::write(&first, b"fixture").expect("fixture writes");
        fs::hard_link(&first, &second).expect("hardlink creates");
        assert_eq!(
            ensure_single_hardlink(&first)
                .expect_err("hardlink fails closed")
                .code(),
            "FOLDER_HARDLINK"
        );
        fs::remove_file(second).expect("hardlink removes");
        fs::remove_file(first).expect("fixture removes");
        fs::remove_dir(directory).expect("temporary directory removes");
    }
}
