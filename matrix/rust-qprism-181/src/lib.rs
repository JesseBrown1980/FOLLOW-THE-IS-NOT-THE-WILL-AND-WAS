#![forbid(unsafe_code)]

pub mod folders;
pub mod outward;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const INPUT_SCHEMA: &str = "PUBLIC-REPO-TREE-WORD-2D-V1";
const OUTPUT_SCHEMA: &str = "PUBLIC-QPRISM-COLOR-LEAVES-RUST-181-V1";
const CENTER_MEMBERS: &str = "HBI,HBP,SHA,SH,HASH";
const TRAVERSAL: &str = "HBI->HBP->SH->HASH->SHA";
const MAX_RECORDS: usize = 512;
const MAX_LEVEL: u8 = 60;
const REFLECTION_WINDOW: usize = 60;
const MAX_INPUT_BYTES: usize = 8_000_000;
const MAX_LINE_BYTES: usize = 8_192;
const MAX_COORDINATE: i64 = 1_000_000;
const D: i128 = 65_537;
const SCALE: i128 = 1_000_000;
const ORB_DEPTH_SCALE: i128 = 1_000_000_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QprismError {
    code: &'static str,
}

impl QprismError {
    pub const fn new(code: &'static str) -> Self {
        Self { code }
    }
    pub const fn code(&self) -> &'static str {
        self.code
    }
}

impl std::fmt::Display for QprismError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code)
    }
}

impl std::error::Error for QprismError {}
type Result<T> = std::result::Result<T, QprismError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputRecord {
    pub repo_id: String,
    pub tree_id: String,
    pub word_id: String,
    pub parent_word_id: String,
    pub u: i64,
    pub v: i64,
    pub level: u8,
    pub blob_sha256: [u8; 32],
    pub input_rgb: [u8; 3],
    pub truth_tag: String,
    canonical_row: Vec<u8>,
}

impl InputRecord {
    fn identity(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.repo_id, self.tree_id, self.word_id, self.level, self.truth_tag
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactOrb {
    pub p: i128,
    pub q: i128,
    pub s: i128,
    pub common_den: i128,
    pub center_num: [i128; 3],
    pub tetra_step: i128,
    pub depth_scaled: i128,
    pub recovered_u: i64,
    pub recovered_v: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Family {
    Brown,
    AntiBrown,
    AntiAntiBrown,
}

impl Family {
    const ALL: [Self; 3] = [Self::Brown, Self::AntiBrown, Self::AntiAntiBrown];
    const fn name(self) -> &'static str {
        match self {
            Self::Brown => "BROWN",
            Self::AntiBrown => "ANTI_BROWN",
            Self::AntiAntiBrown => "ANTI_ANTI_BROWN",
        }
    }
    const fn horizontal_offset(self) -> i64 {
        match self {
            Self::Brown => -5,
            Self::AntiBrown => 0,
            Self::AntiAntiBrown => 5,
        }
    }
    const fn depth_offset(self) -> i64 {
        match self {
            Self::Brown => -15_000,
            Self::AntiBrown => 0,
            Self::AntiAntiBrown => 15_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Leaf {
    source_identity_sha256: String,
    leaf_id: String,
    family: Family,
    input_rgb: [u8; 3],
    shade: [u8; 3],
    level: u8,
    signed_u: i64,
    signed_v: i64,
    view_z: i64,
    projected_u: i64,
    projected_v: i64,
    orb: ExactOrb,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunResult {
    pub records: usize,
    pub leaves: usize,
    pub receipt_sha256: String,
    pub svg_sha256: String,
}

fn checked_add(left: i128, right: i128) -> Result<i128> {
    left.checked_add(right)
        .ok_or_else(|| QprismError::new("INTEGER_OVERFLOW"))
}
fn checked_sub(left: i128, right: i128) -> Result<i128> {
    left.checked_sub(right)
        .ok_or_else(|| QprismError::new("INTEGER_OVERFLOW"))
}
fn checked_mul(left: i128, right: i128) -> Result<i128> {
    left.checked_mul(right)
        .ok_or_else(|| QprismError::new("INTEGER_OVERFLOW"))
}

pub fn exact_orb(record: &InputRecord) -> Result<ExactOrb> {
    let seed = sha256(&record.canonical_row);
    let jitter_u = i128::from(u16::from_be_bytes([seed[0], seed[1]])) + 1;
    let jitter_v = i128::from(u16::from_be_bytes([seed[2], seed[3]])) + 1;
    let p = checked_add(checked_mul(i128::from(record.u), D)?, jitter_u)?;
    let q = checked_add(checked_mul(i128::from(record.v), D)?, jitter_v)?;
    let p_squared = checked_mul(p, p)?;
    let q_squared = checked_mul(q, q)?;
    let d_squared = checked_mul(D, D)?;
    let s = checked_add(checked_add(p_squared, q_squared)?, d_squared)?;
    let unit_x_num = checked_mul(checked_mul(2, p)?, D)?;
    let unit_y_num = checked_mul(checked_mul(2, q)?, D)?;
    let unit_z_num = checked_sub(checked_add(p_squared, q_squared)?, d_squared)?;
    let radius_den = i128::from(record.level) + 2;
    let tetra_step = checked_mul(radius_den, s)?;
    let common_den = checked_mul(SCALE, tetra_step)?;
    let center_num = [
        checked_add(
            checked_mul(999_999, tetra_step)?,
            checked_mul(SCALE, unit_x_num)?,
        )?,
        checked_mul(SCALE, unit_y_num)?,
        checked_mul(SCALE, unit_z_num)?,
    ];
    let one_minus_z_num = checked_sub(s, unit_z_num)?;
    if checked_mul(unit_x_num, D)? != checked_mul(p, one_minus_z_num)?
        || checked_mul(unit_y_num, D)? != checked_mul(q, one_minus_z_num)?
    {
        return Err(QprismError::new("INVERSE_CROSS_CHECK"));
    }
    let u_numerator = checked_sub(p, jitter_u)?;
    let v_numerator = checked_sub(q, jitter_v)?;
    if u_numerator % D != 0 || v_numerator % D != 0 {
        return Err(QprismError::new("INVERSE_DIVISIBILITY"));
    }
    let recovered_u =
        i64::try_from(u_numerator / D).map_err(|_| QprismError::new("RECOVERED_U_RANGE"))?;
    let recovered_v =
        i64::try_from(v_numerator / D).map_err(|_| QprismError::new("RECOVERED_V_RANGE"))?;
    if recovered_u != record.u || recovered_v != record.v || tetra_step <= 0 {
        return Err(QprismError::new("INVERSE_IDENTITY"));
    }
    let depth_scaled = checked_mul(unit_z_num, ORB_DEPTH_SCALE)? / s;
    Ok(ExactOrb {
        p,
        q,
        s,
        common_den,
        center_num,
        tetra_step,
        depth_scaled,
        recovered_u,
        recovered_v,
    })
}

fn shade(input: [u8; 3], family: Family) -> [u8; 3] {
    let base = [139_u16, 90_u16, 43_u16];
    let mut brown = [0_u8; 3];
    for index in 0..3 {
        let value = (2 * u16::from(input[index]) + base[index]) / 3;
        brown[index] = u8::try_from(value).expect("bounded RGB blend");
    }
    match family {
        Family::Brown => brown,
        Family::AntiBrown => brown.map(|value| 255 - value),
        Family::AntiAntiBrown => {
            let mut rebound = [0_u8; 3];
            for index in 0..3 {
                let value = (u16::from(brown[index]) + u16::from(input[index]) + 1) / 2;
                rebound[index] = u8::try_from(value).expect("bounded RGB rebound");
            }
            rebound
        }
    }
}

fn qprism_view_z(record: &InputRecord, family: Family) -> Result<i64> {
    let radial = record
        .u
        .abs()
        .checked_add(record.v.abs())
        .ok_or_else(|| QprismError::new("INTEGER_OVERFLOW"))?;
    MAX_COORDINATE
        .checked_sub(radial)
        .and_then(|value| value.checked_add(family.depth_offset()))
        .ok_or_else(|| QprismError::new("INTEGER_OVERFLOW"))
}

fn signed_projection(x: i64, y: i64, z: i64) -> Result<(i64, i64)> {
    let x = i128::from(x);
    let y = i128::from(y);
    let z = i128::from(z);
    let projected_u = checked_add(checked_sub(checked_mul(2, x)?, y)?, z)? / 10_000;
    let projected_v =
        checked_sub(checked_add(x, checked_mul(2, y)?)?, checked_mul(2, z)?)? / 12_000;
    Ok((
        i64::try_from(projected_u).map_err(|_| QprismError::new("PROJECTED_U_RANGE"))?,
        i64::try_from(projected_v).map_err(|_| QprismError::new("PROJECTED_V_RANGE"))?,
    ))
}

fn derive_leaves(records: &[InputRecord]) -> Result<Vec<Leaf>> {
    let mut leaves = Vec::with_capacity(records.len() * 3);
    let mut identifiers = BTreeSet::new();
    for record in records {
        let orb = exact_orb(record)?;
        let source_identity_sha256 = hex(&sha256(record.identity().as_bytes()));
        for family in Family::ALL {
            let mut material = b"QPRISM181-LEAF\0".to_vec();
            material.extend_from_slice(&record.canonical_row);
            material.extend_from_slice(family.name().as_bytes());
            let leaf_id = hex(&sha256(&material));
            if !identifiers.insert(leaf_id.clone()) {
                return Err(QprismError::new("LEAF_ID_COLLISION"));
            }
            let view_z = qprism_view_z(record, family)?;
            let (projected_u, projected_v) = signed_projection(record.u, record.v, view_z)?;
            leaves.push(Leaf {
                source_identity_sha256: source_identity_sha256.clone(),
                leaf_id,
                family,
                input_rgb: record.input_rgb,
                shade: shade(record.input_rgb, family),
                level: record.level,
                signed_u: record.u,
                signed_v: record.v,
                view_z,
                projected_u,
                projected_v,
                orb: orb.clone(),
            });
        }
    }
    leaves.sort_by(|left, right| {
        left.view_z
            .cmp(&right.view_z)
            .then(left.orb.depth_scaled.cmp(&right.orb.depth_scaled))
            .then(left.level.cmp(&right.level))
            .then(left.leaf_id.cmp(&right.leaf_id))
    });
    Ok(leaves)
}

fn rgb_text(rgb: [u8; 3]) -> String {
    format!("{:02X}{:02X}{:02X}", rgb[0], rgb[1], rgb[2])
}

fn render_receipt(records: &[InputRecord], leaves: &[Leaf], source_sha256: &str) -> Vec<u8> {
    let max_level = records.iter().map(|record| record.level).max().unwrap_or(0);
    let mut lines = vec![
        format!("QPRISMHDR|schema={OUTPUT_SCHEMA}|rust_version=1.81.0|source_sha256={source_sha256}|observed_records={}|leaf_count={}|families_per_record=3|n_level_open=1|reflection_window={REFLECTION_WINDOW}|max_observed_level={max_level}|system_affirmed=0|public_metadata_only=1|raw_contents=0|json=0", records.len(), leaves.len()),
        format!("CENTER|membership={CENTER_MEMBERS}|traversal={}|json=0", percent_encode(TRAVERSAL)),
        "STAGE|order=1|name=2D_INPUT|integer_only=1|json=0".to_owned(),
        "STAGE|order=2|name=3D_QPRISM|checked_i128=1|float_coordinates=0|json=0".to_owned(),
        "STAGE|order=3|name=SIGNED_2D_PROJECTION|depth_sorted=1|identity_exchange=0|json=0".to_owned(),
    ];
    for (order, leaf) in leaves.iter().enumerate() {
        lines.push(format!(
            "LEAF|order={order}|leaf_id={}|source_identity_sha256={}|family={}|level={}|input_u={}|input_v={}|view_x={}|view_y={}|view_z={}|projected_u={}|projected_v={}|recovered_u={}|recovered_v={}|p={}|q={}|d={D}|s={}|center_x_num={}|center_y_num={}|center_z_num={}|center_den={}|tetra_step={}|tetra_determinant=-16|orb_depth_scale={ORB_DEPTH_SCALE}|orb_depth_scaled={}|input_rgb={}|shade_rgb={}|immutable_source_record=1|identity_exchange=0|json=0",
            leaf.leaf_id, leaf.source_identity_sha256, leaf.family.name(), leaf.level,
            leaf.signed_u, leaf.signed_v, leaf.signed_u, leaf.signed_v, leaf.view_z,
            leaf.projected_u, leaf.projected_v, leaf.orb.recovered_u, leaf.orb.recovered_v,
            leaf.orb.p, leaf.orb.q, leaf.orb.s, leaf.orb.center_num[0],
            leaf.orb.center_num[1], leaf.orb.center_num[2], leaf.orb.common_den,
            leaf.orb.tetra_step, leaf.orb.depth_scaled, rgb_text(leaf.input_rgb),
            rgb_text(leaf.shade),
        ));
    }
    let body = format!("{}\n", lines.join("\n"));
    let body_sha256 = hex(&sha256(body.as_bytes()));
    lines.push(format!(
        "QPRISMFTR|body_sha256={body_sha256}|rows={}|json=0",
        lines.len() + 1
    ));
    format!("{}\n", lines.join("\n")).into_bytes()
}

fn screen_x(leaf: &Leaf) -> i64 {
    500 + leaf.projected_u + leaf.family.horizontal_offset()
}

fn screen_y(leaf: &Leaf) -> i64 {
    500 - leaf.projected_v
}

fn render_svg(records: &[InputRecord], leaves: &[Leaf], source_sha256: &str) -> Vec<u8> {
    let max_level = records.iter().map(|record| record.level).max().unwrap_or(0);
    let mut output = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 1000 1000\" role=\"img\" aria-labelledby=\"title description\">\n");
    output.push_str("<title id=\"title\">Public QPRISM 3-D GitHub color leaves</title>\n");
    output.push_str("<desc id=\"description\">A signed two-dimensional view of exact checked-integer three-dimensional QPRISM leaves for every public repository in the sealed owner capture.</desc>\n");
    output.push_str(&format!("<metadata>schema={OUTPUT_SCHEMA};rust_version=1.81.0;integer_only=1;float_coordinates=0;source_sha256={source_sha256};stages=2D_INPUT,3D_QPRISM,SIGNED_2D_PROJECTION;n_level_open=1;reflection_window={REFLECTION_WINDOW};max_observed_level={max_level};SYSTEM_AFFIRMED=0;public_metadata_only=1;raw_contents=0;json=0</metadata>\n"));
    output.push_str("<rect width=\"1000\" height=\"1000\" fill=\"#101318\"/>\n");
    output.push_str("<g id=\"stage-2d-input\" data-stage=\"2D_INPUT\"><path d=\"M 70 500 L 500 70 L 930 500 L 500 930 Z\" fill=\"none\" stroke=\"#513B2D\" stroke-width=\"2\"/></g>\n");
    output.push_str("<g id=\"stage-3d-qprism\" data-stage=\"3D_QPRISM\"><path d=\"M 500 70 L 820 260 L 930 500 L 740 820 L 500 930 L 180 740 L 70 500 L 260 180 Z\" fill=\"none\" stroke=\"#F4F1E8\" stroke-width=\"1\"/><path d=\"M 500 150 L 850 500 L 500 850 L 150 500 Z\" fill=\"none\" stroke=\"#8B5A2B\" stroke-width=\"2\"/></g>\n");
    output.push_str("<g id=\"stage-signed-2d-projection\" data-stage=\"SIGNED_2D_PROJECTION\">\n");
    for leaf in leaves {
        let x = screen_x(leaf);
        let y = screen_y(leaf);
        output.push_str(&format!(
            "<path id=\"leaf-{}\" class=\"qprism-leaf\" d=\"M {x} {} C {} {} {} {} {x} {} C {} {} {} {} {x} {} Z\" fill=\"#{}\" stroke=\"#F4F1E8\" stroke-width=\"1\" data-family=\"{}\" data-source-identity-sha256=\"{}\" data-input-rgb=\"{}\" data-view-z=\"{}\" data-projected-u=\"{}\" data-projected-v=\"{}\" data-orb-depth=\"{}\"/>\n",
            leaf.leaf_id, y - 9, x + 9, y - 7, x + 12, y + 4, y + 11,
            x - 12, y + 4, x - 9, y - 7, y - 9, rgb_text(leaf.shade),
            leaf.family.name(), leaf.source_identity_sha256, rgb_text(leaf.input_rgb),
            leaf.view_z, leaf.projected_u, leaf.projected_v, leaf.orb.depth_scaled,
        ));
    }
    output.push_str("</g>\n</svg>\n");
    output.into_bytes()
}

pub fn run(
    input: &Path,
    receipt_output: &Path,
    svg_output: &Path,
    replace: bool,
) -> Result<RunResult> {
    let source_bytes = read_verified_input(input)?;
    let records = parse_input(&source_bytes)?;
    let leaves = derive_leaves(&records)?;
    if leaves.len() != records.len() * 3 {
        return Err(QprismError::new("LEAF_COUNT"));
    }
    let source_sha256 = hex(&sha256(&source_bytes));
    let receipt = render_receipt(&records, &leaves, &source_sha256);
    let svg = render_svg(&records, &leaves, &source_sha256);
    let receipt_sha256 = hex(&sha256(&receipt));
    let svg_sha256 = hex(&sha256(&svg));
    let receipt_sidecar = sidecar_path(receipt_output)?;
    let svg_sidecar = sidecar_path(svg_output)?;
    ensure_distinct_paths(&[
        input,
        &sidecar_path(input)?,
        receipt_output,
        &receipt_sidecar,
        svg_output,
        &svg_sidecar,
    ])?;
    let receipt_sidecar_bytes =
        format!("{receipt_sha256}  {}\n", file_name(receipt_output)?).into_bytes();
    let svg_sidecar_bytes = format!("{svg_sha256}  {}\n", file_name(svg_output)?).into_bytes();
    atomic_write_set(
        &[
            (receipt_output, receipt.as_slice()),
            (&receipt_sidecar, receipt_sidecar_bytes.as_slice()),
            (svg_output, svg.as_slice()),
            (&svg_sidecar, svg_sidecar_bytes.as_slice()),
        ],
        replace,
    )?;
    Ok(RunResult {
        records: records.len(),
        leaves: leaves.len(),
        receipt_sha256,
        svg_sha256,
    })
}

fn parse_input(bytes: &[u8]) -> Result<Vec<InputRecord>> {
    validate_text(bytes)?;
    let text = std::str::from_utf8(bytes).map_err(|_| QprismError::new("INPUT_UTF8"))?;
    let lines: Vec<&str> = text[..text.len() - 1].split('\n').collect();
    if lines.len() < 3 {
        return Err(QprismError::new("INPUT_ROWS"));
    }
    let header = fields(lines[0], "PUBLIC2DHDR")?;
    require(&header, "schema", INPUT_SCHEMA)?;
    let expected_records = parse_usize(required(&header, "observed_records")?)?;
    require(&header, "max_level", "60")?;
    require(&header, "public_metadata_only", "1")?;
    require(&header, "raw_contents", "0")?;
    require(&header, "required_hidden_dependencies", "0")?;
    require(&header, "center_membership", CENTER_MEMBERS)?;
    if percent_decode(required(&header, "traversal")?)? != TRAVERSAL {
        return Err(QprismError::new("HEADER_TRAVERSAL"));
    }
    require(&header, "json", "0")?;
    if expected_records == 0
        || expected_records > MAX_RECORDS
        || expected_records + 2 != lines.len()
    {
        return Err(QprismError::new("RECORD_COUNT"));
    }

    let footer = fields(lines[lines.len() - 1], "PUBLIC2DFTR")?;
    require(&footer, "rows", &lines.len().to_string())?;
    require(&footer, "json", "0")?;
    let body = format!("{}\n", lines[..lines.len() - 1].join("\n"));
    require(&footer, "body_sha256", &hex(&sha256(body.as_bytes())))?;

    let mut records = Vec::with_capacity(expected_records);
    let mut identities = BTreeSet::new();
    for line in &lines[1..lines.len() - 1] {
        let map = fields(line, "PUBLIC2D")?;
        for key in [
            "repo_id",
            "tree_id",
            "word_id",
            "parent_word_id",
            "truth_tag",
            "chirality",
            "oil_address",
            "route_id",
            "sh",
        ] {
            validate_token(required(&map, key)?)?;
        }
        require(&map, "public", "1")?;
        require(&map, "json", "0")?;
        match required(&map, "truth_tag")? {
            "LIE" | "THRUTH" => {}
            _ => return Err(QprismError::new("TRUTH_TAG")),
        }
        match required(&map, "chirality")? {
            "LEFT" | "RIGHT" => {}
            _ => return Err(QprismError::new("CHIRALITY")),
        }
        match required(&map, "system_instant_is")? {
            "0" | "1" => {}
            _ => return Err(QprismError::new("INSTANT_FLAG")),
        }
        let u = parse_i64(required(&map, "u")?)?;
        let v = parse_i64(required(&map, "v")?)?;
        if u.abs() > MAX_COORDINATE || v.abs() > MAX_COORDINATE {
            return Err(QprismError::new("COORDINATE_RANGE"));
        }
        let level_usize = parse_usize(required(&map, "level")?)?;
        let level = u8::try_from(level_usize).map_err(|_| QprismError::new("LEVEL_RANGE"))?;
        if level > MAX_LEVEL {
            return Err(QprismError::new("LEVEL_RANGE"));
        }
        let blob_sha256 = parse_hex32(required(&map, "blob_sha256")?)?;
        for key in ["hbi", "hbp", "sha", "hash"] {
            parse_hex32(required(&map, key)?)?;
        }
        if required(&map, "sha")? == required(&map, "hash")? {
            return Err(QprismError::new("SHA_HASH_IDENTITY"));
        }
        let input_rgb = parse_rgb(required(&map, "color")?)?;
        let record = InputRecord {
            repo_id: required(&map, "repo_id")?.to_owned(),
            tree_id: required(&map, "tree_id")?.to_owned(),
            word_id: required(&map, "word_id")?.to_owned(),
            parent_word_id: required(&map, "parent_word_id")?.to_owned(),
            u,
            v,
            level,
            blob_sha256,
            input_rgb,
            truth_tag: required(&map, "truth_tag")?.to_owned(),
            canonical_row: line.as_bytes().to_vec(),
        };
        if !identities.insert(record.identity()) {
            return Err(QprismError::new("DUPLICATE_IDENTITY"));
        }
        records.push(record);
    }
    validate_parent_tree(&records)?;
    Ok(records)
}

fn validate_parent_tree(records: &[InputRecord]) -> Result<()> {
    let words: BTreeSet<(&str, &str, &str)> = records
        .iter()
        .map(|record| {
            (
                record.repo_id.as_str(),
                record.tree_id.as_str(),
                record.word_id.as_str(),
            )
        })
        .collect();
    for record in records {
        if record.level == 0 {
            if record.parent_word_id != "ROOT" {
                return Err(QprismError::new("ROOT_PARENT"));
            }
        } else if !words.contains(&(
            record.repo_id.as_str(),
            record.tree_id.as_str(),
            record.parent_word_id.as_str(),
        )) {
            return Err(QprismError::new("MISSING_PARENT"));
        }
    }
    Ok(())
}

fn validate_text(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_INPUT_BYTES {
        return Err(QprismError::new("INPUT_SIZE"));
    }
    if bytes.last() != Some(&b'\n') || bytes.contains(&b'\r') || bytes.contains(&0) {
        return Err(QprismError::new("INPUT_LF"));
    }
    if bytes
        .split(|byte| *byte == b'\n')
        .any(|line| line.len() > MAX_LINE_BYTES)
    {
        return Err(QprismError::new("LINE_SIZE"));
    }
    Ok(())
}

fn fields<'a>(line: &'a str, prefix: &str) -> Result<BTreeMap<&'a str, &'a str>> {
    let mut pieces = line.split('|');
    if pieces.next() != Some(prefix) {
        return Err(QprismError::new("ROW_PREFIX"));
    }
    let mut map = BTreeMap::new();
    for piece in pieces {
        let (key, value) = piece
            .split_once('=')
            .ok_or_else(|| QprismError::new("FIELD_SHAPE"))?;
        if key.is_empty() || value.is_empty() || map.insert(key, value).is_some() {
            return Err(QprismError::new("FIELD_DUPLICATE"));
        }
    }
    Ok(map)
}

fn required<'a>(map: &BTreeMap<&'a str, &'a str>, key: &str) -> Result<&'a str> {
    map.get(key)
        .copied()
        .ok_or_else(|| QprismError::new("FIELD_MISSING"))
}

fn require(map: &BTreeMap<&str, &str>, key: &str, expected: &str) -> Result<()> {
    if required(map, key)? != expected {
        return Err(QprismError::new("FIELD_VALUE"));
    }
    Ok(())
}

fn parse_usize(value: &str) -> Result<usize> {
    value
        .parse()
        .map_err(|_| QprismError::new("UNSIGNED_INTEGER"))
}

fn parse_i64(value: &str) -> Result<i64> {
    value
        .parse()
        .map_err(|_| QprismError::new("SIGNED_INTEGER"))
}

fn parse_hex32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(QprismError::new("HEX32"));
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| QprismError::new("HEX32"))?;
    }
    Ok(output)
}

fn parse_rgb(value: &str) -> Result<[u8; 3]> {
    let digits = value
        .strip_prefix("RGB.")
        .ok_or_else(|| QprismError::new("RGB"))?;
    if digits.len() != 6
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase())
    {
        return Err(QprismError::new("RGB"));
    }
    let packed = u32::from_str_radix(digits, 16).map_err(|_| QprismError::new("RGB"))?;
    Ok([
        ((packed >> 16) & 255) as u8,
        ((packed >> 8) & 255) as u8,
        (packed & 255) as u8,
    ])
}

fn validate_token(value: &str) -> Result<()> {
    if value.len() > 128
        || value.bytes().any(
            |byte| !matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'),
        )
    {
        return Err(QprismError::new("TOKEN"));
    }
    Ok(())
}

fn percent_decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(QprismError::new("PERCENT_ENCODING"));
            }
            let text = std::str::from_utf8(&bytes[index + 1..index + 3])
                .map_err(|_| QprismError::new("PERCENT_ENCODING"))?;
            output.push(
                u8::from_str_radix(text, 16).map_err(|_| QprismError::new("PERCENT_ENCODING"))?,
            );
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).map_err(|_| QprismError::new("PERCENT_ENCODING"))
}

fn percent_encode(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' | b',') {
            output.push(char::from(byte));
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn sidecar_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| QprismError::new("FILE_NAME"))?;
    let mut sidecar_name = OsString::from(name);
    sidecar_name.push(".sha256");
    Ok(path.with_file_name(sidecar_name))
}

fn file_name(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| QprismError::new("FILE_NAME"))
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    ensure_no_links(path)?;
    let metadata = fs::metadata(path).map_err(|_| QprismError::new("READ_METADATA"))?;
    if !metadata.is_file() || metadata.len() > MAX_INPUT_BYTES as u64 {
        return Err(QprismError::new("READ_TYPE_SIZE"));
    }
    let file = File::open(path).map_err(|_| QprismError::new("READ_OPEN"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| QprismError::new("READ_BYTES"))?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(QprismError::new("READ_SIZE"));
    }
    Ok(bytes)
}

fn read_verified_input(input: &Path) -> Result<Vec<u8>> {
    let input_bytes = read_bounded(input)?;
    let sidecar = sidecar_path(input)?;
    let sidecar_bytes = read_bounded(&sidecar)?;
    validate_text(&sidecar_bytes)?;
    let expected = format!("{}  {}\n", hex(&sha256(&input_bytes)), file_name(input)?);
    if sidecar_bytes != expected.as_bytes() {
        return Err(QprismError::new("INPUT_SIDECAR"));
    }
    Ok(input_bytes)
}

fn ensure_no_links(path: &Path) -> Result<()> {
    let mut cursor = Some(path);
    while let Some(current) = cursor {
        if current.as_os_str().is_empty() {
            break;
        }
        if current.exists() {
            let metadata =
                fs::symlink_metadata(current).map_err(|_| QprismError::new("LINK_METADATA"))?;
            if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
                return Err(QprismError::new("LINK_PATH"));
            }
        }
        cursor = current.parent();
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn normalized_path(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| QprismError::new("OUTPUT_PARENT"))?;
    ensure_no_links(parent)?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|_| QprismError::new("OUTPUT_PARENT"))?;
    Ok(canonical_parent.join(
        path.file_name()
            .ok_or_else(|| QprismError::new("FILE_NAME"))?,
    ))
}

fn ensure_distinct_paths(paths: &[&Path]) -> Result<()> {
    let mut normalized = BTreeSet::new();
    for path in paths {
        if !normalized.insert(normalized_path(path)?) {
            return Err(QprismError::new("PATH_ALIAS"));
        }
    }
    Ok(())
}

fn atomic_write_set(entries: &[(&Path, &[u8])], replace: bool) -> Result<()> {
    for (index, (path, bytes)) in entries.iter().enumerate() {
        atomic_write(path, bytes, replace, index)?;
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8], replace: bool, index: usize) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| QprismError::new("OUTPUT_PARENT"))?;
    ensure_no_links(parent)?;
    if !fs::metadata(parent)
        .map_err(|_| QprismError::new("OUTPUT_PARENT"))?
        .is_dir()
    {
        return Err(QprismError::new("OUTPUT_PARENT"));
    }
    if path.exists() {
        ensure_no_links(path)?;
        if !replace {
            return Err(QprismError::new("OUTPUT_EXISTS"));
        }
        if !fs::metadata(path)
            .map_err(|_| QprismError::new("OUTPUT_METADATA"))?
            .is_file()
        {
            return Err(QprismError::new("OUTPUT_TYPE"));
        }
    }
    let name = file_name(path)?;
    let temporary = parent.join(format!(".{name}.qprism-{}-{index}.tmp", std::process::id()));
    let backup = parent.join(format!(".{name}.qprism-{}-{index}.bak", std::process::id()));
    if temporary.exists() || backup.exists() {
        return Err(QprismError::new("ATOMIC_COLLISION"));
    }
    let write_result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| QprismError::new("TEMP_CREATE"))?;
        file.write_all(bytes)
            .map_err(|_| QprismError::new("TEMP_WRITE"))?;
        file.sync_all().map_err(|_| QprismError::new("TEMP_SYNC"))?;
        drop(file);
        let had_existing = path.exists();
        if had_existing {
            fs::rename(path, &backup).map_err(|_| QprismError::new("BACKUP_RENAME"))?;
        }
        if fs::rename(&temporary, path).is_err() {
            if had_existing {
                let _ = fs::rename(&backup, path);
            }
            return Err(QprismError::new("OUTPUT_RENAME"));
        }
        if had_existing {
            fs::remove_file(&backup).map_err(|_| QprismError::new("BACKUP_REMOVE"))?;
        }
        Ok(())
    })();
    if write_result.is_err() && temporary.exists() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}

fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_length = (input.len() as u64).wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());
    let mut state = INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, word) in words[..16].iter_mut().enumerate() {
            let start = index * 4;
            *word = u32::from_be_bytes([
                chunk[start],
                chunk[start + 1],
                chunk[start + 2],
                chunk[start + 3],
            ]);
        }
        for index in 16..64 {
            let small_zero = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let small_one = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(small_zero)
                .wrapping_add(words[index - 7])
                .wrapping_add(small_one);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let large_one = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp_one = h
                .wrapping_add(large_one)
                .wrapping_add(choice)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let large_zero = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp_two = large_zero.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp_one);
            d = c;
            c = b;
            b = a;
            a = temp_one.wrapping_add(temp_two);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
    let mut output = [0_u8; 32];
    for (index, word) in state.iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn exact_transform_round_trips_extrema() {
        for (u, v, level) in [
            (-MAX_COORDINATE, -MAX_COORDINATE, 0),
            (MAX_COORDINATE, MAX_COORDINATE, MAX_LEVEL),
        ] {
            let record = InputRecord {
                repo_id: "r".to_owned(),
                tree_id: "t".to_owned(),
                word_id: "w".to_owned(),
                parent_word_id: "ROOT".to_owned(),
                u,
                v,
                level,
                blob_sha256: [0; 32],
                input_rgb: [0, 127, 255],
                truth_tag: "THRUTH".to_owned(),
                canonical_row: format!("u={u}|v={v}|level={level}").into_bytes(),
            };
            let orb = exact_orb(&record).expect("extreme input remains inside checked i128 bounds");
            assert_eq!((orb.recovered_u, orb.recovered_v), (u, v));
            assert!(orb.common_den > 0);
        }
    }

    #[test]
    fn current_capture_is_plural_depth_aware_and_table_free() {
        let records = parse_input(include_bytes!("../../PUBLIC-OWNER-2D.hbp"))
            .expect("the committed PUBLIC2D capture remains valid");
        assert_eq!(records.len(), 147);
        let leaves = derive_leaves(&records).expect("checked integer leaf derivation succeeds");
        assert_eq!(leaves.len(), 441);

        for family in Family::ALL {
            assert_eq!(
                leaves.iter().filter(|leaf| leaf.family == family).count(),
                records.len()
            );
        }
        let depths: BTreeSet<i64> = leaves.iter().map(|leaf| leaf.view_z).collect();
        assert_eq!(depths.len(), leaves.len());
        let orb_depths: BTreeSet<i128> = leaves.iter().map(|leaf| leaf.orb.depth_scaled).collect();
        assert!(orb_depths.len() > 100);

        let from_low_z = signed_projection(0, 0, -MAX_COORDINATE)
            .expect("low-z signed projection remains bounded");
        let from_high_z = signed_projection(0, 0, MAX_COORDINATE)
            .expect("high-z signed projection remains bounded");
        assert_ne!(from_low_z, from_high_z);

        let source_sha256 = hex(&sha256(include_bytes!("../../PUBLIC-OWNER-2D.hbp")));
        let svg = String::from_utf8(render_svg(&records, &leaves, &source_sha256))
            .expect("renderer emits UTF-8");
        assert_eq!(svg.matches("class=\"qprism-leaf\"").count(), 441);
        assert!(svg.contains("data-stage=\"3D_QPRISM\""));
        assert!(svg.contains("data-stage=\"SIGNED_2D_PROJECTION\""));
        assert!(!svg.contains("<table"));
        assert!(!svg.contains("<circle"));
        assert!(!svg.contains("<script"));
        assert!(!svg.contains("href="));
    }
}
