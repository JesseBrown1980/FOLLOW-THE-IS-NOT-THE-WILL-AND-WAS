#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

const SCHEMA: &str = "ASOLARIA-SYSTEM-UPGRADE-RUST-181-AUDIT-V1";
const SOURCE_ID_DOMAIN: &[u8] = b"ASOLARIA.SYSTEM.UPGRADE.SOURCE.V1";
const MAX_GIT_LIST_BYTES: usize = 32 * 1024 * 1024;
const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditError {
    code: String,
}

impl AuditError {
    pub fn new(code: impl Into<String>) -> Self {
        Self { code: code.into() }
    }

    pub fn code(&self) -> &str {
        &self.code
    }
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.code)
    }
}

impl std::error::Error for AuditError {}

type Result<T> = std::result::Result<T, AuditError>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    worktree_files: u64,
    hbp_files: u64,
    hbi_files: u64,
    sha_files: u64,
    shell_sh_files: u64,
    hash_files: u64,
    sidecars_valid: u64,
    sidecars_missing: u64,
    sidecars_mismatch: u64,
    source_candidates: u64,
    rust_artifact_sources: u64,
    non_rust_artifact_sources: u64,
    rust_sources: u64,
    rust_float_code_files: u64,
    cargo_manifests: u64,
    package_manifests: u64,
    rust_version_181_manifests: u64,
    overflow_profiles: u64,
    toolchain_files: u64,
    exact_toolchain_181_files: u64,
    workflow_files: u64,
    clippy_workflows: u64,
    clippy_hard_gate_workflows: u64,
    clippy_gated_manifests: u64,
    crate_roots: u64,
    forbid_unsafe_roots: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceFinding {
    id: String,
    language: &'static str,
    migration_required: bool,
    float_code: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Debt {
    non_rust_artifact_sources: u64,
    rust_float_code_files: u64,
    sidecars_missing: u64,
    toolchain_gap: u64,
    rust_version_gap: u64,
    overflow_profile_gap: u64,
    clippy_hard_gate_gap: u64,
    forbid_unsafe_gap: u64,
}

impl Debt {
    fn fields(self) -> [(&'static str, u64); 8] {
        [
            ("non_rust_artifact_sources", self.non_rust_artifact_sources),
            ("rust_float_code_files", self.rust_float_code_files),
            ("sidecars_missing", self.sidecars_missing),
            ("toolchain_gap", self.toolchain_gap),
            ("rust_version_gap", self.rust_version_gap),
            ("overflow_profile_gap", self.overflow_profile_gap),
            ("clippy_hard_gate_gap", self.clippy_hard_gate_gap),
            ("forbid_unsafe_gap", self.forbid_unsafe_gap),
        ]
    }

    fn total(self) -> Result<u64> {
        let mut total = 0_u64;
        for (_, value) in self.fields() {
            total = total
                .checked_add(value)
                .ok_or_else(|| AuditError::new("COUNT_OVERFLOW"))?;
        }
        Ok(total)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Audit {
    scope_sha256: String,
    head_sha: String,
    counts: Counts,
    debt: Debt,
    sources: Vec<SourceFinding>,
}

impl Audit {
    pub fn render_hbp(&self) -> Result<Vec<u8>> {
        let mut output = String::new();
        output.push_str(&format!(
            "SYSTEMUPGRADERUN|schema={SCHEMA}|scope_sha256={}|base_head_sha={}|worktree_files={}|worktree_includes_untracked=1|state={}|json=0\n",
            self.scope_sha256,
            self.head_sha,
            self.counts.worktree_files,
            if self.debt.total()? == 0 {
                "COMPLIANT"
            } else {
                "MIGRATION_REQUIRED"
            },
        ));
        output.push_str(
            "CONTRACT|rustc=1.81.0|cargo=1.81.0|integer_only=1|checked_integer_profile=1|float_code=0|unsafe_code=0|clippy=1|clippy_warnings_denied=1|clippy_float_arithmetic_denied=1|hbp_hbi_exact_sidecars=1|historical_receipts_rewritten=0|json=0\n",
        );
        output.push_str(&format!(
            "ARTIFACTS|hbp={}|hbi={}|sha_files={}|shell_sh_files={}|hash_files={}|sidecars_valid={}|sidecars_missing={}|sidecars_mismatch={}|json=0\n",
            self.counts.hbp_files,
            self.counts.hbi_files,
            self.counts.sha_files,
            self.counts.shell_sh_files,
            self.counts.hash_files,
            self.counts.sidecars_valid,
            self.counts.sidecars_missing,
            self.counts.sidecars_mismatch,
        ));
        output.push_str(&format!(
            "RUSTGATE|source_candidates={}|rust_artifact_sources={}|non_rust_artifact_sources={}|rust_sources={}|rust_float_code_files={}|cargo_manifests={}|package_manifests={}|rust_version_181_manifests={}|overflow_profiles={}|toolchain_files={}|exact_toolchain_181_files={}|workflow_files={}|clippy_workflows={}|clippy_hard_gate_workflows={}|clippy_gated_manifests={}|crate_roots={}|forbid_unsafe_roots={}|json=0\n",
            self.counts.source_candidates,
            self.counts.rust_artifact_sources,
            self.counts.non_rust_artifact_sources,
            self.counts.rust_sources,
            self.counts.rust_float_code_files,
            self.counts.cargo_manifests,
            self.counts.package_manifests,
            self.counts.rust_version_181_manifests,
            self.counts.overflow_profiles,
            self.counts.toolchain_files,
            self.counts.exact_toolchain_181_files,
            self.counts.workflow_files,
            self.counts.clippy_workflows,
            self.counts.clippy_hard_gate_workflows,
            self.counts.clippy_gated_manifests,
            self.counts.crate_roots,
            self.counts.forbid_unsafe_roots,
        ));
        output.push_str("DEBT");
        for (name, value) in self.debt.fields() {
            output.push('|');
            output.push_str(name);
            output.push('=');
            output.push_str(&value.to_string());
        }
        output.push_str(&format!("|total={}|json=0\n", self.debt.total()?));
        output.push_str(
            "TARGET|non_rust_artifact_sources=0|rust_float_code_files=0|sidecars_missing=0|toolchain_gap=0|rust_version_gap=0|overflow_profile_gap=0|clippy_hard_gate_gap=0|forbid_unsafe_gap=0|sidecars_mismatch=0|json=0\n",
        );
        for source in &self.sources {
            output.push_str(&format!(
                "SOURCE|id={}|language={}|migration_required={}|float_code={}|path_published=0|json=0\n",
                source.id,
                source.language,
                u8::from(source.migration_required),
                u8::from(source.float_code),
            ));
        }
        output.push_str(
            "BOUNDARY|raw_paths=0|private_identities=0|credentials=0|artifact_bodies_embedded=0|sealed_history_mutated=0|github_runtime_affirmed=0|system_affirmed=0|json=0\n",
        );
        Ok(output.into_bytes())
    }

    pub fn stdout_row(&self) -> String {
        format!(
            "SYSTEMUPGRADE|state={}|worktree_files={}|hbp={}|hbi={}|non_rust_sources={}|float_files={}|missing_sidecars={}|mismatched_sidecars={}|json=0",
            if self.debt.total().unwrap_or(u64::MAX) == 0 {
                "COMPLIANT"
            } else {
                "MIGRATION_REQUIRED"
            },
            self.counts.worktree_files,
            self.counts.hbp_files,
            self.counts.hbi_files,
            self.counts.non_rust_artifact_sources,
            self.counts.rust_float_code_files,
            self.counts.sidecars_missing,
            self.counts.sidecars_mismatch,
        )
    }

    pub fn verify_stdout_row(&self) -> String {
        format!(
            "SYSTEMUPGRADEVERIFY|state=RATCHET_PASS|remaining_debt={}|target_debt=0|json=0",
            self.debt.total().unwrap_or(u64::MAX),
        )
    }
}

pub fn scan_repository(root: &Path, scope: &str) -> Result<Audit> {
    if scope.is_empty() || scope.bytes().any(|byte| byte == b'|' || byte < 0x20) {
        return Err(AuditError::new("SCOPE_INVALID"));
    }
    let root = fs::canonicalize(root).map_err(|_| AuditError::new("ROOT_CANONICALIZE"))?;
    if !root.is_dir() {
        return Err(AuditError::new("ROOT_NOT_DIRECTORY"));
    }
    let paths = git_file_list(&root)?;
    let path_set: BTreeSet<String> = paths.iter().cloned().collect();
    let head_sha = git_text(&root, &["rev-parse", "HEAD"])?;
    if head_sha.len() != 40 || !head_sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AuditError::new("HEAD_SHA_INVALID"));
    }

    let mut counts = Counts::default();
    let mut sources = Vec::new();
    let mut artifacts = Vec::new();
    let mut package_manifest_paths = Vec::new();
    let mut workflows = Vec::new();
    for relative in &paths {
        bump(&mut counts.worktree_files)?;
        let lower = relative.to_ascii_lowercase();
        if lower.ends_with(".hbp") {
            bump(&mut counts.hbp_files)?;
            artifacts.push(relative.clone());
        } else if lower.ends_with(".hbi") {
            bump(&mut counts.hbi_files)?;
            artifacts.push(relative.clone());
        }
        if lower.ends_with(".sha") || lower.ends_with(".sha256") {
            bump(&mut counts.sha_files)?;
        }
        if lower.ends_with(".sh") {
            bump(&mut counts.shell_sh_files)?;
        }
        if lower.ends_with(".hash") {
            bump(&mut counts.hash_files)?;
        }
        if lower.ends_with(".rs") {
            bump(&mut counts.rust_sources)?;
        }
        if file_name_is(relative, "Cargo.toml") {
            bump(&mut counts.cargo_manifests)?;
            let bytes = read_relative(&root, relative, MAX_SOURCE_BYTES)?;
            let manifest = text(&bytes)?;
            if manifest.contains("[package]") {
                bump(&mut counts.package_manifests)?;
                package_manifest_paths.push(relative.clone());
                if manifest.contains("rust-version = \"1.81\"") {
                    bump(&mut counts.rust_version_181_manifests)?;
                }
            }
            if manifest.contains("[profile.release]") && manifest.contains("overflow-checks = true")
            {
                bump(&mut counts.overflow_profiles)?;
            }
        }
        if file_name_is(relative, "rust-toolchain.toml") || file_name_is(relative, "rust-toolchain")
        {
            bump(&mut counts.toolchain_files)?;
            let bytes = read_relative(&root, relative, MAX_SOURCE_BYTES)?;
            if text(&bytes)?.contains("channel = \"1.81.0\"") {
                bump(&mut counts.exact_toolchain_181_files)?;
            }
        }
        if is_workflow(&lower) {
            bump(&mut counts.workflow_files)?;
            let bytes = read_relative(&root, relative, MAX_SOURCE_BYTES)?;
            let workflow = text(&bytes)?;
            workflows.push(workflow.to_owned());
            if workflow.contains("clippy") {
                bump(&mut counts.clippy_workflows)?;
            }
            if workflow.contains("1.81.0")
                && workflow.contains("clippy")
                && workflow.contains("-D warnings")
                && workflow.contains("clippy::float_arithmetic")
            {
                bump(&mut counts.clippy_hard_gate_workflows)?;
            }
        }
        if is_crate_root(&lower) {
            bump(&mut counts.crate_roots)?;
            let bytes = read_relative(&root, relative, MAX_SOURCE_BYTES)?;
            if text(&bytes)?.contains("#![forbid(unsafe_code)]") {
                bump(&mut counts.forbid_unsafe_roots)?;
            }
        }
        let Some(language) = source_language(&lower) else {
            continue;
        };
        let bytes = read_relative(&root, relative, MAX_SOURCE_BYTES)?;
        if !contains_artifact_reference(&bytes) {
            continue;
        }
        bump(&mut counts.source_candidates)?;
        let is_rust = language == "RUST";
        let float_code = is_rust && contains_rust_float_code(&bytes)?;
        if is_rust {
            bump(&mut counts.rust_artifact_sources)?;
            if float_code {
                bump(&mut counts.rust_float_code_files)?;
            }
        } else {
            bump(&mut counts.non_rust_artifact_sources)?;
        }
        sources.push(SourceFinding {
            id: source_id(scope, relative),
            language,
            migration_required: !is_rust || float_code,
            float_code,
        });
    }

    for target in artifacts {
        let sidecar = format!("{target}.sha256");
        if !path_set.contains(&sidecar) {
            bump(&mut counts.sidecars_missing)?;
            continue;
        }
        let target_bytes = read_relative(&root, &target, MAX_ARTIFACT_BYTES)?;
        let sidecar_bytes = read_relative(&root, &sidecar, MAX_SOURCE_BYTES)?;
        let basename = Path::new(&target)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| AuditError::new("ARTIFACT_BASENAME_INVALID"))?;
        let expected = format!("{}  {basename}\n", hex(&sha256(&target_bytes)));
        if sidecar_bytes == expected.as_bytes() {
            bump(&mut counts.sidecars_valid)?;
        } else {
            bump(&mut counts.sidecars_mismatch)?;
        }
    }

    for manifest in &package_manifest_paths {
        if workflows
            .iter()
            .any(|workflow| workflow_binds_hard_clippy(workflow, manifest))
        {
            bump(&mut counts.clippy_gated_manifests)?;
        }
    }

    sources.sort_by(|left, right| left.id.cmp(&right.id));
    let required_toolchains = if counts.package_manifests == 0 {
        bool_count(counts.rust_sources > 0)
    } else {
        counts.package_manifests
    };
    let toolchain_gap = required_toolchains
        .checked_sub(counts.exact_toolchain_181_files.min(required_toolchains))
        .ok_or_else(|| AuditError::new("COUNT_INVARIANT"))?;
    let rust_version_gap = counts
        .package_manifests
        .checked_sub(counts.rust_version_181_manifests)
        .ok_or_else(|| AuditError::new("COUNT_INVARIANT"))?;
    let overflow_profile_gap = counts
        .cargo_manifests
        .checked_sub(counts.overflow_profiles.min(counts.cargo_manifests))
        .ok_or_else(|| AuditError::new("COUNT_INVARIANT"))?;
    let clippy_hard_gate_gap = counts
        .package_manifests
        .checked_sub(counts.clippy_gated_manifests)
        .ok_or_else(|| AuditError::new("COUNT_INVARIANT"))?;
    let forbid_unsafe_gap = counts
        .crate_roots
        .checked_sub(counts.forbid_unsafe_roots)
        .ok_or_else(|| AuditError::new("COUNT_INVARIANT"))?;
    let debt = Debt {
        non_rust_artifact_sources: counts.non_rust_artifact_sources,
        rust_float_code_files: counts.rust_float_code_files,
        sidecars_missing: counts.sidecars_missing,
        toolchain_gap,
        rust_version_gap,
        overflow_profile_gap,
        clippy_hard_gate_gap,
        forbid_unsafe_gap,
    };
    Ok(Audit {
        scope_sha256: hex(&sha256(scope.as_bytes())),
        head_sha,
        counts,
        debt,
        sources,
    })
}

pub fn verify_baseline(audit: &Audit, baseline: &Path) -> Result<()> {
    let bytes = read_verified_receipt(baseline)?;
    let baseline_text = text(&bytes)?;
    let (baseline_scope, baseline_debt, baseline_ids) = parse_baseline(baseline_text)?;
    if baseline_scope != audit.scope_sha256 {
        return Err(AuditError::new("BASELINE_SCOPE_MISMATCH"));
    }
    if audit.counts.sidecars_mismatch != 0 {
        return Err(AuditError::new("SIDECAR_MISMATCH_PRESENT"));
    }
    let current_fields: BTreeMap<&str, u64> = audit.debt.fields().into_iter().collect();
    for (name, baseline_value) in baseline_debt {
        let current = current_fields
            .get(name.as_str())
            .ok_or_else(|| AuditError::new("BASELINE_DEBT_FIELD_UNKNOWN"))?;
        if *current > baseline_value {
            return Err(AuditError::new(format!("RATCHET_REGRESSION_{name}")));
        }
    }
    let current_ids: BTreeSet<&str> = audit
        .sources
        .iter()
        .filter(|source| source.migration_required)
        .map(|source| source.id.as_str())
        .collect();
    if !current_ids.iter().all(|id| baseline_ids.contains(*id)) {
        return Err(AuditError::new("RATCHET_NEW_MIGRATION_SOURCE"));
    }
    Ok(())
}

pub fn write_receipt(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    if bytes.last() != Some(&b'\n') {
        return Err(AuditError::new("RECEIPT_NOT_LF_TERMINATED"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| AuditError::new("OUTPUT_PARENT_MISSING"))?;
    if !parent.is_dir() {
        return Err(AuditError::new("OUTPUT_PARENT_INVALID"));
    }
    let sidecar = sidecar_path(path)?;
    for target in [path, sidecar.as_path()] {
        if target.exists() {
            if !replace {
                return Err(AuditError::new("OUTPUT_EXISTS"));
            }
            if fs::symlink_metadata(target)
                .map_err(|_| AuditError::new("OUTPUT_METADATA"))?
                .file_type()
                .is_symlink()
            {
                return Err(AuditError::new("OUTPUT_LINK"));
            }
        }
    }
    fs::write(path, bytes).map_err(|_| AuditError::new("OUTPUT_WRITE"))?;
    let basename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AuditError::new("OUTPUT_BASENAME"))?;
    let sidecar_bytes = format!("{}  {basename}\n", hex(&sha256(bytes)));
    fs::write(sidecar, sidecar_bytes).map_err(|_| AuditError::new("SIDECAR_WRITE"))?;
    Ok(())
}

fn parse_baseline(text: &str) -> Result<(String, BTreeMap<String, u64>, BTreeSet<String>)> {
    let mut scope = None;
    let mut debt = None;
    let mut ids = BTreeSet::new();
    for line in text.lines() {
        if line.is_empty() || !line.ends_with("|json=0") {
            return Err(AuditError::new("BASELINE_ROW_CONTRACT"));
        }
        if line.starts_with("SYSTEMUPGRADERUN|") {
            if scope.is_some() {
                return Err(AuditError::new("BASELINE_HEADER_DUPLICATE"));
            }
            let fields = parse_fields(line)?;
            if fields.get("schema") != Some(&SCHEMA) {
                return Err(AuditError::new("BASELINE_SCHEMA"));
            }
            let value = fields
                .get("scope_sha256")
                .ok_or_else(|| AuditError::new("BASELINE_SCOPE_MISSING"))?;
            if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(AuditError::new("BASELINE_SCOPE_INVALID"));
            }
            scope = Some((*value).to_owned());
        } else if line.starts_with("DEBT|") {
            if debt.is_some() {
                return Err(AuditError::new("BASELINE_DEBT_DUPLICATE"));
            }
            let fields = parse_fields(line)?;
            let mut values = BTreeMap::new();
            for name in Debt::default().fields().map(|(name, _)| name) {
                let value = fields
                    .get(name)
                    .ok_or_else(|| AuditError::new("BASELINE_DEBT_FIELD_MISSING"))?
                    .parse::<u64>()
                    .map_err(|_| AuditError::new("BASELINE_DEBT_VALUE"))?;
                values.insert(name.to_owned(), value);
            }
            debt = Some(values);
        } else if line.starts_with("SOURCE|") {
            let fields = parse_fields(line)?;
            if fields.get("migration_required") == Some(&"1") {
                let id = fields
                    .get("id")
                    .ok_or_else(|| AuditError::new("BASELINE_SOURCE_ID_MISSING"))?;
                if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(AuditError::new("BASELINE_SOURCE_ID_INVALID"));
                }
                if !ids.insert((*id).to_owned()) {
                    return Err(AuditError::new("BASELINE_SOURCE_ID_DUPLICATE"));
                }
            }
        }
    }
    Ok((
        scope.ok_or_else(|| AuditError::new("BASELINE_HEADER_MISSING"))?,
        debt.ok_or_else(|| AuditError::new("BASELINE_DEBT_MISSING"))?,
        ids,
    ))
}

fn parse_fields(line: &str) -> Result<BTreeMap<&str, &str>> {
    let mut fields = BTreeMap::new();
    for field in line.split('|').skip(1) {
        let (name, value) = field
            .split_once('=')
            .ok_or_else(|| AuditError::new("HBP_FIELD_SHAPE"))?;
        if name.is_empty() || value.is_empty() || fields.insert(name, value).is_some() {
            return Err(AuditError::new("HBP_FIELD_INVALID"));
        }
    }
    Ok(fields)
}

fn read_verified_receipt(path: &Path) -> Result<Vec<u8>> {
    let bytes = read_bounded(path, MAX_ARTIFACT_BYTES)?;
    if bytes.last() != Some(&b'\n') || bytes.contains(&b'\r') {
        return Err(AuditError::new("BASELINE_NOT_LF"));
    }
    let sidecar = sidecar_path(path)?;
    let sidecar_bytes = read_bounded(&sidecar, MAX_SOURCE_BYTES)?;
    let basename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AuditError::new("BASELINE_BASENAME"))?;
    let expected = format!("{}  {basename}\n", hex(&sha256(&bytes)));
    if sidecar_bytes != expected.as_bytes() {
        return Err(AuditError::new("BASELINE_SIDECAR_MISMATCH"));
    }
    Ok(bytes)
}

fn git_file_list(root: &Path) -> Result<Vec<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .output()
        .map_err(|_| AuditError::new("GIT_LS_FILES_EXEC"))?;
    if !output.status.success() {
        return Err(AuditError::new("GIT_LS_FILES_STATUS"));
    }
    if output.stdout.len() > MAX_GIT_LIST_BYTES {
        return Err(AuditError::new("GIT_LS_FILES_BOUND"));
    }
    let mut paths = Vec::new();
    for raw in output.stdout.split(|byte| *byte == 0) {
        if raw.is_empty() {
            continue;
        }
        let relative = std::str::from_utf8(raw)
            .map_err(|_| AuditError::new("GIT_PATH_NOT_UTF8"))?
            .to_owned();
        validate_relative(&relative)?;
        paths.push(relative);
    }
    paths.sort();
    if paths.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AuditError::new("GIT_PATH_DUPLICATE"));
    }
    Ok(paths)
}

fn git_text(root: &Path, arguments: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .map_err(|_| AuditError::new("GIT_EXEC"))?;
    if !output.status.success() {
        return Err(AuditError::new("GIT_STATUS"));
    }
    let output_text = std::str::from_utf8(&output.stdout)
        .map_err(|_| AuditError::new("GIT_OUTPUT_UTF8"))?
        .trim()
        .to_owned();
    Ok(output_text)
}

fn validate_relative(relative: &str) -> Result<()> {
    if relative.is_empty() || relative.contains('\\') || relative.contains('|') {
        return Err(AuditError::new("GIT_PATH_INVALID"));
    }
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AuditError::new("GIT_PATH_ESCAPE"));
    }
    Ok(())
}

fn read_relative(root: &Path, relative: &str, maximum: u64) -> Result<Vec<u8>> {
    validate_relative(relative)?;
    read_bounded(&root.join(relative), maximum)
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|_| AuditError::new("READ_METADATA"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(AuditError::new("READ_TYPE_OR_BOUND"));
    }
    fs::read(path).map_err(|_| AuditError::new("READ_BYTES"))
}

fn sidecar_path(path: &Path) -> Result<PathBuf> {
    let mut name = path
        .file_name()
        .ok_or_else(|| AuditError::new("SIDECAR_BASENAME"))?
        .to_os_string();
    name.push(".sha256");
    Ok(path.with_file_name(name))
}

fn file_name_is(relative: &str, expected: &str) -> bool {
    Path::new(relative)
        .file_name()
        .and_then(|name| name.to_str())
        == Some(expected)
}

fn is_workflow(lower: &str) -> bool {
    lower.starts_with(".github/workflows/") && (lower.ends_with(".yml") || lower.ends_with(".yaml"))
}

fn workflow_binds_hard_clippy(workflow: &str, manifest: &str) -> bool {
    workflow.lines().any(|line| {
        let words: Vec<&str> = line.split_ascii_whitespace().collect();
        let manifest_bound = words.windows(2).any(|pair| {
            pair[0] == "--manifest-path" && pair[1].trim_matches(['\'', '"']) == manifest
        });
        line.contains("cargo +1.81.0 clippy")
            && manifest_bound
            && line.contains("-D warnings")
            && line.contains("clippy::float_arithmetic")
    })
}

fn is_crate_root(lower: &str) -> bool {
    lower.ends_with("/src/lib.rs")
        || lower.ends_with("/src/main.rs")
        || lower == "src/lib.rs"
        || lower == "src/main.rs"
}

fn source_language(lower: &str) -> Option<&'static str> {
    [
        (".rs", "RUST"),
        (".py", "PYTHON"),
        (".js", "JAVASCRIPT"),
        (".mjs", "JAVASCRIPT"),
        (".cjs", "JAVASCRIPT"),
        (".ts", "TYPESCRIPT"),
        (".tsx", "TYPESCRIPT"),
        (".ps1", "POWERSHELL"),
        (".sh", "SHELL"),
        (".cmd", "CMD"),
        (".bat", "BATCH"),
        (".go", "GO"),
        (".rb", "RUBY"),
        (".java", "JAVA"),
        (".c", "C"),
        (".cc", "CPP"),
        (".cpp", "CPP"),
    ]
    .into_iter()
    .find_map(|(suffix, language)| lower.ends_with(suffix).then_some(language))
}

fn contains_artifact_reference(bytes: &[u8]) -> bool {
    let lower = bytes.to_ascii_lowercase();
    lower
        .windows(4)
        .any(|window| window == b".hbp" || window == b".hbi")
        || lower
            .windows(b"hbi,hbp,sha,sh,hash".len())
            .any(|window| window == b"hbi,hbp,sha,sh,hash")
}

fn contains_rust_float_code(bytes: &[u8]) -> Result<bool> {
    let source = text(bytes)?;
    let code = rust_code_projection(source)?;
    let bytes = code.as_bytes();
    let mut index = 0_usize;
    while index < bytes.len() {
        if is_identifier_start(bytes[index]) {
            let start = index;
            index = checked_step(index, 1)?;
            while index < bytes.len() && is_identifier_continue(bytes[index]) {
                index = checked_step(index, 1)?;
            }
            if &bytes[start..index] == b"f32" || &bytes[start..index] == b"f64" {
                return Ok(true);
            }
            continue;
        }
        if bytes[index].is_ascii_digit() {
            let (end, is_float) = scan_rust_number(bytes, index)?;
            if is_float {
                return Ok(true);
            }
            if end == index {
                return Err(AuditError::new("NUMBER_SCAN_STALL"));
            }
            index = end;
            continue;
        }
        index = checked_step(index, 1)?;
    }
    Ok(false)
}

fn scan_rust_number(bytes: &[u8], index: usize) -> Result<(usize, bool)> {
    let mut cursor = index;
    let prefix = bytes.get(index..index.saturating_add(2));
    let radix = match prefix {
        Some([b'0', b'x' | b'X']) => Some(16_u8),
        Some([b'0', b'o' | b'O']) => Some(8_u8),
        Some([b'0', b'b' | b'B']) => Some(2_u8),
        _ => None,
    };
    if let Some(radix) = radix {
        cursor = checked_step(cursor, 2)?;
        while cursor < bytes.len()
            && (bytes[cursor] == b'_' || digit_in_radix(bytes[cursor], radix))
        {
            cursor = checked_step(cursor, 1)?;
        }
        while cursor < bytes.len() && is_identifier_continue(bytes[cursor]) {
            cursor = checked_step(cursor, 1)?;
        }
        return Ok((cursor, false));
    }

    while cursor < bytes.len() && (bytes[cursor].is_ascii_digit() || bytes[cursor] == b'_') {
        cursor = checked_step(cursor, 1)?;
    }
    let mut is_float = false;
    if bytes.get(cursor) == Some(&b'.') && bytes.get(checked_step(cursor, 1)?) != Some(&b'.') {
        let after_dot = checked_step(cursor, 1)?;
        let next = bytes.get(after_dot).copied();
        if next.map_or(true, |byte| !is_identifier_start(byte)) {
            is_float = true;
            cursor = after_dot;
            while cursor < bytes.len() && (bytes[cursor].is_ascii_digit() || bytes[cursor] == b'_')
            {
                cursor = checked_step(cursor, 1)?;
            }
        }
    }
    if matches!(bytes.get(cursor), Some(b'e' | b'E')) {
        let mut exponent = checked_step(cursor, 1)?;
        if matches!(bytes.get(exponent), Some(b'+' | b'-')) {
            exponent = checked_step(exponent, 1)?;
        }
        if bytes.get(exponent).is_some_and(u8::is_ascii_digit) {
            is_float = true;
            cursor = checked_step(exponent, 1)?;
            while cursor < bytes.len() && (bytes[cursor].is_ascii_digit() || bytes[cursor] == b'_')
            {
                cursor = checked_step(cursor, 1)?;
            }
        }
    }
    if bytes.get(cursor..cursor.saturating_add(3)) == Some(b"f32")
        || bytes.get(cursor..cursor.saturating_add(3)) == Some(b"f64")
    {
        is_float = true;
        cursor = checked_step(cursor, 3)?;
    } else {
        while cursor < bytes.len() && is_identifier_continue(bytes[cursor]) {
            cursor = checked_step(cursor, 1)?;
        }
    }
    Ok((cursor, is_float))
}

fn digit_in_radix(byte: u8, radix: u8) -> bool {
    match radix {
        2 => matches!(byte, b'0' | b'1'),
        8 => matches!(byte, b'0'..=b'7'),
        16 => byte.is_ascii_hexdigit(),
        _ => false,
    }
}

fn rust_code_projection(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let mut output = vec![b' '; bytes.len()];
    let mut index = 0_usize;
    let mut block_depth = 0_u64;
    while index < bytes.len() {
        if block_depth > 0 {
            if bytes.get(index..checked_step(index, 2)?) == Some(b"/*") {
                block_depth = block_depth
                    .checked_add(1)
                    .ok_or_else(|| AuditError::new("COMMENT_DEPTH_OVERFLOW"))?;
                index = checked_step(index, 2)?;
            } else if bytes.get(index..checked_step(index, 2)?) == Some(b"*/") {
                block_depth = block_depth
                    .checked_sub(1)
                    .ok_or_else(|| AuditError::new("COMMENT_DEPTH_UNDERFLOW"))?;
                index = checked_step(index, 2)?;
            } else {
                index = checked_step(index, 1)?;
            }
            continue;
        }
        if bytes.get(index..checked_step(index, 2)?) == Some(b"//") {
            while index < bytes.len() && bytes[index] != b'\n' {
                index = checked_step(index, 1)?;
            }
            continue;
        }
        if bytes.get(index..checked_step(index, 2)?) == Some(b"/*") {
            block_depth = 1;
            index = checked_step(index, 2)?;
            continue;
        }
        if let Some(end) = raw_string_end(bytes, index)? {
            index = end;
            continue;
        }
        if bytes[index] == b'"'
            || (bytes[index] == b'b' && bytes.get(checked_step(index, 1)?) == Some(&b'"'))
        {
            index = quoted_end(bytes, index, b'"')?;
            continue;
        }
        if bytes[index] == b'\'' && is_char_literal(bytes, index)? {
            index = quoted_end(bytes, index, b'\'')?;
            continue;
        }
        output[index] = bytes[index];
        index = checked_step(index, 1)?;
    }
    if block_depth != 0 {
        return Err(AuditError::new("UNCLOSED_BLOCK_COMMENT"));
    }
    String::from_utf8(output).map_err(|_| AuditError::new("CODE_PROJECTION_UTF8"))
}

fn raw_string_end(bytes: &[u8], index: usize) -> Result<Option<usize>> {
    let mut cursor = index;
    if bytes.get(cursor) == Some(&b'b') {
        cursor = checked_step(cursor, 1)?;
    }
    if bytes.get(cursor) != Some(&b'r') {
        return Ok(None);
    }
    cursor = checked_step(cursor, 1)?;
    let mut hashes = 0_usize;
    while bytes.get(cursor) == Some(&b'#') {
        hashes = checked_step(hashes, 1)?;
        cursor = checked_step(cursor, 1)?;
    }
    if bytes.get(cursor) != Some(&b'"') {
        return Ok(None);
    }
    cursor = checked_step(cursor, 1)?;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' {
            let after_quote = checked_step(cursor, 1)?;
            let end = after_quote
                .checked_add(hashes)
                .ok_or_else(|| AuditError::new("INDEX_OVERFLOW"))?;
            if end <= bytes.len() && bytes[after_quote..end].iter().all(|byte| *byte == b'#') {
                return Ok(Some(end));
            }
        }
        cursor = checked_step(cursor, 1)?;
    }
    Err(AuditError::new("UNCLOSED_RAW_STRING"))
}

fn quoted_end(bytes: &[u8], index: usize, quote: u8) -> Result<usize> {
    let mut cursor = if bytes[index] == b'b' {
        checked_step(index, 2)?
    } else {
        checked_step(index, 1)?
    };
    let mut escaped = false;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        cursor = checked_step(cursor, 1)?;
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == quote {
            return Ok(cursor);
        }
    }
    Err(AuditError::new("UNCLOSED_QUOTED_LITERAL"))
}

fn is_char_literal(bytes: &[u8], index: usize) -> Result<bool> {
    let next_index = checked_step(index, 1)?;
    let Some(next) = bytes.get(next_index).copied() else {
        return Ok(false);
    };
    if next == b'\\' {
        return Ok(true);
    }
    let close_index = checked_step(index, 2)?;
    Ok(bytes.get(close_index) == Some(&b'\''))
}

fn checked_step(index: usize, step: usize) -> Result<usize> {
    index
        .checked_add(step)
        .ok_or_else(|| AuditError::new("INDEX_OVERFLOW"))
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_identifier_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn source_id(scope: &str, relative: &str) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SOURCE_ID_DOMAIN);
    bytes.push(0);
    bytes.extend_from_slice(scope.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(relative.as_bytes());
    hex(&sha256(&bytes))
}

fn bool_count(value: bool) -> u64 {
    u64::from(value)
}

fn bump(value: &mut u64) -> Result<()> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| AuditError::new("COUNT_OVERFLOW"))?;
    Ok(())
}

fn text(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| AuditError::new("TEXT_NOT_UTF8"))
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
    fn sha_vectors_match() {
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
    fn float_scanner_sees_code_and_ignores_text() {
        assert!(contains_rust_float_code(b"fn x(v: f64) { let y = 1.25; }").unwrap());
        assert!(contains_rust_float_code(b"fn x() { let y = 1e3; }").unwrap());
        assert!(contains_rust_float_code(b"fn x() { let y = 1.; let z = 2f32; }").unwrap());
        assert!(
            !contains_rust_float_code(b"// f64 1.25\nconst V: &str = r#\"f32 2.5 1.81.0\"#;")
                .unwrap()
        );
        assert!(!contains_rust_float_code(b"fn x() { let r = 1..25; }").unwrap());
        assert!(!contains_rust_float_code(
            b"fn x() { let a = 0xff_u32; let b = 12usize; let c = 0b1010; }"
        )
        .unwrap());
    }

    #[test]
    fn artifact_reference_is_case_insensitive() {
        assert!(contains_artifact_reference(b"OUTPUT.HBP"));
        assert!(contains_artifact_reference(b"hbi,hbp,sha,sh,hash"));
        assert!(!contains_artifact_reference(b"ordinary source"));
    }

    #[test]
    fn clippy_binding_is_exact_and_on_the_hard_gate_line() {
        let manifest = "matrix/audit/Cargo.toml";
        let good = "cargo +1.81.0 clippy --manifest-path matrix/audit/Cargo.toml --all-targets --locked -- -D warnings -D clippy::float_arithmetic";
        let wrong_command = "cargo +1.81.0 fmt --manifest-path matrix/audit/Cargo.toml -- --check\ncargo +1.81.0 clippy --manifest-path matrix/other/Cargo.toml -- -D warnings -D clippy::float_arithmetic";
        let prefix_only = "cargo +1.81.0 clippy --manifest-path matrix/audit/Cargo.toml.extra -- -D warnings -D clippy::float_arithmetic";
        assert!(workflow_binds_hard_clippy(good, manifest));
        assert!(!workflow_binds_hard_clippy(wrong_command, manifest));
        assert!(!workflow_binds_hard_clippy(prefix_only, manifest));
    }

    #[test]
    fn rendered_rows_publish_identifiers_not_paths() {
        let audit = Audit {
            scope_sha256: "a".repeat(64),
            head_sha: "b".repeat(40),
            counts: Counts::default(),
            debt: Debt::default(),
            sources: vec![SourceFinding {
                id: "c".repeat(64),
                language: "PYTHON",
                migration_required: true,
                float_code: false,
            }],
        };
        let output = String::from_utf8(audit.render_hbp().unwrap()).unwrap();
        assert!(output.contains("path_published=0"));
        assert!(!output.contains("C:\\"));
        assert!(output.lines().all(|line| line.ends_with("|json=0")));
    }
}
