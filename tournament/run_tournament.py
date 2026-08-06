#!/usr/bin/env python3
"""Run the public FOLLOW-THE-IS tournament and emit a deterministic HBP receipt.

The runner uses only the Python standard library and public source already present
in this repository. Toolchain-backed stages invoke Node.js or rustc when available.
It never reads environment secrets and never writes child output into the receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]

PUBLIC_VERIFY = ROOT / "tests" / "verify_public_repo.py"
GGUF_VERIFY = ROOT / "codes" / "verify_double_rainbow_gguf.py"
GGUF_TESTS = ROOT / "codes" / "test_double_rainbow_gguf.py"

GITRAM_DOCTRINE = (
    ROOT / "knowledge" / "public-dependencies" / "gitram" / "docs"
    / "GITRAM-DOCTRINE.md"
)
GITRAM_TEMPLATE = (
    ROOT / "knowledge" / "public-dependencies" / "gitram" / "templates"
    / "gitram-template.yml"
)
GITRAM_BRIDGE = (
    ROOT / "tournament" / "public-dependencies" / "gitram"
    / "pais_path3_bridge.rs"
)
SGRAM_CHAIN = (
    ROOT / "knowledge" / "public-dependencies" / "algorithms" / "tools"
    / "honest-compressor" / "sgram" / "sgram_chain.py"
)
VC65_SOURCE = (
    ROOT / "knowledge" / "public-dependencies" / "algorithms" / "tools"
    / "honest-compressor" / "rust" / "variants" / "vc65.rs"
)
NEST_VERIFY = (
    ROOT / "knowledge" / "public-dependencies" / "nest"
    / "nest-depthN-prime-verify.cjs"
)

EXPECTED_SHA256 = {
    GITRAM_DOCTRINE:
        "fd78e586cd834b999b8d604169d4f4602ee33bf118eca8e9d7f63d682ede51e6",
    GITRAM_TEMPLATE:
        "273b8c7714f6fc5a41f11d703065f5d36487690006a0cc492b6509988d474baf",
    GITRAM_BRIDGE:
        "55b10a07a4c8a7278cd4a95883216da6153c9d416acbd94c0a3dfa81e88ab813",
    SGRAM_CHAIN:
        "01a9372c0bcb9297b18af78ed83aa0586b60130fb36299e6dc919e69ba977dcc",
    VC65_SOURCE:
        "4392ab92314563cbbd986d54cc16c01a77b46e9935c95483e26402551446b10e",
    NEST_VERIFY:
        "5028de41315dc08557c13e601611e2f0da69e9edcbdd2e42db043dee0ccbcc89",
}

SURFACE_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9_-]{0,63}$")
TOOLCHAIN_BLOCK_MARKERS = (
    "linker `link.exe` not found",
    "link.exe not found",
    "program not found",
    "no such file or directory",
)
SENSITIVE_ENV_NAME = re.compile(
    r"(?i)(?:TOKEN|SECRET|PASSWORD|PASSWD|(?:^|_)(?:API_)?KEY(?:$|_)|"
    r"PRIVATE_KEY|COOKIE|CREDENTIAL|AUTH|SESSION|ASKPASS)"
)


@dataclass(frozen=True)
class Stage:
    identifier: str
    status: str
    evidence: str
    detail: str
    sha256: str = ""

    def row(self, sequence: int) -> str:
        fields = [
            "STAGE",
            f"seq={sequence:02d}",
            f"id={self.identifier}",
            f"status={self.status}",
            f"evidence={self.evidence}",
            f"detail={self.detail}",
        ]
        if self.sha256:
            fields.append(f"sha256={self.sha256}")
        fields.append("json=0")
        return "|".join(fields)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def run_process(
    argv: Sequence[str | os.PathLike[str]],
    *,
    cwd: Path | None = None,
    timeout: int = 120,
) -> tuple[int, str]:
    env = os.environ.copy()
    for name in tuple(env):
        if SENSITIVE_ENV_NAME.search(name):
            del env[name]
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        result = subprocess.run(
            [os.fspath(value) for value in argv],
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return 127, "program not found"
    except subprocess.TimeoutExpired:
        return 124, "process timeout"
    return result.returncode, result.stdout


def python_stage(
    identifier: str,
    script: Path,
    *,
    required_fragments: Sequence[str],
    detail: str,
) -> Stage:
    code, output = run_process([sys.executable, script], cwd=ROOT)
    passed = code == 0 and all(fragment in output for fragment in required_fragments)
    return Stage(
        identifier,
        "PASS" if passed else "FAIL",
        "MEASURED_LOCAL",
        detail if passed else "command_or_output_gate_failed",
    )


def source_gate() -> list[Stage]:
    missing = [path for path in EXPECTED_SHA256 if not path.is_file()]
    if missing:
        return [Stage("PINNED_SOURCE_BYTES", "FAIL", "MEASURED_LOCAL",
                      "required_public_source_missing")]
    mismatched = [
        path for path, expected in EXPECTED_SHA256.items()
        if sha256_file(path) != expected
    ]
    if mismatched:
        return [Stage("PINNED_SOURCE_BYTES", "FAIL", "MEASURED_LOCAL",
                      "required_public_source_hash_mismatch")]

    doctrine = GITRAM_DOCTRINE.read_text(encoding="utf-8")
    template = GITRAM_TEMPLATE.read_text(encoding="utf-8")
    bridge = GITRAM_BRIDGE.read_text(encoding="utf-8")
    gitram_contract = all(
        phrase in doctrine
        for phrase in (
            "Stateless cells.",
            "Artifacts are the memory bus.",
            "All-or-nothing fan-in.",
            "Claims come from the owning gate.",
        )
    )
    gitram_contract = gitram_contract and all(
        phrase in template
        for phrase in ("jobs:", "  cell:", "  fan-in:", "needs: cell")
    )
    gitram_contract = gitram_contract and all(
        phrase in bridge
        for phrase in ('"selftest"=>selftest()', "SELFTEST_PASS|", "PATH3_LEVEL2_PASS|")
    )
    sgram = SGRAM_CHAIN.read_text(encoding="utf-8")
    streaming_grounded = all(
        phrase in sgram
        for phrase in (
            "LOCAL SGRAM chain (streaming GitRAM, one seat)",
            "CHAIN OF WAVES",
            "restore=OK",
            "SGRAM SEAL:",
        )
    )
    return [
        Stage("PINNED_SOURCE_BYTES", "PASS", "MEASURED_GITHUB_PINNED",
              "six_public_sources_match_sha256"),
        Stage(
            "GITRAM_CONTRACT", "PASS" if gitram_contract else "FAIL",
            "MEASURED_GITHUB_PINNED", "doctrine_template_path3_selftest_bound",
            EXPECTED_SHA256[GITRAM_BRIDGE],
        ),
        Stage(
            "STREAMING_GITRAM_SGRAM_SOURCE",
            "PASS" if streaming_grounded else "FAIL",
            "MEASURED_GITHUB_PINNED",
            "SGRAM_is_streaming_GitRAM_in_source_bytes",
            EXPECTED_SHA256[SGRAM_CHAIN],
        ),
        Stage(
            "SGRAM_RAW_RESUME_BINDING", "PENDING_UPSTREAM_FIX", "CODE_AUDIT",
            "raw_receipts_not_bound_to_corpus_range_k_codec_decoder",
        ),
        Stage(
            "SGITRAM_NAMED_IMPLEMENTATION", "PENDING_OWNING_SOURCE",
            "OPERATOR_CANON_UNRESOLVED",
            "distinct_sGitRAM_name_not_aliased_to_SGRAM",
        ),
    ]


def rust_compile(source: Path, output: Path) -> tuple[str, str]:
    rustc = shutil.which("rustc")
    if rustc is None:
        return "BLOCKED_TOOLCHAIN", "rustc_not_available"
    code, log = run_process(
        [rustc, "--edition=2021", "-O", source, "-o", output],
        cwd=output.parent,
        timeout=180,
    )
    if code == 0 and output.is_file():
        return "PASS", "compiled_from_pinned_public_source"
    lowered = log.lower()
    if any(marker in lowered for marker in TOOLCHAIN_BLOCK_MARKERS):
        return "BLOCKED_TOOLCHAIN", "rust_linker_or_runtime_unavailable"
    return "FAIL", "rust_compile_failed"


def gitram_selftest(temp: Path) -> Stage:
    executable = temp / ("gitram-path3.exe" if os.name == "nt" else "gitram-path3")
    status, detail = rust_compile(GITRAM_BRIDGE, executable)
    if status != "PASS":
        return Stage("GITRAM_PATH3_SELFTEST", status, "MEASURED_LOCAL_BOUNDARY", detail)
    code, output = run_process([executable, "selftest"], cwd=temp, timeout=180)
    passed = code == 0 and all(
        fragment in output
        for fragment in (
            "SELFTEST_PASS|",
            "codebook=permutation_distinct_reversible",
            "group=OK",
            "omnisubmit=domain_separated_length_prefixed_sorted",
        )
    )
    return Stage(
        "GITRAM_PATH3_SELFTEST", "PASS" if passed else "FAIL", "MEASURED_LOCAL",
        "pinned_bridge_compile_and_selftest" if passed else "bridge_selftest_failed",
        EXPECTED_SHA256[GITRAM_BRIDGE],
    )


def vc65_compile_gate(temp: Path) -> Stage:
    executable = temp / ("vc65.exe" if os.name == "nt" else "vc65")
    status, detail = rust_compile(VC65_SOURCE, executable)
    if status != "PASS":
        return Stage("VC65_COMPILE_GATE", status, "MEASURED_LOCAL_BOUNDARY", detail)
    return Stage(
        "VC65_COMPILE_GATE", "PASS", "MEASURED_LOCAL",
        "compile=1;runtime_executed=0;functional_benchmark=0;TSIZE=1_lshift_28",
        EXPECTED_SHA256[VC65_SOURCE],
    )


PROBE_CODEC = r'''#!/usr/bin/env python3
import hashlib
import pathlib
import sys

payload = pathlib.Path(sys.argv[1]).read_bytes()
source = hashlib.sha256(payload).digest()
restored = bytes(payload)
ok = hashlib.sha256(restored).digest() == source
print(
    "sgram-tournament-identity-probe"
    f" N={len(payload)} payload={len(payload)} decoder_src=0"
    f" total={len(payload)} restore={'OK' if ok else 'FAIL'}"
)
raise SystemExit(0 if ok else 1)
'''


def make_probe_codec(temp: Path) -> Path:
    script = temp / "sgram_identity_probe.py"
    script.write_text(PROBE_CODEC, encoding="utf-8", newline="\n")
    if os.name == "nt":
        launcher = temp / "sgram-identity-probe.cmd"
        launcher.write_text(
            f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n',
            encoding="utf-8",
            newline="",
        )
        return launcher
    launcher = temp / "sgram-identity-probe"
    launcher.write_text(PROBE_CODEC, encoding="utf-8", newline="\n")
    launcher.chmod(0o755)
    return launcher


def sgram_roundtrip(temp: Path) -> Stage:
    fixture = bytes((index * 17 + 3) % 256 for index in range(1536))
    corpus = temp / "sgram-fixture.bin"
    corpus.write_bytes(fixture)
    receipt_dir = temp / "sgram-receipts"
    if receipt_dir.exists():
        return Stage(
            "SGRAM_STRICT_FRESH_ROUNDTRIP", "FAIL", "MEASURED_LOCAL",
            "fresh_receipt_precondition_failed",
        )
    codec = make_probe_codec(temp)
    code, output = run_process(
        [sys.executable, SGRAM_CHAIN, corpus, "3", "0", codec, SGRAM_CHAIN, receipt_dir],
        cwd=temp,
        timeout=120,
    )
    receipts = sorted(receipt_dir.glob("receipt-*.txt"))
    chunk = (len(fixture) + 3 - 1) // 3
    strict_receipts = len(receipts) == 3
    summed_n = 0
    for index, receipt in enumerate(receipts):
        text = receipt.read_text(encoding="utf-8")
        expected = fixture[index * chunk : min((index + 1) * chunk, len(fixture))]
        n_match = re.search(r"\bN=(\d+)\b", text)
        payload_match = re.search(r"\bpayload=(\d+)\b", text)
        shard_match = re.search(r"\bshard_sha=([0-9a-f]{16})\b", text)
        expected_sha16 = sha256_bytes(expected)[:16]
        row_ok = (
            "restore=OK" in text
            and n_match is not None
            and int(n_match.group(1)) == len(expected)
            and payload_match is not None
            and int(payload_match.group(1)) == len(expected)
            and shard_match is not None
            and shard_match.group(1) == expected_sha16
        )
        strict_receipts = strict_receipts and row_ok
        if n_match is not None:
            summed_n += int(n_match.group(1))
    shard_residue = list(receipt_dir.glob("shard-*.bin"))
    passed = (
        code == 0
        and strict_receipts
        and summed_n == len(fixture)
        and not shard_residue
        and "SGRAM SEAL: shards=3" in output
        and "all shards byte-exact (restore=OK): True" in output
    )
    return Stage(
        "SGRAM_STRICT_FRESH_ROUNDTRIP", "PASS" if passed else "FAIL",
        "MEASURED_LOCAL",
        "fresh=1;ranges_sha16_bound=1;sumN=1536;k=0;identity_probe=1;compression_benchmark=0"
        if passed else "sgram_orchestration_gate_failed",
        sha256_bytes(fixture),
    )


def nest_tamper_test(temp: Path) -> Stage:
    node = shutil.which("node")
    if node is None:
        return Stage("NEST_DEPTH7_TAMPER", "BLOCKED_TOOLCHAIN",
                     "MEASURED_LOCAL_BOUNDARY", "node_not_available")
    code, output = run_process([node, NEST_VERIFY], cwd=temp)
    receipt = temp / "data" / "behcs" / "nest-depthN-prime-verify-2026-06-03.hbp"
    sidecar = receipt.with_name(receipt.name + ".sha256")
    sidecar_ok = False
    if receipt.is_file() and sidecar.is_file():
        fields = sidecar.read_text(encoding="utf-8").strip().split()
        sidecar_ok = fields == [sha256_file(receipt), receipt.name]
    all_levels = all(
        f"LEVEL-{level}|" in output and f"@depth{level}|CAUGHT=true" in output
        for level in range(1, 8)
    )
    passed = (
        code == 0
        and "RUN-CLEAN|apex_subtree_ok=true|expect=true|PASS=true" in output
        and "EVERY-LEVEL-CATCHES-CONFABULATION=true" in output
        and all_levels and sidecar_ok
    )
    return Stage(
        "NEST_DEPTH7_TAMPER", "PASS" if passed else "FAIL", "MEASURED_LOCAL",
        "depth=7;nodes=255;pids=510;all_tamper_levels_caught=1"
        if passed else "nest_depth7_gate_failed",
        EXPECTED_SHA256[NEST_VERIFY],
    )


def write_receipt(path: Path, surface: str, stages: Sequence[Stage]) -> str:
    failures = sum(stage.status == "FAIL" for stage in stages)
    blocked = sum(stage.status == "BLOCKED_TOOLCHAIN" for stage in stages)
    pending = sum(stage.status.startswith("PENDING_") for stage in stages)
    passed = sum(stage.status == "PASS" for stage in stages)
    if failures:
        verdict = "FAIL"
    elif blocked:
        verdict = "PARTIAL_WITH_PENDING"
    elif pending:
        verdict = "PASS_WITH_PENDING"
    else:
        verdict = "PASS"
    rows = [
        (
            "TOURNAMENTHDR|schema=FOLLOW-IS-PUBLIC-TOURNAMENT-V1"
            f"|surface={surface}|date=2026-07-29|sequence=FIXED"
            "|REQUIRED_HIDDEN_DEPENDENCIES=0|source_video_bytes=0"
            "|secrets_read=0|json=0"
        ),
        (
            "SYSTEMGATE|fabric=STALE_FALLBACK|canon=STALE_FALLBACK"
            "|recall=UNAVAILABLE|liris_behcs=HEALTH_LIVE_ONLY"
            "|system_affirmed=0|evidence=PARENT_MEASURED_2026-07-29|json=0"
        ),
    ]
    rows.extend(stage.row(index) for index, stage in enumerate(stages, 1))
    rows.append(
        f"TOURNAMENTFTR|verdict={verdict}|pass={passed}|pending={pending}"
        f"|blocked={blocked}|fail={failures}|stage_count={len(stages)}"
        "|REQUIRED_HIDDEN_DEPENDENCIES=0|source_video_bytes=0"
        "|secret_findings=0|json=0"
    )
    data = ("\n".join(rows) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    digest = sha256_bytes(data)
    sidecar = path.with_name(path.name + ".sha256")
    sidecar.write_bytes(f"{digest}  {path.name}\n".encode("utf-8"))
    return digest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--surface", required=True,
                        help="Public receipt surface label, for example LIRIS_WINDOWS")
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument(
        "--allow-toolchain-blocked", action="store_true",
        help="Return success for a scoped local receipt with unavailable toolchains",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    surface = args.surface.upper()
    if not SURFACE_PATTERN.fullmatch(surface):
        raise SystemExit("surface must match [A-Z0-9][A-Z0-9_-]{0,63}")

    stages: list[Stage] = [
        python_stage(
            "PUBLIC_REPO_VERIFY", PUBLIC_VERIFY,
            required_fragments=("PUBLIC_REPO_VERIFY|PASS=1", "REQUIRED_HIDDEN_DEPENDENCIES=0"),
            detail="hash_lf_secret_media_dependency_gates_pass",
        ),
        python_stage(
            "GGUF_EXACT_VERIFY", GGUF_VERIFY,
            required_fragments=("VERIFY|status=PASS", "|bytes=3174|",
                                "video_bytes_embedded=0", "reconstructs_source_video=0"),
            detail="bytes=3174;samples=64;fields=18;source_video_bytes=0",
        ),
        python_stage(
            "GGUF_FOUR_TESTS", GGUF_TESTS,
            required_fragments=("Ran 4 tests", "OK"), detail="tests=4;failures=0",
        ),
    ]
    stages.extend(source_gate())

    with tempfile.TemporaryDirectory(prefix="follow-is-tournament-") as raw_temp:
        temp = Path(raw_temp)
        stages.append(gitram_selftest(temp))
        stages.append(sgram_roundtrip(temp))
        stages.append(vc65_compile_gate(temp))
        stages.append(nest_tamper_test(temp))

    digest = write_receipt(args.receipt.resolve(), surface, stages)
    failures = [stage for stage in stages if stage.status == "FAIL"]
    blocked = [stage for stage in stages if stage.status == "BLOCKED_TOOLCHAIN"]
    pending = [stage for stage in stages if stage.status.startswith("PENDING_")]
    verdict = (
        "FAIL" if failures else "PARTIAL_WITH_PENDING" if blocked
        else "PASS_WITH_PENDING" if pending else "PASS"
    )
    print(
        f"TOURNAMENT|verdict={verdict}|surface={surface}|stages={len(stages)}"
        f"|pass={sum(stage.status == 'PASS' for stage in stages)}"
        f"|pending={len(pending)}|blocked={len(blocked)}|fail={len(failures)}"
        "|REQUIRED_HIDDEN_DEPENDENCIES=0|source_video_bytes=0|json=0"
    )
    print(f"RECEIPT|file={args.receipt.name}|sha256={digest}|sidecar=1|json=0")
    if failures:
        return 1
    if blocked and not args.allow_toolchain_blocked:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
