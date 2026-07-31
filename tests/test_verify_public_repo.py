#!/usr/bin/env python3
"""Regression tests for bounded public-file enumeration."""

from __future__ import annotations

import contextlib
import hashlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT_DIR = Path(__file__).resolve().parents[1]
MATRIX_DIR = ROOT_DIR / "matrix"
TESTS_DIR = ROOT_DIR / "tests"
sys.path.insert(0, str(MATRIX_DIR))
sys.path.insert(0, str(TESTS_DIR))

import build_timed_86400_flowes_x3x3 as flow
import finalize_timed_86400_flowes_x3x3 as final
import verify_public_repo as verifier


class PublicFileEnumerationTests(unittest.TestCase):
    def test_force_added_build_named_path_remains_public(self) -> None:
        paths = verifier.decode_git_file_list(
            b"README.md\0target/declared-public.hbp\0"
        )
        self.assertEqual(
            [path.as_posix() for path in paths],
            ["README.md", "target/declared-public.hbp"],
        )

    def test_traversal_duplicate_and_unterminated_lists_are_rejected(self) -> None:
        for payload in (
            b"../outside\0",
            b"same\0same\0",
            b"unterminated",
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    verifier.decode_git_file_list(payload)


class CompactFinalGateTests(unittest.TestCase):
    def test_checkpoint_domain_hash_matches_launched_builder(self) -> None:
        genesis = verifier.compact_final_domain_hash(
            flow.SCHEMA + "|JOURNAL_GENESIS",
            flow.COMMITTED_SOURCE_HBP_SHA256,
            flow.TARGET_SECONDS,
        )
        self.assertEqual(
            genesis,
            "8f7881ec3768b206384388e690e30449c14818c408edce4ff1aa5e59d63bf666",
        )
        self.assertEqual(
            verifier.compact_final_checkpoint_hash(
                flow.COMMITTED_SOURCE_HBP_SHA256,
                flow.TARGET_SECONDS,
                0,
                1,
                0,
                1,
                genesis,
            ),
            "7686c93990dbe7ce8a30ce5a7872fe2f2f8ac0a87da5ed3b6c62db022759a7bf",
        )

    def test_resealed_fake_checkpoint_chain_is_rejected(self) -> None:
        schedule = flow.schedule(flow.TARGET_SECONDS)
        previous = flow.domain_hash(
            flow.SCHEMA + "|JOURNAL_GENESIS",
            flow.COMMITTED_SOURCE_HBP_SHA256,
            flow.TARGET_SECONDS,
        )
        checkpoints = []
        for index, seconds in enumerate(schedule):
            checkpoint_hash = flow.checkpoint_hash(
                flow.COMMITTED_SOURCE_HBP_SHA256,
                flow.TARGET_SECONDS,
                index,
                seconds,
                0,
                seconds,
                previous,
            )
            checkpoints.append(
                flow.Checkpoint(
                    index, seconds, 0, seconds, previous, checkpoint_hash,
                )
            )
            previous = checkpoint_hash
        journal = flow.Journal(
            flow.TARGET_SECONDS,
            "REAL_MONOTONIC",
            flow.COMMITTED_SOURCE_HBP_SHA256,
            flow.COMMITTED_SOURCE_HBI_SHA256,
            (flow.Session(0, 0),),
            tuple(checkpoints),
        )
        lines = flow.journal_bytes(journal).decode("utf-8").splitlines()
        for index, _ in enumerate(schedule):
            row_index = index + 2
            row = flow.parse_tuple(lines[row_index], "CHECKPOINT")
            fake_previous = (
                "f" * 64
                if index == 0
                else hashlib.sha256(f"fake-{index - 1}".encode()).hexdigest()
            )
            fake_hash = hashlib.sha256(f"fake-{index}".encode()).hexdigest()
            lines[row_index] = flow.tuple_row(
                "CHECKPOINT",
                i=row["i"],
                checkpoint_seconds=row["checkpoint_seconds"],
                session_i=row["session_i"],
                session_credited_seconds=row["session_credited_seconds"],
                previous_hash=fake_previous,
                checkpoint_hash=fake_hash,
                monotonic_session_only=1,
                json=0,
            )
        body = ("\n".join(lines[:-1]) + "\n").encode("utf-8")
        lines[-1] = flow.tuple_row(
            "FLOWEX9JOURNALFTR",
            body_sha256=hashlib.sha256(body).hexdigest(),
            rows=len(lines),
            json=0,
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / flow.OUTPUT_JOURNAL
            path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    verifier.verify_compact_final_journal(path)

    def test_artifact_root_matches_minted_domain_formula(self) -> None:
        records = [
            {
                "kind": kind,
                "file": name,
                "bytes": str(index),
                "sha256": hashlib.sha256(kind.encode("utf-8")).hexdigest(),
            }
            for index, (kind, name) in enumerate(
                verifier.COMPACT_FINAL_EXPANDED, 1,
            )
        ]
        self.assertEqual(
            verifier.compact_final_artifact_root(records),
            "c02d611a7c376591dbd71a23ba686f8b7814aeedaf94a53445c99159edaf9caa",
        )

    def test_absent_partial_and_activated_missing_states(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in verifier.COMPACT_FINAL_ACTIVATION_FILES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    verifier.COMPACT_FINAL_INACTIVE_MARKER + "\n",
                    encoding="utf-8",
                )
            self.assertEqual(
                verifier.verify_compact_final_gate(root),
                (False, False),
            )

            final_dir = root / verifier.COMPACT_FINAL_DIRECTORY
            final_dir.mkdir(parents=True)
            (final_dir / verifier.COMPACT_FINAL_JOURNAL).write_bytes(b"partial\n")
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    verifier.verify_compact_final_gate(root)

            (final_dir / verifier.COMPACT_FINAL_JOURNAL).unlink()
            final_dir.rmdir()
            for relative in verifier.COMPACT_FINAL_ACTIVATION_FILES:
                (root / relative).write_text(
                    verifier.COMPACT_FINAL_ACTIVATION_MARKER + "\n",
                    encoding="utf-8",
                )
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    verifier.verify_compact_final_gate(root)

    def test_activation_requires_exact_three_surface_agreement(self) -> None:
        files = verifier.COMPACT_FINAL_ACTIVATION_FILES
        all_enabled = (1 << len(files)) - 1
        for mask in range(1 << len(files)):
            with self.subTest(mask=mask), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for index, relative in enumerate(files):
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    marker = (
                        verifier.COMPACT_FINAL_ACTIVATION_MARKER
                        if mask & (1 << index)
                        else verifier.COMPACT_FINAL_INACTIVE_MARKER
                    )
                    path.write_text(marker + "\n", encoding="utf-8")
                if mask == 0:
                    self.assertFalse(verifier.compact_final_witness_required(root))
                elif mask == all_enabled:
                    self.assertTrue(verifier.compact_final_witness_required(root))
                else:
                    with contextlib.redirect_stderr(io.StringIO()):
                        with self.assertRaises(SystemExit):
                            verifier.compact_final_witness_required(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in files[:-1]:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    verifier.COMPACT_FINAL_INACTIVE_MARKER + "\n",
                    encoding="utf-8",
                )
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    verifier.compact_final_witness_required(root)

    def test_activation_rejects_missing_or_duplicate_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = []
            for relative in verifier.COMPACT_FINAL_ACTIVATION_FILES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    verifier.COMPACT_FINAL_INACTIVE_MARKER + "\n",
                    encoding="utf-8",
                )
                paths.append(path)
            for invalid in (
                "CURRENT_PROJECTION=RUNNING\n",
                "COMPACT_FINAL_WITNESS_REQUIRED=10\n",
                (
                    verifier.COMPACT_FINAL_INACTIVE_MARKER + "\n"
                    + verifier.COMPACT_FINAL_ACTIVATION_MARKER + "\n"
                ),
                (verifier.COMPACT_FINAL_INACTIVE_MARKER + "\n") * 2,
            ):
                paths[0].write_text(invalid, encoding="utf-8")
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        verifier.compact_final_witness_required(root)

    def test_present_gate_always_runs_owning_deterministic_rebuild(self) -> None:
        root = Path("bounded-test-root")
        final_dir = root / verifier.COMPACT_FINAL_DIRECTORY
        expected = {
            "journal_sha256": "a" * 64,
            "hbp_sha256": "b" * 64,
            "hbi_sha256": "c" * 64,
            "artifact_root_sha256": "d" * 64,
        }
        with (
            mock.patch.object(
                verifier, "compact_final_witness_required", return_value=False,
            ),
            mock.patch.object(
                verifier, "optional_compact_final_witness_present",
                return_value=True,
            ),
            mock.patch.object(
                verifier, "verify_compact_final_deterministic_rebuild",
            ) as rebuild,
            mock.patch.object(
                verifier, "compact_final_rebuild_expectation",
                return_value=expected,
            ),
        ):
            self.assertEqual(
                verifier.verify_compact_final_gate(root), (True, False),
            )
        rebuild.assert_called_once_with(root, final_dir, expected)

    def test_rebuild_result_is_exact_tuple_text_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            matrix = root / "matrix"
            matrix.mkdir()
            tool = matrix / "finalize_timed_86400_flowes_x3x3.py"
            tool.write_text("# bounded test tool\n", encoding="utf-8")
            tool.with_name(tool.name + ".sha256").write_text(
                f"{hashlib.sha256(tool.read_bytes()).hexdigest()}  {tool.name}\n",
                encoding="utf-8",
                newline="\n",
            )
            final_dir = matrix / "timed-86400-flowes-x3x3-final"
            final_dir.mkdir()
            digest = "a" * 64
            expected = {
                "journal_sha256": digest,
                "hbp_sha256": digest,
                "hbi_sha256": digest,
                "artifact_root_sha256": digest,
            }
            valid = (
                "LIRISFLOWEX9FINAL|PASS=1|mode=VERIFY_PUBLIC"
                f"|journal_sha256={digest}|hbp_sha256={digest}"
                f"|hbi_sha256={digest}|artifact_root_sha256={digest}"
                "|independent_time_attestation=0|system_affirmed=0"
                "|credentials=0|json=0\n"
            ).encode("utf-8")
            success = subprocess.CompletedProcess([], 0, valid, b"")
            with mock.patch.object(
                subprocess, "run", return_value=success,
            ) as child:
                verifier.verify_compact_final_deterministic_rebuild(
                    root, final_dir, expected,
                )
            argv = child.call_args.args[0]
            options = child.call_args.kwargs
            self.assertEqual(
                argv[:5], [sys.executable, "-B", "-E", "-s", "-S"],
            )
            self.assertNotIn("shell", options)
            self.assertIs(options["stdin"], subprocess.DEVNULL)
            self.assertEqual(options["timeout"], 180)

            invalid = subprocess.CompletedProcess(
                [], 0, valid.replace(b"json=0", b"json=1"), b"",
            )
            with (
                mock.patch.object(subprocess, "run", return_value=invalid),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                verifier.verify_compact_final_deterministic_rebuild(
                    root, final_dir, expected,
                )

            tool.with_name(tool.name + ".sha256").unlink()
            with (
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                verifier.verify_compact_final_deterministic_rebuild(
                    root, final_dir, expected,
                )


class CompactFinalSemanticContractTests(unittest.TestCase):
    def test_public_gate_matches_production_derived_semantics(self) -> None:
        source = flow.load_source(MATRIX_DIR)
        derived = {
            key: str(value)
            for key, value in final._semantic_fields(
                source, final.PRODUCTION_POLICY,
            ).items()
        }
        self.assertEqual(derived, verifier.COMPACT_FINAL_SEMANTICS)


class GradientAuditGateTests(unittest.TestCase):
    @staticmethod
    def copy_pair(root: Path) -> None:
        for relative in (
            verifier.GRADIENT_AUDIT_HBP,
            verifier.GRADIENT_AUDIT_HBI,
        ):
            source = ROOT_DIR / relative
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
            source_sidecar = source.with_name(source.name + ".sha256")
            target_sidecar = target.with_name(target.name + ".sha256")
            target_sidecar.write_bytes(source_sidecar.read_bytes())

    @staticmethod
    def reseal(path: Path, footer_kind: str) -> None:
        lines = path.read_text(encoding="utf-8").splitlines()
        body = ("\n".join(lines[:-1]) + "\n").encode("utf-8")
        lines[-1] = (
            f"{footer_kind}|body_sha256={hashlib.sha256(body).hexdigest()}"
            f"|rows={len(lines)}|json=0"
        )
        data = ("\n".join(lines) + "\n").encode("utf-8")
        path.write_bytes(data)
        path.with_name(path.name + ".sha256").write_text(
            f"{hashlib.sha256(data).hexdigest()}  {path.name}\n",
            encoding="utf-8",
            newline="\n",
        )

    def test_exact_gradient_pair_is_required_and_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_pair(root)
            with mock.patch.object(verifier, "ROOT", root):
                verifier.verify_rust_181_gradient_semantics_receipt()

    def test_each_gradient_receipt_and_sidecar_is_required(self) -> None:
        relatives = (
            verifier.GRADIENT_AUDIT_HBP,
            verifier.GRADIENT_AUDIT_HBP + ".sha256",
            verifier.GRADIENT_AUDIT_HBI,
            verifier.GRADIENT_AUDIT_HBI + ".sha256",
        )
        for relative in relatives:
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.copy_pair(root)
                    (root / relative).unlink()
                    with mock.patch.object(verifier, "ROOT", root):
                        with contextlib.redirect_stderr(io.StringIO()):
                            with self.assertRaises(SystemExit):
                                verifier.verify_rust_181_gradient_semantics_receipt()

    def test_resealed_binary_semantics_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_pair(root)
            hbp = root / verifier.GRADIENT_AUDIT_HBP
            text = hbp.read_text(encoding="utf-8")
            self.assertIn("|semantic_binary=0|", text)
            hbp.write_text(
                text.replace("|semantic_binary=0|", "|semantic_binary=1|", 1),
                encoding="utf-8",
                newline="\n",
            )
            self.reseal(hbp, "GRADIENTAUDITFTR")
            with mock.patch.object(verifier, "ROOT", root):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        verifier.verify_rust_181_gradient_semantics_receipt()

    def test_resealed_closed_n_level_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_pair(root)
            hbi = root / verifier.GRADIENT_AUDIT_HBI
            text = hbi.read_text(encoding="utf-8")
            self.assertIn("|n_level_open=1|", text)
            hbi.write_text(
                text.replace("|n_level_open=1|", "|n_level_open=0|", 1),
                encoding="utf-8",
                newline="\n",
            )
            self.reseal(hbi, "GRADIENTAUDITIDXFTR")
            with mock.patch.object(verifier, "ROOT", root):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        verifier.verify_rust_181_gradient_semantics_receipt()

    def test_resealed_gradient_and_hbi_binding_tampers_are_rejected(self) -> None:
        mutations = (
            (
                verifier.GRADIENT_AUDIT_HBP,
                "|unique_colors=10586|",
                "|unique_colors=2|",
                "GRADIENTAUDITFTR",
            ),
            (
                verifier.GRADIENT_AUDIT_HBI,
                "|hbp_sha256=" + verifier.GRADIENT_AUDIT_HBP_SHA256 + "|",
                "|hbp_sha256=" + "0" * 64 + "|",
                "GRADIENTAUDITIDXFTR",
            ),
        )
        for relative, old, new, footer_kind in mutations:
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.copy_pair(root)
                    path = root / relative
                    text = path.read_text(encoding="utf-8")
                    self.assertIn(old, text)
                    path.write_text(
                        text.replace(old, new, 1),
                        encoding="utf-8",
                        newline="\n",
                    )
                    self.reseal(path, footer_kind)
                    with mock.patch.object(verifier, "ROOT", root):
                        with contextlib.redirect_stderr(io.StringIO()):
                            with self.assertRaises(SystemExit):
                                verifier.verify_rust_181_gradient_semantics_receipt()


if __name__ == "__main__":
    unittest.main()
