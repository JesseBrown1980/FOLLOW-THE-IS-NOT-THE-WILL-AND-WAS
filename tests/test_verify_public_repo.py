#!/usr/bin/env python3
"""Regression tests for bounded public-file enumeration."""

from __future__ import annotations

import contextlib
import hashlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
MATRIX_DIR = ROOT_DIR / "matrix"
TESTS_DIR = ROOT_DIR / "tests"
sys.path.insert(0, str(MATRIX_DIR))
sys.path.insert(0, str(TESTS_DIR))

import build_timed_86400_flowes_x3x3 as flow
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
                path.write_text("CURRENT_PROJECTION=RUNNING\n", encoding="utf-8")
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
            (root / "README.md").write_text(
                verifier.COMPACT_FINAL_ACTIVATION_MARKER + "\n",
                encoding="utf-8",
            )
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    verifier.verify_compact_final_gate(root)


if __name__ == "__main__":
    unittest.main()
