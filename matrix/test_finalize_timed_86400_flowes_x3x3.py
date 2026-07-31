#!/usr/bin/env python3
"""Focused tests for the compact 86,400-second final-witness tool."""

from __future__ import annotations

import ast
import contextlib
import hashlib
import io
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import build_timed_86400_flowes_x3x3 as flow
import finalize_timed_86400_flowes_x3x3 as final
from test_build_timed_86400_flowes_x3x3 import make_source, seal


def reseal_text(path: Path, footer_tag: str, mutate) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    body_rows = lines[:-1]
    mutate(body_rows)
    body = ("\n".join(body_rows) + "\n").encode("utf-8")
    body_rows.append(
        flow.tuple_row(
            footer_tag, body_sha256=flow.sha256_bytes(body),
            rows=len(body_rows) + 1, json=0,
        )
    )
    seal(path, ("\n".join(body_rows) + "\n").encode("utf-8"))


class CompactFinalWitnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source_dir = self.root / "source"
        self.source = make_source(self.source_dir)
        self.output_dir = self.root / "complete"
        self.policy = final._injected_test_policy()
        journal = flow.Journal(
            8, "INJECTED_TEST_CLOCK", self.source.hbp_sha256,
            self.source.hbi_sha256, (), (),
        )
        journal = flow.begin_session(journal)
        journal = flow.append_reached_checkpoints(journal, 8)
        bundle = flow.build_bundle(self.source, journal)
        with flow.WriterLock(self.output_dir, "compact-final-test") as lock:
            flow.write_bundle(self.output_dir, bundle, replace=False, writer_lock=lock)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def mint(self, name: str = "evidence") -> Path:
        evidence = self.root / name
        final._mint(self.source_dir, self.output_dir, evidence, self.policy)
        return evidence

    def verify(self, evidence: Path) -> dict[str, str]:
        return final._verify_public(self.source_dir, evidence, self.policy)

    def test_positive_roundtrip_exact_six_files_and_rows(self) -> None:
        evidence = self.mint()
        hashes = self.verify(evidence)
        self.assertEqual(set(path.name for path in evidence.iterdir()), set(final.PUBLIC_NAMES))
        self.assertEqual(set(hashes), {flow.OUTPUT_JOURNAL, final.FINAL_HBP, final.FINAL_HBI, "artifact_root"})
        hbp = (evidence / final.FINAL_HBP).read_bytes()
        hbi = (evidence / final.FINAL_HBI).read_bytes()
        self.assertEqual(len(hbp.decode("utf-8").splitlines()), 19)
        self.assertEqual(len(hbi.decode("utf-8").splitlines()), 6)
        private = str(self.output_dir.resolve()).encode("utf-8")
        self.assertNotIn(private, hbp)
        self.assertNotIn(private, hbi)
        lines = hbp.decode("utf-8").splitlines()
        local_rows = [
            flow.parse_tuple(line, "LOCALARTIFACT")
            for line in lines
            if line.startswith("LOCALARTIFACT|")
        ]
        self.assertEqual([row["kind"] for row in local_rows], [kind for kind, _ in final.EXPANDED_SPECS])
        self.assertTrue(all(row["published"] == "0" for row in local_rows))
        self.assertTrue(all(row["regenerable"] == "1" for row in local_rows))
        svg = next(row for row in local_rows if row["kind"] == "SVG")
        self.assertEqual(
            {key: svg[key] for key in ("static", "script", "network", "execution")},
            {"static": "1", "script": "0", "network": "0", "execution": "0"},
        )
        gguf = next(row for row in local_rows if row["kind"] == "GGUF")
        self.assertEqual(gguf["descriptor_only"], "1")
        regeneration = flow.parse_tuple(lines[13], "REGENERATION")
        self.assertEqual(regeneration["a_equals_live"], "1")
        self.assertEqual(
            regeneration["a_equals_live_scope"], "MINT_LOCAL_PROVENANCE"
        )

    def test_artifact_root_exact_formula(self) -> None:
        evidence = self.mint()
        hbp_lines = (evidence / final.FINAL_HBP).read_text(encoding="utf-8").splitlines()
        local_rows = [
            flow.parse_tuple(line, "LOCALARTIFACT")
            for line in hbp_lines
            if line.startswith("LOCALARTIFACT|")
        ]
        records = tuple(
            final.ArtifactRecord(
                row["kind"], row["file"], int(row["bytes"]), row["sha256"]
            )
            for row in local_rows
        )
        root = flow.parse_tuple(hbp_lines[12], "ARTIFACTROOT")
        preimage = final.ARTIFACT_ROOT_DOMAIN.encode("utf-8") + b"\0"
        for record in records:
            preimage += (
                record.kind.encode("utf-8") + b"\0"
                + record.name.encode("utf-8") + b"\0"
                + str(record.size).encode("ascii") + b"\0"
                + record.sha256.encode("ascii") + b"\n"
            )
        self.assertEqual(root["value"], hashlib.sha256(preimage).hexdigest())
        self.assertEqual(root["domain"], final.ARTIFACT_ROOT_DOMAIN)
        self.assertEqual(root["order"], final.EXPANDED_ORDER)
        oracle_records = tuple(
            final.ArtifactRecord(kind, name, size, byte * 64)
            for (kind, _), name, size, byte in zip(
                final.EXPANDED_SPECS,
                ("a.hbp", "b.hbi", "c.svg", "d.gguf", "e.hbp"),
                (1, 2, 3, 4, 5),
                ("0", "1", "2", "3", "4"),
            )
        )
        self.assertEqual(
            final.artifact_root(oracle_records),
            "0b2df87bc3a33e0ace98e78a089b69faabcfee45ee71c7a4905ef5aa929b8db0",
        )

    def test_production_rejects_incomplete_and_fake_timing(self) -> None:
        production_test = replace(
            final.PRODUCTION_POLICY, require_committed_source=False
        )
        incomplete = flow.Journal(
            86_400, "REAL_MONOTONIC", self.source.hbp_sha256,
            self.source.hbi_sha256, (), (),
        )
        incomplete = flow.begin_session(incomplete)
        incomplete = flow.append_reached_checkpoints(incomplete, 4)
        incomplete_dir = self.root / "incomplete"
        incomplete_dir.mkdir()
        seal(
            incomplete_dir / flow.OUTPUT_JOURNAL,
            flow.journal_bytes(incomplete),
        )
        with self.assertRaises(flow.FlowesError):
            final._load_complete_journal(self.source, incomplete_dir, production_test)

        fake = flow.fake_complete_journal(self.source, 86_400)
        fake_dir = self.root / "fake-production"
        fake_dir.mkdir()
        seal(fake_dir / flow.OUTPUT_JOURNAL, flow.journal_bytes(fake))
        with self.assertRaises(flow.FlowesError):
            final._load_complete_journal(self.source, fake_dir, production_test)

    def test_modified_session_checkpoint_and_hash_are_rejected(self) -> None:
        cases = {
            "session": lambda rows: rows.__setitem__(
                1, rows[1].replace("baseline_seconds=0", "baseline_seconds=1", 1)
            ),
            "checkpoint": lambda rows: rows.__setitem__(
                2, rows[2].replace("checkpoint_seconds=1", "checkpoint_seconds=2", 1)
            ),
            "hash": lambda rows: rows.__setitem__(
                2, rows[2].replace("checkpoint_hash=", "checkpoint_hash=f", 1)
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                evidence = self.mint("evidence-" + name)
                journal = evidence / flow.OUTPUT_JOURNAL
                reseal_text(journal, "FLOWEX9JOURNALFTR", mutate)
                with self.assertRaises(flow.FlowesError):
                    self.verify(evidence)

    def test_missing_duplicate_and_reordered_local_artifact_are_rejected(self) -> None:
        missing_root = self.root / "missing-root"
        shutil.copytree(self.output_dir, missing_root)
        (missing_root / flow.OUTPUT_SVG).unlink()
        (missing_root / (flow.OUTPUT_SVG + ".sha256")).unlink()
        with self.assertRaises(flow.FlowesError):
            final._mint(self.source_dir, missing_root, self.root / "missing-evidence", self.policy)

        duplicate_root = self.root / "duplicate-root"
        shutil.copytree(self.output_dir, duplicate_root)
        duplicate = duplicate_root / "DUPLICATE.svg"
        seal(duplicate, (duplicate_root / flow.OUTPUT_SVG).read_bytes())
        with self.assertRaises(flow.FlowesError):
            final._mint(self.source_dir, duplicate_root, self.root / "duplicate-evidence", self.policy)

        reordered_root = self.root / "reordered-root"
        shutil.copytree(self.output_dir, reordered_root)

        def swap_artifacts(rows: list[str]) -> None:
            indexes = [i for i, row in enumerate(rows) if row.startswith("ARTIFACT|")]
            rows[indexes[0]], rows[indexes[1]] = rows[indexes[1]], rows[indexes[0]]

        reseal_text(
            reordered_root / flow.OUTPUT_HBI, "FLOWEX9V2IDXFTR", swap_artifacts
        )
        with self.assertRaises(flow.FlowesError):
            final._mint(self.source_dir, reordered_root, self.root / "reordered-evidence", self.policy)

    def test_published_and_regenerable_mutations_are_rejected(self) -> None:
        mutations = {
            "published": ("published=0", "published=1"),
            "regenerable": ("regenerable=1", "regenerable=0"),
        }
        for name, (old, new) in mutations.items():
            with self.subTest(name=name):
                evidence = self.mint("evidence-" + name)

                def mutate(rows: list[str]) -> None:
                    index = next(i for i, row in enumerate(rows) if row.startswith("LOCALARTIFACT|"))
                    rows[index] = rows[index].replace(old, new, 1)

                reseal_text(
                    evidence / final.FINAL_HBP,
                    "LIRISFLOWEX9FINALFTR",
                    mutate,
                )
                with self.assertRaises(flow.FlowesError):
                    self.verify(evidence)

    def test_private_path_injection_is_rejected(self) -> None:
        evidence = self.mint()

        def mutate(rows: list[str]) -> None:
            index = next(i for i, row in enumerate(rows) if row.startswith("LOCALARTIFACT|"))
            fields = flow.parse_tuple(rows[index], "LOCALARTIFACT")
            rows[index] = rows[index].replace(
                "file=" + fields["file"],
                "file=C%3A%5Cprivate%5Csecret.hbp",
                1,
            )

        reseal_text(
            evidence / final.FINAL_HBP, "LIRISFLOWEX9FINALFTR", mutate
        )
        with self.assertRaises(flow.FlowesError):
            self.verify(evidence)
        encoded = flow.tuple_row("ROW", path=str(self.root), json=0).encode("utf-8")
        with self.assertRaises(flow.FlowesError):
            final._assert_paths_absent((encoded,), (self.root,))

    def test_sidecar_tamper_is_rejected(self) -> None:
        evidence = self.mint()
        sidecar = evidence / (final.FINAL_HBI + ".sha256")
        sidecar.write_bytes(sidecar.read_bytes() + b"X")
        with self.assertRaises(flow.FlowesError):
            self.verify(evidence)

        local_root = self.root / "local-sidecar-tamper"
        shutil.copytree(self.output_dir, local_root)
        local_sidecar = local_root / (flow.OUTPUT_GGUF + ".sha256")
        local_sidecar.write_bytes(local_sidecar.read_bytes() + b"X")
        with self.assertRaises(flow.FlowesError):
            final._mint(
                self.source_dir, local_root,
                self.root / "local-sidecar-evidence", self.policy,
            )

    def test_malformed_row_cli_fails_closed_without_private_path(self) -> None:
        evidence = self.mint()

        def mutate(rows: list[str]) -> None:
            index = next(i for i, row in enumerate(rows) if row.startswith("SESSION|"))
            rows[index] = rows[index].replace("baseline_seconds=0|", "", 1)

        reseal_text(
            evidence / flow.OUTPUT_JOURNAL, "FLOWEX9JOURNALFTR", mutate
        )
        with self.assertRaises(flow.FlowesError):
            final._load_complete_journal(self.source, evidence, self.policy)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = final.main(
                ["verify-public", str(self.source_dir), str(evidence)]
            )
        diagnostic = stderr.getvalue()
        self.assertEqual(result, 1)
        self.assertIn("LIRISFLOWEX9FINAL|PASS=0", diagnostic)
        self.assertNotIn("Traceback", diagnostic)
        self.assertNotIn(str(self.root), diagnostic)

    def test_nonempty_destination_and_source_output_overlap_are_rejected(self) -> None:
        occupied = self.root / "occupied"
        occupied.mkdir()
        (occupied / "keep.txt").write_text("keep", encoding="utf-8")
        with self.assertRaises(flow.FlowesError):
            final._mint(self.source_dir, self.output_dir, occupied, self.policy)
        with self.assertRaises(flow.FlowesError):
            final._mint(
                self.source_dir, self.output_dir,
                self.output_dir / "public-evidence", self.policy,
            )

    def test_cli_has_no_target_or_timing_override(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                final.parse_args(
                    [
                        "mint", "source", "complete", "evidence",
                        "--target-seconds", "8",
                    ]
                )
            with self.assertRaises(SystemExit):
                final.parse_args(
                    [
                        "verify-public", "source", "evidence",
                        "--timing-mode", "INJECTED_TEST_CLOCK",
                    ]
                )

    def test_production_module_adds_no_float_literals(self) -> None:
        tree = ast.parse(Path(final.__file__).read_text(encoding="utf-8"))
        values = [
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, float)
        ]
        self.assertEqual(values, [])


if __name__ == "__main__":
    unittest.main()
