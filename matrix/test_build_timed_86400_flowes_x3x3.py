#!/usr/bin/env python3
"""Focused regression tests for the additive FLOWes X3 X3 V2 builder."""

from __future__ import annotations

import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import build_timed_86400_flowes_x3x3 as flow


class FakeClock:
    def __init__(self) -> None:
        self.now_ns = 0

    def monotonic_ns(self) -> int:
        return self.now_ns

    def sleep(self, seconds: float) -> None:
        self.now_ns += int(seconds * 1_000_000_000)

    def advance(self, seconds: int) -> None:
        self.now_ns += seconds * 1_000_000_000


def seal(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    path.with_name(path.name + ".sha256").write_bytes(flow.sidecar_bytes(path.name, data))


def add_footer(rows: list[str], tag: str) -> bytes:
    body = ("\n".join(rows) + "\n").encode("utf-8")
    rows.append(flow.tuple_row(tag, body_sha256=flow.sha256_bytes(body), rows=len(rows) + 1, json=0))
    return ("\n".join(rows) + "\n").encode("utf-8")


def make_source(directory: Path, folder_count: int = 2) -> flow.SourceBundle:
    leaves = folder_count * len(flow.FAMILIES)
    rows = [
        flow.tuple_row(
            "FOLDEROILRUN", schema=flow.SOURCE_SCHEMA,
            source_schema="TEST-FOLDER-3D-TREE-V1", repositories=1,
            folders=folder_count, families=3, leaves=leaves,
            descriptor_width=64, json=0,
        ),
        flow.tuple_row(
            "SOURCE", sha256=flow.domain_hash("test-source"),
            source_capture_sha256=flow.domain_hash("test-capture"),
            public_set_sha256=flow.domain_hash("test-public"),
            sidecar_verified=1, public_metadata_only=1, raw_paths=0,
            raw_bodies=0, git_tree_commitments=1,
            tree_sha1_recoverable=0, path_dictionary_resistance_claim=0, json=0,
        ),
        flow.tuple_row(
            "CENTER", nullspace=0, center_members=",".join(flow.CENTER_MEMBERS),
            traversal=flow.CENTER_TRAVERSAL, sha_equals_hash=0,
            brown_center="RGB.8B5A2B", close_to=1, json=0,
        ),
        flow.tuple_row("STAGE", i=0, name="FOLDER_HBP_TO_EXACT_INTEGER_3D", integer_only=1, float=0, json=0),
        flow.tuple_row("STAGE", i=1, name="THREE_INDEPENDENT_CALMING_OIL_FAMILIES", families=3, identity_exchange=0, json=0),
        flow.tuple_row("STAGE", i=2, name="SIGNED_STATIC_PROJECTION_AND_DESCRIPTOR_SEAL", formats="HBP,HBI,SVG,GGUF", json=0),
        flow.tuple_row(
            "BOUNDARY", paths_published=0, direct_path_hashes=0,
            raw_tree_sha1_published=0, git_tree_commitments=1,
            path_dictionary_resistance_claim=0, media_bodies_read=0,
            media_bytes_embedded=0, repository_bodies_read=0,
            repository_bytes_embedded=0, private_repo_rows=0,
            private_repo_names=0, credentials=0, network=0, execution=0,
            physical_energy=0, authority=0, system_affirmed=0, json=0,
        ),
    ]
    rows.extend(
        flow.tuple_row(
            "FAMILY", i=family_i, name=family,
            independent_identity=1, calming_oil_label=1,
            physical_energy=0, authority=0, json=0,
        )
        for family_i, family in enumerate(flow.FAMILIES)
    )
    leaf_i = 0
    for folder_i in range(folder_count):
        repo_id = flow.domain_hash("repo", folder_i)
        folder_id = flow.domain_hash("folder", folder_i)
        tree = flow.domain_hash("tree", folder_i)
        obj = flow.domain_hash("object", folder_i)
        for family_i, family in enumerate(flow.FAMILIES):
            leaf_id = flow.domain_hash("leaf", folder_i, family)
            commitments = {
                key: flow.domain_hash("source-" + key, folder_i, family)
                for key in ("hbi", "hbp", "sh", "hash", "sha")
            }
            rows.append(
                flow.tuple_row(
                    "OIL", i=leaf_i, folder_i=folder_i,
                    repo_id=repo_id, folder_id=folder_id,
                    parent_folder_id="0" * 64, sibling_ordinal=folder_i,
                    level=folder_i + 1, source_kind="TEST_TREE", family=family,
                    source_identity_sha256=flow.domain_hash("identity", folder_i),
                    parent_identity_sha256=flow.domain_hash("parent", folder_i),
                    leaf_id=leaf_id, tree_commitment_sha256=tree,
                    object_sha256=obj, direct_blobs=0, direct_trees=0,
                    direct_commits=0, direct_symlinks=0,
                    view_x=folder_i * 100 + family_i,
                    view_y=folder_i * -50 - family_i,
                    view_z=folder_i * 25 + family_i,
                    projected_u=folder_i * 7 + family_i,
                    projected_v=folder_i * -9 - family_i,
                    color=f"RGB.{family_i + 1:06X}",
                    hbi=commitments["hbi"], hbp=commitments["hbp"],
                    sh=commitments["sh"], hash=commitments["hash"],
                    sha=commitments["sha"], path_bytes_embedded=0,
                    media_bytes_embedded=0, repository_bytes_embedded=0,
                    credentials=0, network=0, execution=0,
                    physical_energy=0, authority=0, json=0,
                )
            )
            leaf_i += 1
    rows.extend(
        [
            flow.tuple_row(
                "HASH", role="SPHERICAL_FOLDER_OIL_OBJECT_COMMITMENT",
                algorithm="SHA256", value=flow.domain_hash("source-object"),
                distinct_from_hbp_byte_sha=1, json=0,
            ),
            flow.tuple_row(
                "SUMMARY", repositories=1, folders=folder_count,
                families=3, leaves=leaves, path_bytes_embedded=0,
                media_bytes_embedded=0, repository_bytes_embedded=0,
                credentials=0, network=0, execution=0,
                physical_energy=0, authority=0, json=0,
            ),
        ]
    )
    hbp = add_footer(rows, "FOLDEROILFTR")
    hbp_sha = flow.sha256_bytes(hbp)
    hbi_rows = [
        flow.tuple_row(
            "FOLDEROILIDX", schema=flow.SOURCE_SCHEMA,
            repositories=1, folders=folder_count, families=3,
            leaves=leaves, json=0,
        ),
        flow.tuple_row(
            "SOURCE", schema="TEST-FOLDER-3D-TREE-V1",
            sha256=flow.domain_hash("source-index"), sidecar_verified=1, json=0,
        ),
        flow.tuple_row("ARTIFACT", kind="HBP", file=flow.SOURCE_HBP, sha256=hbp_sha, json=0),
        flow.tuple_row("ARTIFACT", kind="SVG", file="test.svg", sha256=flow.domain_hash("svg"), static=1, script=0, network=0, execution=0, json=0),
        flow.tuple_row("ARTIFACT", kind="GGUF", file="test.gguf", sha256=flow.domain_hash("gguf"), json=0),
        flow.tuple_row("CENTER", nullspace=0, center_members=",".join(flow.CENTER_MEMBERS), traversal=flow.CENTER_TRAVERSAL, sha_equals_hash=0, object_hash=flow.domain_hash("idx-object"), json=0),
        flow.tuple_row("BOUNDARY", credentials=0, network=0, execution=0, physical_energy=0, authority=0, json=0),
        flow.tuple_row("RECIPE", sh="TEST", integer_only=1, float=0, dependencies=0, json=0),
    ]
    hbi = add_footer(hbi_rows, "FOLDEROILIDXFTR")
    directory.mkdir(parents=True, exist_ok=True)
    seal(directory / flow.SOURCE_HBP, hbp)
    seal(directory / flow.SOURCE_HBI, hbi)
    return flow.load_source(directory, require_committed=False)


def crafted_journal(
    source: flow.SourceBundle,
    sessions: tuple[flow.Session, ...],
    session_ids: tuple[int, ...],
    target_seconds: int = 8,
) -> flow.Journal:
    checkpoints: list[flow.Checkpoint] = []
    previous = flow.domain_hash(
        flow.SCHEMA + "|JOURNAL_GENESIS", source.hbp_sha256, target_seconds
    )
    for index, (seconds, session_i) in enumerate(
        zip(flow.schedule(target_seconds), session_ids)
    ):
        credited = seconds - sessions[session_i].baseline_seconds
        digest = flow.checkpoint_hash(
            source.hbp_sha256, target_seconds, index, seconds,
            session_i, credited, previous,
        )
        checkpoints.append(
            flow.Checkpoint(
                index, seconds, session_i, credited, previous, digest
            )
        )
        previous = digest
    return flow.Journal(
        target_seconds, "INJECTED_TEST_CLOCK", source.hbp_sha256,
        source.hbi_sha256, sessions, tuple(checkpoints),
    )


class FlowesV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source_override = os.environ.get("ASOLARIA_FLOWES_SOURCE_DIR")
        cls.source_dir = (
            Path(source_override).resolve()
            if source_override
            else Path(__file__).resolve().parent
        )
        cls.committed = flow.load_source(cls.source_dir)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def small_bundle(self, name: str = "out") -> tuple[Path, Path, flow.SourceBundle]:
        source_dir = self.root / "source"
        source = make_source(source_dir)
        output_dir = self.root / name
        flow.fake_clock_build(
            source_dir, output_dir, require_committed=False, target_seconds=8
        )
        return source_dir, output_dir, source

    def seed_complete_injected_journal(
        self, source_dir: Path, output_dir: Path
    ) -> flow.Journal:
        source = flow.load_source(source_dir, require_committed=False)
        journal = flow.Journal(
            8, "INJECTED_TEST_CLOCK", source.hbp_sha256,
            source.hbi_sha256, (), (),
        )
        journal = flow.begin_session(journal)
        journal = flow.append_reached_checkpoints(journal, 8)
        output_dir.mkdir(parents=True, exist_ok=True)
        with flow.WriterLock(output_dir, "test-seed") as writer_lock:
            flow.save_journal(output_dir, journal, writer_lock)
        return journal

    def test_schedule_and_committed_population(self) -> None:
        checkpoints = flow.schedule(flow.TARGET_SECONDS)
        self.assertEqual(len(checkpoints), 19)
        self.assertEqual(checkpoints[:4], (1, 2, 3, 4))
        self.assertEqual(checkpoints[-1], 86_400)
        self.assertEqual(self.committed.folder_count, 3_536)
        self.assertEqual(len(self.committed.leaves), 10_608)
        self.assertEqual(len(flow.build_cells(self.committed)), 31_824)
        self.assertEqual(len(flow.build_rings(self.committed, checkpoints)), 171)

    def test_fake_bundle_population_json0_and_bindings(self) -> None:
        source_dir, output_dir, source = self.small_bundle()
        hashes = flow.verify_bundle(
            source_dir, output_dir, require_committed=False,
            target_seconds=8, timing_mode="DETERMINISTIC_FAKE_CLOCK",
        )
        self.assertEqual(set(hashes), set(flow.OUTPUT_NAMES))
        for name in flow.OUTPUT_NAMES:
            flow.verify_sidecar(output_dir / name)
        hbp_lines = (output_dir / flow.OUTPUT_HBP).read_text(encoding="utf-8").splitlines()
        self.assertTrue(all(line.endswith("|json=0") for line in hbp_lines))
        rings = [flow.parse_tuple(line, "RING") for line in hbp_lines if line.startswith("RING|")]
        cells = [flow.parse_tuple(line, "FLOWE") for line in hbp_lines if line.startswith("FLOWE|")]
        self.assertEqual(len(rings), 45)
        self.assertEqual(len(cells), source.folder_count * 9)
        self.assertTrue(all(int(row["observed_rows"]) <= 60 for row in rings))
        self.assertTrue(all(row["observed_only"] == "1" and row["future_rows"] == "0" for row in rings))
        for row in cells:
            values = [row[key] for key in ("hbi", "hbp", "sha", "sh", "hash")]
            self.assertEqual(len(set(values)), 5)
            self.assertEqual(row["network"], row["execution"])
            self.assertEqual(row["execution"], row["authority"])
            self.assertEqual(row["authority"], row["physical_energy"])
            self.assertEqual(row["physical_energy"], "0")
        hbi = (output_dir / flow.OUTPUT_HBI).read_text(encoding="utf-8")
        self.assertIn(f"file={flow.OUTPUT_STDOUT}", hbi)
        self.assertIn(f"file={flow.OUTPUT_JOURNAL}", hbi)

    def test_ring_previous_hash_chain_per_axis(self) -> None:
        source_dir, output_dir, source = self.small_bundle()
        lines = (output_dir / flow.OUTPUT_HBP).read_text(encoding="utf-8").splitlines()
        rings = [flow.parse_tuple(line, "RING") for line in lines if line.startswith("RING|")]
        previous: dict[tuple[str, str], str] = {}
        for row in rings:
            axis = (row["family"], row["direction"])
            if axis in previous:
                self.assertEqual(row["previous_ring_hash"], previous[axis])
            else:
                self.assertEqual(
                    row["previous_ring_hash"],
                    flow.domain_hash(flow.SCHEMA + "|RING_GENESIS", source.hbp_sha256, *axis),
                )
            previous[axis] = row["ring_hash"]

    def test_deterministic_fake_clock_build(self) -> None:
        source_dir, first, _ = self.small_bundle("first")
        second = self.root / "second"
        flow.fake_clock_build(
            source_dir, second, require_committed=False, target_seconds=8
        )
        for name in flow.OUTPUT_NAMES:
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())

    def test_conservative_restart_ignores_process_gap(self) -> None:
        source_dir = self.root / "source"
        make_source(source_dir)
        output_dir = self.root / "watch"
        clock = FakeClock()
        first = flow.watch(
            source_dir, output_dir, require_committed=False,
            target_seconds=8, clock=clock, poll_seconds=1,
            stop_after_checkpoints=4, emit=lambda _: None,
        )
        self.assertEqual(first.accumulated_seconds, 4)
        self.assertEqual(len(first.sessions), 1)
        clock.advance(100)
        second = flow.watch(
            source_dir, output_dir, require_committed=False,
            target_seconds=8, clock=clock, poll_seconds=1, emit=lambda _: None,
        )
        self.assertTrue(second.complete)
        self.assertEqual(second.accumulated_seconds, 8)
        self.assertEqual(len(second.sessions), 2)
        self.assertEqual(second.sessions[1].baseline_seconds, 4)
        self.assertEqual(second.checkpoints[-1].session_credited_seconds, 4)
        flow.verify_bundle(
            source_dir, output_dir, require_committed=False,
            target_seconds=8, timing_mode="INJECTED_TEST_CLOCK",
        )

    def test_injected_clock_cannot_claim_real_measured_timing(self) -> None:
        source_dir = self.root / "source"
        make_source(source_dir)
        output_dir = self.root / "injected"
        flow.watch(
            source_dir, output_dir, require_committed=False,
            target_seconds=8, clock=FakeClock(), poll_seconds=1,
            emit=lambda _: None,
        )
        header = flow.parse_tuple(
            (output_dir / flow.OUTPUT_HBP).read_text(encoding="utf-8").splitlines()[0],
            "FLOWEX9V2HDR",
        )
        self.assertEqual(header["timing_mode"], "INJECTED_TEST_CLOCK")
        self.assertEqual(header["timing_evidence"], "INJECTED_CLOCK_TEST_ONLY")
        self.assertNotIn("MEASURED", header["timing_evidence"])
        flow.verify_bundle(
            source_dir, output_dir, require_committed=False,
            target_seconds=8, timing_mode="INJECTED_TEST_CLOCK",
        )
        direct_output = self.root / "direct-real-attack"
        with flow.WriterLock(direct_output, "test-attack") as writer_lock:
            with self.assertRaises(flow.FlowesError):
                flow._watch_locked(
                    source_dir, direct_output, writer_lock=writer_lock,
                    timing_mode="REAL_MONOTONIC", require_committed=False,
                    target_seconds=8, clock=FakeClock(), poll_seconds=1,
                    stop_after_checkpoints=1, emit=lambda _: None,
                )

    def test_writer_lock_contention_and_reacquisition(self) -> None:
        output_dir = self.root / "locked"
        with flow.WriterLock(output_dir, "first") as first:
            first.assert_held(output_dir)
            with self.assertRaises(flow.FlowesError):
                with flow.WriterLock(output_dir, "second"):
                    self.fail("overlapping writer acquired the same output lock")
        with flow.WriterLock(output_dir, "after-release") as reacquired:
            reacquired.assert_held(output_dir)

    @unittest.skipUnless(os.name == "nt", "Windows paths are case-insensitive")
    def test_writer_lock_rejects_case_alias_before_output_exists(self) -> None:
        output_dir = self.root / "Flowe-Lock-Case-Audit"
        alternate = Path(str(output_dir).swapcase())
        self.assertFalse(output_dir.exists())
        self.assertNotEqual(str(output_dir), str(alternate))
        with flow.WriterLock(output_dir, "first") as first:
            first.assert_held(alternate)
            with self.assertRaises(flow.FlowesError):
                with flow.WriterLock(alternate, "case-alias"):
                    self.fail("case alias acquired a second writer lock")

    def test_final_fake_build_report_occurs_while_writer_lock_is_held(self) -> None:
        source_dir = self.root / "source"
        make_source(source_dir)
        output_dir = self.root / "locked-report"
        callback_observed_contention: list[bool] = []

        def emit(_: str) -> None:
            try:
                with flow.WriterLock(output_dir, "competing-writer"):
                    callback_observed_contention.append(False)
            except flow.FlowesError:
                callback_observed_contention.append(True)

        flow.fake_clock_build(
            source_dir, output_dir, require_committed=False,
            target_seconds=8, emit=emit,
        )
        self.assertEqual(callback_observed_contention, [True])

    def test_complete_journal_without_outputs_materializes_on_restart(self) -> None:
        source_dir = self.root / "source"
        make_source(source_dir)
        output_dir = self.root / "crash-before-publish"
        self.seed_complete_injected_journal(source_dir, output_dir)
        self.assertFalse((output_dir / flow.OUTPUT_HBP).exists())
        result = flow.watch(
            source_dir, output_dir, require_committed=False,
            target_seconds=8, clock=FakeClock(), poll_seconds=1,
            emit=lambda _: None,
        )
        self.assertTrue(result.complete)
        flow.verify_bundle(
            source_dir, output_dir, require_committed=False,
            target_seconds=8, timing_mode="INJECTED_TEST_CLOCK",
        )

    def test_restart_repairs_wholly_missing_pair_only(self) -> None:
        source_dir = self.root / "source"
        make_source(source_dir)
        output_dir = self.root / "missing-pair"
        self.seed_complete_injected_journal(source_dir, output_dir)
        flow.watch(
            source_dir, output_dir, require_committed=False,
            target_seconds=8, clock=FakeClock(), poll_seconds=1, emit=lambda _: None,
        )
        expected = (output_dir / flow.OUTPUT_HBI).read_bytes()
        (output_dir / flow.OUTPUT_HBI).unlink()
        (output_dir / (flow.OUTPUT_HBI + ".sha256")).unlink()
        flow.watch(
            source_dir, output_dir, require_committed=False,
            target_seconds=8, clock=FakeClock(), poll_seconds=1, emit=lambda _: None,
        )
        self.assertEqual((output_dir / flow.OUTPUT_HBI).read_bytes(), expected)

    def test_restart_rejects_orphan_output_pair(self) -> None:
        source_dir = self.root / "source"
        make_source(source_dir)
        output_dir = self.root / "orphan"
        self.seed_complete_injected_journal(source_dir, output_dir)
        flow.watch(
            source_dir, output_dir, require_committed=False,
            target_seconds=8, clock=FakeClock(), poll_seconds=1, emit=lambda _: None,
        )
        (output_dir / (flow.OUTPUT_HBI + ".sha256")).unlink()
        with self.assertRaises(flow.FlowesError):
            flow.watch(
                source_dir, output_dir, require_committed=False,
                target_seconds=8, clock=FakeClock(), poll_seconds=1, emit=lambda _: None,
            )

    def test_restart_rejects_mismatched_existing_pair(self) -> None:
        source_dir = self.root / "source"
        make_source(source_dir)
        output_dir = self.root / "mismatch"
        self.seed_complete_injected_journal(source_dir, output_dir)
        flow.watch(
            source_dir, output_dir, require_committed=False,
            target_seconds=8, clock=FakeClock(), poll_seconds=1, emit=lambda _: None,
        )
        path = output_dir / flow.OUTPUT_HBI
        seal(path, path.read_bytes().replace(b"status=COMPLETE", b"status=TAMPERED", 1))
        with self.assertRaises(flow.FlowesError):
            flow.watch(
                source_dir, output_dir, require_committed=False,
                target_seconds=8, clock=FakeClock(), poll_seconds=1, emit=lambda _: None,
            )

    def test_canonical_bad_session_baselines_and_rollback_are_rejected(self) -> None:
        source_dir = self.root / "source"
        source = make_source(source_dir)
        cases = {
            "future": crafted_journal(
                source, (flow.Session(0, 0), flow.Session(1, 8)),
                (0, 0, 0, 0, 1),
            ),
            "regressed": crafted_journal(
                source, (flow.Session(0, 0), flow.Session(1, 2)),
                (0, 0, 0, 0, 1),
            ),
            "rollback": crafted_journal(
                source, (flow.Session(0, 0), flow.Session(1, 4)),
                (0, 0, 1, 0, 1),
            ),
            "unused-session": crafted_journal(
                source, (flow.Session(0, 0), flow.Session(1, 1)),
                (1, 1, 1, 1, 1),
            ),
        }
        for name, journal in cases.items():
            with self.subTest(name=name):
                output_dir = self.root / ("bad-" + name)
                output_dir.mkdir()
                seal(output_dir / flow.OUTPUT_JOURNAL, flow.journal_bytes(journal))
                with self.assertRaises(flow.FlowesError):
                    flow.load_journal(
                        output_dir, source, 8, "INJECTED_TEST_CLOCK"
                    )

    def test_cell_object_hash_binds_all_five_center_commitments(self) -> None:
        source_dir = self.root / "source"
        source = make_source(source_dir)
        cells = list(flow.build_cells(source))
        before = flow.cell_aggregate_hash(cells)
        commitments = list(cells[0].commitments)
        commitments[2] = flow.domain_hash("tampered-SHA-center-member")
        cells[0] = replace(cells[0], commitments=tuple(commitments))
        after = flow.cell_aggregate_hash(cells)
        self.assertNotEqual(before, after)

    def test_source_sidecar_tamper_is_rejected(self) -> None:
        source_dir = self.root / "source"
        make_source(source_dir)
        path = source_dir / flow.SOURCE_HBP
        path.write_bytes(path.read_bytes() + b"X")
        with self.assertRaises(flow.FlowesError):
            flow.load_source(source_dir, require_committed=False)

    def test_noncanonical_sidecar_bytes_are_rejected(self) -> None:
        target = self.root / "canonical.hbp"
        data = b"ROW|json=0\n"
        target.write_bytes(data)
        canonical = flow.sidecar_bytes(target.name, data)
        variants = (
            canonical.rstrip(b"\n"),
            b" " + canonical,
            canonical.replace(b"  ", b"\t"),
            canonical + b"\n",
        )
        for variant in variants:
            with self.subTest(variant=variant):
                target.with_name(target.name + ".sha256").write_bytes(variant)
                with self.assertRaises(flow.FlowesError):
                    flow.verify_sidecar(target)

    def test_output_tamper_with_resealed_sidecar_is_rejected(self) -> None:
        source_dir, output_dir, _ = self.small_bundle()
        path = output_dir / flow.OUTPUT_HBP
        data = path.read_bytes().replace(b"status=COMPLETE", b"status=TAMPERED", 1)
        seal(path, data)
        with self.assertRaises(flow.FlowesError):
            flow.verify_bundle(
                source_dir, output_dir, require_committed=False,
                target_seconds=8, timing_mode="DETERMINISTIC_FAKE_CLOCK",
            )

    def test_journal_tamper_with_resealed_sidecar_is_rejected(self) -> None:
        source_dir, output_dir, _ = self.small_bundle()
        path = output_dir / flow.OUTPUT_JOURNAL
        data = path.read_bytes().replace(b"monotonic_session_only=1", b"monotonic_session_only=0", 1)
        seal(path, data)
        with self.assertRaises(flow.FlowesError):
            flow.verify_bundle(
                source_dir, output_dir, require_committed=False,
                target_seconds=8, timing_mode="DETERMINISTIC_FAKE_CLOCK",
            )

    def test_gguf_descriptor_corruption_is_rejected(self) -> None:
        source_dir, output_dir, source = self.small_bundle()
        data = bytearray((output_dir / flow.OUTPUT_GGUF).read_bytes())
        data[-1] ^= 1
        with self.assertRaises(flow.FlowesError):
            flow.verify_gguf_bytes(bytes(data), source, 8)


if __name__ == "__main__":
    unittest.main()
