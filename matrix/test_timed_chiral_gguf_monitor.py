#!/usr/bin/env python3
"""Tests for the offline timed chiral GGUF monitor."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

try:
    from .spherical_public_projection import Record, render_inventory
    from .timed_chiral_gguf_monitor import (
        GGUF_NAME,
        HBI_NAME,
        HBP_NAME,
        MonitorError,
        TARGET_SECONDS,
        run_monitor,
        schedule,
        verify_gguf,
        watch_monitor,
    )
except ImportError:
    from spherical_public_projection import Record, render_inventory
    from timed_chiral_gguf_monitor import (
        GGUF_NAME,
        HBI_NAME,
        HBP_NAME,
        MonitorError,
        TARGET_SECONDS,
        run_monitor,
        schedule,
        verify_gguf,
        watch_monitor,
    )


def h(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def source_bytes() -> bytes:
    records = (
        Record(
            repo_id="repo.one",
            tree_id="tree.main",
            word_id="root",
            parent_word_id="ROOT",
            u=-7,
            v=9,
            level=0,
            blob_sha256=h("blob"),
            truth_tag="THRUTH",
            system_instant_is=True,
            chirality="LEFT",
            color="RGB.123456",
            oil_address="BROWN.NEAR.ONE",
            route_id="shadow.cat.1",
            hbi=h("hbi"),
            hbp=h("hbp"),
            sha=h("sha"),
            sh="GH.PUBLIC.TREE.V1",
            hash=h("hash"),
        ),
    )
    return render_inventory(records)


class TimedChiralMonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "public.hbp"
        self.output = self.root / "out"
        self.output.mkdir()
        source = source_bytes()
        self.source.write_bytes(source)
        self.source.with_name(self.source.name + ".sha256").write_text(
            f"{hashlib.sha256(source).hexdigest()}  {self.source.name}\n",
            encoding="utf-8",
            newline="\n",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_at(self, seconds: int) -> str:
        return run_monitor(
            self.source,
            self.output,
            started_ns=1_000_000_000,
            clock_ns=lambda: 1_000_000_000 + seconds * 1_000_000_000,
        )

    def test_schedule_starts_one_two_three_four_and_is_bounded(self) -> None:
        values = schedule(TARGET_SECONDS)
        self.assertEqual(values[:4], (1, 2, 3, 4))
        self.assertEqual(values[-1], TARGET_SECONDS)
        self.assertLess(len(values), 32)

    def test_running_reports_and_no_gguf(self) -> None:
        self.assertEqual(self.run_at(4), "RUNNING")
        text = (self.output / HBP_NAME).read_text(encoding="utf-8")
        self.assertIn("status=RUNNING", text)
        self.assertEqual(
            sum(line.startswith("OUTWARD|") for line in text.splitlines()), 4
        )
        self.assertIn("center_membership=HBI,HBP,SHA,SH,HASH", text)
        self.assertIn("traversal=HBI-%3EHBP-%3ESH-%3EHASH-%3ESHA", text)
        self.assertFalse((self.output / GGUF_NAME).exists())
        self.assertFalse((self.output / (GGUF_NAME + ".sha256")).exists())

    def test_completion_emits_valid_descriptor_only_gguf_and_sidecars(self) -> None:
        self.assertEqual(self.run_at(TARGET_SECONDS), "COMPLETE")
        gguf = (self.output / GGUF_NAME).read_bytes()
        source_hash = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.assertEqual(
            verify_gguf(gguf, source_hash, 1, TARGET_SECONDS),
            hashlib.sha256(gguf).hexdigest(),
        )
        self.assertNotIn(b"repo.one", gguf)
        self.assertNotIn(b"tree.main", gguf)
        hbp = (self.output / HBP_NAME).read_bytes()
        hbi = (self.output / HBI_NAME).read_bytes()
        self.assertIn(b"status=COMPLETE", hbp)
        self.assertIn(b"GGUF|state=PRESENT", hbp)
        self.assertIn(hashlib.sha256(gguf).hexdigest().encode("ascii"), hbi)
        for name, data in (
            (GGUF_NAME, gguf),
            (HBP_NAME, hbp),
            (HBI_NAME, hbi),
        ):
            expected = f"{hashlib.sha256(data).hexdigest()}  {name}\n".encode()
            self.assertEqual(
                (self.output / (name + ".sha256")).read_bytes(), expected
            )

    def test_gguf_metadata_is_exact_and_boundary_is_verified(self) -> None:
        self.assertEqual(self.run_at(TARGET_SECONDS), "COMPLETE")
        gguf = bytearray((self.output / GGUF_NAME).read_bytes())
        marker = b"derived public descriptors only; no source rows or repository bytes"
        start = gguf.index(marker)
        gguf[start] ^= 1
        source_hash = hashlib.sha256(self.source.read_bytes()).hexdigest()
        with self.assertRaisesRegex(MonitorError, "GGUF_METADATA"):
            verify_gguf(bytes(gguf), source_hash, 1, TARGET_SECONDS)

    def test_bad_input_fails_before_outputs(self) -> None:
        self.source.write_bytes(b"not-an-hbp\n")
        with self.assertRaises(Exception):
            self.run_at(4)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_source_sidecar_is_required_and_exact(self) -> None:
        self.source.with_name(self.source.name + ".sha256").write_text(
            f"{'0' * 64}  {self.source.name}\n", encoding="utf-8", newline="\n"
        )
        with self.assertRaisesRegex(MonitorError, "SOURCE_SIDECAR_MISMATCH"):
            self.run_at(4)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_early_gguf_is_held(self) -> None:
        (self.output / GGUF_NAME).write_bytes(b"unexpected")
        with self.assertRaisesRegex(MonitorError, "EARLY_GGUF_PRESENT"):
            self.run_at(3)

    def test_source_cannot_be_an_output_role(self) -> None:
        collision = self.output / HBP_NAME
        collision.write_bytes(source_bytes())
        with self.assertRaisesRegex(MonitorError, "PATH_ROLE_COLLISION"):
            run_monitor(
                collision,
                self.output,
                started_ns=0,
                clock_ns=lambda: 4_000_000_000,
            )

    def test_watch_uses_fake_monotonic_clock_and_emits_each_checkpoint(self) -> None:
        class FakeClock:
            def __init__(self) -> None:
                self.nanoseconds = 5_000_000_000

            def now(self) -> int:
                return self.nanoseconds

            def wait(self, seconds: float) -> None:
                self.nanoseconds += int(seconds * 1_000_000_000)

        fake = FakeClock()
        progress: list[str] = []
        self.assertEqual(
            watch_monitor(
                self.source,
                self.output,
                started_ns=fake.now(),
                clock_ns=fake.now,
                wait=fake.wait,
                progress=progress.append,
                target_seconds=8,
            ),
            "COMPLETE",
        )
        self.assertEqual(len(progress), len(schedule(8)))
        self.assertEqual(
            [
                int(row.split("scheduled_seconds=", 1)[1].split("|", 1)[0])
                for row in progress
            ],
            list(schedule(8)),
        )
        self.assertTrue(all(row.endswith("|json=0") for row in progress))
        self.assertIn("status=COMPLETE", progress[-1])
        self.assertTrue((self.output / GGUF_NAME).is_file())


if __name__ == "__main__":
    unittest.main()
