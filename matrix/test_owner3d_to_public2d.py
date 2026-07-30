#!/usr/bin/env python3
"""Focused tests for the sealed OWNER3D -> PUBLIC2D adapter."""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from . import collect_public_owner_inventory as collector
    from . import owner3d_to_public2d as adapter
    from . import spherical_public_projection as projection
except ImportError:  # Direct script execution from matrix/.
    import collect_public_owner_inventory as collector
    import owner3d_to_public2d as adapter
    import spherical_public_projection as projection


class Owner3DToPublic2DTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.hbp_path = self.root / "PUBLIC-OWNER-3D-TREE.hbp"
        self.hbi_path = self.root / "PUBLIC-OWNER-3D-TREE.hbi"
        self.seals = [
            collector.RepoSeal(
                index=0,
                name="alpha-public",
                branch="main",
                state="PUBLIC_TREE_COMPLETE",
                commit="1" * 40,
                tree="2" * 40,
                entries=3,
                blobs=2,
                trees=1,
                commits=0,
                symlinks=0,
                image_entries=1,
                video_entries=1,
                media_declared_bytes=321,
                media_size_unknown_entries=0,
                media_root_sha256="6" * 64,
                object_root_sha256="3" * 64,
                word_rime_root_sha256="4" * 64,
                word_count=7,
                color="#8B5A2B",
            ),
            collector.RepoSeal(
                index=1,
                name="beta-unborn",
                branch="main",
                state="EMPTY_UNBORN",
                commit=collector.ZERO_SHA1,
                tree=collector.ZERO_SHA1,
                entries=0,
                blobs=0,
                trees=0,
                commits=0,
                symlinks=0,
                image_entries=0,
                video_entries=0,
                media_declared_bytes=0,
                media_size_unknown_entries=0,
                media_root_sha256=collector.EMPTY_SHA256,
                object_root_sha256=collector.EMPTY_SHA256,
                word_rime_root_sha256="5" * 64,
                word_count=2,
                color=collector.color_from_root(collector.EMPTY_SHA256),
            ),
        ]
        self.write_owner_seal(collector.build_hbp(
            "JesseBrown1980", "2026-07-29T23:00:00.000Z", self.seals
        ))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write_sidecar(path: Path, data: bytes) -> None:
        path.with_name(path.name + ".sha256").write_bytes(
            f"{hashlib.sha256(data).hexdigest()}  {path.name}\n".encode("ascii")
        )

    def write_owner_seal(self, hbp: bytes) -> None:
        self.hbp_path.write_bytes(hbp)
        self.write_sidecar(self.hbp_path, hbp)
        root = collector.spherical_root(self.seals)
        hbi = collector.build_hbi(
            self.hbp_path, hashlib.sha256(hbp).hexdigest(), root, len(self.seals)
        )
        self.hbi_path.write_bytes(hbi)
        self.write_sidecar(self.hbi_path, hbi)

    def test_collector_center_has_membership_and_traversal_without_sign(self) -> None:
        hbp = self.hbp_path.read_text(encoding="utf-8")
        hbi = self.hbi_path.read_text(encoding="utf-8")
        center = (
            "CENTER|nullspace=0|center_members=HBI,HBP,SHA,SH,HASH"
            "|traversal=HBI,HBP,SH,HASH,SHA|sha_equals_hash=0"
        )
        self.assertIn(center + "|brown_center=#8B5A2B|close_to=1|json=0", hbp)
        self.assertIn(center + "|json=0", hbi)
        self.assertNotIn("|sign=", hbp + hbi)

    def test_media_classifier_is_extension_only_and_blob_only(self) -> None:
        self.assertEqual(collector.media_kind_from_path("art/RAINBOW.PNG", "blob"), "IMAGE")
        self.assertEqual(collector.media_kind_from_path("film/clip.WeBm", "blob"), "VIDEO")
        self.assertIsNone(collector.media_kind_from_path("notes/image.png.txt", "blob"))
        self.assertIsNone(collector.media_kind_from_path("folder/video.mp4", "tree"))
        text = self.hbp_path.read_text(encoding="utf-8")
        self.assertIn("media_classification=PATH_EXTENSION_METADATA_ONLY", text)
        self.assertIn("media_bytes_embedded=0", text)

    def test_media_declared_bytes_keep_unknown_sizes_separate(self) -> None:
        commit = {
            "sha": "1" * 40,
            "commit": {"tree": {"sha": "2" * 40}},
        }
        tree = {
            "truncated": False,
            "tree": [
                {"path": "art/RAINBOW.PNG", "mode": "100644", "type": "blob", "sha": "3" * 40},
                {"path": "film/clip.MP4", "mode": "100644", "type": "blob", "sha": "4" * 40, "size": 123},
                {"path": "notes/clip.mp4.txt", "mode": "100644", "type": "blob", "sha": "5" * 40, "size": 7},
                {"path": "folder.webp", "mode": "040000", "type": "tree", "sha": "6" * 40},
            ],
        }
        repository = {"name": "media-test", "default_branch": "main", "size": 1}
        with mock.patch.object(collector, "run_gh_json", side_effect=[commit, tree]):
            seal = collector.seal_repository("gh", "JesseBrown1980", 0, repository)
        self.assertEqual(seal.image_entries, 1)
        self.assertEqual(seal.video_entries, 1)
        self.assertEqual(seal.media_declared_bytes, 123)
        self.assertEqual(seal.media_size_unknown_entries, 1)
        self.assertNotEqual(seal.media_root_sha256, collector.EMPTY_SHA256)

    def test_media_declared_byte_bound_is_shared_and_exact(self) -> None:
        self.assertEqual(
            collector.MAX_MEDIA_DECLARED_BYTES,
            adapter.MAX_MEDIA_DECLARED_BYTES,
        )
        self.assertEqual(adapter.MAX_MEDIA_DECLARED_BYTES, 1_000_000_000_000_000)
        self.assertEqual(
            adapter.integer(
                str(adapter.MAX_MEDIA_DECLARED_BYTES),
                0,
                adapter.MAX_MEDIA_DECLARED_BYTES,
                "MEDIA_BOUND",
            ),
            adapter.MAX_MEDIA_DECLARED_BYTES,
        )
        with self.assertRaisesRegex(adapter.AdapterError, "MEDIA_BOUND"):
            adapter.integer(
                str(adapter.MAX_MEDIA_DECLARED_BYTES + 1),
                0,
                adapter.MAX_MEDIA_DECLARED_BYTES,
                "MEDIA_BOUND",
            )

    def test_collector_rejects_output_role_aliases_before_writes(self) -> None:
        same = self.root / "SAME.hbp"
        with self.assertRaisesRegex(collector.InventoryError, "path role collision"):
            collector.resolve_output_roles(same, same)
        with self.assertRaisesRegex(collector.InventoryError, "path role collision"):
            collector.resolve_output_roles(
                self.root / "CAPTURE.hbp",
                self.root / "CAPTURE.hbp.sha256",
            )
        with self.assertRaisesRegex(collector.InventoryError, "path role collision"):
            collector.resolve_output_roles(
                self.root / "INDEX.hbi.sha256",
                self.root / "INDEX.hbi",
            )
        output, index = collector.resolve_output_roles(
            self.root / "CAPTURE.hbp",
            self.root / "INDEX.hbi",
        )
        self.assertNotEqual(output, index)

    def test_collector_rejects_linked_output_roles(self) -> None:
        target = self.root / "real-output"
        target.mkdir()
        link = self.root / "linked-output"
        try:
            link.symlink_to(target, target_is_directory=True)
        except (NotImplementedError, OSError):
            self.skipTest("directory symlinks are unavailable on this seat")
        with self.assertRaisesRegex(collector.InventoryError, "link-like path"):
            collector.resolve_output_roles(
                link / "CAPTURE.hbp",
                self.root / "INDEX.hbi",
            )

    def test_collector_rejects_existing_hardlink_aliases(self) -> None:
        output = self.root / "CAPTURE.hbp"
        index = self.root / "INDEX.hbi"
        output.write_bytes(b"sealed")
        try:
            os.link(output, index)
        except OSError:
            self.skipTest("hard links are unavailable on this seat")
        with self.assertRaisesRegex(collector.InventoryError, "path role collision"):
            collector.resolve_output_roles(output, index)

    def test_strict_conversion_is_deterministic_and_projection_accepted(self) -> None:
        first = self.root / "FIRST.hbp"
        second = self.root / "SECOND.hbp"
        first_sha = adapter.convert_file(self.hbi_path, first)
        second_sha = adapter.convert_file(self.hbi_path, second)
        self.assertEqual(first_sha, second_sha)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        parsed = projection.parse_inventory(first)
        self.assertEqual(len(parsed.records), 2)
        self.assertTrue(all(record.level == 0 for record in parsed.records))
        self.assertTrue(all(record.parent_word_id == "ROOT" for record in parsed.records))
        self.assertEqual(sum(record.system_instant_is for record in parsed.records), 1)
        self.assertNotIn(b"alpha-public", first.read_bytes())
        self.assertNotIn(b"beta-unborn", first.read_bytes())
        self.assertNotIn(b"private", first.read_bytes().lower())
        expected_sidecar = f"{first_sha}  {first.name}\n".encode("ascii")
        self.assertEqual(first.with_name(first.name + ".sha256").read_bytes(), expected_sidecar)

    def test_hbp_center_tamper_fails_even_with_resealed_outer_hashes(self) -> None:
        hbp = self.hbp_path.read_bytes().replace(
            b"center_members=HBI,HBP,SHA,SH,HASH",
            b"center_members=HBI,HBP,SH,HASH,SHA",
        )
        self.write_owner_seal(hbp)
        with self.assertRaisesRegex(adapter.AdapterError, "CENTER_CONTRACT"):
            adapter.verify_owner_seal(self.hbi_path)

    def test_extra_private_metadata_field_fails_closed(self) -> None:
        hbp = self.hbp_path.read_bytes().replace(
            b"|branch=main|state=PUBLIC_TREE_COMPLETE",
            b"|branch=main|private=0|state=PUBLIC_TREE_COMPLETE",
            1,
        )
        self.write_owner_seal(hbp)
        with self.assertRaisesRegex(adapter.AdapterError, "REPO_FIELDS"):
            adapter.verify_owner_seal(self.hbi_path)

    def test_sidecar_mismatch_fails_closed(self) -> None:
        self.hbi_path.with_name(self.hbi_path.name + ".sha256").write_bytes(
            f"{'0' * 64}  {self.hbi_path.name}\n".encode("ascii")
        )
        with self.assertRaisesRegex(adapter.AdapterError, "SIDECAR_MISMATCH"):
            adapter.verify_owner_seal(self.hbi_path)

    def test_link_or_junction_chain_is_rejected(self) -> None:
        with mock.patch.object(
            adapter.projection,
            "reject_link_chain",
            side_effect=projection.ProjectionError("LINK_OR_JUNCTION_CHAIN"),
        ):
            with self.assertRaisesRegex(adapter.AdapterError, "LINK_OR_JUNCTION_CHAIN"):
                adapter.verify_owner_seal(self.hbi_path)


if __name__ == "__main__":
    unittest.main()
