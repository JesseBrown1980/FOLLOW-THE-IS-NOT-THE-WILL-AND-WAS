#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import spherical_public_projection as projection


def h(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def make_record(
    word: str,
    parent: str,
    level: int,
    tag: str,
    *,
    u: int,
    v: int,
    instant: bool,
    chirality: str = "LEFT",
) -> projection.Record:
    return projection.Record(
        repo_id="public.repo",
        tree_id="main.tree",
        word_id=word,
        parent_word_id=parent,
        u=u,
        v=v,
        level=level,
        blob_sha256=h("blob:" + word),
        truth_tag=tag,
        system_instant_is=instant,
        chirality=chirality,
        color="BROWN.ANTI.ANTI",
        oil_address="OIL.NEGATIVE.CENTRE.POSITIVE",
        route_id="shadow.cat.route",
        hbi=h("hbi:" + word),
        hbp=h("hbp:" + word),
        sha=h("sha:" + word),
        sh="recipe." + word,
        hash=h("hash:" + word),
    )


def records() -> tuple[projection.Record, ...]:
    return (
        make_record(
            "root",
            "ROOT",
            0,
            "THRUTH",
            u=-7,
            v=11,
            instant=False,
        ),
        make_record(
            "lie.child",
            "root",
            1,
            "LIE",
            u=-3,
            v=-5,
            instant=True,
        ),
        make_record(
            "thruth.child",
            "root",
            2,
            "THRUTH",
            u=13,
            v=-17,
            instant=True,
            chirality="RIGHT",
        ),
    )


class SphericalPublicProjectionTests(unittest.TestCase):
    def test_deterministic_reversible_non_coplanar_projection(self) -> None:
        inventory_bytes = projection.render_inventory(records())
        inventory = projection.parse_inventory_bytes(inventory_bytes)
        first = projection.render_projection(inventory)
        second = projection.render_projection(inventory)
        self.assertEqual(first, second)
        self.assertEqual(projection.verify_projection_bytes(first), projection.digest(first))

        text = first.decode("utf-8")
        self.assertIn("truth_tag=LIE", text)
        self.assertIn("truth_tag=THRUTH", text)
        self.assertEqual(text.count("ORB3D|"), 3)
        self.assertEqual(text.count("PROJECTION2D|"), 3)
        self.assertEqual(text.count("PRISM_WARNING|"), 3)
        self.assertEqual(text.count("CHIRAL_SWITCH|"), 3)
        self.assertEqual(text.count("SELFREPORT|"), 2)
        self.assertIn("signed_u=-7|signed_v=11|recovered_u=-7|recovered_v=11", text)
        self.assertIn("brown_center=999999/1000000", text)

        raw_lines, parsed = projection.parse_output_rows(first)
        del raw_lines
        for fields in (item for kind, item in parsed if kind == "ORB3D"):
            vertices = tuple(
                projection.parse_point(fields[f"vertex_{index}"])
                for index in range(4)
            )
            self.assertNotEqual(projection.tetra_volume6(vertices), 0)

    def test_center_prism_and_chiral_contracts(self) -> None:
        output = projection.render_projection(
            projection.parse_inventory_bytes(
                projection.render_inventory(records())
            )
        )
        _, parsed = projection.parse_output_rows(output)
        center = projection.one_row(parsed, "CENTER")
        self.assertEqual(
            center["exact"],
            "CENTER(NULLSPACE)=0={HBI,HBP,SHA,SH,HASH}",
        )
        self.assertEqual(center["members"], "HBI,HBP,SHA,SH,HASH")
        self.assertEqual(center["traversal"], "HBI->HBP->SH->HASH->SHA")
        self.assertEqual(center["value"], "0")

        for kind in ("PROJECTION2D", "PRISM_WARNING", "CHIRAL_SWITCH"):
            for fields in (item for row_kind, item in parsed if row_kind == kind):
                self.assertEqual(fields["bidirectional_prism_warning"], "1")
                self.assertEqual(fields["carrier_layer"], projection.CARRIER_LAYER)
                self.assertEqual(fields["spherical_is_field_bidirectional"], "0")
                self.assertEqual(fields["identity_exchange"], "0")
                members = tuple(
                    fields[name] for name in ("hbi", "hbp", "sha", "sh", "hash")
                )
                self.assertEqual(len(set(members)), 5)
                self.assertNotEqual(fields["sha"], fields["hash"])
        reports = [item for kind, item in parsed if kind == "SELFREPORT"]
        self.assertTrue(reports)
        for fields in reports:
            self.assertEqual(
                fields["destination"], "SHADOW_CAT_INFINITY_HOTEL"
            )
            self.assertEqual(fields["network_opened"], "0")
            self.assertEqual(fields["authority_granted"], "0")
            self.assertEqual(fields["publication_gate"], "EXPLICIT_REQUIRED")

    def test_deterministic_public_color_and_chirality(self) -> None:
        item = records()[1]
        color = projection.color_from_commitment(item.blob_sha256)
        self.assertRegex(color, r"^#[0-9A-F]{6}$")
        self.assertEqual(
            color, projection.color_from_commitment(item.blob_sha256)
        )
        self.assertEqual(projection.switched_chirality("LEFT", True), "RIGHT")
        self.assertEqual(projection.switched_chirality("RIGHT", True), "LEFT")
        self.assertEqual(projection.switched_chirality("LEFT", False), "LEFT")

    def test_tampering_fails_closed(self) -> None:
        output = projection.render_projection(
            projection.parse_inventory_bytes(
                projection.render_inventory(records())
            )
        )
        tampered = output.replace(b"signed_u=-7", b"signed_u=-8", 1)
        with self.assertRaises(projection.ProjectionError):
            projection.verify_projection_bytes(tampered)

    def test_strict_bounds_paths_center_and_tree(self) -> None:
        with self.assertRaisesRegex(projection.ProjectionError, "INVALID_RECORD_COUNT"):
            projection.render_inventory(tuple(records()[0] for _ in range(513)))

        invalid_level = projection.Record(
            **{**records()[0].__dict__, "level": 61}
        )
        with self.assertRaisesRegex(projection.ProjectionError, "INVALID_LEVEL"):
            projection.render_inventory((invalid_level,))

        invalid_path = projection.Record(
            **{**records()[0].__dict__, "repo_id": "owner/repo"}
        )
        with self.assertRaisesRegex(projection.ProjectionError, "INVALID_REPO_ID"):
            projection.render_inventory((invalid_path,))

        collapsed = projection.Record(
            **{**records()[0].__dict__, "hash": records()[0].sha}
        )
        with self.assertRaisesRegex(projection.ProjectionError, "CENTER_MEMBERS"):
            projection.render_inventory((collapsed,))

        missing_parent = projection.Record(
            **{**records()[1].__dict__, "parent_word_id": "missing"}
        )
        with self.assertRaisesRegex(projection.ProjectionError, "MISSING_OR_AMBIGUOUS_PARENT"):
            projection.render_inventory((records()[0], missing_parent))

    def test_hold_reject_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "bad.hbp"
            output = root / "projection.hbp"
            hold = root / "hold.hbp"
            source.write_bytes(b"NOT-HBP\n")
            output.write_bytes(b"prior-output-stays\n")
            with self.assertRaises(projection.ProjectionError):
                projection.project_file(
                    source,
                    output,
                    replace=True,
                    hold=hold,
                )
            self.assertEqual(output.read_bytes(), b"prior-output-stays\n")
            report = hold.read_text(encoding="utf-8")
            self.assertIn("HOLD|", report)
            self.assertIn("raw_rows_included=0", report)
            self.assertIn("rollback_preserved=1", report)
            self.assertNotIn("NOT-HBP", report)

    def test_atomic_project_and_no_implicit_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "inventory.hbp"
            output = root / "projection.hbp"
            source.write_bytes(projection.render_inventory(records()))
            result = projection.project_file(source, output)
            self.assertEqual(result, projection.verify_projection_file(output))
            with self.assertRaisesRegex(projection.ProjectionError, "OUTPUT_EXISTS"):
                projection.project_file(source, output)

    def test_source_has_no_network_or_process_lane(self) -> None:
        source = Path(projection.__file__).read_text(encoding="utf-8")
        for forbidden in (
            "import subprocess",
            "import socket",
            "urllib.request",
            "requests.",
            "http.client",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
