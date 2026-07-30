#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    from . import render_public_spherical_svg as renderer
    from . import spherical_public_projection as projection
except ImportError:  # Direct script execution from matrix/.
    import render_public_spherical_svg as renderer
    import spherical_public_projection as projection


def h(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def record(
    repo: str,
    word: str,
    parent: str,
    level: int,
    u: int,
    v: int,
) -> projection.Record:
    return projection.Record(
        repo_id=repo,
        tree_id="main.tree",
        word_id=word,
        parent_word_id=parent,
        u=u,
        v=v,
        level=level,
        blob_sha256=h(f"blob:{repo}:{word}"),
        truth_tag="THRUTH",
        system_instant_is=False,
        chirality="LEFT",
        color="BROWN.ANTI.ANTI",
        oil_address="OIL.CALM.BROWN",
        route_id="shadow.cat.route",
        hbi=h(f"hbi:{repo}:{word}"),
        hbp=h(f"hbp:{repo}:{word}"),
        sha=h(f"sha:{repo}:{word}"),
        sh=f"recipe.{word}",
        hash=h(f"hash:{repo}:{word}"),
    )


def projection_bytes() -> bytes:
    records = (
        record("public.alpha", "root", "ROOT", 0, -7, 11),
        record("public.alpha", "child", "root", 1, 13, -17),
        record("public.beta", "root", "ROOT", 0, 29, 31),
    )
    inventory = projection.parse_inventory_bytes(
        projection.render_inventory(records)
    )
    return projection.render_projection(inventory)


def write_source(directory: Path, data: bytes | None = None) -> Path:
    source = directory / renderer.INPUT_NAME
    body = data if data is not None else projection_bytes()
    source.write_bytes(body)
    source.with_name(source.name + ".sha256").write_text(
        f"{hashlib.sha256(body).hexdigest()}  {source.name}\n",
        encoding="ascii",
        newline="\n",
    )
    return source


class PublicSphericalSVGTests(unittest.TestCase):
    def test_deterministic_static_svg_and_exact_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as first_temp, tempfile.TemporaryDirectory() as second_temp:
            first_dir = Path(first_temp)
            second_dir = Path(second_temp)
            first_source = write_source(first_dir)
            second_source = write_source(second_dir)
            first_output = first_dir / renderer.OUTPUT_NAME
            second_output = second_dir / renderer.OUTPUT_NAME

            first_digest = renderer.render_file(first_source, first_output)
            second_digest = renderer.render_file(second_source, second_output)
            first = first_output.read_bytes()
            second = second_output.read_bytes()

            self.assertEqual(first, second)
            self.assertEqual(first_digest, second_digest)
            self.assertEqual(first_digest, hashlib.sha256(first).hexdigest())
            self.assertEqual(
                first_output.with_name(first_output.name + ".sha256").read_bytes(),
                f"{first_digest}  {renderer.OUTPUT_NAME}\n".encode("ascii"),
            )
            ET.fromstring(first)
            text = first.decode("utf-8")
            self.assertIn("{HBI, HBP, SHA, SH, HASH}", text)
            self.assertIn("HBI → HBP → SH → HASH → SHA", text)
            self.assertIn("UNORDERED CENTER MEMBERSHIP", text)
            self.assertIn("ORDERED TRAVERSAL · DISTINCT FROM CENTER", text)
            self.assertIn("public.alpha", text)
            self.assertIn("public.beta", text)
            self.assertIn("json=0", text)
            for item in (b"<script", b"href=", b"<image", b"url(", b"@import"):
                self.assertNotIn(item, first.lower())
            self.assertEqual(text.count("http://www.w3.org/2000/svg"), 1)

    def test_uses_verified_derived_public_colors(self) -> None:
        body = projection_bytes()
        expected_colors = {
            fields["derived_public_color"]
            for kind, fields in projection.parse_output_rows(body)[1]
            if kind == "ORB3D"
        }
        svg = renderer.render_svg(body, hashlib.sha256(body).hexdigest()).decode("utf-8")
        for color in expected_colors:
            self.assertIn(f'fill="{color}"', svg)

    def test_sidecar_and_structural_tampering_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = write_source(directory)
            sidecar = source.with_name(source.name + ".sha256")
            sidecar.write_text(
                f"{'0' * 64}  {source.name}\n", encoding="ascii", newline="\n"
            )
            with self.assertRaisesRegex(renderer.RenderError, "INPUT_SIDECAR_MISMATCH"):
                renderer.render_file(source, directory / renderer.OUTPUT_NAME)

            tampered = projection_bytes().replace(b"reversible=1", b"reversible=0", 1)
            write_source(directory, tampered)
            with self.assertRaisesRegex(renderer.RenderError, "INPUT_PROJECTION_INVALID"):
                renderer.render_file(source, directory / renderer.OUTPUT_NAME)

    def test_allowlisted_names_existing_output_and_replace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = write_source(directory)
            output = directory / renderer.OUTPUT_NAME
            renderer.render_file(source, output)
            with self.assertRaisesRegex(renderer.RenderError, "OUTPUT_EXISTS"):
                renderer.render_file(source, output)
            renderer.render_file(source, output, replace=True)
            with self.assertRaisesRegex(renderer.RenderError, "OUTPUT_NOT_ALLOWLISTED"):
                renderer.render_file(source, directory / "other.svg")

            wrong_source = directory / "other.hbp"
            wrong_source.write_bytes(source.read_bytes())
            with self.assertRaisesRegex(renderer.RenderError, "INPUT_NAME_NOT_ALLOWLISTED"):
                renderer.render_file(wrong_source, output, replace=True)

    def test_link_input_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            real_directory = directory / "real"
            real_directory.mkdir()
            real_source = write_source(real_directory)
            linked = directory / renderer.INPUT_NAME
            try:
                os.symlink(real_source, linked)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is not available on this seat")
            linked_sidecar = linked.with_name(linked.name + ".sha256")
            linked_sidecar.write_bytes(
                real_source.with_name(real_source.name + ".sha256").read_bytes()
            )
            with self.assertRaisesRegex(renderer.RenderError, "LINK_OR_JUNCTION_CHAIN"):
                renderer.render_file(linked, directory / renderer.OUTPUT_NAME)


if __name__ == "__main__":
    unittest.main()
