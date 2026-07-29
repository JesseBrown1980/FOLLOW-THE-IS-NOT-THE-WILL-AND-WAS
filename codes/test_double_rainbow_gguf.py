#!/usr/bin/env python3
"""Regression tests for the committed Double Rainbow color-state GGUF."""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

from double_rainbow_to_gguf import (
    DEFAULT_OUTPUT,
    DEFAULT_RECEIPT,
    FIELD_NAMES,
    SAMPLE_COUNT,
    SOURCE_ID,
    SOURCE_URL,
    TARGET_BYTES,
)
from verify_double_rainbow_gguf import unsigned_descriptor, verify


class DoubleRainbowGGUFTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.path = Path(DEFAULT_OUTPUT)
        cls.parsed, cls.digest = verify(cls.path)
        cls.descriptor = unsigned_descriptor(cls.parsed)

    def test_exact_size_and_source_commitments(self) -> None:
        self.assertEqual(self.path.stat().st_size, TARGET_BYTES)
        self.assertEqual(self.parsed.metadata["asolaria.source.youtube_id"], SOURCE_ID)
        self.assertEqual(self.parsed.metadata["asolaria.source.url"], SOURCE_URL)
        self.assertEqual(
            self.parsed.metadata["asolaria.source.sha256"],
            "192f77f1eb7e84cf07fb0c9a87ce7ab0611ad7d355452b772d2d20d3b288160f",
        )
        self.assertEqual(self.parsed.metadata["asolaria.source.frames"], 5229)

    def test_descriptor_shape_hash_and_ranges(self) -> None:
        self.assertEqual(len(self.descriptor), SAMPLE_COUNT * len(FIELD_NAMES))
        self.assertEqual(
            hashlib.sha256(self.descriptor).hexdigest(),
            self.parsed.metadata["asolaria.descriptor.sha256"],
        )
        for sample in range(SAMPLE_COUNT):
            start = sample * len(FIELD_NAMES)
            values = self.descriptor[start : start + len(FIELD_NAMES)]
            self.assertEqual(len(values), len(FIELD_NAMES))
            negative, centre, positive = values[9:12]
            self.assertLessEqual(abs((negative + centre + positive) - 255), 1)
            red, green, blue = values[12:15]
            self.assertLessEqual(red + green + blue, 257)
        self.assertEqual(self.descriptor[8], 0)

    def test_explicit_non_video_boundary(self) -> None:
        for key in (
            "asolaria.video_bytes_embedded",
            "asolaria.audio_bytes_embedded",
            "asolaria.lossless_video_claim",
            "asolaria.reconstructs_source_video",
        ):
            self.assertEqual(self.parsed.metadata[key], 0)
        self.assertIn(
            "derived color/time descriptors only",
            self.parsed.metadata["asolaria.boundary"],
        )
        self.assertEqual(
            set(tensor.name for tensor in self.parsed.tensors),
            {"color_state", "size_padding"},
        )
        self.assertFalse(any(self.parsed.tensor_bytes("size_padding")))

    def test_receipt_has_all_slices_and_matching_sidecar(self) -> None:
        receipt = Path(DEFAULT_RECEIPT)
        body = receipt.read_bytes()
        lines = body.decode("utf-8").splitlines()
        self.assertEqual(sum(line.startswith("SLICE|") for line in lines), SAMPLE_COUNT)
        self.assertTrue(
            any(
                line.startswith("BOUNDARY|")
                and "video_bytes_embedded=0" in line
                and "lossless_video_claim=0" in line
                for line in lines
            )
        )
        sidecar = receipt.with_name(receipt.name + ".sha256")
        expected = f"{hashlib.sha256(body).hexdigest()}  {receipt.name}"
        self.assertEqual(sidecar.read_text(encoding="utf-8").strip(), expected)


if __name__ == "__main__":
    unittest.main()
