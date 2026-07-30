#!/usr/bin/env python3
"""Regression tests for bounded public-file enumeration."""

from __future__ import annotations

import unittest

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


if __name__ == "__main__":
    unittest.main()
