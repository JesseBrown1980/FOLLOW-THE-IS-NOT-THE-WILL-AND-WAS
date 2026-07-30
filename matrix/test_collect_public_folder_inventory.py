#!/usr/bin/env python3
"""Offline fixtures for the public folder occurrence collector."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from collect_public_folder_inventory import (
    GhPublicSource,
    InventoryError,
    MAX_LEVEL,
    PublicRepository,
    acquire_inventory,
    build_hbi,
    build_hbp,
    folder_object_root,
    normalize_public_repositories,
    output_roles,
    parse_tuple_line,
    public_repository_set_sha256,
    repository_id,
    run_bounded_command,
    sha256,
    validate_path,
    verify_hbi_bytes,
    verify_hbp_bytes,
    write_inventory,
)


OWNER = "JesseBrown1980"
CAPTURED_AT = "2026-07-30T12:34:56.789Z"


def oid(character: str) -> str:
    return character * 40


def public_repo(
    name: str, node_id: str, branch: str | None
) -> PublicRepository:
    return PublicRepository(
        OWNER,
        node_id,
        name,
        branch,
        repository_id(OWNER, node_id),
    )


class FixtureSource:
    def __init__(
        self,
        repositories: list[PublicRepository],
        commits: dict[str, Any],
        trees: dict[str, Any],
        postflight: list[PublicRepository] | None = None,
    ) -> None:
        self.repositories = list(repositories)
        self.postflight = list(postflight) if postflight is not None else None
        self.commits = commits
        self.trees = trees
        self.list_calls = 0
        self.commit_calls: list[tuple[str, str, str]] = []
        self.tree_calls: list[tuple[str, str, str]] = []

    def list_public_repositories(self, owner: str) -> list[PublicRepository]:
        if owner != OWNER:
            raise AssertionError("unexpected fixture owner")
        self.list_calls += 1
        if self.list_calls == 2 and self.postflight is not None:
            return list(self.postflight)
        return list(self.repositories)

    def get_commit(self, owner: str, name: str, branch: str) -> Any:
        self.commit_calls.append((owner, name, branch))
        return self.commits[name]

    def get_recursive_tree(self, owner: str, name: str, tree_oid: str) -> Any:
        self.tree_calls.append((owner, name, tree_oid))
        return self.trees[name]


def hierarchy_source() -> FixtureSource:
    alpha = public_repo("alpha-private-looking-canary", "R_NODE_ALPHA", "main-canary")
    unborn = public_repo("beta-unborn-canary", "R_NODE_BETA", None)
    entries = [
        {"path": "docs-canary", "mode": "040000", "type": "tree", "sha": oid("2")},
        {
            "path": "docs-canary/deep-canary",
            "mode": "040000",
            "type": "tree",
            "sha": oid("3"),
        },
        {
            "path": "docs-canary/deep-canary/payload-canary.bin",
            "mode": "100644",
            "type": "blob",
            "sha": oid("5"),
            "size": 9,
        },
        {
            "path": "docs-canary/readme-canary.md",
            "mode": "100644",
            "type": "blob",
            "sha": oid("6"),
            "size": 4,
        },
        {
            "path": "docs-canary/link-canary",
            "mode": "120000",
            "type": "blob",
            "sha": oid("9"),
            "size": 10,
        },
        {"path": "mirror-canary", "mode": "040000", "type": "tree", "sha": oid("2")},
        {"path": "vendor-canary", "mode": "040000", "type": "tree", "sha": oid("4")},
        {
            "path": "vendor-canary/gitlink-canary",
            "mode": "160000",
            "type": "commit",
            "sha": oid("8"),
        },
        {
            "path": "root-canary.txt",
            "mode": "100755",
            "type": "blob",
            "sha": oid("7"),
            "size": 1,
        },
    ]
    return FixtureSource(
        [alpha, unborn],
        {
            alpha.name: {
                "sha": oid("a"),
                "commit": {"tree": {"sha": oid("1")}},
            }
        },
        {
            alpha.name: {
                "sha": oid("1"),
                "truncated": False,
                "tree": entries,
            }
        },
    )


class FolderInventoryTests(unittest.TestCase):
    def test_hierarchy_occurrences_are_distinct_and_paths_stay_local(self) -> None:
        source = hierarchy_source()
        inventory = acquire_inventory(source, OWNER, CAPTURED_AT)
        self.assertEqual(source.list_calls, 2)
        self.assertEqual(len(source.commit_calls), 1)
        self.assertEqual(len(source.tree_calls), 1)
        self.assertEqual(
            (
                inventory.repositories,
                inventory.branched,
                inventory.unborn,
                inventory.repository_roots,
                inventory.git_tree_folder_occurrences,
                len(inventory.folders),
                inventory.max_level,
            ),
            (2, 1, 1, 1, 4, 5, 2),
        )
        self.assertEqual(
            (
                inventory.direct_blobs,
                inventory.direct_trees,
                inventory.direct_commits,
                inventory.symlinks,
                inventory.unique_tree_objects,
            ),
            (4, 4, 1, 1, 4),
        )

        hbp = build_hbp(inventory)
        result = verify_hbp_bytes(hbp)
        self.assertEqual(result["folders"], 5)
        self.assertEqual(result["repositories"], 2)
        self.assertEqual(
            result["public_set_sha256"],
            public_repository_set_sha256(source.repositories),
        )
        object_root = folder_object_root(inventory.folders)
        hbi = build_hbi("PUBLIC-FOLDER-3D-TREE.hbp", hbp, object_root, inventory)
        index = verify_hbi_bytes(hbi, expected_hbp_sha256=sha256(hbp))
        self.assertEqual(index["folders"], 5)
        self.assertEqual(index["public_set_sha256"], result["public_set_sha256"])

        text = (hbp + hbi).decode("utf-8")
        for raw_value in (
            "alpha-private-looking-canary",
            "beta-unborn-canary",
            "main-canary",
            "docs-canary",
            "deep-canary",
            "payload-canary",
            "mirror-canary",
            "vendor-canary",
            "root-canary",
            oid("1"),
            oid("2"),
            oid("a"),
        ):
            self.assertNotIn(raw_value, text)
        self.assertNotIn(sha256(b"docs-canary"), text)
        self.assertNotIn(sha256(b"docs-canary/deep-canary"), text)
        self.assertIn("paths_published=0", text)
        self.assertIn("path_hashes_published=0", text)
        self.assertIn("tree_sha1_published=0", text)
        self.assertIn("private_repo_rows=0", text)
        self.assertIn("brown_center=RGB.8B5A2B", text)

        folder_fields = [
            parse_tuple_line(line)[1]
            for line in hbp.decode("utf-8").splitlines()
            if line.startswith("FOLDER|")
        ]
        roots = [
            fields
            for fields in folder_fields
            if fields["source_kind"] == "REPOSITORY_ROOT"
        ]
        self.assertEqual(len(roots), 1)
        self.assertEqual(roots[0]["parent_folder_id"], "0" * 64)
        self.assertEqual(roots[0]["direct_trees"], "3")
        self.assertEqual(roots[0]["direct_blobs"], "1")
        reused = {}
        for fields in folder_fields:
            reused.setdefault(fields["tree_commitment_sha256"], []).append(
                fields["folder_id"]
            )
        repeated_occurrences = [ids for ids in reused.values() if len(ids) == 2]
        self.assertEqual(len(repeated_occurrences), 1)
        self.assertEqual(len(set(repeated_occurrences[0])), 2)

        second = acquire_inventory(hierarchy_source(), OWNER, CAPTURED_AT)
        self.assertEqual(build_hbp(second), hbp)

    def test_private_and_wrong_owner_rows_fail_closed(self) -> None:
        base = {
            "id": "R_NODE",
            "name": "public-one",
            "nameWithOwner": f"{OWNER}/public-one",
            "isPrivate": False,
            "defaultBranchRef": None,
        }
        normalized = normalize_public_repositories([base], OWNER)
        self.assertEqual(len(normalized), 1)
        empty_branch_object = dict(base)
        empty_branch_object["defaultBranchRef"] = {"name": ""}
        normalized_empty = normalize_public_repositories(
            [empty_branch_object], OWNER
        )
        self.assertIsNone(normalized_empty[0].branch)
        malformed_branch_object = dict(base)
        malformed_branch_object["defaultBranchRef"] = {"name": None}
        with self.assertRaises(InventoryError):
            normalize_public_repositories([malformed_branch_object], OWNER)
        private = dict(base)
        private["isPrivate"] = True
        with self.assertRaises(InventoryError):
            normalize_public_repositories([private], OWNER)
        wrong_owner = dict(base)
        wrong_owner["nameWithOwner"] = "SomeoneElse/public-one"
        with self.assertRaises(InventoryError):
            normalize_public_repositories([wrong_owner], OWNER)
        with self.assertRaises(InventoryError):
            GhPublicSource.validate_public_api_endpoint("user/repos")
        with self.assertRaises(InventoryError):
            GhPublicSource.validate_public_api_endpoint(
                f"repos/{OWNER}/public-one"
            )
        GhPublicSource.validate_public_api_endpoint(
            f"repos/{OWNER}/public-one/commits/main"
        )
        GhPublicSource.validate_public_api_endpoint(
            f"repos/{OWNER}/public-one/git/trees/{oid('a')}?recursive=1"
        )

    def test_public_set_postflight_change_is_rejected(self) -> None:
        source = hierarchy_source()
        alpha = source.repositories[0]
        changed = PublicRepository(
            alpha.owner,
            alpha.node_id,
            alpha.name,
            "moved-main",
            alpha.repo_id,
        )
        source.postflight = [changed, source.repositories[1]]
        with self.assertRaisesRegex(InventoryError, "set changed"):
            acquire_inventory(source, OWNER, CAPTURED_AT)

    def test_tamper_incomplete_tree_modes_and_bounds_are_rejected(self) -> None:
        inventory = acquire_inventory(hierarchy_source(), OWNER, CAPTURED_AT)
        hbp = build_hbp(inventory)
        tampered = hbp.replace(b"|direct_blobs=1|", b"|direct_blobs=2|", 1)
        self.assertNotEqual(tampered, hbp)
        with self.assertRaises(InventoryError):
            verify_hbp_bytes(tampered)
        footer_tamper = hbp.replace(b"body_sha256=", b"body_sha256=0", 1)
        with self.assertRaises(InventoryError):
            verify_hbp_bytes(footer_tamper)

        truncated = hierarchy_source()
        truncated.trees[truncated.repositories[0].name]["truncated"] = True
        with self.assertRaisesRegex(InventoryError, "incomplete"):
            acquire_inventory(truncated, OWNER, CAPTURED_AT)
        bad_mode = hierarchy_source()
        bad_mode.trees[bad_mode.repositories[0].name]["tree"][0]["mode"] = "100644"
        with self.assertRaisesRegex(InventoryError, "mode/type"):
            acquire_inventory(bad_mode, OWNER, CAPTURED_AT)
        too_deep = "/".join(f"d{index}" for index in range(MAX_LEVEL + 1))
        with self.assertRaisesRegex(InventoryError, "level"):
            validate_path(too_deep)

    def test_output_role_alias_links_and_sidecars_are_checked(self) -> None:
        inventory = acquire_inventory(hierarchy_source(), OWNER, CAPTURED_AT)
        hbp = build_hbp(inventory)
        hbi = build_hbi(
            "PUBLIC-FOLDER-3D-TREE.hbp",
            hbp,
            folder_object_root(inventory.folders),
            inventory,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            same = root / "same.hbp"
            with self.assertRaisesRegex(InventoryError, "collision"):
                output_roles(same, same)

            hbp_path = root / "tree.hbp"
            hbi_path = root / "tree.hbi"
            write_inventory(hbp_path, hbi_path, hbp, hbi)
            self.assertEqual(hbp_path.read_bytes(), hbp)
            self.assertEqual(hbi_path.read_bytes(), hbi)
            self.assertEqual(
                (root / "tree.hbp.sha256").read_text(encoding="ascii"),
                f"{sha256(hbp)}  tree.hbp\n",
            )
            self.assertEqual(
                (root / "tree.hbi.sha256").read_text(encoding="ascii"),
                f"{sha256(hbi)}  tree.hbi\n",
            )

            hard_a = root / "hard-a"
            hard_b = root / "hard-b"
            hard_a.write_bytes(b"x")
            try:
                os.link(hard_a, hard_b)
            except OSError as exc:
                self.skipTest(f"hardlinks unavailable on fixture filesystem: {exc}")
            with self.assertRaisesRegex(InventoryError, "hard-linked"):
                output_roles(hard_a, root / "other.hbi")

    def test_stream_caps_request_caps_and_deadline_fail_closed(self) -> None:
        environment = os.environ.copy()
        with self.assertRaises(InventoryError):
            run_bounded_command(
                [sys.executable, "-c", "import sys;sys.stdout.write('x'*4096)"],
                64,
                64,
                10,
                environment,
            )

        calls: list[list[str]] = []

        def runner(
            argv: Any,
            stdout_limit: int,
            stderr_limit: int,
            timeout: int,
            env: dict[str, str],
        ) -> bytes:
            del stdout_limit, stderr_limit, timeout, env
            calls.append(list(argv))
            return b"{}"

        now = [0.0]
        source = GhPublicSource(
            "gh",
            runner,
            max_commands=1,
            acquisition_deadline_seconds=10,
            clock=lambda: now[0],
        )
        self.assertEqual(source._run(["version"], 128), b"{}")
        with self.assertRaisesRegex(InventoryError, "request count"):
            source._run(["version"], 128)
        self.assertEqual(len(calls), 1)

        def deadline_runner(
            argv: Any,
            stdout_limit: int,
            stderr_limit: int,
            timeout: int,
            env: dict[str, str],
        ) -> bytes:
            del argv, stdout_limit, stderr_limit, timeout, env
            now[0] = 11.0
            return b"{}"

        now[0] = 0.0
        deadline = GhPublicSource(
            "gh",
            deadline_runner,
            max_commands=2,
            acquisition_deadline_seconds=10,
            clock=lambda: now[0],
        )
        with self.assertRaisesRegex(InventoryError, "deadline"):
            deadline._run(["version"], 128)


if __name__ == "__main__":
    unittest.main()
