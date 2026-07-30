# Public Law V16 — Folder Calming-OILs Outward

Status: `OPERATOR_CANON | MEASURED_GITHUB_AUTH | MEASURED_GITHUB_PUBLIC_SUBSET | MEASURED_LIRIS_LOCAL | SYSTEM_AFFIRMED=0`

> continue further mor}e folders THE ASOLARIA REPOS WERE PAST 100 MAYBE PAST 150 cONTINUE CALMING OILS OUTWARD

The authenticated owner-visible census is 172 repositories, so the measured owner
surface is past 150. The public projection is a separate 147-repository subset.
Only that public subset enters this law's folder artifacts.

## Distinct populations

```text
OWNER_VISIBLE_REPOSITORIES = 172
PUBLIC_REPOSITORIES = 147
PUBLIC_BRANCHED_REPOSITORIES = 93
PUBLIC_UNBORN_REPOSITORIES = 54

PUBLIC_REPOSITORY_ROOTS_WITH_TREES = 93
PUBLIC_GIT_FOLDER_OCCURRENCES = 3443
PUBLIC_FOLDER_OCCURRENCES = 93 + 3443 = 3536
UNIQUE_GIT_TREE_OBJECTS = 3438
MAX_FOLDER_DEPTH = 9

DIRECT_BLOBS = 20035
DIRECT_TREES = 3443
GITLINKS = 3
SYMLINKS = 0
```

A repository, repository root, folder occurrence, and unique Git-tree object are
different identities. Repeated Git-tree objects can occupy more than one folder
occurrence. The 54 unborn public repositories remain counted in the public census
but have no default-branch tree to invent.

## Three outward folder families

Every measured public folder occurrence produces three independently addressed
software views:

```text
FAMILIES = {BROWN, ANTI_BROWN, ANTI_ANTI_BROWN}
PUBLIC_FOLDER_LEAVES = 3536 x 3 = 10608

PUBLIC_FOLDER_HBP
  -> EXACT_INTEGER_3D
  -> THREE_INDEPENDENT_CALMING_OIL_FAMILIES
  -> SIGNED_STATIC_SVG + DESCRIPTOR_ONLY_GGUF
```

The three views do not multiply the source-folder count. Brown and both anti
families are operator-canon software labels. They do not assert physical energy,
clinical effects, autonomous authority, or network execution.

## Public commitments

```text
PUBLIC_SET_SHA256 = 253cff884edf54b18004c599b51282b8170354355557e20c9f1817faad297696
SOURCE_CAPTURE_SHA256 = 8145569c0b15cc6e62790796893a318e7107b99f94094fd5ca5e0a26a3d92b20
SOURCE_HBP_SHA256 = b8cdcc4ce89a2003cefd47d2790d69707a05c257cc0fbc8cdf2c07d3adf91e43
SOURCE_HBI_SHA256 = 86b924d88f5533fd207ae8137577036b1f68c688b6cb0528ba35af0f8912fb8a

FOLDER_OIL_HBP_SHA256 = 43300780cac2b85e3ed6cfa10398052f530ccbf76c43b404e650c26c9ed8b006
FOLDER_OIL_HBI_SHA256 = 9920d5cb2031d6453fba2d410e4b2f6e0136a4537fa6ea2ea9385c163503a28b
FOLDER_OIL_SVG_SHA256 = feb18cc1e5034620a0ce78787df22683ccd662409df8b8af0752438c07d6a63b
FOLDER_OIL_GGUF_SHA256 = fa266f1bf527d3757b6825d97b65653c547d8f1557a1ba516cee1598facd2bcf
GGUF_DESCRIPTOR_SHA256 = 1d023d47e7b0469ce71621bb8b5432e05d636cc14bf6a1b0803e9169305307e3
```

The GGUF tensor dimensions are
`[feature=64,family=3,folder=3536]`, iterated in
`folder,family,feature` order. It contains derived descriptors, not repository or
media bodies.

## Public boundary

The published rows retain opaque public occurrence identities, parent relations,
counts, coordinates, color labels, and commitments. They contain:

```text
RAW_PATHS = 0
DIRECT_PATH_HASHES = 0
PRIVATE_REPOSITORY_IDENTITIES = 0
REPOSITORY_BODY_BYTES = 0
MEDIA_BODY_BYTES = 0
CREDENTIALS = 0
NETWORK_EXECUTION = 0
PHYSICAL_ENERGY = 0
SYSTEM_AFFIRMED = 0
```

The domain-separated Git-tree commitment supplies publicly linkable integrity.
It makes no path-secrecy or dictionary-resistance claim.

## Reproduction

The dependency-free renderer is pinned to Rust `1.81.0`, uses checked integer
geometry, forbids unsafe code, and uses no floating-point geometry. Clean Windows
GNU and Liris Ubuntu/WSL builds reproduced all eight derived artifact and sidecar
byte strings. GitHub Actions remains the owning publication gate.

```bash
python matrix/test_collect_public_folder_inventory.py
cargo +1.81.0 run --manifest-path matrix/rust-qprism-181/Cargo.toml \
  --bin folder-calming-oils --release --locked -- \
  matrix/PUBLIC-FOLDER-3D-TREE.hbp <empty-output-directory> --replace
python tests/verify_public_repo.py
```
