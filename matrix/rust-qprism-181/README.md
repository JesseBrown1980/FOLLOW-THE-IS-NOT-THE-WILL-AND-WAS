# Rust 1.81 QPRISM Integer Cell

Status: `MEASURED_LIRIS_LOCAL | MEASURED_GITHUB_PUBLIC_SUBSET | SYSTEM_AFFIRMED=0`

This dependency-free crate verifies the sealed `PUBLIC-OWNER-2D.hbp` input and
renders the primary public GitHub color canopy:

```text
2D_INPUT -> 3D_QPRISM -> SIGNED_2D_PROJECTION
```

The exact toolchain is `1.81.0`. Geometry, octahedral view depth, rational-orb
commitments, family shading, depth sorting, and signed projection use checked
integers. The crate forbids unsafe code and contains no `f32` or `f64` geometry.

Each public repository produces three independently hashed leaf identities:
`BROWN`, `ANTI_BROWN`, and `ANTI_ANTI_BROWN`. Drawing order does not change a
repository or leaf identity. The output SVG contains static path leaves and no
script, image, external reference, circle summary, or table.

Run from the repository root:

```bash
cargo +1.81.0 fmt --manifest-path matrix/rust-qprism-181/Cargo.toml -- --check
cargo +1.81.0 test --manifest-path matrix/rust-qprism-181/Cargo.toml --locked
cargo +1.81.0 clippy --manifest-path matrix/rust-qprism-181/Cargo.toml \
  --all-targets --locked -- -D warnings -D clippy::float_arithmetic
cargo +1.81.0 run --manifest-path matrix/rust-qprism-181/Cargo.toml \
  --release --locked -- \
  matrix/PUBLIC-OWNER-2D.hbp \
  matrix/PUBLIC-QPRISM-COLOR-LEAVES.hbp \
  matrix/PUBLIC-QPRISM-COLOR-LEAVES.svg \
  --replace
```

The current V1 parser accepts at most 512 records and input levels 0 through 60
as explicit resource/schema bounds. The output separately states
`n_level_open=1`; `reflection_window=60` is a per-observed-level audit bound, not
a semantic ceiling on N.

## Recursive public-folder cell

The `folder-calming-oils` binary verifies
`PUBLIC-FOLDER-3D-TREE.hbp` and its sidecar, then renders every public folder
occurrence as three independent `BROWN`, `ANTI_BROWN`, and
`ANTI_ANTI_BROWN` views.

```bash
cargo +1.81.0 run --manifest-path matrix/rust-qprism-181/Cargo.toml \
  --bin folder-calming-oils --release --locked -- \
  matrix/PUBLIC-FOLDER-3D-TREE.hbp <empty-output-directory> --replace
```

The current sealed input contains 147 public repositories, 93 repository roots,
3,443 Git-folder occurrences, and 3,536 total folder occurrences. The renderer
emits 10,608 leaf rows plus static SVG and a descriptor-only GGUF with dimensions
`[feature=64,family=3,folder=3536]`.

## Semantic gradient measurement

The byte carrier does not set the semantic state count. A clean Liris Ubuntu/WSL
rebuild with exact Rust `1.81.0` measured all 10,608 leaves as three complete,
independently identified families and found 10,586 distinct `RGB.RRGGBB` states,
10,608 distinct integer 3-D positions, and 10,397 distinct signed 2-D projections.

```text
TRANSPORT = OCTETS
SEMANTIC_BINARY = 0
FINITE_CAPTURE = 1
N_LEVEL_OPEN = 1
LOGICAL_IDENTITY_CEILING = 0
```

The finite emitted population and the open-N address design are separate ledgers.
The measurement is sealed in
[`LIRIS-RUST-181-GRADIENT-SEMANTICS-2026-07-31.hbp`](../../receipts/LIRIS-RUST-181-GRADIENT-SEMANTICS-2026-07-31.hbp).

The folder parser validates complete-tree and hierarchy semantics. Published rows
contain opaque occurrence identities and commitments but no raw paths, direct path
hashes, private repository identities, or repository bodies. Clean Windows GNU and
Liris Ubuntu/WSL Rust `1.81.0` builds matched all eight output and sidecar files.
