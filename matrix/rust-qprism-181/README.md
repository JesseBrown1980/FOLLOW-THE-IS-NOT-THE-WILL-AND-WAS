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
