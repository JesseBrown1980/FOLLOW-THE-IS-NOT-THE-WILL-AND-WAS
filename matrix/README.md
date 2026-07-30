# Public Matrix Pipeline

Status: `MEASURED_LIRIS_LOCAL | SYSTEM_AFFIRMED=0`

This directory carries the public GitHub projection pipeline:

```text
authenticated public-only owner census
  -> sealed OWNER3D HBP + HBI + SHA-256 sidecars
  -> PUBLIC2D adapter
  -> exact Rust 1.81 checked-integer 2D -> 3D QPRISM -> signed-2D projection
  -> 3 independently addressed color leaves per public repository
  -> deterministic static color-canopy SVG
  -> exact-rational Python projection and THIN_TRIPLE_RAINBOW compatibility view
  -> monotonic timed GGUF monitor
  -> additive V2 public image/video extension-metadata capture
  -> exact Rust 1.81 four-detector x three-direction outward waves
  -> static outward color SVG + stackable descriptor-only GGUF
```

The center is the unordered membership set
`{HBI,HBP,SHA,SH,HASH}`. Its ordered traversal is
`HBI -> HBP -> SH -> HASH -> SHA`. Each bounded level reflects at most 60
already observed commitments. `OIL.CALM.BROWN` and related calming-OIL values are
projection labels; they do not assert physical or clinical effects.

## Evidence surfaces

- `PUBLIC_API_SUBSET`: the collector calls GitHub's public owner/repository and
  public Git-tree endpoints only.
- `MEASURED_GITHUB`: applies after authenticated GitHub identity and the exact
  public repository surface are measured.
- `SYSTEM_AFFIRMED=0`: GitHub publication evidence is separate from live
  fabric/canon affirmation.

The public rows contain aggregate repository commitments and public identifiers.
They contain no raw repository contents, private-repository metadata, credentials,
private keys, account cookies, or local response notebooks.

## Active commands

From the repository root:

```powershell
gh auth status
py -3.12 matrix/collect_public_owner_inventory.py --owner JesseBrown1980 --output matrix/PUBLIC-OWNER-3D-TREE.hbp --index matrix/PUBLIC-OWNER-3D-TREE.hbi
py -3.12 matrix/owner3d_to_public2d.py matrix/PUBLIC-OWNER-3D-TREE.hbi matrix/PUBLIC-OWNER-2D.hbp --replace
py -3.12 matrix/collect_public_owner_inventory.py --owner JesseBrown1980 --output matrix/PUBLIC-OWNER-3D-MEDIA-TREE.hbp --index matrix/PUBLIC-OWNER-3D-MEDIA-TREE.hbi
py -3.12 matrix/owner3d_to_public2d.py matrix/PUBLIC-OWNER-3D-MEDIA-TREE.hbi matrix/PUBLIC-OWNER-MEDIA-POSITION-2D.hbp --replace
cargo +1.81.0 run --manifest-path matrix/rust-qprism-181/Cargo.toml --bin rust-qprism-181 --release --locked -- matrix/PUBLIC-OWNER-2D.hbp matrix/PUBLIC-QPRISM-COLOR-LEAVES.hbp matrix/PUBLIC-QPRISM-COLOR-LEAVES.svg --replace
cargo +1.81.0 run --manifest-path matrix/rust-qprism-181/Cargo.toml --bin outward-truth-waves --release --locked -- matrix/PUBLIC-OWNER-3D-MEDIA-TREE.hbp matrix --replace
cargo +1.81.0 fmt --manifest-path matrix/rust-qprism-181/Cargo.toml -- --check
cargo +1.81.0 test --manifest-path matrix/rust-qprism-181/Cargo.toml --locked
cargo +1.81.0 clippy --manifest-path matrix/rust-qprism-181/Cargo.toml --all-targets --locked -- -D warnings -D clippy::float_arithmetic
py -3.12 matrix/spherical_public_projection.py project matrix/PUBLIC-OWNER-2D.hbp matrix/PUBLIC-SPHERICAL-PROJECTION.hbp --replace
py -3.12 matrix/spherical_public_projection.py verify matrix/PUBLIC-SPHERICAL-PROJECTION.hbp
py -3.12 matrix/render_public_spherical_svg.py matrix/PUBLIC-SPHERICAL-PROJECTION.hbp matrix/PUBLIC-SPHERICAL-PROJECTION.svg --replace
py -3.12 matrix/timed_chiral_gguf_monitor.py matrix/PUBLIC-OWNER-2D.hbp <empty-output-directory> --watch --target-seconds 7200
py -3.12 matrix/test_owner3d_to_public2d.py
py -3.12 matrix/test_spherical_public_projection.py
py -3.12 matrix/test_render_public_spherical_svg.py
py -3.12 matrix/test_timed_chiral_gguf_monitor.py
```

`PUBLIC-QPRISM-COLOR-LEAVES.svg` is the primary human view. It contains three
leaf-path identities for each of the 147 public repository records in the current
authenticated public-owner capture: 441 leaves total. The backend HBP is a sealed
tuple receipt, not the visual interface. Drawing depth changes only view order;
repository and leaf identities remain unchanged.

The Rust cell is dependency-free and pinned to `1.81.0`. Its geometry, color
shading, depth ordering, and projection use checked integers only. The public
metadata capture has an open semantic N-level relation; `60` is the bounded
reflection window applied at each observed level, not a final semantic level.

The timed monitor verifies the PUBLIC2D sidecar, writes HBP/HBI status at the real
monotonic checkpoints `1,2,3,4,8,...,7200`, and emits its derived descriptor-only
GGUF only after 7,200 elapsed seconds. `<empty-output-directory>` is an explicit
operator-selected runtime directory; monitor outputs are not publication authority
until their final bytes are reviewed and committed through the GitHub gate.

The reviewed immutable run is now committed as `TIMED-CHIRAL-MONITOR.hbi`,
`TIMED-CHIRAL-MONITOR.hbp`, and `TIMED-CHIRAL-PUBLIC-COLOR-ORBITS.gguf`. It is
bound to the unchanged `f3a9ade5...` V1 PUBLIC2D source and reproduces byte for
byte from a deterministic 7,200-second completion calculation.

The additive media V2 capture leaves that V1 source unchanged. It classifies
public Git-tree blob paths by extension and publishes only per-repository counts,
declared Git-object byte totals, unknown-size counts, and commitments. It stores
zero media paths and zero media bodies. `PUBLIC-OUTWARD-TRUTH-WAVES.svg` renders
the four detectors and three signed directions per repository; its GGUF contains
metadata/color-wave descriptors, not pixels, frames, audio, or repository bodies.

## Why JSON appears

GitHub's REST transport and held-out test fixtures may use JSON as a cold
compatibility, acquisition, or validation boundary. JSON is not the active matrix
row format. The active artifacts are LF-normalized HBI/HBP tuple text; every active
row ends in `json=0`, and SHA-256 sidecars bind the final bytes.
