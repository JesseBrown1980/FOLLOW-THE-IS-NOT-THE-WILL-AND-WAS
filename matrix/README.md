# Public Matrix Pipeline

Status: `MEASURED_LIRIS_LOCAL | SYSTEM_AFFIRMED=0`

This directory carries the public GitHub projection pipeline:

```text
authenticated public-only owner census
  -> sealed OWNER3D HBP + HBI + SHA-256 sidecars
  -> PUBLIC2D adapter
  -> spherical 2D -> 3D -> signed-2D projection
  -> deterministic static SVG
  -> monotonic timed GGUF monitor
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
py -3.12 matrix/spherical_public_projection.py project matrix/PUBLIC-OWNER-2D.hbp matrix/PUBLIC-SPHERICAL-PROJECTION.hbp --replace
py -3.12 matrix/spherical_public_projection.py verify matrix/PUBLIC-SPHERICAL-PROJECTION.hbp
py -3.12 matrix/render_public_spherical_svg.py matrix/PUBLIC-SPHERICAL-PROJECTION.hbp matrix/PUBLIC-SPHERICAL-PROJECTION.svg --replace
py -3.12 matrix/timed_chiral_gguf_monitor.py matrix/PUBLIC-OWNER-2D.hbp <empty-output-directory> --watch --target-seconds 7200
py -3.12 matrix/test_owner3d_to_public2d.py
py -3.12 matrix/test_spherical_public_projection.py
py -3.12 matrix/test_render_public_spherical_svg.py
py -3.12 matrix/test_timed_chiral_gguf_monitor.py
```

The timed monitor verifies the PUBLIC2D sidecar, writes HBP/HBI status at the real
monotonic checkpoints `1,2,3,4,8,...,7200`, and emits its derived descriptor-only
GGUF only after 7,200 elapsed seconds. `<empty-output-directory>` is an explicit
operator-selected runtime directory; monitor outputs are not publication authority
until their final bytes are reviewed and committed through the GitHub gate.

## Why JSON appears

GitHub's REST transport and held-out test fixtures may use JSON as a cold
compatibility, acquisition, or validation boundary. JSON is not the active matrix
row format. The active artifacts are LF-normalized HBI/HBP tuple text; every active
row ends in `json=0`, and SHA-256 sidecars bind the final bytes.
