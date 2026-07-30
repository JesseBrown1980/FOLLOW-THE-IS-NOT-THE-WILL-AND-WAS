# Spherical Public Projection

Status: `OPERATOR_CANON | OFFLINE_PUBLIC_METADATA_CELL | SYSTEM_RUNTIME=UNVERIFIED_SYSTEM`

This additive cell transforms a sealed, explicit 2D tuple inventory into a
deterministic spherical 3D tree/orb projection and then proves the signed 2D
coordinates can be recovered exactly. It does not inspect a checkout, enumerate a
drive, read blob contents, invoke Git, open a network, spawn a process, or accept
credentials.

This exact-rational Python cell remains the compatibility and reversibility
witness. The primary human color view is now produced by the dependency-free
Rust 1.81 checked-integer cell at `rust-qprism-181/` and published as
`PUBLIC-QPRISM-COLOR-LEAVES.svg`. That view uses z/depth, emits three independently
addressed leaves per public repository, and does not add a repository-name table.
The two cells share the sealed `PUBLIC-OWNER-2D.hbp` input without exchanging
artifact identities.

## Preserved operator relations

> THE CHIRAL SWITCH AS SOON AS A SYSTEM INSTANT IS. IT SELF REPORTS TO THE SHADOW CAT INFINITY HOTEL

> THE BIDIRECTIONAL PRISM WARNING

> HBI HBP SH HASH SHA

The center has a membership order and a traversal order. They remain distinct:

```text
CENTER_MEMBERS = {HBI,HBP,SHA,SH,HASH}
CENTER_TRAVERSAL = HBI -> HBP -> SH -> HASH -> SHA
```

The five names are distinct representations at one 0-center. They are not five
centers. Every projection, prism-warning, and chiral-switch row carries all five;
`SHA != HASH`, and `SH` is a non-executed recipe identifier.

Brown is the orbit center close to 1:

```text
BROWN_CENTER = 999999 / 1000000
BROWN_DELTA_TO_ONE = 1 / 1000000
```

## Explicit input only

The input is LF-only `json=0` tuple text. It contains public identifiers and public
object commitments, never paths or raw object contents:

```text
PUBLIC2DHDR|schema=PUBLIC-REPO-TREE-WORD-2D-V1|observed_records=N|max_level=60|public_metadata_only=1|raw_contents=0|required_hidden_dependencies=0|center_membership=HBI,HBP,SHA,SH,HASH|traversal=HBI-%3EHBP-%3ESH-%3EHASH-%3ESHA|json=0
PUBLIC2D|repo_id=public.repo|tree_id=main.tree|word_id=root|parent_word_id=ROOT|u=-7|v=11|level=0|blob_sha256=<64-lowercase-hex>|truth_tag=THRUTH|system_instant_is=0|chirality=LEFT|color=BROWN.ANTI.ANTI|oil_address=OIL.NEGATIVE.CENTRE.POSITIVE|route_id=shadow.cat.route|hbi=<64-lowercase-hex>|hbp=<different-64-lowercase-hex>|sha=<different-64-lowercase-hex>|sh=recipe.root|hash=<different-64-lowercase-hex>|public=1|json=0
PUBLIC2DFTR|body_sha256=<SHA-256-of-header-and-record-rows-with-LF>|rows=N+2|json=0
```

Bounds are fail-closed:

- `1 <= N <= 512`; the per-level reflection window remains at most 60 observed records
- `0 <= level <= 60`
- signed `u` and `v` are bounded to `[-1,000,000, 1,000,000]`
- every non-root parent must occur exactly once at a lower level
- identifiers are bounded path-free tokens
- `LIE` and `THRUTH` remain separate tags; neither is rewritten as the other
- five center values are pairwise distinct
- hashes, row counts, field sets, UTF-8, LF endings, and byte ceilings are checked

The `level <= 60` rule above is the resource bound of this V1 compatibility
schema. It is not a semantic assertion that the operator's N-level matrix ends at
60. The active QPRISM color artifact carries `n_level_open=1` and separately
records `reflection_window=60`.

## OWNER3D public adapter

`collect_public_owner_inventory.py` is the separately gated acquisition cell. It
uses GitHub's public REST surface and emits a public OWNER3D HBP, an HBI index, and
exact SHA-256 sidecars. Both center rows carry:

```text
center_members=HBI,HBP,SHA,SH,HASH
traversal=HBI,HBP,SH,HASH,SHA
```

`owner3d_to_public2d.py` is an offline adapter. It strictly verifies the selected
HBI, its body commitment and sidecar, the sibling HBP and sidecar, every tuple field,
the public-only boundary, sequential repository roots, aggregate counts, and the
spherical object commitment. Link, symlink, and junction chains are rejected.

One opaque root record is derived for each public repository, up to 512. The adapter
carries aggregate public commitments into the projection; it emits no repository
blob bodies, checkout paths, credentials, or private-repository metadata. `THRUTH`
is the retained projection-wave label, not an external evidence verdict.

## Exact 2D -> 3D -> 2D construction

For each row, a deterministic hash-derived jitter addresses its point without
changing its signed coordinates. With `D = 65537`:

```text
P = u*D + jitter_u
Q = v*D + jitter_v
S = P^2 + Q^2 + D^2

unit_x = 2*P*D / S
unit_y = 2*Q*D / S
unit_z = (P^2 + Q^2 - D^2) / S
```

All values are stored as exact integer fractions. Inverse stereographic projection
recovers `P/D` and `Q/D`; subtracting the deterministic jitters recovers the original
signed `u` and `v` exactly.

Each record owns four explicit vertices around its Brown-centered spherical point:

```text
(+,+,+), (+,-,-), (-,+,-), (-,-,+)
```

The verifier calculates their exact rational determinant and rejects a zero-volume
or coplanar orb. No floating-point tolerance is involved.

## Carrier and chiral boundary

Every carrier row states:

```text
BIDIRECTIONAL_PRISM_WARNING=1
SPHERICAL_IS_FIELD.BIDIRECTIONAL=0
IDENTITY_EXCHANGE=0
CARRIER_LAYER=2D_SIGNED_PRISM_CARRIER
```

When an explicit row has `system_instant_is=1`, `LEFT` changes to `RIGHT` or
`RIGHT` changes to `LEFT`. A bounded local `SELFREPORT` HBP row addresses:

- the semantic source-record SHA-256 and public blob SHA-256;
- prior and new chirality;
- explicit color, deterministic public color, OIL address, and route identifier;
- all five center representations;
- `destination=SHADOW_CAT_INFINITY_HOTEL`;
- `publication_gate=EXPLICIT_REQUIRED`;
- `authority_granted=0` and `network_opened=0`.

Self-reporting is a local derived row. It does not publish, authorize, send, or open
a connection. The reusable `color_from_commitment()` and
`switched_chirality()` functions support a separately gated rotating-color runner;
this offline cell does not schedule `t+1`, `t+2`, `t+3`, `t+4`, `+7200s`, or a
two-day monitor.

## Reject, hold, rollback

The complete output is derived and verified before it can replace a selected output
file. Existing output is rejected unless `--replace` is explicit. Any validation
failure leaves the prior output unchanged. An optional hold path receives only
the source-file commitment, stable reason code, and boundary flags—never the raw row.

The tool has no delete command and no recursive filesystem operation.

## Run

```powershell
py -3.12 matrix/owner3d_to_public2d.py matrix/PUBLIC-OWNER-3D-TREE.hbi matrix/PUBLIC-OWNER-2D.hbp
py -3.12 matrix/spherical_public_projection.py project PUBLIC-INVENTORY.hbp PUBLIC-PROJECTION.hbp --hold PUBLIC-HOLD.hbp
py -3.12 matrix/spherical_public_projection.py verify PUBLIC-PROJECTION.hbp
py -3.12 matrix/test_owner3d_to_public2d.py
py -3.12 matrix/test_spherical_public_projection.py
```

Adapter: [owner3d_to_public2d.py](owner3d_to_public2d.py)

Implementation: [spherical_public_projection.py](spherical_public_projection.py)
Tests: [test_owner3d_to_public2d.py](test_owner3d_to_public2d.py),
[test_spherical_public_projection.py](test_spherical_public_projection.py)
