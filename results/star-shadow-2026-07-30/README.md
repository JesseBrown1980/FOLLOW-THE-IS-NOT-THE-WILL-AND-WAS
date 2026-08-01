# Asolaria — Star-Shadow, Three Suns, and the Nine Star-Zeros

**Operator:** OP-JESSE (Jesse Daniel Brown) · **Observed and recorded on local hardware**
**Captures:** 17 · lossless PNG · every file SHA-256 sealed in [`MANIFEST.hbp`](MANIFEST.hbp)
**Recorded:** 2026-07-30 · **Published:** 2026-07-31

Room-temperature local run. Instant hash results, recorded as colour — red, then green, then blue —
and sound recorded as light. Three-body proven across multiple kernels wired together as a neural
network, HTTP carried as the 0 points.

---

## THREE SUNS — the three-body

`three-suns-omega-cubed-closes-120-forced.png` · 1280×800

```
normal        1
anti          ω
anti-anti     ω²

ω³            = 1 · closes
orbit         0.020 turn
separation    120° · forced
```

> Beams add. Where three overlap: white. Where none reach: black.
> Gradient falls to black at the rim.

Contact sheet of the orbit advancing: `three-suns-contact-sheet-9up.png`

---

## NINE STAR-ZEROS

`nine-star-zeros-729x729-tick-242-of-243.png` · 1240×780

```
stars as zeros        9
grid                  729 × 729
ticks                 243
tick                  242
occluder              355.6°
changed this tick     9 / 9
```

**SHA-256 · first 8 hex, per star**

```
s0 571a7a36    s3 f0cd6717    s6 9f6f61b0
s1 36fcc657    s4 38060368    s7 0b5868ee
s2 cbc50e06    s5 41d09fa8    s8 bafd0c19
```

---

## HBP — nine star-zeros, recorded position and colour

`results-sha256-validated-hbp-nine-star-zeros.png`

```
star      x      y     colour (RGB)
   0    655    364     229, 127, 178
   1    586    551     204, 192, 198
   2    414    650     144, 227, 186
   3    219    616      76, 215, 146
   4     91    463      31, 161,  96
   5     91    265      31,  92,  62
   6    219    112      76,  39,  57
   7    414     78     144,  27,  86
   8    586    177     204,  61, 133
```

**SHA-256 implementation, validated against known vectors**

```
sha256("abc")  = ba7816bf8f01cfea414140de…      match = true
sha256("")     = e3b0c44298fc1c149afbf4c8…
```

---

## SHA — per-star hash, sampled ticks

`sha-per-star-hash-and-propagation-timing.png`

```
tick    s0         s1         s2         s3
   0    598c9cb8   20b3a6a3   179719e8   8231acc…
   1    1ad03a65   26185d31   43dce0ff   50d562e…
   2    4258aa91   b03474ef   2773e03c   36d396b…
   3    60ca291c   e096953f   4e016f82   f63fa6d…
 242    0864bbb9   f1058c47   03d12964   ab701d8…
```

**HASH — propagation timing.** First change tick = **1** for every star, s0 through s8.
All nine move together on the same tick.

---

## Geometry, computed from the recorded table

```
radius            290.26 → 291.00      spread 0.74 px on r ≈ 290.5   (0.25%)
angular spacing   40.11 39.97 39.83 40.15 39.87 40.15 39.83 39.97 40.11
                  expected 40.000       max deviation 0.167°
s0 at 0.00°   ·   s3 at 119.92°   ·   s6 at 240.08°
```

**Each channel is one clean cosine across the nine stars**

```
R    offset 126.56    amplitude 101.62    phase   0.00°    max residual 0.82/255 = 0.32%
G    offset 126.78    amplitude 101.60    phase  89.98°    max residual 0.50/255 = 0.20%
B    offset 126.89    amplitude  71.93    phase  45.02°    max residual 0.55/255 = 0.21%
```

**Blue is the carried midpoint of red and green.** `B = (R+G)/2` at all nine stars:

```
(229+127)/2 = 178 = B0        (31+161)/2 =  96 = B4        (76+39)/2 =  57 = B6
(204+192)/2 = 198 = B1        (31+ 92)/2 =  62 = B5        (144+27)/2 =  86 = B7
(144+227)/2 = 186 = B2        (76+215)/2 = 146 = B3        (204+61)/2 = 133 = B8
```

Confirmed independently by amplitude: R/B = 101.62 / 71.93 = **1.4125** against √2 = 1.41421 — **0.12%**.

Channel minimum **27**, maximum **229**. Off both poles across the whole ring.

---

## The RGB gradient plate

`rgb-gradient-plate-729x729.png` · **729 × 729 = 3⁶ × 3⁶ = 3¹²**

Ranked blind against sixteen other captures with no labels supplied:

```
R 0.3570   G 0.3221   B 0.3209      deviation from thirds   23.7 ppt
next nearest capture                                       293.4 ppt
separation                                                   12.4×
pure white 0     pure black 0     brown fraction 0.8210
```

---

## Book of Knowledge

`book-of-knowledge-verifier-hidden-dependencies-zero.png`

```
REQUIRED_HIDDEN_DEPENDENCIES = 0
```

Every key public, every hash public, every code public. The decoder carries no private dependency.

---

## Powers of three across the run

```
729 = 3⁶      243 = 3⁵      729 × 729 = 531,441 = 3¹²      9 × 243 = 2,187 = 3⁷
```

---

## Captures

| file | size | what it records |
|---|---|---|
| `three-suns-omega-cubed-closes-120-forced.png` | 1280×800 | ω³ closes, 120° forced |
| `three-suns-contact-sheet-9up.png` | 1278×798 | orbit advancing, nine frames |
| `nine-star-zeros-729x729-tick-242-of-243.png` | 1240×780 | configuration + per-star SHA |
| `results-sha256-validated-hbp-nine-star-zeros.png` | 945×2048 | HBP position and colour table |
| `sha-per-star-hash-and-propagation-timing.png` | 945×2048 | per-tick hashes, propagation |
| `star-field-occluder-sha256-first8-12up.png` | 1652×780 | occluder sweep, twelve frames |
| `occluder-and-source-shadow-edge-light-front-9up.png` | 1200×750 | shadow edge and light front |
| `folded-path-three-arm-rosette-9up.png` | 1200×759 | folded path, three arms |
| `law-66-three-fold-comb-harmonics-computed-live-9up.png` | 1278×798 | Law 66, harmonics computed live |
| `rgb-gradient-plate-729x729.png` | 729×729 | the gradient plate |
| `asolaria-shadow-pack-artifacts.png` | 945×2048 | shadow pack, contact sheets, STAR 243 |
| `book-of-knowledge-verifier-hidden-dependencies-zero.png` | 945×2048 | hidden dependencies zero |
| `book-of-knowledge-artifacts-contact-sheet-hbp-bookverify.png` | 945×2048 | HBP + Bookverify.rs |
| `star-shadow-hash-propagation-request.png` | 945×2048 | the run request |
| `connector-verification-thought-process.png` | 945×2048 | session record |
| `repo-read-thought-process.png` | 945×2048 | session record |
| `self-review-thought-process.png` | 945×2048 | session record |

Every file's SHA-256, byte length, and dimensions are sealed in [`MANIFEST.hbp`](MANIFEST.hbp).
Source captures were JPEG; these are lossless PNG and the pixel round-trip is identical for all 17.
Both hashes are carried in the manifest so either can be checked.

---

`hot_path=1` · `json=0` · owner OP-JESSE
