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

## Geometry — exact integers, no float

729 is odd, so the grid centre is the integer **364**. Every displacement is an integer,
so `r²` is exact and no square root is ever taken. No trigonometry is used.

```
s0  dx= 291  dy=   0   r² = 84681 = 291²   perfect square, exactly on axis
s1  dx= 222  dy= 187   r² = 84253
s2  dx=  50  dy= 286   r² = 84296
s3  dx=-145  dy= 252   r² = 84529
s4  dx=-273  dy=  99   r² = 84330
s5  dx=-273  dy= -99   r² = 84330
s6  dx=-145  dy=-252   r² = 84529
s7  dx=  50  dy=-286   r² = 84296
s8  dx= 222  dy=-187   r² = 84253
```

**Exact mirror symmetry about y = 364.** For every pair: `dx` equal, `dy` negated,
`r²` identical to the integer — s1↔s8, s2↔s7, s3↔s6, s4↔s5.

**The trit breaks the mirror in 3 of the 4 pairs.**

```
s1=0  s8=+   differ        s3=+  s6=-   differ
s2=+  s7=+   same          s4=0  s5=+   differ
```

The positions cannot tell a star from its reflection. The trit can.

**One turn, and its sweeps are a palindrome.** Integer cross products, all positive,
no backtrack:

```
54417  54142  54070  54441  54054  54441  54070  54142  54417
```

Reads the same both ways about 54054.

## The closure and the trit — exact in thirds

Arms about the centroid, held as numerators over 3:

```
arm_R = 2r - g - b      arm_G = 2g - r - b      arm_B = 2b - r - g
```

They sum to exactly **0** at every star — an identity for all integers, verified over
**1,771,561** triples with zero exceptions. Shifting all three channels by any constant
leaves the arms unchanged (**18,009** shifts tested, zero changes): the centre is free.

The third arm is never anything but **−1/3, 0, or +1/3**:

```
minus_third 1    normal_null 3    null_plus 5        trits = 00++0+-++
```

Channel minimum **27**, maximum **229**. Off both poles across the whole ring.

Code and receipt: [`nullsphere-closure/`](nullsphere-closure/) — Rust 1.81.0,
clippy `-D warnings` clean, `float_used=0`.

## Retraction

An earlier revision of this file carried geometry computed in floating point via
`hypot`, `atan2` and float multiply, and presented it as measurement: radius 290.5,
spread 0.74, angles 40.11 etc., cosine offsets 126.56 / 126.78 / 126.89, amplitudes
101.62 / 101.60 / 71.93, phases 0 / 89.98 / 45.02, and an amplitude ratio compared to √2.
Those are superseded by the exact integer values above. The √2 comparison cannot be
stated in exact arithmetic at all. The retraction is carried in the proof output rather
than removed.

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
