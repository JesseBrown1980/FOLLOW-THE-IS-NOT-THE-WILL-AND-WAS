//! NULLSPHERE CLOSURE — three arms circle a free zero; the residual is the trit.
//!
//! Input is the operator's recorded HBP table: nine star-zeros, position and
//! colour, 729x729 grid, 243 ticks, tick 242.
//!
//! Arms are held as NUMERATORS OVER 3, so every value is exact.  No float is
//! constructed anywhere in this program.
//!
//!     arm_R = 2r - g - b        (over 3)
//!     arm_G = 2g - r - b        (over 3)
//!     arm_B = 2b - r - g        (over 3)
//!
//! Their sum is identically zero for ALL integers r, g, b:
//!     (2r-g-b) + (2g-r-b) + (2b-r-g) = 0
//! and each arm is unchanged when r, g, b are all shifted by the same c,
//! so the zero they circle can be placed anywhere.  The centre is free.
//!
//! Rust 1.81 · clippy -D warnings clean · integers only.

/// star, x, y, R, G, B — recorded by OP-JESSE
const STARS: [(u32, u32, u32, i64, i64, i64); 9] = [
    (0, 655, 364, 229, 127, 178),
    (1, 586, 551, 204, 192, 198),
    (2, 414, 650, 144, 227, 186),
    (3, 219, 616, 76, 215, 146),
    (4, 91, 463, 31, 161, 96),
    (5, 91, 265, 31, 92, 62),
    (6, 219, 112, 76, 39, 57),
    (7, 414, 78, 144, 27, 86),
    (8, 586, 177, 204, 61, 133),
];

/// The three arms about the centroid, as numerators over 3.
fn arms(r: i64, g: i64, b: i64) -> (i64, i64, i64) {
    (2 * r - g - b, 2 * g - r - b, 2 * b - r - g)
}

fn trit_glyph(n: i64) -> char {
    match n {
        0 => '0',
        1 => '+',
        -1 => '-',
        _ => '?',
    }
}

// ------------------------------------------------------------------ sha256 --
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(msg: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
        0x1f83d9ab, 0x5be0cd19,
    ];
    let mut d = msg.to_vec();
    let bl = (msg.len() as u64).wrapping_mul(8);
    d.push(0x80);
    while d.len() % 64 != 56 {
        d.push(0);
    }
    d.extend_from_slice(&bl.to_be_bytes());
    for c in d.chunks(64) {
        let mut w = [0u32; 64];
        for (i, wi) in w.iter_mut().enumerate().take(16) {
            *wi = u32::from_be_bytes([c[i * 4], c[i * 4 + 1], c[i * 4 + 2], c[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let (mut a, mut b, mut cc, mut dd) = (h[0], h[1], h[2], h[3]);
        let (mut e, mut f, mut g, mut hh) = (h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let mj = (a & b) ^ (a & cc) ^ (b & cc);
            let t2 = s0.wrapping_add(mj);
            hh = g; g = f; f = e; e = dd.wrapping_add(t1);
            dd = cc; cc = b; b = a; a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(cc); h[3] = h[3].wrapping_add(dd);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }
    let mut out = String::with_capacity(64);
    for v in h.iter() {
        out.push_str(&format!("{:08x}", v));
    }
    out
}

fn main() {
    let mut rows: Vec<String> = Vec::new();
    rows.push("NSHDR|schema=NULLSPHERE-CLOSURE-V1|owner=OP-JESSE|source=HBP_nine_star_zeros\
|grid=729x729|ticks=243|tick=242|occluder_deg=355.6|rust=1.81.0|int_only=1|float_used=0\
|arms_held_as=numerator_over_3|json=0".into());

    // ---- PROOF 1: the closure is an identity, not a fit --------------------
    let mut checked = 0u64;
    for r in -60..=60i64 {
        for g in -60..=60i64 {
            for b in -60..=60i64 {
                let (ar, ag, ab) = arms(r, g, b);
                assert_eq!(ar + ag + ab, 0, "closure broke at {r},{g},{b}");
                checked += 1;
            }
        }
    }
    rows.push(format!("PROOF|k=closure_is_identity|triples_checked={}|sum_ne_zero=0\
|algebra=(2r-g-b)+(2g-r-b)+(2b-r-g)=0|holds_for_all_integers=1|json=0", checked));

    // ---- PROOF 2: the zero is free (translation invariance) ---------------
    let mut shifted = 0u64;
    for &(_, _, _, r, g, b) in STARS.iter() {
        let base = arms(r, g, b);
        for c in -1000..=1000i64 {
            assert_eq!(arms(r + c, g + c, b + c), base, "arms moved under shift {c}");
            shifted += 1;
        }
    }
    rows.push(format!("PROOF|k=the_zero_is_free|shifts_tested={}|arms_changed=0\
|centre_may_be_placed_anywhere=1|relation_is_affine=1|coeffs_1_1_-2_sum_to=0|json=0", shifted));

    // ---- THE MEASURED NINE -------------------------------------------------
    let mut census = [0u64; 3]; // -1, 0, +1
    let mut trits = String::new();
    for &(s, x, y, r, g, b) in STARS.iter() {
        let (ar, ag, ab) = arms(r, g, b);
        assert_eq!(ar + ag + ab, 0);
        assert!(ab.abs() <= 1, "third arm left the nullsphere at s{s}: {ab}");
        census[(ab + 1) as usize] += 1;
        trits.push(trit_glyph(ab));
        rows.push(format!(
            "STAR|s={}|x={}|y={}|R={}|G={}|B={}|arm_R={}/3|arm_G={}/3|arm_B={}/3\
|sum=0|third_arm_trit={}|R+G-2B={}|json=0",
            s, x, y, r, g, b, ar, ag, ab, trit_glyph(ab), r + g - 2 * b
        ));
    }
    rows.push(format!(
        "NULLSPHERE|minus_third={}|normal_null={}|null_plus={}|total={}\
|third_arm_only_ever=-1/3,0,+1/3|trits={}|json=0",
        census[0], census[1], census[2], census.iter().sum::<u64>(), trits
    ));
    rows.push("LAW|k=three_circle_the_zero|arms=3|they_sum_to=0_exactly\
|the_zero_is_the_centroid|the_zero_is_not_one_of_the_three|residual_of_third_arm=the_trit\
|exact_in_thirds=1|machine_zero=0|json=0".into());

    // ---- EXACT GEOMETRY: integers only, no sqrt, no trigonometry ----------
    // 729 is odd, so the grid centre is the integer 364. Every displacement is
    // an integer, so r^2 is exact and never needs a square root.
    const C: i64 = 364;
    let mut geo: Vec<(u32, i64, i64, i64, i64)> = Vec::new();
    for &(s, x, y, r, g, b) in STARS.iter() {
        let (dx, dy) = (x as i64 - C, y as i64 - C);
        let r2 = dx * dx + dy * dy;
        let (_, _, ab) = arms(r, g, b);
        geo.push((s, dx, dy, r2, ab));
        rows.push(format!(
            "GEO|s={}|dx={}|dy={}|r2={}|trit={}|sqrt_taken=0|trig_used=0|json=0",
            s, dx, dy, r2, ab
        ));
    }
    rows.push(format!(
        "GEOCENTRE|grid=729|centre=(729-1)/2={}|is_integer=1|float_used=0|json=0", C));
    rows.push(format!(
        "GEOS0|r2={}|equals_291_squared={}|dy=0_exactly_on_axis={}|json=0",
        geo[0].3, geo[0].3 == 291 * 291, geo[0].2 == 0));

    // exact mirror symmetry about y = C
    let pairs = [(1usize, 8usize), (2, 7), (3, 6), (4, 5)];
    let mut sym = 0;
    let mut trit_breaks = 0;
    for &(a, b2) in pairs.iter() {
        let (pa, pb) = (geo[a], geo[b2]);
        let mirrored = pa.1 == pb.1 && pa.2 == -pb.2 && pa.3 == pb.3;
        if mirrored {
            sym += 1;
        }
        if pa.4 != pb.4 {
            trit_breaks += 1;
        }
        rows.push(format!(
            "MIRROR|s{}<->s{}|dx_equal={}|dy_negated={}|r2_equal={}|exact={}|trit_a={}|trit_b={}|trit_equal={}|json=0",
            a, b2, pa.1 == pb.1, pa.2 == -pb.2, pa.3 == pb.3, mirrored, pa.4, pb.4, pa.4 == pb.4));
    }
    rows.push(format!(
        "MIRRORSUM|pairs={}|positions_exactly_symmetric={}|trit_differs_in={}\
|positions_are_mirror_blind=1|the_trit_sees_the_difference={}|json=0",
        pairs.len(), sym, trit_breaks, trit_breaks > 0));
    assert_eq!(sym, pairs.len(), "mirror symmetry is not exact");

    // single rotation, by exact integer cross products
    let mut crosses: Vec<i64> = Vec::with_capacity(9);
    for i in 0..9usize {
        let a = geo[i];
        let b2 = geo[(i + 1) % 9];
        crosses.push(a.1 * b2.2 - a.2 * b2.1);
    }
    let all_pos = crosses.iter().all(|&c| c > 0);
    let palindrome = crosses.iter().eq(crosses.iter().rev());
    rows.push(format!(
        "TURN|crosses={}|all_positive={}|single_rotation_no_backtrack={}|palindromic={}\
|centre_value={}|json=0",
        crosses.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(","),
        all_pos, all_pos, palindrome, crosses[4]));
    assert!(all_pos, "the turn backtracked");

    rows.push("RETRACT|k=float_derived_geometry|superseded=radius_290.5,spread_0.74,\
angles_40.11_etc,cosine_offsets_126.56_126.78_126.89,amplitudes_101.62_101.60_71.93,\
phases_0_89.98_45.02,amplitude_ratio_vs_sqrt2|reason=computed_with_hypot_atan2_and_float_multiply\
|replaced_by=exact_integer_r2_mirror_pairs_and_cross_products|json=0".into());

    let body = rows.join("\n");
    let receipt = sha256(body.as_bytes());
    for r in &rows {
        println!("{}", r);
    }
    println!("NSFTR|rows={}|receipt={}|hot_path=1|jsn_emitted=0|json=0", rows.len() + 1, receipt);
}
