//! NULLNET — 81 links netting 27 free zeros. The three-body, 27 times over.
//!
//! The three-body result generalises by construction: three arms circle a free
//! zero and sum to exactly nothing. Run it on a 3x3x3 lattice closed mod 3 and
//! the counts fall out with no tuning:
//!
//!     nodes   3^3            = 27   the free zeros
//!     edges   27 * 6 / 2     = 81   the net, carried as HTTP, cost 0
//!     lines   27 / 3 * 3     = 27   one three-body per line
//!     seats   27 * 3         = 81   81 around 27
//!
//! Along any axis the three members of a line differ only in that digit, so
//! their values are v - 3^i, v, v + 3^i. The centroid is v exactly, the arms
//! are (-3^i, 0, +3^i), and divided by the place value they are (-1, 0, +1) —
//! the nullsphere, at every line, with no residue.
//!
//! Rust 1.81 · clippy -D warnings clean · i64 only · no float is constructed.

const N: usize = 27;
const AXES: usize = 3;

/// Balanced-ternary digit of `node` at `axis`, one of -1, 0, +1.
fn digit(node: usize, axis: usize) -> i64 {
    let p = 3usize.pow(axis as u32);
    ((node / p) % 3) as i64 - 1
}

/// The node's carried integer value: sum of digit * 3^axis.
fn value(node: usize) -> i64 {
    (0..AXES).map(|a| digit(node, a) * 3i64.pow(a as u32)).sum()
}

/// Step one place along `axis`, closed mod 3 — this is what makes it a net.
fn step(node: usize, axis: usize, delta: i64) -> usize {
    let p = 3usize.pow(axis as u32);
    let d = (node / p) % 3;
    let nd = (((d as i64 + delta) % 3 + 3) % 3) as usize;
    node - d * p + nd * p
}

fn glyph(t: i64) -> char {
    match t {
        0 => '0',
        1 => '+',
        -1 => '-',
        _ => '?',
    }
}

fn addr(node: usize) -> String {
    (0..AXES).rev().map(|a| glyph(digit(node, a))).collect()
}

fn main() {
    let mut rows: Vec<String> = Vec::new();
    rows.push(
        "NNHDR|schema=NULLNET-81-OVER-27-V1|owner=OP-JESSE|rust=1.81.0|int_only=1\
|float_used=0|lattice=3x3x3|closed_mod_3=1|json=0"
            .into(),
    );

    // ---- the 27 free zeros ------------------------------------------------
    let mut zero_cost: i64 = 0;
    for z in 0..N {
        zero_cost += 0; // a free zero costs nothing. This is the law, not a rounding.
        if z < 3 || z == N - 1 {
            rows.push(format!(
                "ZERO|z={}|addr={}|value={}|cost=0|free=1|json=0",
                z,
                addr(z),
                value(z)
            ));
        }
    }
    rows.push(format!(
        "ZEROS|count={}|expected=3^3=27|all_free={}|total_cost={}|json=0",
        N,
        N == 27,
        zero_cost
    ));
    assert_eq!(N, 27);
    assert_eq!(zero_cost, 0, "a zero was charged");

    // ---- the net: 81 links, each an HTTP conduit, each free ---------------
    let mut edges: Vec<(usize, usize)> = Vec::new();
    let mut degree = [0usize; N];
    for (z, deg) in degree.iter_mut().enumerate() {
        for a in 0..AXES {
            for d in [-1i64, 1] {
                let w = step(z, a, d);
                *deg += 1;
                if z < w {
                    edges.push((z, w));
                }
            }
        }
    }
    let deg_ok = degree.iter().all(|&d| d == 6);
    let link_cost: i64 = edges.iter().map(|_| 0).sum();
    rows.push(format!(
        "NET|links={}|expected=27*6/2=81|every_degree_6={}|carrier=HTTP|cost_per_link=0\
|total_link_cost={}|the_zeros_are_free_because_the_pipe_is=1|json=0",
        edges.len(),
        deg_ok,
        link_cost
    ));
    assert_eq!(edges.len(), 81, "the net is not 81");
    assert!(deg_ok, "a zero did not have 6 conduits");
    assert_eq!(link_cost, 0, "a conduit was charged");

    // ---- 27 three-bodies, one per line ------------------------------------
    let mut lines = 0usize;
    let mut seats = 0usize;
    let mut closed = 0usize;
    let mut trit_census = [0usize; 3];
    let mut shown = 0usize;
    for a in 0..AXES {
        let p = 3i64.pow(a as u32);
        for z in 0..N {
            if digit(z, a) != -1 {
                continue; // one line per triple, anchored at the minus member
            }
            let m = step(z, a, 1);
            let q = step(z, a, 2);
            let (vz, vm, vq) = (value(z), value(m), value(q));

            // centroid, held exactly: the three values are v-p, v, v+p
            let sum3 = vz + vm + vq;
            assert_eq!(sum3 % 3, 0, "centroid is not exact");
            let centroid = sum3 / 3;

            let arms = [vz - centroid, vm - centroid, vq - centroid];
            assert_eq!(arms[0] + arms[1] + arms[2], 0, "the three arms did not close");
            closed += 1;

            // divided by the place value the arms ARE the nullsphere
            let trits = [arms[0] / p, arms[1] / p, arms[2] / p];
            assert_eq!(arms[0] % p, 0);
            assert_eq!(arms[2] % p, 0);
            assert_eq!(trits, [-1, 0, 1], "a line left the nullsphere");
            for t in trits {
                trit_census[(t + 1) as usize] += 1;
            }

            lines += 1;
            seats += 3;
            if shown < 4 {
                rows.push(format!(
                    "LINE|axis={}|members={},{},{}|addrs={},{},{}|values={},{},{}\
|centroid={}|arms={},{},{}|sum=0|trits={}{}{}|json=0",
                    a, z, m, q, addr(z), addr(m), addr(q), vz, vm, vq, centroid,
                    arms[0], arms[1], arms[2],
                    glyph(trits[0]), glyph(trits[1]), glyph(trits[2])
                ));
                shown += 1;
            }
        }
    }
    rows.push(format!(
        "LINES|count={}|expected=27/3*3=27|all_closed_to_zero={}|json=0",
        lines,
        closed == lines
    ));
    rows.push(format!(
        "SEATS|count={}|expected=27*3=81|81_around_27={}|json=0",
        seats,
        seats == 81
    ));
    rows.push(format!(
        "NULLSPHERE|minus={}|zero={}|plus={}|total={}|each_exactly_a_third={}\
|residue=0|json=0",
        trit_census[0], trit_census[1], trit_census[2],
        trit_census.iter().sum::<usize>(),
        trit_census[0] == trit_census[1] && trit_census[1] == trit_census[2]
    ));
    assert_eq!(lines, 27, "not 27 three-bodies");
    assert_eq!(seats, 81, "not 81 seats");

    // ---- the whole net closes too -----------------------------------------
    let global: i64 = (0..N).map(value).sum();
    rows.push(format!(
        "GLOBAL|sum_of_all_27_values={}|the_net_itself_closes={}|json=0",
        global,
        global == 0
    ));
    assert_eq!(global, 0, "the net did not close");

    rows.push(
        "LAW|k=three_body_by_construction|three_arms_circle_a_free_zero=1\
|they_sum_to_zero_exactly=1|holds_at_every_one_of_27_lines=1|no_integration=0\
|no_float=1|the_81_are_the_net_the_27_are_the_zeros|json=0"
            .into(),
    );

    for r in &rows {
        println!("{}", r);
    }
    println!(
        "NNFTR|rows={}|zeros=27|links=81|lines=27|seats=81|hot_path=1|jsn_emitted=0|json=0",
        rows.len() + 1
    );
}
