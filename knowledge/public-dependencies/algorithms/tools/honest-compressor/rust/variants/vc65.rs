// cm3ti16.rs — INTEGER-deterministic cm3t at 16-bit probability (tuned from cm3ti). Submission-grade: every arithmetic op is
// integer (fixed-point), so the compressed bytes are bit-identical on any CPU and
// reproducible by any language that copies these exact integer ops (the point the
// review raised: floats drift across platforms; integers do not). Same model shape
// as cm3t (orders 0..k hashed + order-5 match + 2 word models, logistic mixer, two
// SSE/APM stages, binary range coder) but with lpaq-style integer stretch/squash
// tables and a fixed-point mixer. Lossless (SHA restore) or the run is invalid.
use std::collections::HashMap;
use std::fs;
use std::time::Instant;

const TBITS: u32 = 28;
const TSIZE: usize = 1 << TBITS;
const TMASK: u64 = (TSIZE as u64) - 1;
const MO: usize = 5;

// ---- integer stretch/squash (lpaq1-style), p in [0,4095], d in [-2047,2047] ----
struct Tables { squash: Vec<i32>, stretch: Vec<i32> }
impl Tables {
    fn new() -> Tables {
        // squash: d -> p ; build from the logistic curve using integer table + interp
        let base: [i32; 33] = [22,36,60,98,162,267,439,720,1179,1921,3108,4971,7812,11955,17625,24743,
            32768,40793,47911,53581,57724,60565,62428,63615,64357,64816,65097,65269,65374,65438,65476,65500,65514];
        let mut squash = vec![0i32; 4096]; // index d+2048 for d in [-2047,2048]
        for d in -2047..=2047 {
            let w = d & 127;
            let idx = ((d >> 7) + 16) as usize;
            let v = (base[idx] * (128 - w) + base[idx + 1] * w + 64) >> 7;
            squash[(d + 2048) as usize] = v;
        }
        squash[0] = 1; // clamp ends (16-bit)
        let mut stretch = vec![0i32; 65536];
        let mut pi = 0usize;
        for d in -2047..=2047 {
            let p = squash[(d + 2048) as usize] as usize;
            while pi <= p { stretch[pi] = d; pi += 1; }
        }
        while pi < 65536 { stretch[pi] = 2047; pi += 1; }
        Tables { squash, stretch }
    }
    #[inline] fn squash(&self, d: i32) -> i32 {
        let d = if d < -2047 { -2047 } else if d > 2047 { 2047 } else { d };
        self.squash[(d + 2048) as usize]
    }
    #[inline] fn stretch(&self, p: i32) -> i32 { self.stretch[p as usize & 65535] }
}

struct Model {
    k: usize, b: u32, nin: usize,
    tb: Tables,
    t: Vec<Vec<u16>>, tn: Vec<Vec<u8>>,
    t0: Vec<u16>, t0n: Vec<u8>,
    tw: Vec<Vec<u16>>, twn: Vec<Vec<u8>>,
    tu: Vec<u16>, tun: Vec<u8>, seg_pos: usize, last_delim: u64, uctx: u64, uidx: usize,
    rate: [i32; 256],
    w: Vec<i32>,      // mixer A: selected by (bit,last-byte)
    w2: Vec<i32>,     // mixer B: selected by (bit,SECTOR) — the color-sector gate
    wrow2: usize, sector: usize, sector_b: usize, wrow2b: usize,
    apm: Vec<u16>,    // 1024*33, prob*16 fixed (0..4095)
    apm2: Vec<u16>,
    hist: Vec<u8>,
    mpos: HashMap<u64, usize>,
    match_ptr: i64, match_len: usize,
    ctx_h: Vec<u64>, wh: u64, pwh: u64,
    idxs: Vec<usize>, widx: [usize; 2],
    st: Vec<i32>,     // stretched inputs
    o0idx: usize, wrow: usize,
    pred_glyph: i32, match_bit: i32,
    p_pre: i32,       // pre-SSE mixed prob (0..4095)
    a1: (usize, i32, i32), a2: (usize, i32, i32),
    bucket_base: usize, wctx1: u64, wctx2: u64,
}

impl Model {
    fn new(v: usize, k: usize) -> Model {
        let b = std::cmp::max(1, 64 - ((v as u64 - 1).leading_zeros())) as u32;
        let nin = k + 4 + 1;  // + gated URL/path context (combined with sector mixer)
        let mut rate = [0i32; 256];
        // count-adaptive fixed-point rate ~ 65536/(n+1.5), matures to 1/32 (=2048) — a
        // pure-integer mirror of the float 1/(n+1.5) ramp (portable constants).
        for n in 0..256 { rate[n] = if n < 30 { (65536i32 * 2) / (2 * n as i32 + 3) } else { 2048 }; }
        let mut apm = vec![0u16; 1024 * 33];
        let mut apm2 = vec![0u16; 1024 * 33];
        let tb = Tables::new();
        for c in 0..1024 {
            for j in 0..33 {
                // init APM to identity: bin j maps to squash of that stretched value
                let d = ((j as i32) - 16) * 128;
                let p = tb.squash(d) as u16;
                apm[c * 33 + j] = p; apm2[c * 33 + j] = p;
            }
        }
        Model {
            k, b, nin, tb,
            t: (0..k).map(|_| vec![32768u16; TSIZE]).collect(),
            tn: (0..k).map(|_| vec![0u8; TSIZE]).collect(),
            t0: vec![32768u16; 1 << (b + 1)], t0n: vec![0u8; 1 << (b + 1)],
            tw: (0..2).map(|_| vec![32768u16; TSIZE]).collect(),
            twn: (0..2).map(|_| vec![0u8; TSIZE]).collect(),
            tu: vec![32768u16; TSIZE], tun: vec![0u8; TSIZE], seg_pos: 0, last_delim: 0, uctx: 0, uidx: 0,
            rate,
            w: vec![(0.3 * 65536.0) as i32; (b as usize * 256) * nin],
            w2: vec![(0.3 * 65536.0) as i32; (b as usize * 65536) * nin],
            wrow2: 0, sector: 0, sector_b: 0, wrow2b: 0,
            apm, apm2,
            hist: Vec::new(), mpos: HashMap::new(),
            match_ptr: -1, match_len: 0,
            ctx_h: vec![0u64; k + 1], wh: 0, pwh: 0,
            idxs: vec![0usize; k], widx: [0, 0],
            st: vec![0i32; nin],
            o0idx: 0, wrow: 0, pred_glyph: -1, match_bit: -1, p_pre: 32768,
            a1: (0, 0, 0), a2: (0, 0, 0),
            bucket_base: 0, wctx1: 0, wctx2: 0,
        }
    }

    fn begin_symbol(&mut self) {
        let n = self.hist.len();
        for o in 1..=self.k {
            let mut v: u64 = 0;
            if n >= o {
                for &g in &self.hist[n - o..] {
                    v = v.wrapping_mul(0x9E3779B1).wrapping_add(g as u64 + 1) & 0xFFFFFFFF;
                }
                v = (v ^ (o as u64).wrapping_mul(0x85EBCA6B)) & 0xFFFFFFFF;
            }
            self.ctx_h[o] = v;
        }
        if self.match_ptr < 0 && n >= MO {
            let mut key: u64 = 0;
            for &g in &self.hist[n - MO..] {
                key = key.wrapping_mul(0x01000193).wrapping_add(g as u64 + 1) & 0xFFFFFFFF;
            }
            if let Some(&p) = self.mpos.get(&key) { if p < n { self.match_ptr = p as i64; self.match_len = MO; } }
        }
        self.pred_glyph = if self.match_ptr >= 0 && (self.match_ptr as usize) < n { self.hist[self.match_ptr as usize] as i32 } else { -1 };
        self.bucket_base = if n > 0 { (self.hist[n - 1] & 0xFF) as usize } else { 0 };
        self.uctx = ((self.seg_pos as u64).wrapping_mul(0x9E3779B1) ^ (self.last_delim+1).wrapping_mul(0x85EBCA6B)) & 0xFFFFFFFF;
        let lb = if n>0 { self.hist[n-1] as i32 } else { 0 };
        let lb2 = if n>1 { self.hist[n-2] as i32 } else { 0 };
        let lb3 = if n>2 { self.hist[n-3] as i32 } else { 0 };
        let lb4 = if n>3 { self.hist[n-4] as i32 } else { 0 };
        let cls = |b: i32| -> usize { if (65..=90).contains(&b)||(97..=122).contains(&b) {0}
            else if (48..=57).contains(&b) {1}
            else if b==32||b==10||b==9 {2}
            else if b==60||b==62||b==38||b==91||b==93||b==123||b==125||b==124||b==61||b==34 {3}
            else if b>=128 {4} else {5} };
        let b1 = cls(lb); let b2 = cls(lb2); let b3 = cls(lb3); let b4 = cls(lb4);
        let run1 = if b2==b1 { if b3==b1 { if b4==b1 {3} else {2} } else {1} } else {0};
        let run2 = if b3==b2 { if b4==b2 {2} else {1} } else {0};
        self.sector = ((lb & 0xFF) as usize)*256 + ((lb2 & 0xFF) as usize);
        self.sector_b = ((lb2 & 0xFF) as usize)*256 + ((lb3 & 0xFF) as usize);
        self.wctx1 = (self.wh ^ 0x8DA6B343) & 0xFFFFFFFF;
        self.wctx2 = (self.wh.wrapping_mul(0x01000193) ^ self.pwh.wrapping_mul(0x9E3779B1)) & 0xFFFFFFFF;
    }

    // APM refine: ctx row, stretched-p interpolation over 33 bins; returns refined p
    #[inline]
    fn apm_apply(tb: &Tables, tbl: &[u16], ctx: usize, p: i32) -> (i32, (usize, i32, i32)) {
        let s = tb.stretch(p) + 2048;            // 0..4095
        let idx = (s >> 7) as usize;             // 0..31
        let w = s & 127;
        let base = ctx * 33 + idx;
        let lo = tbl[base] as i32; let hi = tbl[base + 1] as i32;
        let pr = (lo * (128 - w) + hi * w) >> 7;
        (pr, (base, w, 0))
    }

    fn predict_bit(&mut self, c: usize, j: u32) -> i32 {
        let k = self.k;
        for o in 1..=k {
            let idx = ((self.ctx_h[o] ^ (c as u64).wrapping_mul(0xB5297A4D)) & TMASK) as usize;
            self.idxs[o - 1] = idx;
            self.st[o - 1] = self.tb.stretch(self.t[o - 1][idx] as i32);
        }
        self.o0idx = c & ((1usize << (self.b + 1)) - 1);
        self.st[k] = self.tb.stretch(self.t0[self.o0idx] as i32);
        if self.pred_glyph >= 0 {
            let pb = (self.pred_glyph >> (self.b - 1 - j)) & 1;
            let strength = std::cmp::min(self.match_len, 28) as i32 * 64; // stretched units
            self.st[k + 1] = if pb == 1 { strength } else { -strength };
            self.match_bit = pb;
        } else { self.st[k + 1] = 0; self.match_bit = -1; }
        let wi1 = ((self.wctx1 ^ (c as u64).wrapping_mul(0xB5297A4D)) & TMASK) as usize;
        let wi2 = ((self.wctx2 ^ (c as u64).wrapping_mul(0xB5297A4D)) & TMASK) as usize;
        self.widx = [wi1, wi2];
        self.st[k + 2] = self.tb.stretch(self.tw[0][wi1] as i32);
        self.st[k + 3] = self.tb.stretch(self.tw[1][wi2] as i32);
        let uidx=((self.uctx^(c as u64).wrapping_mul(0xB5297A4D))&TMASK) as usize;
        self.uidx=uidx; self.st[k+4]=self.tb.stretch(self.tu[uidx] as i32);
        // fixed-point mixer
        self.wrow = (j as usize * 256 + self.bucket_base) * self.nin;
        self.wrow2 = (j as usize * 65536 + self.sector) * self.nin;
        self.wrow2b = (j as usize * 65536 + self.sector_b) * self.nin;
        let mut dot: i64 = 0;
        for i in 0..self.nin { dot += (4*self.w[self.wrow + i] as i64 + 2*self.w2[self.wrow2 + i] as i64 + 2*self.w2[self.wrow2b + i] as i64) * self.st[i] as i64; }
        let d = (dot >> 19) as i32;  // /8: 4*w + 2*sector + 2*neighbor (even gradient)
        let p1 = self.tb.squash(d);
        self.p_pre = p1;
        // SSE stage 1 (order-1 keyed), trust ~ (1/16) via integer blend
        let actx = if k >= 1 { ((self.ctx_h[1] ^ (c as u64).wrapping_mul(0x2545F491)) & 1023) as usize } else { c & 1023 };
        let (pa, s1) = Model::apm_apply(&self.tb, &self.apm, actx, p1);
        self.a1 = (s1.0, s1.1, p1);
        let p_s1 = (pa + p1 * 3) >> 2;            // ~0.25 apm trust
        let mlb = std::cmp::min(self.match_len, 3);
        let actx2 = (mlb * 256 + self.bucket_base) & 1023;
        let (pa2, s2) = Model::apm_apply(&self.tb, &self.apm2, actx2, p_s1);
        self.a2 = (s2.0, s2.1, p_s1);
        let mut p = (pa2 + p_s1 * 3) >> 2;
        if p < 1 { p = 1; } if p > 65534 { p = 65534; }
        p
    }

    fn update_bit(&mut self, bit: i32) {
        let k = self.k;
        let err = (bit << 16) - self.p_pre;      // scaled error (p in 0..4095 ~ <<12? use 4096)
        for i in 0..self.nin {
            self.w[self.wrow + i] += (self.st[i] * err) >> 14;
            self.w2[self.wrow2 + i] += (self.st[i] * err) >> 15;
            self.w2[self.wrow2b + i] += (self.st[i] * err) >> 15;
        }
        for o in 1..=k {
            let idx = self.idxs[o - 1]; let nn = self.tn[o - 1][idx] as usize;
            let v = self.t[o - 1][idx] as i32;
            self.t[o - 1][idx] = (v + ((((bit << 16) - v) * self.rate[nn]) >> 16)).clamp(1, 65534) as u16;
            if nn < 255 { self.tn[o - 1][idx] = (nn + 1) as u8; }
        }
        let idx = self.o0idx; let nn = self.t0n[idx] as usize; let v = self.t0[idx] as i32;
        self.t0[idx] = (v + ((((bit << 16) - v) * self.rate[nn]) >> 16)).clamp(1, 65534) as u16;
        if nn < 255 { self.t0n[idx] = (nn + 1) as u8; }
        for wi in 0..2 {
            let idx = self.widx[wi]; let nn = self.twn[wi][idx] as usize; let v = self.tw[wi][idx] as i32;
            self.tw[wi][idx] = (v + ((((bit << 16) - v) * self.rate[nn]) >> 16)).clamp(1, 65534) as u16;
            if nn < 255 { self.twn[wi][idx] = (nn + 1) as u8; }
        }
        { let idx=self.uidx; let nn=self.tun[idx] as usize; let v=self.tu[idx] as i32;
          self.tu[idx]=(v+((((bit<<16)-v)*self.rate[nn])>>16)).clamp(1,65534) as u16;
          if nn<255 { self.tun[idx]=(nn+1) as u8; } }
        let g = bit << 16;
        let (b1, w1, _) = self.a1;
        let lo = self.apm[b1] as i32; let hi = self.apm[b1 + 1] as i32;
        self.apm[b1] = (lo + (((g - lo) * (128 - w1)) >> 12)).clamp(1, 65534) as u16;
        self.apm[b1 + 1] = (hi + (((g - hi) * w1) >> 12)).clamp(1, 65534) as u16;
        let (b2, w2, _) = self.a2;
        let lo = self.apm2[b2] as i32; let hi = self.apm2[b2 + 1] as i32;
        self.apm2[b2] = (lo + (((g - lo) * (128 - w2)) >> 12)).clamp(1, 65534) as u16;
        self.apm2[b2 + 1] = (hi + (((g - hi) * w2) >> 12)).clamp(1, 65534) as u16;
        if self.match_bit >= 0 && self.match_bit != bit { self.match_ptr = -1; self.match_len = 0; }
    }

    fn update_symbol(&mut self, s: i32) {
        let sb = (s & 0xFF) as u8;
        if (48..=57).contains(&sb) || (65..=90).contains(&sb) || (97..=122).contains(&sb) {
            self.wh = self.wh.wrapping_mul(0x01000193).wrapping_add((sb as u64 | 0x20) + 1) & 0xFFFFFFFF;
        } else { if self.wh != 0 { self.pwh = self.wh; } self.wh = 0; }
        if sb==47||sb==46||sb==58||sb==63||sb==38||sb==61||sb==64||sb==37 { self.last_delim=sb as u64; self.seg_pos=0; }
        else if sb==32||sb==10||sb==9||sb==60||sb==62 { self.last_delim=0; self.seg_pos=0; }
        else { self.seg_pos=(self.seg_pos+1).min(31); }
        if self.match_ptr >= 0 {
            if self.hist[self.match_ptr as usize] as i32 == s { self.match_ptr += 1; self.match_len += 1; }
            else { self.match_ptr = -1; self.match_len = 0; }
        }
        self.hist.push((s & 0xFF) as u8);
        let n = self.hist.len();
        if n >= MO {
            let mut key: u64 = 0;
            for &g in &self.hist[n - MO..] { key = key.wrapping_mul(0x01000193).wrapping_add(g as u64 + 1) & 0xFFFFFFFF; }
            self.mpos.insert(key, n);
        }
    }
}

// ---- integer binary range coder (p in 0..4095, 12-bit) ----
struct Enc { x1: u32, x2: u32, out: Vec<u8> }
impl Enc {
    fn new() -> Enc { Enc { x1: 0, x2: 0xFFFFFFFF, out: Vec::new() } }
    fn encode(&mut self, bit: i32, p: i32) {
        let range = (self.x2 - self.x1) as u64;
        let mut xmid = self.x1 + ((range * p as u64) >> 16) as u32;
        if xmid < self.x1 { xmid = self.x1; } if xmid >= self.x2 { xmid = self.x2 - 1; }
        if bit == 1 { self.x2 = xmid; } else { self.x1 = xmid + 1; }
        while (self.x1 ^ self.x2) & 0xFF000000 == 0 {
            self.out.push((self.x2 >> 24) as u8); self.x1 <<= 8; self.x2 = (self.x2 << 8) | 0xFF;
        }
    }
    fn flush(mut self) -> Vec<u8> { for _ in 0..4 { self.out.push((self.x1 >> 24) as u8); self.x1 <<= 8; } self.out }
}
struct Dec<'a> { x1: u32, x2: u32, x: u32, data: &'a [u8], pos: usize }
impl<'a> Dec<'a> {
    fn new(data: &'a [u8]) -> Dec<'a> {
        let mut x = 0u32; for i in 0..4 { x = (x << 8) | (*data.get(i).unwrap_or(&0) as u32); }
        Dec { x1: 0, x2: 0xFFFFFFFF, x, data, pos: 4 }
    }
    fn decode(&mut self, p: i32) -> i32 {
        let range = (self.x2 - self.x1) as u64;
        let mut xmid = self.x1 + ((range * p as u64) >> 16) as u32;
        if xmid < self.x1 { xmid = self.x1; } if xmid >= self.x2 { xmid = self.x2 - 1; }
        let bit = if self.x <= xmid { 1 } else { 0 };
        if bit == 1 { self.x2 = xmid; } else { self.x1 = xmid + 1; }
        while (self.x1 ^ self.x2) & 0xFF000000 == 0 {
            self.x1 <<= 8; self.x2 = (self.x2 << 8) | 0xFF;
            let nxt = *self.data.get(self.pos).unwrap_or(&0) as u32; self.x = (self.x << 8) | nxt; self.pos += 1;
        }
        bit
    }
}

fn compress(data: &[u8], k: usize) -> Vec<u8> {
    let mut m = Model::new(256, k); let mut enc = Enc::new(); let b = m.b;
    for &byte in data {
        let s = byte as i32; m.begin_symbol(); let mut c = 1usize;
        for j in 0..b {
            let bit = (s >> (b - 1 - j)) & 1;
            let p = m.predict_bit(c, j);
            enc.encode(bit, p); m.update_bit(bit); c = (c << 1) | bit as usize;
        }
        m.update_symbol(s);
    }
    enc.flush()
}
fn decompress(comp: &[u8], n: usize, k: usize) -> Vec<u8> {
    let mut m = Model::new(256, k); let mut dec = Dec::new(comp); let b = m.b;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        m.begin_symbol(); let mut c = 1usize;
        for j in 0..b {
            let p = m.predict_bit(c, j);
            let bit = dec.decode(p); m.update_bit(bit); c = (c << 1) | bit as usize;
        }
        let s = (c - (1 << b)) as i32; m.update_symbol(s); out.push((s & 0xFF) as u8);
    }
    out
}

fn sha256(data: &[u8]) -> String {
    let mut h: [u32;8]=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    const K:[u32;64]=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    let mut msg=data.to_vec(); let bl=(data.len() as u64)*8; msg.push(0x80);
    while msg.len()%64!=56 { msg.push(0); } msg.extend_from_slice(&bl.to_be_bytes());
    for ch in msg.chunks(64) {
        let mut w=[0u32;64];
        for i in 0..16 { w[i]=u32::from_be_bytes([ch[i*4],ch[i*4+1],ch[i*4+2],ch[i*4+3]]); }
        for i in 16..64 { let s0=w[i-15].rotate_right(7)^w[i-15].rotate_right(18)^(w[i-15]>>3); let s1=w[i-2].rotate_right(17)^w[i-2].rotate_right(19)^(w[i-2]>>10); w[i]=w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1); }
        let (mut a,mut b,mut c,mut d,mut e,mut f,mut g,mut hh)=(h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7]);
        for i in 0..64 { let s1=e.rotate_right(6)^e.rotate_right(11)^e.rotate_right(25); let ch2=(e&f)^((!e)&g); let t1=hh.wrapping_add(s1).wrapping_add(ch2).wrapping_add(K[i]).wrapping_add(w[i]); let s0=a.rotate_right(2)^a.rotate_right(13)^a.rotate_right(22); let maj=(a&b)^(a&c)^(b&c); let t2=s0.wrapping_add(maj); hh=g;g=f;f=e;e=d.wrapping_add(t1);d=c;c=b;b=a;a=t1.wrapping_add(t2); }
        h[0]=h[0].wrapping_add(a);h[1]=h[1].wrapping_add(b);h[2]=h[2].wrapping_add(c);h[3]=h[3].wrapping_add(d);h[4]=h[4].wrapping_add(e);h[5]=h[5].wrapping_add(f);h[6]=h[6].wrapping_add(g);h[7]=h[7].wrapping_add(hh);
    }
    let mut s=String::new(); for v in h.iter() { s.push_str(&format!("{:08x}", v)); } s
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 { eprintln!("usage: cm3ti <file> <k> [--emit out.bin]"); std::process::exit(1); }
    let data = fs::read(&args[1]).unwrap(); let n = data.len(); let k: usize = args[2].parse().unwrap();
    let sha_in = sha256(&data);
    let t0 = Instant::now(); let comp = compress(&data, k); let enc_s = t0.elapsed().as_secs_f64();
    let t1 = Instant::now(); let body = decompress(&comp, n, k); let dec_s = t1.elapsed().as_secs_f64();
    let ok = sha256(&body) == sha_in;
    let comp_sha = sha256(&comp);
    if args.len() >= 5 && args[3] == "--emit" { fs::write(&args[4], &comp).unwrap(); }
    let src_b = fs::metadata("vc27.rs").map(|m| m.len()).unwrap_or(0);
    let payload = comp.len() as u64; let total = payload + src_b;
    println!("cm3ti-vc65-fullstack k={} N={} payload={} decoder_src={} total={} bpc_total={:.4} restore={} comp_sha={} enc={:.0}s dec={:.0}s",
        k, n, payload, src_b, total, (total as f64*8.0)/n as f64, if ok {"OK"} else {"FAIL"}, &comp_sha[..16], enc_s, dec_s);
}
