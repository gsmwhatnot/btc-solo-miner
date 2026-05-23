use super::{DigestWords, ScanBatchResult, TargetWords, H0, K};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

const LANES: usize = 16;

pub fn avx512_available() -> bool {
    std::is_x86_feature_detected!("avx512f")
}

pub fn avx512_sha256d80(header: &[u8; 80]) -> Option<[u8; 32]> {
    let ctx = Sha256d80Avx512::new(header)?;
    Some(ctx.hash_nonce(u32::from_le_bytes(
        header[76..80].try_into().expect("nonce length"),
    )))
}

pub struct Sha256d80Avx512 {
    midstate: [u32; 8],
    tail_template: [u32; 16],
}

impl Sha256d80Avx512 {
    pub fn new(header: &[u8; 80]) -> Option<Self> {
        if !avx512_available() {
            return None;
        }
        Some(Self::new_portable(header))
    }

    fn new_portable(header: &[u8; 80]) -> Self {
        let scalar = super::Sha256d80::new(header);
        Self {
            midstate: scalar.midstate,
            tail_template: scalar.tail_template,
        }
    }

    pub fn hash_nonce(&self, nonce: u32) -> [u8; 32] {
        let batch = self.scan_batch(nonce as u64, 1, TargetWords::MAX);
        batch.found_hash.expect("max target matches every hash")
    }

    pub fn scan_batch(&self, start: u64, count: u64, target: TargetWords) -> ScanBatchResult {
        unsafe { self.scan_batch_unchecked(start, count, target) }
    }

    pub fn count_batch_with_target(&self, start: u64, count: u64, target: TargetWords) -> u64 {
        unsafe { self.count_batch_with_target_unchecked(start, count, target) }
    }

    #[target_feature(enable = "avx512f")]
    unsafe fn scan_batch_unchecked(
        &self,
        start: u64,
        count: u64,
        target: TargetWords,
    ) -> ScanBatchResult {
        let mut offset = 0u64;
        while offset + LANES as u64 <= count {
            let digests = self.hash16(start.wrapping_add(offset));
            for lane in 0..LANES {
                let digest = digest_lane(&digests, lane);
                if digest.meets_target(target) {
                    return ScanBatchResult {
                        hashes_checked: offset + lane as u64 + 1,
                        found_nonce: Some(start.wrapping_add(offset + lane as u64) as u32),
                        found_hash: Some(digest.to_be_bytes()),
                    };
                }
            }
            offset += LANES as u64;
        }

        while offset < count {
            let nonce = start.wrapping_add(offset) as u32;
            let digest = super::Sha256d80 {
                midstate: self.midstate,
                tail_template: self.tail_template,
            }
            .hash_nonce_words(nonce);
            if digest.meets_target(target) {
                return ScanBatchResult {
                    hashes_checked: offset + 1,
                    found_nonce: Some(nonce),
                    found_hash: Some(digest.to_be_bytes()),
                };
            }
            offset += 1;
        }

        ScanBatchResult {
            hashes_checked: count,
            found_nonce: None,
            found_hash: None,
        }
    }

    #[target_feature(enable = "avx512f")]
    unsafe fn count_batch_with_target_unchecked(
        &self,
        start: u64,
        count: u64,
        target: TargetWords,
    ) -> u64 {
        let mut matches = 0u64;
        let mut offset = 0u64;
        while offset + LANES as u64 <= count {
            let digests = self.hash16(start.wrapping_add(offset));
            for lane in 0..LANES {
                if digest_lane(&digests, lane).meets_target(target) {
                    matches += 1;
                }
            }
            offset += LANES as u64;
        }

        while offset < count {
            let nonce = start.wrapping_add(offset) as u32;
            let digest = super::Sha256d80 {
                midstate: self.midstate,
                tail_template: self.tail_template,
            }
            .hash_nonce_words(nonce);
            if digest.meets_target(target) {
                matches += 1;
            }
            offset += 1;
        }
        matches
    }

    #[target_feature(enable = "avx512f")]
    unsafe fn hash16(&self, start: u64) -> [__m512i; 8] {
        let mut tail = [_mm512_setzero_si512(); 16];
        for (i, word) in tail.iter_mut().enumerate() {
            *word = _mm512_set1_epi32(self.tail_template[i] as i32);
        }
        tail[3] = nonce_words(start);

        let midstate = [
            _mm512_set1_epi32(self.midstate[0] as i32),
            _mm512_set1_epi32(self.midstate[1] as i32),
            _mm512_set1_epi32(self.midstate[2] as i32),
            _mm512_set1_epi32(self.midstate[3] as i32),
            _mm512_set1_epi32(self.midstate[4] as i32),
            _mm512_set1_epi32(self.midstate[5] as i32),
            _mm512_set1_epi32(self.midstate[6] as i32),
            _mm512_set1_epi32(self.midstate[7] as i32),
        ];
        let first = compress(midstate, tail);

        let mut second = [_mm512_setzero_si512(); 16];
        second[..8].copy_from_slice(&first);
        second[8] = _mm512_set1_epi32(0x8000_0000u32 as i32);
        second[15] = _mm512_set1_epi32(32 * 8);
        compress(h0_vec(), second)
    }
}

#[target_feature(enable = "avx512f")]
unsafe fn nonce_words(start: u64) -> __m512i {
    let mut words = [0u32; LANES];
    for (lane, word) in words.iter_mut().enumerate() {
        *word = (start.wrapping_add(lane as u64) as u32).swap_bytes();
    }
    _mm512_loadu_si512(words.as_ptr().cast())
}

#[target_feature(enable = "avx512f")]
unsafe fn h0_vec() -> [__m512i; 8] {
    [
        _mm512_set1_epi32(H0[0] as i32),
        _mm512_set1_epi32(H0[1] as i32),
        _mm512_set1_epi32(H0[2] as i32),
        _mm512_set1_epi32(H0[3] as i32),
        _mm512_set1_epi32(H0[4] as i32),
        _mm512_set1_epi32(H0[5] as i32),
        _mm512_set1_epi32(H0[6] as i32),
        _mm512_set1_epi32(H0[7] as i32),
    ]
}

#[target_feature(enable = "avx512f")]
unsafe fn compress(state: [__m512i; 8], block_words: [__m512i; 16]) -> [__m512i; 8] {
    let mut w = [_mm512_setzero_si512(); 64];
    w[..16].copy_from_slice(&block_words);
    for i in 16..64 {
        w[i] = add4(
            small_sigma1(w[i - 2]),
            w[i - 7],
            small_sigma0(w[i - 15]),
            w[i - 16],
        );
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for i in 0..64 {
        let t1 = add5(
            h,
            big_sigma1(e),
            ch(e, f, g),
            _mm512_set1_epi32(K[i] as i32),
            w[i],
        );
        let t2 = add2(big_sigma0(a), maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = add2(d, t1);
        d = c;
        c = b;
        b = a;
        a = add2(t1, t2);
    }

    [
        add2(state[0], a),
        add2(state[1], b),
        add2(state[2], c),
        add2(state[3], d),
        add2(state[4], e),
        add2(state[5], f),
        add2(state[6], g),
        add2(state[7], h),
    ]
}

#[target_feature(enable = "avx512f")]
unsafe fn add2(a: __m512i, b: __m512i) -> __m512i {
    _mm512_add_epi32(a, b)
}

#[target_feature(enable = "avx512f")]
unsafe fn add4(a: __m512i, b: __m512i, c: __m512i, d: __m512i) -> __m512i {
    add2(add2(a, b), add2(c, d))
}

#[target_feature(enable = "avx512f")]
unsafe fn add5(a: __m512i, b: __m512i, c: __m512i, d: __m512i, e: __m512i) -> __m512i {
    add2(add4(a, b, c, d), e)
}

#[target_feature(enable = "avx512f")]
unsafe fn ch(x: __m512i, y: __m512i, z: __m512i) -> __m512i {
    _mm512_xor_si512(_mm512_and_si512(x, y), _mm512_andnot_si512(x, z))
}

#[target_feature(enable = "avx512f")]
unsafe fn maj(x: __m512i, y: __m512i, z: __m512i) -> __m512i {
    _mm512_xor_si512(
        _mm512_xor_si512(_mm512_and_si512(x, y), _mm512_and_si512(x, z)),
        _mm512_and_si512(y, z),
    )
}

#[target_feature(enable = "avx512f")]
unsafe fn rotr2(x: __m512i) -> __m512i {
    _mm512_or_si512(_mm512_srli_epi32::<2>(x), _mm512_slli_epi32::<30>(x))
}

#[target_feature(enable = "avx512f")]
unsafe fn rotr6(x: __m512i) -> __m512i {
    _mm512_or_si512(_mm512_srli_epi32::<6>(x), _mm512_slli_epi32::<26>(x))
}

#[target_feature(enable = "avx512f")]
unsafe fn rotr7(x: __m512i) -> __m512i {
    _mm512_or_si512(_mm512_srli_epi32::<7>(x), _mm512_slli_epi32::<25>(x))
}

#[target_feature(enable = "avx512f")]
unsafe fn rotr11(x: __m512i) -> __m512i {
    _mm512_or_si512(_mm512_srli_epi32::<11>(x), _mm512_slli_epi32::<21>(x))
}

#[target_feature(enable = "avx512f")]
unsafe fn rotr13(x: __m512i) -> __m512i {
    _mm512_or_si512(_mm512_srli_epi32::<13>(x), _mm512_slli_epi32::<19>(x))
}

#[target_feature(enable = "avx512f")]
unsafe fn rotr17(x: __m512i) -> __m512i {
    _mm512_or_si512(_mm512_srli_epi32::<17>(x), _mm512_slli_epi32::<15>(x))
}

#[target_feature(enable = "avx512f")]
unsafe fn rotr18(x: __m512i) -> __m512i {
    _mm512_or_si512(_mm512_srli_epi32::<18>(x), _mm512_slli_epi32::<14>(x))
}

#[target_feature(enable = "avx512f")]
unsafe fn rotr19(x: __m512i) -> __m512i {
    _mm512_or_si512(_mm512_srli_epi32::<19>(x), _mm512_slli_epi32::<13>(x))
}

#[target_feature(enable = "avx512f")]
unsafe fn rotr22(x: __m512i) -> __m512i {
    _mm512_or_si512(_mm512_srli_epi32::<22>(x), _mm512_slli_epi32::<10>(x))
}

#[target_feature(enable = "avx512f")]
unsafe fn rotr25(x: __m512i) -> __m512i {
    _mm512_or_si512(_mm512_srli_epi32::<25>(x), _mm512_slli_epi32::<7>(x))
}

#[target_feature(enable = "avx512f")]
unsafe fn big_sigma0(x: __m512i) -> __m512i {
    _mm512_xor_si512(_mm512_xor_si512(rotr2(x), rotr13(x)), rotr22(x))
}

#[target_feature(enable = "avx512f")]
unsafe fn big_sigma1(x: __m512i) -> __m512i {
    _mm512_xor_si512(_mm512_xor_si512(rotr6(x), rotr11(x)), rotr25(x))
}

#[target_feature(enable = "avx512f")]
unsafe fn small_sigma0(x: __m512i) -> __m512i {
    _mm512_xor_si512(
        _mm512_xor_si512(rotr7(x), rotr18(x)),
        _mm512_srli_epi32::<3>(x),
    )
}

#[target_feature(enable = "avx512f")]
unsafe fn small_sigma1(x: __m512i) -> __m512i {
    _mm512_xor_si512(
        _mm512_xor_si512(rotr17(x), rotr19(x)),
        _mm512_srli_epi32::<10>(x),
    )
}

#[target_feature(enable = "avx512f")]
unsafe fn digest_lane(digest: &[__m512i; 8], lane: usize) -> DigestWords {
    let mut words = [[0u32; LANES]; 8];
    for i in 0..8 {
        _mm512_storeu_si512(words[i].as_mut_ptr().cast(), digest[i]);
    }
    DigestWords([
        words[0][lane],
        words[1][lane],
        words[2][lane],
        words[3][lane],
        words[4][lane],
        words[5][lane],
        words[6][lane],
        words[7][lane],
    ])
}
