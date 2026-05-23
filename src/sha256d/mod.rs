use sha2::compress256;
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256};

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline(always)]
fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline(always)]
fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline(always)]
fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

#[inline(always)]
fn read_be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("slice length is fixed by caller"))
}

#[inline(always)]
fn compress(state: [u32; 8], block_words: [u32; 16]) -> [u32; 8] {
    let mut w = [0u32; 64];
    w[..16].copy_from_slice(&block_words);
    for i in 16..64 {
        w[i] = small_sigma1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(small_sigma0(w[i - 15]))
            .wrapping_add(w[i - 16]);
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
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    [
        state[0].wrapping_add(a),
        state[1].wrapping_add(b),
        state[2].wrapping_add(c),
        state[3].wrapping_add(d),
        state[4].wrapping_add(e),
        state[5].wrapping_add(f),
        state[6].wrapping_add(g),
        state[7].wrapping_add(h),
    ]
}

pub fn library_sha256d80(header: &[u8; 80]) -> [u8; 32] {
    let first = Sha256::digest(header);
    let second = Sha256::digest(first);
    second.into()
}

pub fn specialized_sha256d80(header: &[u8; 80]) -> [u8; 32] {
    let ctx = Sha256d80::new(header);
    ctx.hash_nonce(read_be_u32(&header[76..80]).swap_bytes())
}

pub fn compression_sha256d80(header: &[u8; 80]) -> [u8; 32] {
    let ctx = Sha256d80Compression::new(header);
    ctx.hash_nonce(read_be_u32(&header[76..80]).swap_bytes())
}

pub fn hash_meets_target(hash: [u8; 32], target: [u8; 32]) -> bool {
    TargetWords::from_be_bytes(target).matches_hash(hash)
}

pub fn bits_to_target(bits_le: [u8; 4]) -> Result<[u8; 32], String> {
    let bits = u32::from_le_bytes(bits_le);
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007f_ffff;
    if bits & 0x0080_0000 != 0 {
        return Err("compact target encodes a negative value".to_string());
    }
    if mantissa == 0 {
        return Err("compact target encodes zero".to_string());
    }

    let mantissa_bytes = mantissa.to_be_bytes();
    let compact = [mantissa_bytes[1], mantissa_bytes[2], mantissa_bytes[3]];
    let mut target = [0u8; 32];

    if exponent <= 3 {
        let value = mantissa >> (8 * (3 - exponent));
        let value_bytes = value.to_be_bytes();
        target[29..32].copy_from_slice(&value_bytes[1..4]);
    } else {
        let start = 32usize
            .checked_sub(exponent)
            .ok_or_else(|| "compact target overflows 256 bits".to_string())?;
        target[start..start + 3].copy_from_slice(&compact);
    }

    Ok(target)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use shani::{shani_available, shani_sha256d80, Sha256d80Shani};

#[derive(Clone, Copy, Debug)]
pub struct TargetWords([u32; 8]);

impl TargetWords {
    pub fn from_be_bytes(target: [u8; 32]) -> Self {
        let mut words = [0u32; 8];
        for (i, chunk) in target.chunks_exact(4).enumerate() {
            words[i] = u32::from_be_bytes(chunk.try_into().expect("target chunk is 4 bytes"));
        }
        Self(words)
    }

    #[inline(always)]
    pub fn matches_digest_words(self, digest: DigestWords) -> bool {
        for i in 0..8 {
            let hash_word = digest.0[7 - i].swap_bytes();
            let target_word = self.0[i];
            if hash_word < target_word {
                return true;
            }
            if hash_word > target_word {
                return false;
            }
        }
        true
    }

    pub fn matches_hash(self, hash: [u8; 32]) -> bool {
        for (hash_byte, target_byte) in hash
            .iter()
            .rev()
            .zip(self.0.iter().flat_map(|word| word.to_be_bytes()))
        {
            if *hash_byte < target_byte {
                return true;
            }
            if *hash_byte > target_byte {
                return false;
            }
        }
        true
    }
}

pub struct Sha256d80 {
    midstate: [u32; 8],
    tail_template: [u32; 16],
}

impl Sha256d80 {
    pub fn new(header: &[u8; 80]) -> Self {
        let mut chunk0 = [0u32; 16];
        for i in 0..16 {
            chunk0[i] = read_be_u32(&header[i * 4..i * 4 + 4]);
        }

        let mut tail_template = [0u32; 16];
        for i in 0..4 {
            tail_template[i] = read_be_u32(&header[64 + i * 4..68 + i * 4]);
        }
        tail_template[4] = 0x8000_0000;
        tail_template[15] = 80 * 8;

        Self {
            midstate: compress(H0, chunk0),
            tail_template,
        }
    }

    #[inline(always)]
    pub fn hash_nonce(&self, nonce: u32) -> [u8; 32] {
        self.hash_nonce_words(nonce).to_be_bytes()
    }

    #[inline(always)]
    pub fn hash_nonce_words(&self, nonce: u32) -> DigestWords {
        let mut tail = self.tail_template;
        tail[3] = u32::from_be_bytes(nonce.to_le_bytes());
        let first = compress(self.midstate, tail);

        let mut second_block = [0u32; 16];
        second_block[..8].copy_from_slice(&first);
        second_block[8] = 0x8000_0000;
        second_block[15] = 32 * 8;

        DigestWords(compress(H0, second_block))
    }

    pub fn scan_batch(&self, start: u64, count: u64, target: TargetWords) -> ScanBatchResult {
        for offset in 0..count {
            let nonce = start.wrapping_add(offset) as u32;
            let digest = self.hash_nonce_words(nonce);
            if digest.meets_target(target) {
                return ScanBatchResult {
                    hashes_checked: offset + 1,
                    found_nonce: Some(nonce),
                    found_hash: Some(digest.to_be_bytes()),
                };
            }
        }

        ScanBatchResult {
            hashes_checked: count,
            found_nonce: None,
            found_hash: None,
        }
    }
}

#[derive(Clone, Copy)]
pub struct DigestWords([u32; 8]);

impl DigestWords {
    #[inline(always)]
    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, word) in self.0.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    #[inline(always)]
    pub fn checksum(self) -> u64 {
        let hi = (self.0[0] as u64) << 32 | self.0[1] as u64;
        let lo = (self.0[6] as u64) << 32 | self.0[7] as u64;
        hi ^ lo
    }

    #[inline(always)]
    pub fn meets_target(self, target: TargetWords) -> bool {
        target.matches_digest_words(self)
    }
}

pub struct Sha256d80Compression {
    midstate: [u32; 8],
    tail_template: [u8; 64],
}

impl Sha256d80Compression {
    pub fn new(header: &[u8; 80]) -> Self {
        let mut midstate = H0;
        let chunk0 = GenericArray::clone_from_slice(&header[..64]);
        compress256(&mut midstate, std::slice::from_ref(&chunk0));

        let mut tail_template = [0u8; 64];
        tail_template[..16].copy_from_slice(&header[64..80]);
        tail_template[16] = 0x80;
        tail_template[56..64].copy_from_slice(&(80u64 * 8).to_be_bytes());

        Self {
            midstate,
            tail_template,
        }
    }

    #[inline(always)]
    pub fn hash_nonce(&self, nonce: u32) -> [u8; 32] {
        self.hash_nonce_words(nonce).to_be_bytes()
    }

    #[inline(always)]
    pub fn hash_nonce_words(&self, nonce: u32) -> DigestWords {
        let mut tail = self.tail_template;
        tail[12..16].copy_from_slice(&nonce.to_le_bytes());
        let tail_block = GenericArray::clone_from_slice(&tail);

        let mut first = self.midstate;
        compress256(&mut first, std::slice::from_ref(&tail_block));

        let mut second = [0u8; 64];
        for (i, word) in first.iter().enumerate() {
            second[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        second[32] = 0x80;
        second[56..64].copy_from_slice(&(32u64 * 8).to_be_bytes());
        let second_block = GenericArray::clone_from_slice(&second);

        let mut final_state = H0;
        compress256(&mut final_state, std::slice::from_ref(&second_block));
        DigestWords(final_state)
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod shani;

#[derive(Clone, Copy, Debug)]
pub struct ScanBatchResult {
    pub hashes_checked: u64,
    pub found_nonce: Option<u32>,
    pub found_hash: Option<[u8; 32]>,
}

pub fn decode_hex_80(hex: &str) -> Result<[u8; 80], String> {
    if hex.len() != 160 {
        return Err(format!("expected 160 hex characters, got {}", hex.len()));
    }

    let mut out = [0u8; 80];
    let bytes = hex.as_bytes();
    for i in 0..80 {
        let hi = hex_value(bytes[i * 2])?;
        let lo = hex_value(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex byte 0x{byte:02x}")),
    }
}

#[cfg(test)]
mod tests;
