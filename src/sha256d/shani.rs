use super::{DigestWords, ScanBatchResult, TargetWords, H0, K};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

pub fn shani_available() -> bool {
    std::is_x86_feature_detected!("sha")
        && std::is_x86_feature_detected!("sse2")
        && std::is_x86_feature_detected!("ssse3")
        && std::is_x86_feature_detected!("sse4.1")
}

pub fn shani_sha256d80(header: &[u8; 80]) -> Option<[u8; 32]> {
    let ctx = Sha256d80Shani::new(header)?;
    Some(ctx.hash_nonce(u32::from_le_bytes(
        header[76..80].try_into().expect("nonce length"),
    )))
}

#[inline(always)]
fn write_nonce_le(block: &mut [u8; 64], nonce: u32) {
    unsafe {
        std::ptr::write_unaligned(block.as_mut_ptr().add(12).cast::<u32>(), nonce.to_le());
    }
}

pub struct Sha256d80Shani {
    midstate: [u32; 8],
    tail_template: [u8; 64],
}

impl Sha256d80Shani {
    pub fn new(header: &[u8; 80]) -> Option<Self> {
        if !shani_available() {
            return None;
        }
        Some(unsafe { Self::new_unchecked(header) })
    }

    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    unsafe fn new_unchecked(header: &[u8; 80]) -> Self {
        let mut midstate = H0;
        let mut chunk0 = [0u8; 64];
        chunk0.copy_from_slice(&header[..64]);
        compress_one(&mut midstate, &chunk0);

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
        unsafe { self.hash_nonce_words_unchecked(nonce) }
    }

    #[inline(always)]
    pub fn checksum_batch(&self, start: u64, count: u64) -> (u64, u64) {
        unsafe { self.checksum_batch_unchecked(start, count) }
    }

    pub fn scan_batch(&self, start: u64, count: u64, target: TargetWords) -> ScanBatchResult {
        unsafe { self.scan_batch_unchecked(start, count, target) }
    }

    pub fn scan_batch_interleaved2(
        &self,
        start: u64,
        count: u64,
        target: TargetWords,
    ) -> ScanBatchResult {
        unsafe { self.scan_batch_interleaved2_unchecked(start, count, target) }
    }

    pub fn scan_batch_interleaved4(
        &self,
        start: u64,
        count: u64,
        target: TargetWords,
    ) -> ScanBatchResult {
        unsafe { self.scan_batch_interleaved4_unchecked(start, count, target) }
    }

    pub fn scan_batch_interleaved8(
        &self,
        start: u64,
        count: u64,
        target: TargetWords,
    ) -> ScanBatchResult {
        unsafe { self.scan_batch_interleaved8_unchecked(start, count, target) }
    }

    pub fn count_batch_with_target(&self, start: u64, count: u64, target: TargetWords) -> u64 {
        unsafe { self.count_batch_with_target_unchecked(start, count, target) }
    }

    pub fn count_batch_with_target_interleaved2(
        &self,
        start: u64,
        count: u64,
        target: TargetWords,
    ) -> u64 {
        unsafe { self.count_batch_with_target_interleaved2_unchecked(start, count, target) }
    }

    pub fn count_batch_with_target_interleaved4(
        &self,
        start: u64,
        count: u64,
        target: TargetWords,
    ) -> u64 {
        unsafe { self.count_batch_with_target_interleaved4_unchecked(start, count, target) }
    }

    pub fn count_batch_with_target_interleaved8(
        &self,
        start: u64,
        count: u64,
        target: TargetWords,
    ) -> u64 {
        unsafe { self.count_batch_with_target_interleaved8_unchecked(start, count, target) }
    }

    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    unsafe fn hash_nonce_words_unchecked(&self, nonce: u32) -> DigestWords {
        let mut tail = self.tail_template;
        write_nonce_le(&mut tail, nonce);

        let mut first = self.midstate;
        compress_one(&mut first, &tail);

        let mut second = [0u8; 64];
        for (i, word) in first.iter().enumerate() {
            second[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        second[32] = 0x80;
        second[56..64].copy_from_slice(&(32u64 * 8).to_be_bytes());

        let mut final_state = H0;
        compress_one(&mut final_state, &second);
        DigestWords(final_state)
    }

    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    unsafe fn checksum_batch_unchecked(&self, start: u64, count: u64) -> (u64, u64) {
        let mut checksum = 0u64;
        let mut tail = self.tail_template;
        let mut second = [0u8; 64];
        second[32] = 0x80;
        second[56..64].copy_from_slice(&(32u64 * 8).to_be_bytes());

        for offset in 0..count {
            let nonce = start.wrapping_add(offset) as u32;
            write_nonce_le(&mut tail, nonce);

            let mut first = self.midstate;
            compress_one(&mut first, &tail);

            for (i, word) in first.iter().enumerate() {
                second[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }

            let mut final_state = H0;
            compress_one(&mut final_state, &second);
            let digest = DigestWords(final_state);
            checksum ^= digest.checksum().rotate_left(nonce & 63);
        }

        (count, checksum)
    }

    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    unsafe fn scan_batch_unchecked(
        &self,
        start: u64,
        count: u64,
        target: TargetWords,
    ) -> ScanBatchResult {
        let mut tail = self.tail_template;
        let mut second = [0u8; 64];
        second[32] = 0x80;
        second[56..64].copy_from_slice(&(32u64 * 8).to_be_bytes());

        for offset in 0..count {
            let nonce = start.wrapping_add(offset) as u32;
            write_nonce_le(&mut tail, nonce);

            let mut first = self.midstate;
            compress_one(&mut first, &tail);

            for (i, word) in first.iter().enumerate() {
                second[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }

            let mut final_state = H0;
            compress_one(&mut final_state, &second);
            let digest = DigestWords(final_state);
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

    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    unsafe fn scan_batch_interleaved2_unchecked(
        &self,
        start: u64,
        count: u64,
        target: TargetWords,
    ) -> ScanBatchResult {
        let mut tail0 = self.tail_template;
        let mut tail1 = self.tail_template;
        let mut second0 = [0u8; 64];
        let mut second1 = [0u8; 64];
        second0[32] = 0x80;
        second1[32] = 0x80;
        let second_len = (32u64 * 8).to_be_bytes();
        second0[56..64].copy_from_slice(&second_len);
        second1[56..64].copy_from_slice(&second_len);
        let pair_count = count & !1;

        let mut offset = 0u64;
        while offset < pair_count {
            let nonce0 = start.wrapping_add(offset) as u32;
            let nonce1 = start.wrapping_add(offset + 1) as u32;
            write_nonce_le(&mut tail0, nonce0);
            write_nonce_le(&mut tail1, nonce1);

            let mut first0 = self.midstate;
            let mut first1 = self.midstate;
            compress_two(&mut first0, &tail0, &mut first1, &tail1);

            for (i, word) in first0.iter().enumerate() {
                second0[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first1.iter().enumerate() {
                second1[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }

            let mut final0 = H0;
            let mut final1 = H0;
            compress_two(&mut final0, &second0, &mut final1, &second1);

            let digest0 = DigestWords(final0);
            if digest0.meets_target(target) {
                return ScanBatchResult {
                    hashes_checked: offset + 1,
                    found_nonce: Some(nonce0),
                    found_hash: Some(digest0.to_be_bytes()),
                };
            }
            let digest1 = DigestWords(final1);
            if digest1.meets_target(target) {
                return ScanBatchResult {
                    hashes_checked: offset + 2,
                    found_nonce: Some(nonce1),
                    found_hash: Some(digest1.to_be_bytes()),
                };
            }

            offset += 2;
        }

        if pair_count != count {
            let tail = self.scan_batch_unchecked(start.wrapping_add(pair_count), 1, target);
            return ScanBatchResult {
                hashes_checked: pair_count + tail.hashes_checked,
                found_nonce: tail.found_nonce,
                found_hash: tail.found_hash,
            };
        }

        ScanBatchResult {
            hashes_checked: count,
            found_nonce: None,
            found_hash: None,
        }
    }

    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    unsafe fn scan_batch_interleaved4_unchecked(
        &self,
        start: u64,
        count: u64,
        target: TargetWords,
    ) -> ScanBatchResult {
        let mut tail0 = self.tail_template;
        let mut tail1 = self.tail_template;
        let mut tail2 = self.tail_template;
        let mut tail3 = self.tail_template;
        let mut second0 = [0u8; 64];
        let mut second1 = [0u8; 64];
        let mut second2 = [0u8; 64];
        let mut second3 = [0u8; 64];
        second0[32] = 0x80;
        second1[32] = 0x80;
        second2[32] = 0x80;
        second3[32] = 0x80;
        let second_len = (32u64 * 8).to_be_bytes();
        second0[56..64].copy_from_slice(&second_len);
        second1[56..64].copy_from_slice(&second_len);
        second2[56..64].copy_from_slice(&second_len);
        second3[56..64].copy_from_slice(&second_len);
        let group_count = count & !3;

        let mut offset = 0u64;
        while offset < group_count {
            let nonce0 = start.wrapping_add(offset) as u32;
            let nonce1 = start.wrapping_add(offset + 1) as u32;
            let nonce2 = start.wrapping_add(offset + 2) as u32;
            let nonce3 = start.wrapping_add(offset + 3) as u32;
            write_nonce_le(&mut tail0, nonce0);
            write_nonce_le(&mut tail1, nonce1);
            write_nonce_le(&mut tail2, nonce2);
            write_nonce_le(&mut tail3, nonce3);

            let mut first0 = self.midstate;
            let mut first1 = self.midstate;
            let mut first2 = self.midstate;
            let mut first3 = self.midstate;
            compress_two(&mut first0, &tail0, &mut first1, &tail1);
            compress_two(&mut first2, &tail2, &mut first3, &tail3);

            for (i, word) in first0.iter().enumerate() {
                second0[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first1.iter().enumerate() {
                second1[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first2.iter().enumerate() {
                second2[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first3.iter().enumerate() {
                second3[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }

            let mut final0 = H0;
            let mut final1 = H0;
            let mut final2 = H0;
            let mut final3 = H0;
            compress_two(&mut final0, &second0, &mut final1, &second1);
            compress_two(&mut final2, &second2, &mut final3, &second3);

            let digest0 = DigestWords(final0);
            if digest0.meets_target(target) {
                return ScanBatchResult {
                    hashes_checked: offset + 1,
                    found_nonce: Some(nonce0),
                    found_hash: Some(digest0.to_be_bytes()),
                };
            }
            let digest1 = DigestWords(final1);
            if digest1.meets_target(target) {
                return ScanBatchResult {
                    hashes_checked: offset + 2,
                    found_nonce: Some(nonce1),
                    found_hash: Some(digest1.to_be_bytes()),
                };
            }
            let digest2 = DigestWords(final2);
            if digest2.meets_target(target) {
                return ScanBatchResult {
                    hashes_checked: offset + 3,
                    found_nonce: Some(nonce2),
                    found_hash: Some(digest2.to_be_bytes()),
                };
            }
            let digest3 = DigestWords(final3);
            if digest3.meets_target(target) {
                return ScanBatchResult {
                    hashes_checked: offset + 4,
                    found_nonce: Some(nonce3),
                    found_hash: Some(digest3.to_be_bytes()),
                };
            }

            offset += 4;
        }

        if group_count != count {
            let tail = self.scan_batch_interleaved2_unchecked(
                start.wrapping_add(group_count),
                count - group_count,
                target,
            );
            return ScanBatchResult {
                hashes_checked: group_count + tail.hashes_checked,
                found_nonce: tail.found_nonce,
                found_hash: tail.found_hash,
            };
        }

        ScanBatchResult {
            hashes_checked: count,
            found_nonce: None,
            found_hash: None,
        }
    }

    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    unsafe fn scan_batch_interleaved8_unchecked(
        &self,
        start: u64,
        count: u64,
        target: TargetWords,
    ) -> ScanBatchResult {
        let mut tail0 = self.tail_template;
        let mut tail1 = self.tail_template;
        let mut tail2 = self.tail_template;
        let mut tail3 = self.tail_template;
        let mut tail4 = self.tail_template;
        let mut tail5 = self.tail_template;
        let mut tail6 = self.tail_template;
        let mut tail7 = self.tail_template;
        let mut second0 = [0u8; 64];
        let mut second1 = [0u8; 64];
        let mut second2 = [0u8; 64];
        let mut second3 = [0u8; 64];
        let mut second4 = [0u8; 64];
        let mut second5 = [0u8; 64];
        let mut second6 = [0u8; 64];
        let mut second7 = [0u8; 64];
        let second_len = (32u64 * 8).to_be_bytes();
        second0[32] = 0x80;
        second1[32] = 0x80;
        second2[32] = 0x80;
        second3[32] = 0x80;
        second4[32] = 0x80;
        second5[32] = 0x80;
        second6[32] = 0x80;
        second7[32] = 0x80;
        second0[56..64].copy_from_slice(&second_len);
        second1[56..64].copy_from_slice(&second_len);
        second2[56..64].copy_from_slice(&second_len);
        second3[56..64].copy_from_slice(&second_len);
        second4[56..64].copy_from_slice(&second_len);
        second5[56..64].copy_from_slice(&second_len);
        second6[56..64].copy_from_slice(&second_len);
        second7[56..64].copy_from_slice(&second_len);
        let group_count = count & !7;

        let mut offset = 0u64;
        while offset < group_count {
            let nonce0 = start.wrapping_add(offset) as u32;
            let nonce1 = start.wrapping_add(offset + 1) as u32;
            let nonce2 = start.wrapping_add(offset + 2) as u32;
            let nonce3 = start.wrapping_add(offset + 3) as u32;
            let nonce4 = start.wrapping_add(offset + 4) as u32;
            let nonce5 = start.wrapping_add(offset + 5) as u32;
            let nonce6 = start.wrapping_add(offset + 6) as u32;
            let nonce7 = start.wrapping_add(offset + 7) as u32;
            write_nonce_le(&mut tail0, nonce0);
            write_nonce_le(&mut tail1, nonce1);
            write_nonce_le(&mut tail2, nonce2);
            write_nonce_le(&mut tail3, nonce3);
            write_nonce_le(&mut tail4, nonce4);
            write_nonce_le(&mut tail5, nonce5);
            write_nonce_le(&mut tail6, nonce6);
            write_nonce_le(&mut tail7, nonce7);

            let mut first0 = self.midstate;
            let mut first1 = self.midstate;
            let mut first2 = self.midstate;
            let mut first3 = self.midstate;
            let mut first4 = self.midstate;
            let mut first5 = self.midstate;
            let mut first6 = self.midstate;
            let mut first7 = self.midstate;
            compress_two(&mut first0, &tail0, &mut first1, &tail1);
            compress_two(&mut first2, &tail2, &mut first3, &tail3);
            compress_two(&mut first4, &tail4, &mut first5, &tail5);
            compress_two(&mut first6, &tail6, &mut first7, &tail7);

            for (i, word) in first0.iter().enumerate() {
                second0[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first1.iter().enumerate() {
                second1[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first2.iter().enumerate() {
                second2[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first3.iter().enumerate() {
                second3[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first4.iter().enumerate() {
                second4[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first5.iter().enumerate() {
                second5[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first6.iter().enumerate() {
                second6[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first7.iter().enumerate() {
                second7[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }

            let mut final0 = H0;
            let mut final1 = H0;
            let mut final2 = H0;
            let mut final3 = H0;
            let mut final4 = H0;
            let mut final5 = H0;
            let mut final6 = H0;
            let mut final7 = H0;
            compress_two(&mut final0, &second0, &mut final1, &second1);
            compress_two(&mut final2, &second2, &mut final3, &second3);
            compress_two(&mut final4, &second4, &mut final5, &second5);
            compress_two(&mut final6, &second6, &mut final7, &second7);

            let digest0 = DigestWords(final0);
            if digest0.meets_target(target) {
                return ScanBatchResult {
                    hashes_checked: offset + 1,
                    found_nonce: Some(nonce0),
                    found_hash: Some(digest0.to_be_bytes()),
                };
            }
            let digest1 = DigestWords(final1);
            if digest1.meets_target(target) {
                return ScanBatchResult {
                    hashes_checked: offset + 2,
                    found_nonce: Some(nonce1),
                    found_hash: Some(digest1.to_be_bytes()),
                };
            }
            let digest2 = DigestWords(final2);
            if digest2.meets_target(target) {
                return ScanBatchResult {
                    hashes_checked: offset + 3,
                    found_nonce: Some(nonce2),
                    found_hash: Some(digest2.to_be_bytes()),
                };
            }
            let digest3 = DigestWords(final3);
            if digest3.meets_target(target) {
                return ScanBatchResult {
                    hashes_checked: offset + 4,
                    found_nonce: Some(nonce3),
                    found_hash: Some(digest3.to_be_bytes()),
                };
            }
            let digest4 = DigestWords(final4);
            if digest4.meets_target(target) {
                return ScanBatchResult {
                    hashes_checked: offset + 5,
                    found_nonce: Some(nonce4),
                    found_hash: Some(digest4.to_be_bytes()),
                };
            }
            let digest5 = DigestWords(final5);
            if digest5.meets_target(target) {
                return ScanBatchResult {
                    hashes_checked: offset + 6,
                    found_nonce: Some(nonce5),
                    found_hash: Some(digest5.to_be_bytes()),
                };
            }
            let digest6 = DigestWords(final6);
            if digest6.meets_target(target) {
                return ScanBatchResult {
                    hashes_checked: offset + 7,
                    found_nonce: Some(nonce6),
                    found_hash: Some(digest6.to_be_bytes()),
                };
            }
            let digest7 = DigestWords(final7);
            if digest7.meets_target(target) {
                return ScanBatchResult {
                    hashes_checked: offset + 8,
                    found_nonce: Some(nonce7),
                    found_hash: Some(digest7.to_be_bytes()),
                };
            }

            offset += 8;
        }

        if group_count != count {
            let tail = self.scan_batch_interleaved4_unchecked(
                start.wrapping_add(group_count),
                count - group_count,
                target,
            );
            return ScanBatchResult {
                hashes_checked: group_count + tail.hashes_checked,
                found_nonce: tail.found_nonce,
                found_hash: tail.found_hash,
            };
        }

        ScanBatchResult {
            hashes_checked: count,
            found_nonce: None,
            found_hash: None,
        }
    }

    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    unsafe fn count_batch_with_target_unchecked(
        &self,
        start: u64,
        count: u64,
        target: TargetWords,
    ) -> u64 {
        let mut tail = self.tail_template;
        let mut second = [0u8; 64];
        second[32] = 0x80;
        second[56..64].copy_from_slice(&(32u64 * 8).to_be_bytes());
        let mut matches = 0u64;

        for offset in 0..count {
            let nonce = start.wrapping_add(offset) as u32;
            write_nonce_le(&mut tail, nonce);

            let mut first = self.midstate;
            compress_one(&mut first, &tail);

            for (i, word) in first.iter().enumerate() {
                second[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }

            let mut final_state = H0;
            compress_one(&mut final_state, &second);
            if DigestWords(final_state).meets_target(target) {
                matches = matches.wrapping_add(1);
            }
        }

        matches
    }

    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    unsafe fn count_batch_with_target_interleaved2_unchecked(
        &self,
        start: u64,
        count: u64,
        target: TargetWords,
    ) -> u64 {
        let mut tail0 = self.tail_template;
        let mut tail1 = self.tail_template;
        let mut second0 = [0u8; 64];
        let mut second1 = [0u8; 64];
        second0[32] = 0x80;
        second1[32] = 0x80;
        second0[56..64].copy_from_slice(&(32u64 * 8).to_be_bytes());
        second1[56..64].copy_from_slice(&(32u64 * 8).to_be_bytes());
        let mut matches = 0u64;
        let pair_count = count & !1;

        let mut offset = 0u64;
        while offset < pair_count {
            let nonce0 = start.wrapping_add(offset) as u32;
            let nonce1 = start.wrapping_add(offset + 1) as u32;
            write_nonce_le(&mut tail0, nonce0);
            write_nonce_le(&mut tail1, nonce1);

            let mut first0 = self.midstate;
            let mut first1 = self.midstate;
            compress_two(&mut first0, &tail0, &mut first1, &tail1);

            for (i, word) in first0.iter().enumerate() {
                second0[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first1.iter().enumerate() {
                second1[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }

            let mut final0 = H0;
            let mut final1 = H0;
            compress_two(&mut final0, &second0, &mut final1, &second1);

            if DigestWords(final0).meets_target(target) {
                matches = matches.wrapping_add(1);
            }
            if DigestWords(final1).meets_target(target) {
                matches = matches.wrapping_add(1);
            }

            offset += 2;
        }

        if pair_count != count {
            matches = matches.wrapping_add(self.count_batch_with_target_unchecked(
                start.wrapping_add(pair_count),
                1,
                target,
            ));
        }

        matches
    }

    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    unsafe fn count_batch_with_target_interleaved4_unchecked(
        &self,
        start: u64,
        count: u64,
        target: TargetWords,
    ) -> u64 {
        let mut tail0 = self.tail_template;
        let mut tail1 = self.tail_template;
        let mut tail2 = self.tail_template;
        let mut tail3 = self.tail_template;
        let mut second0 = [0u8; 64];
        let mut second1 = [0u8; 64];
        let mut second2 = [0u8; 64];
        let mut second3 = [0u8; 64];
        second0[32] = 0x80;
        second1[32] = 0x80;
        second2[32] = 0x80;
        second3[32] = 0x80;
        let second_len = (32u64 * 8).to_be_bytes();
        second0[56..64].copy_from_slice(&second_len);
        second1[56..64].copy_from_slice(&second_len);
        second2[56..64].copy_from_slice(&second_len);
        second3[56..64].copy_from_slice(&second_len);
        let mut matches = 0u64;
        let group_count = count & !3;

        let mut offset = 0u64;
        while offset < group_count {
            let nonce0 = start.wrapping_add(offset) as u32;
            let nonce1 = start.wrapping_add(offset + 1) as u32;
            let nonce2 = start.wrapping_add(offset + 2) as u32;
            let nonce3 = start.wrapping_add(offset + 3) as u32;
            write_nonce_le(&mut tail0, nonce0);
            write_nonce_le(&mut tail1, nonce1);
            write_nonce_le(&mut tail2, nonce2);
            write_nonce_le(&mut tail3, nonce3);

            let mut first0 = self.midstate;
            let mut first1 = self.midstate;
            let mut first2 = self.midstate;
            let mut first3 = self.midstate;
            compress_two(&mut first0, &tail0, &mut first1, &tail1);
            compress_two(&mut first2, &tail2, &mut first3, &tail3);

            for (i, word) in first0.iter().enumerate() {
                second0[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first1.iter().enumerate() {
                second1[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first2.iter().enumerate() {
                second2[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first3.iter().enumerate() {
                second3[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }

            let mut final0 = H0;
            let mut final1 = H0;
            let mut final2 = H0;
            let mut final3 = H0;
            compress_two(&mut final0, &second0, &mut final1, &second1);
            compress_two(&mut final2, &second2, &mut final3, &second3);

            if DigestWords(final0).meets_target(target) {
                matches = matches.wrapping_add(1);
            }
            if DigestWords(final1).meets_target(target) {
                matches = matches.wrapping_add(1);
            }
            if DigestWords(final2).meets_target(target) {
                matches = matches.wrapping_add(1);
            }
            if DigestWords(final3).meets_target(target) {
                matches = matches.wrapping_add(1);
            }

            offset += 4;
        }

        if group_count != count {
            matches = matches.wrapping_add(self.count_batch_with_target_interleaved2_unchecked(
                start.wrapping_add(group_count),
                count - group_count,
                target,
            ));
        }

        matches
    }

    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    unsafe fn count_batch_with_target_interleaved8_unchecked(
        &self,
        start: u64,
        count: u64,
        target: TargetWords,
    ) -> u64 {
        let mut tail0 = self.tail_template;
        let mut tail1 = self.tail_template;
        let mut tail2 = self.tail_template;
        let mut tail3 = self.tail_template;
        let mut tail4 = self.tail_template;
        let mut tail5 = self.tail_template;
        let mut tail6 = self.tail_template;
        let mut tail7 = self.tail_template;
        let mut second0 = [0u8; 64];
        let mut second1 = [0u8; 64];
        let mut second2 = [0u8; 64];
        let mut second3 = [0u8; 64];
        let mut second4 = [0u8; 64];
        let mut second5 = [0u8; 64];
        let mut second6 = [0u8; 64];
        let mut second7 = [0u8; 64];
        let second_len = (32u64 * 8).to_be_bytes();
        second0[32] = 0x80;
        second1[32] = 0x80;
        second2[32] = 0x80;
        second3[32] = 0x80;
        second4[32] = 0x80;
        second5[32] = 0x80;
        second6[32] = 0x80;
        second7[32] = 0x80;
        second0[56..64].copy_from_slice(&second_len);
        second1[56..64].copy_from_slice(&second_len);
        second2[56..64].copy_from_slice(&second_len);
        second3[56..64].copy_from_slice(&second_len);
        second4[56..64].copy_from_slice(&second_len);
        second5[56..64].copy_from_slice(&second_len);
        second6[56..64].copy_from_slice(&second_len);
        second7[56..64].copy_from_slice(&second_len);

        let mut matches = 0u64;
        let group_count = count & !7;
        let mut offset = 0u64;

        while offset < group_count {
            let nonce0 = start.wrapping_add(offset) as u32;
            let nonce1 = start.wrapping_add(offset + 1) as u32;
            let nonce2 = start.wrapping_add(offset + 2) as u32;
            let nonce3 = start.wrapping_add(offset + 3) as u32;
            let nonce4 = start.wrapping_add(offset + 4) as u32;
            let nonce5 = start.wrapping_add(offset + 5) as u32;
            let nonce6 = start.wrapping_add(offset + 6) as u32;
            let nonce7 = start.wrapping_add(offset + 7) as u32;
            write_nonce_le(&mut tail0, nonce0);
            write_nonce_le(&mut tail1, nonce1);
            write_nonce_le(&mut tail2, nonce2);
            write_nonce_le(&mut tail3, nonce3);
            write_nonce_le(&mut tail4, nonce4);
            write_nonce_le(&mut tail5, nonce5);
            write_nonce_le(&mut tail6, nonce6);
            write_nonce_le(&mut tail7, nonce7);

            let mut first0 = self.midstate;
            let mut first1 = self.midstate;
            let mut first2 = self.midstate;
            let mut first3 = self.midstate;
            let mut first4 = self.midstate;
            let mut first5 = self.midstate;
            let mut first6 = self.midstate;
            let mut first7 = self.midstate;
            compress_two(&mut first0, &tail0, &mut first1, &tail1);
            compress_two(&mut first2, &tail2, &mut first3, &tail3);
            compress_two(&mut first4, &tail4, &mut first5, &tail5);
            compress_two(&mut first6, &tail6, &mut first7, &tail7);

            for (i, word) in first0.iter().enumerate() {
                second0[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first1.iter().enumerate() {
                second1[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first2.iter().enumerate() {
                second2[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first3.iter().enumerate() {
                second3[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first4.iter().enumerate() {
                second4[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first5.iter().enumerate() {
                second5[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first6.iter().enumerate() {
                second6[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            for (i, word) in first7.iter().enumerate() {
                second7[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }

            let mut final0 = H0;
            let mut final1 = H0;
            let mut final2 = H0;
            let mut final3 = H0;
            let mut final4 = H0;
            let mut final5 = H0;
            let mut final6 = H0;
            let mut final7 = H0;
            compress_two(&mut final0, &second0, &mut final1, &second1);
            compress_two(&mut final2, &second2, &mut final3, &second3);
            compress_two(&mut final4, &second4, &mut final5, &second5);
            compress_two(&mut final6, &second6, &mut final7, &second7);

            if DigestWords(final0).meets_target(target) {
                matches = matches.wrapping_add(1);
            }
            if DigestWords(final1).meets_target(target) {
                matches = matches.wrapping_add(1);
            }
            if DigestWords(final2).meets_target(target) {
                matches = matches.wrapping_add(1);
            }
            if DigestWords(final3).meets_target(target) {
                matches = matches.wrapping_add(1);
            }
            if DigestWords(final4).meets_target(target) {
                matches = matches.wrapping_add(1);
            }
            if DigestWords(final5).meets_target(target) {
                matches = matches.wrapping_add(1);
            }
            if DigestWords(final6).meets_target(target) {
                matches = matches.wrapping_add(1);
            }
            if DigestWords(final7).meets_target(target) {
                matches = matches.wrapping_add(1);
            }

            offset += 8;
        }

        if group_count != count {
            matches = matches.wrapping_add(self.count_batch_with_target_interleaved4_unchecked(
                start.wrapping_add(group_count),
                count - group_count,
                target,
            ));
        }

        matches
    }
}

#[inline(always)]
unsafe fn schedule(v0: __m128i, v1: __m128i, v2: __m128i, v3: __m128i) -> __m128i {
    let t1 = _mm_sha256msg1_epu32(v0, v1);
    let t2 = _mm_alignr_epi8(v3, v2, 4);
    let t3 = _mm_add_epi32(t1, t2);
    _mm_sha256msg2_epu32(t3, v3)
}

macro_rules! rounds4 {
    ($abef:ident, $cdgh:ident, $rest:expr, $i:expr) => {{
        let kv = _mm_set_epi32(
            K[($i) * 4 + 3] as i32,
            K[($i) * 4 + 2] as i32,
            K[($i) * 4 + 1] as i32,
            K[($i) * 4] as i32,
        );
        let t1 = _mm_add_epi32($rest, kv);
        $cdgh = _mm_sha256rnds2_epu32($cdgh, $abef, t1);
        let t2 = _mm_shuffle_epi32(t1, 0x0e);
        $abef = _mm_sha256rnds2_epu32($abef, $cdgh, t2);
    }};
}

macro_rules! schedule_rounds4 {
    (
            $abef:ident, $cdgh:ident,
            $w0:expr, $w1:expr, $w2:expr, $w3:expr, $w4:expr,
            $i:expr
        ) => {{
        $w4 = schedule($w0, $w1, $w2, $w3);
        rounds4!($abef, $cdgh, $w4, $i);
    }};
}

#[allow(clippy::cast_ptr_alignment)]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn compress_one(state: &mut [u32; 8], block: &[u8; 64]) {
    let mask: __m128i = _mm_set_epi64x(
        0x0c0d_0e0f_0809_0a0bu64 as i64,
        0x0405_0607_0001_0203u64 as i64,
    );

    let state_ptr = state.as_ptr() as *const __m128i;
    let dcba = _mm_loadu_si128(state_ptr.add(0));
    let efgh = _mm_loadu_si128(state_ptr.add(1));

    let cdab = _mm_shuffle_epi32(dcba, 0xb1);
    let efgh = _mm_shuffle_epi32(efgh, 0x1b);
    let mut abef = _mm_alignr_epi8(cdab, efgh, 8);
    let mut cdgh = _mm_blend_epi16(efgh, cdab, 0xf0);

    let abef_save = abef;
    let cdgh_save = cdgh;

    let data_ptr = block.as_ptr() as *const __m128i;
    let mut w0 = _mm_shuffle_epi8(_mm_loadu_si128(data_ptr.add(0)), mask);
    let mut w1 = _mm_shuffle_epi8(_mm_loadu_si128(data_ptr.add(1)), mask);
    let mut w2 = _mm_shuffle_epi8(_mm_loadu_si128(data_ptr.add(2)), mask);
    let mut w3 = _mm_shuffle_epi8(_mm_loadu_si128(data_ptr.add(3)), mask);
    let mut w4;

    rounds4!(abef, cdgh, w0, 0);
    rounds4!(abef, cdgh, w1, 1);
    rounds4!(abef, cdgh, w2, 2);
    rounds4!(abef, cdgh, w3, 3);
    schedule_rounds4!(abef, cdgh, w0, w1, w2, w3, w4, 4);
    schedule_rounds4!(abef, cdgh, w1, w2, w3, w4, w0, 5);
    schedule_rounds4!(abef, cdgh, w2, w3, w4, w0, w1, 6);
    schedule_rounds4!(abef, cdgh, w3, w4, w0, w1, w2, 7);
    schedule_rounds4!(abef, cdgh, w4, w0, w1, w2, w3, 8);
    schedule_rounds4!(abef, cdgh, w0, w1, w2, w3, w4, 9);
    schedule_rounds4!(abef, cdgh, w1, w2, w3, w4, w0, 10);
    schedule_rounds4!(abef, cdgh, w2, w3, w4, w0, w1, 11);
    schedule_rounds4!(abef, cdgh, w3, w4, w0, w1, w2, 12);
    schedule_rounds4!(abef, cdgh, w4, w0, w1, w2, w3, 13);
    schedule_rounds4!(abef, cdgh, w0, w1, w2, w3, w4, 14);
    schedule_rounds4!(abef, cdgh, w1, w2, w3, w4, w0, 15);

    abef = _mm_add_epi32(abef, abef_save);
    cdgh = _mm_add_epi32(cdgh, cdgh_save);

    let feba = _mm_shuffle_epi32(abef, 0x1b);
    let dchg = _mm_shuffle_epi32(cdgh, 0xb1);
    let dcba = _mm_blend_epi16(feba, dchg, 0xf0);
    let hgef = _mm_alignr_epi8(dchg, feba, 8);

    let state_ptr_mut = state.as_mut_ptr() as *mut __m128i;
    _mm_storeu_si128(state_ptr_mut.add(0), dcba);
    _mm_storeu_si128(state_ptr_mut.add(1), hgef);
}

#[allow(clippy::cast_ptr_alignment)]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn compress_two(
    state0: &mut [u32; 8],
    block0: &[u8; 64],
    state1: &mut [u32; 8],
    block1: &[u8; 64],
) {
    let mask: __m128i = _mm_set_epi64x(
        0x0c0d_0e0f_0809_0a0bu64 as i64,
        0x0405_0607_0001_0203u64 as i64,
    );

    let state0_ptr = state0.as_ptr() as *const __m128i;
    let dcba0 = _mm_loadu_si128(state0_ptr.add(0));
    let efgh0 = _mm_loadu_si128(state0_ptr.add(1));
    let cdab0 = _mm_shuffle_epi32(dcba0, 0xb1);
    let efgh0 = _mm_shuffle_epi32(efgh0, 0x1b);
    let mut abef0 = _mm_alignr_epi8(cdab0, efgh0, 8);
    let mut cdgh0 = _mm_blend_epi16(efgh0, cdab0, 0xf0);
    let abef0_save = abef0;
    let cdgh0_save = cdgh0;

    let state1_ptr = state1.as_ptr() as *const __m128i;
    let dcba1 = _mm_loadu_si128(state1_ptr.add(0));
    let efgh1 = _mm_loadu_si128(state1_ptr.add(1));
    let cdab1 = _mm_shuffle_epi32(dcba1, 0xb1);
    let efgh1 = _mm_shuffle_epi32(efgh1, 0x1b);
    let mut abef1 = _mm_alignr_epi8(cdab1, efgh1, 8);
    let mut cdgh1 = _mm_blend_epi16(efgh1, cdab1, 0xf0);
    let abef1_save = abef1;
    let cdgh1_save = cdgh1;

    let data0_ptr = block0.as_ptr() as *const __m128i;
    let mut w00 = _mm_shuffle_epi8(_mm_loadu_si128(data0_ptr.add(0)), mask);
    let mut w01 = _mm_shuffle_epi8(_mm_loadu_si128(data0_ptr.add(1)), mask);
    let mut w02 = _mm_shuffle_epi8(_mm_loadu_si128(data0_ptr.add(2)), mask);
    let mut w03 = _mm_shuffle_epi8(_mm_loadu_si128(data0_ptr.add(3)), mask);
    let mut w04;

    let data1_ptr = block1.as_ptr() as *const __m128i;
    let mut w10 = _mm_shuffle_epi8(_mm_loadu_si128(data1_ptr.add(0)), mask);
    let mut w11 = _mm_shuffle_epi8(_mm_loadu_si128(data1_ptr.add(1)), mask);
    let mut w12 = _mm_shuffle_epi8(_mm_loadu_si128(data1_ptr.add(2)), mask);
    let mut w13 = _mm_shuffle_epi8(_mm_loadu_si128(data1_ptr.add(3)), mask);
    let mut w14;

    rounds4!(abef0, cdgh0, w00, 0);
    rounds4!(abef1, cdgh1, w10, 0);
    rounds4!(abef0, cdgh0, w01, 1);
    rounds4!(abef1, cdgh1, w11, 1);
    rounds4!(abef0, cdgh0, w02, 2);
    rounds4!(abef1, cdgh1, w12, 2);
    rounds4!(abef0, cdgh0, w03, 3);
    rounds4!(abef1, cdgh1, w13, 3);
    schedule_rounds4!(abef0, cdgh0, w00, w01, w02, w03, w04, 4);
    schedule_rounds4!(abef1, cdgh1, w10, w11, w12, w13, w14, 4);
    schedule_rounds4!(abef0, cdgh0, w01, w02, w03, w04, w00, 5);
    schedule_rounds4!(abef1, cdgh1, w11, w12, w13, w14, w10, 5);
    schedule_rounds4!(abef0, cdgh0, w02, w03, w04, w00, w01, 6);
    schedule_rounds4!(abef1, cdgh1, w12, w13, w14, w10, w11, 6);
    schedule_rounds4!(abef0, cdgh0, w03, w04, w00, w01, w02, 7);
    schedule_rounds4!(abef1, cdgh1, w13, w14, w10, w11, w12, 7);
    schedule_rounds4!(abef0, cdgh0, w04, w00, w01, w02, w03, 8);
    schedule_rounds4!(abef1, cdgh1, w14, w10, w11, w12, w13, 8);
    schedule_rounds4!(abef0, cdgh0, w00, w01, w02, w03, w04, 9);
    schedule_rounds4!(abef1, cdgh1, w10, w11, w12, w13, w14, 9);
    schedule_rounds4!(abef0, cdgh0, w01, w02, w03, w04, w00, 10);
    schedule_rounds4!(abef1, cdgh1, w11, w12, w13, w14, w10, 10);
    schedule_rounds4!(abef0, cdgh0, w02, w03, w04, w00, w01, 11);
    schedule_rounds4!(abef1, cdgh1, w12, w13, w14, w10, w11, 11);
    schedule_rounds4!(abef0, cdgh0, w03, w04, w00, w01, w02, 12);
    schedule_rounds4!(abef1, cdgh1, w13, w14, w10, w11, w12, 12);
    schedule_rounds4!(abef0, cdgh0, w04, w00, w01, w02, w03, 13);
    schedule_rounds4!(abef1, cdgh1, w14, w10, w11, w12, w13, 13);
    schedule_rounds4!(abef0, cdgh0, w00, w01, w02, w03, w04, 14);
    schedule_rounds4!(abef1, cdgh1, w10, w11, w12, w13, w14, 14);
    schedule_rounds4!(abef0, cdgh0, w01, w02, w03, w04, w00, 15);
    schedule_rounds4!(abef1, cdgh1, w11, w12, w13, w14, w10, 15);

    abef0 = _mm_add_epi32(abef0, abef0_save);
    cdgh0 = _mm_add_epi32(cdgh0, cdgh0_save);
    abef1 = _mm_add_epi32(abef1, abef1_save);
    cdgh1 = _mm_add_epi32(cdgh1, cdgh1_save);

    store_state(state0, abef0, cdgh0);
    store_state(state1, abef1, cdgh1);
}

#[inline(always)]
#[allow(clippy::cast_ptr_alignment)]
unsafe fn store_state(state: &mut [u32; 8], abef: __m128i, cdgh: __m128i) {
    let feba = _mm_shuffle_epi32(abef, 0x1b);
    let dchg = _mm_shuffle_epi32(cdgh, 0xb1);
    let dcba = _mm_blend_epi16(feba, dchg, 0xf0);
    let hgef = _mm_alignr_epi8(dchg, feba, 8);

    let state_ptr_mut = state.as_mut_ptr() as *mut __m128i;
    _mm_storeu_si128(state_ptr_mut.add(0), dcba);
    _mm_storeu_si128(state_ptr_mut.add(1), hgef);
}
