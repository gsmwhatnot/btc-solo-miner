use super::*;

const GENESIS_HEADER: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";

#[test]
fn specialized_matches_library_for_genesis_header() {
    let header = decode_hex_80(GENESIS_HEADER).unwrap();
    assert_eq!(specialized_sha256d80(&header), library_sha256d80(&header));
    assert_eq!(compression_sha256d80(&header), library_sha256d80(&header));
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if let Some(shani) = shani_sha256d80(&header) {
        assert_eq!(shani, library_sha256d80(&header));
    }
}

#[test]
fn specialized_matches_library_for_nonce_changes() {
    let mut header = decode_hex_80(GENESIS_HEADER).unwrap();
    for nonce in [0, 1, 2, 42, 1_000_000, u32::MAX] {
        header[76..80].copy_from_slice(&nonce.to_le_bytes());
        assert_eq!(specialized_sha256d80(&header), library_sha256d80(&header));
        assert_eq!(compression_sha256d80(&header), library_sha256d80(&header));
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if let Some(shani) = shani_sha256d80(&header) {
            assert_eq!(shani, library_sha256d80(&header));
        }
    }
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn interleaved_count_matches_single_stream_count() {
    if !shani_available() {
        return;
    }

    let mut header = decode_hex_80(GENESIS_HEADER).unwrap();
    header[76..80].copy_from_slice(&0u32.to_le_bytes());
    let mut target = library_sha256d80(&header);
    target.reverse();
    let target = TargetWords::from_be_bytes(target);
    let shani = Sha256d80Shani::new(&header).unwrap();

    let single = shani.count_batch_with_target(0, 10_001, target);
    let interleaved = shani.count_batch_with_target_interleaved2(0, 10_001, target);
    assert_eq!(single, interleaved);
    let interleaved4 = shani.count_batch_with_target_interleaved4(0, 10_001, target);
    assert_eq!(single, interleaved4);
    let interleaved8 = shani.count_batch_with_target_interleaved8(0, 10_001, target);
    assert_eq!(single, interleaved8);
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn interleaved_scan_finds_known_genesis_nonce() {
    if !shani_available() {
        return;
    }

    let header = decode_hex_80(GENESIS_HEADER).unwrap();
    let actual_nonce = u32::from_le_bytes(header[76..80].try_into().unwrap());
    let target = bits_to_target(header[72..76].try_into().unwrap()).unwrap();
    let target_words = TargetWords::from_be_bytes(target);
    let expected_hash = library_sha256d80(&header);
    let shani = Sha256d80Shani::new(&header).unwrap();

    for (start, count) in [
        (actual_nonce, 1),
        (actual_nonce - 3, 7),
        (actual_nonce - 7, 15),
        (actual_nonce - 8, 17),
        (actual_nonce - 65, 131),
        (actual_nonce - 1024, 2049),
    ] {
        let single = shani.scan_batch(start as u64, count, target_words);
        let interleaved2 = shani.scan_batch_interleaved2(start as u64, count, target_words);
        let interleaved4 = shani.scan_batch_interleaved4(start as u64, count, target_words);
        let interleaved8 = shani.scan_batch_interleaved8(start as u64, count, target_words);

        assert_eq!(single.found_nonce, Some(actual_nonce));
        assert_eq!(single.found_hash, Some(expected_hash));
        assert_eq!(interleaved2.found_nonce, single.found_nonce);
        assert_eq!(interleaved2.found_hash, single.found_hash);
        assert_eq!(interleaved2.hashes_checked, single.hashes_checked);
        assert_eq!(interleaved4.found_nonce, single.found_nonce);
        assert_eq!(interleaved4.found_hash, single.found_hash);
        assert_eq!(interleaved4.hashes_checked, single.hashes_checked);
        assert_eq!(interleaved8.found_nonce, single.found_nonce);
        assert_eq!(interleaved8.found_hash, single.found_hash);
        assert_eq!(interleaved8.hashes_checked, single.hashes_checked);
    }
}
