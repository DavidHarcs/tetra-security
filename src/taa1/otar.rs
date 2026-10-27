//! Key sealing for over-the-air rekeying (OTAR): TA51 / TA52 (ETSI TS 104 053-3
//! clauses 5.10 and 5.11), used by the SwMI to deliver a static cipher key SCK
//! to a radio inside D-OTAR SCK PROVIDE (EN 300 392-7 clause 4.5.2).
//!
//! The SCK and its number are expanded with redundancy (EXP3), encrypted with
//! BL1 under a key formed from the session key KSO and the SCK version
//! number, and the 128-bit result is shrunk to 120 bits. TA52 reverses this
//! and reports a manipulation flag when the redundancy does not check out
//! (clause 4.3.4). The same pair seals GCKs (TA81/TA82 differ only in the
//! element sizes) and GSKOs.
//!
//! Byte order follows the published reference vectors: `sck[0]` is the most
//! significant byte of the key as written in hex.

use super::hurdle::Hurdle;

/// Sealed SCK, 120 bits (A.8.76 "Sealed key").
pub const SSCK_LEN: usize = 15;

/// EXP3 (clause 5.4.3) as applied to SCK ‖ SCKN: 88 → 120 bits, each group of
/// bytes followed by its XOR.
fn expand_88_to_120(b: &[u8; 11]) -> [u8; 15] {
    [
        b[0],
        b[1],
        b[0] ^ b[1],
        b[2],
        b[3],
        b[4],
        b[2] ^ b[3] ^ b[4],
        b[5],
        b[6],
        b[7],
        b[5] ^ b[6] ^ b[7],
        b[8],
        b[9],
        b[10],
        b[8] ^ b[9] ^ b[10],
    ]
}

/// The key for BL1: eight copies of the 16-bit version number XORed with KSO
/// (clause 5.10.2).
fn sealing_key(kso: &[u8; 16], sck_vn: u16) -> [u8; 16] {
    let vn = sck_vn.to_be_bytes();
    let mut key = [0u8; 16];
    for (i, k) in key.iter_mut().enumerate() {
        *k = kso[i] ^ vn[i & 1];
    }
    key
}

/// TA51: seal `sck` (number `sckn`, version `sck_vn`) under the session key
/// `kso` (= TA41(K, RSO)). Returns SSCK.
pub fn ta51(sck: &[u8; 10], sck_vn: u16, kso: &[u8; 16], sckn: u8) -> [u8; SSCK_LEN] {
    let mut unsealed = [0u8; 11];
    unsealed[..10].copy_from_slice(sck);
    unsealed[10] = sckn & 0x1f;
    let mut plain = [0u8; 16];
    plain[..15].copy_from_slice(&expand_88_to_120(&unsealed));
    // plain[15] stays zero: the padding byte that lets TA52 recover the stolen ciphertext byte.

    let bc = Hurdle::new(&sealing_key(kso, sck_vn));
    let c1 = bc.encrypt(plain[..8].try_into().expect("8 bytes"));
    let mut mixed = [0u8; 8];
    for i in 0..8 {
        mixed[i] = plain[8 + i] ^ c1[i];
    }
    let c2 = bc.encrypt(&mixed);
    // Output derivation (clause 5.8.3): one byte of the first block is discarded.
    let mut out = [0u8; SSCK_LEN];
    out[..7].copy_from_slice(&c1[..7]);
    out[7..].copy_from_slice(&c2);
    out
}

/// TA52: unseal an SSCK. `Ok((sck, sckn))` when the redundancy checks out,
/// `Err(())` when the manipulation flag is set (wrong KSO, wrong version
/// number, or a corrupted key).
pub fn ta52(ssck: &[u8; SSCK_LEN], kso: &[u8; 16], sck_vn: u16) -> Result<([u8; 10], u8), ()> {
    let bc = Hurdle::new(&sealing_key(kso, sck_vn));
    // Second block first: its last plaintext byte was zero, so decrypting it yields the
    // discarded ciphertext byte of the first block.
    let d2 = bc.decrypt(ssck[7..].try_into().expect("8 bytes"));
    let mut c1 = [0u8; 8];
    c1[..7].copy_from_slice(&ssck[..7]);
    c1[7] = d2[7];
    let p1 = bc.decrypt(&c1);
    let mut p = [0u8; 15];
    p[..8].copy_from_slice(&p1);
    for i in 0..7 {
        p[8 + i] = d2[i] ^ c1[i];
    }
    let unsealed = [p[0], p[1], p[3], p[4], p[5], p[7], p[8], p[9], p[11], p[12], p[13]];
    let manipulated = (p[0] ^ p[1]) != p[2]
        || (p[3] ^ p[4] ^ p[5]) != p[6]
        || (p[7] ^ p[8] ^ p[9]) != p[10]
        || (p[11] ^ p[12] ^ p[13]) != p[14]
        || unsealed[10] & 0xe0 != 0;
    if manipulated {
        return Err(());
    }
    let mut sck = [0u8; 10];
    sck.copy_from_slice(&unsealed[..10]);
    Ok((sck, unsealed[10]))
}

/// Sealed GCK, 120 bits (A.8.76 "Sealed key"; same size as a sealed SCK).
pub const SGCK_LEN: usize = 15;

/// EXP for GCK ‖ GCKN (TA81): 96 → 120 bits, each 4-byte group followed by its
/// XOR, with the 2-byte GCKN occupying the last group.
fn expand_gck(gck: &[u8; 10], gckn: &[u8; 2]) -> [u8; 15] {
    [
        gck[0],
        gck[1],
        gck[2],
        gck[3],
        gck[0] ^ gck[1] ^ gck[2] ^ gck[3],
        gck[4],
        gck[5],
        gck[6],
        gck[7],
        gck[4] ^ gck[5] ^ gck[6] ^ gck[7],
        gck[8],
        gck[9],
        gckn[0],
        gckn[1],
        gck[8] ^ gck[9] ^ gckn[0] ^ gckn[1],
    ]
}

/// TA81: seal `gck` (number `gckn`, version `gck_vn`) under the sealing key
/// `key` (derived from the GSKO). Returns the sealed GCK. ETSI TS 104 053-3.
/// Same BL1/CBC-with-ciphertext-stealing construction as TA51; only the
/// redundancy layout differs (GCK carries a 2-byte GCKN rather than SCKN).
pub fn ta81(gck: &[u8; 10], gck_vn: u16, gckn: &[u8; 2], key: &[u8; 16]) -> [u8; SGCK_LEN] {
    let mut plain = [0u8; 16];
    plain[..15].copy_from_slice(&expand_gck(gck, gckn));
    // plain[15] stays zero (the padding byte TA82 uses to recover the stolen byte).
    let bc = Hurdle::new(&sealing_key(key, gck_vn));
    let c1 = bc.encrypt(plain[..8].try_into().expect("8 bytes"));
    let mut mixed = [0u8; 8];
    for i in 0..8 {
        mixed[i] = plain[8 + i] ^ c1[i];
    }
    let c2 = bc.encrypt(&mixed);
    let mut out = [0u8; SGCK_LEN];
    out[..7].copy_from_slice(&c1[..7]);
    out[7..].copy_from_slice(&c2);
    out
}

/// TA82: unseal a sealed GCK. `Ok((gck, gckn))` when the redundancy checks out,
/// `Err(())` when the manipulation flag is set (wrong key, wrong version, or a
/// corrupted key).
pub fn ta82(sgck: &[u8; SGCK_LEN], gck_vn: u16, key: &[u8; 16]) -> Result<([u8; 10], [u8; 2]), ()> {
    let bc = Hurdle::new(&sealing_key(key, gck_vn));
    let d2 = bc.decrypt(sgck[7..].try_into().expect("8 bytes"));
    let mut c1 = [0u8; 8];
    c1[..7].copy_from_slice(&sgck[..7]);
    c1[7] = d2[7];
    let p1 = bc.decrypt(&c1);
    let mut p = [0u8; 15];
    p[..8].copy_from_slice(&p1);
    for i in 0..7 {
        p[8 + i] = d2[i] ^ c1[i];
    }
    let gck = [p[0], p[1], p[2], p[3], p[5], p[6], p[7], p[8], p[10], p[11]];
    let gckn = [p[12], p[13]];
    let manipulated = (p[0] ^ p[1] ^ p[2] ^ p[3]) != p[4]
        || (p[5] ^ p[6] ^ p[7] ^ p[8]) != p[9]
        || (p[10] ^ p[11] ^ p[12] ^ p[13]) != p[14];
    if manipulated {
        return Err(());
    }
    Ok((gck, gckn))
}

/// Sealed GSKO, 120 bits (same size and construction as a sealed GCK).
pub const SGSKO_LEN: usize = SGCK_LEN;

/// TA91: seal a 96-bit group session key for OTAR (`gsko`, version `gsko_vn`)
/// under the sealing key `key` (= TA41(K, RSO) for individual delivery). The
/// GSKO carries the OTAR key-encryption key used to then distribute GCKs in
/// group mode. ETSI TS 104 053-3.
///
/// TA91 is TA81 applied to the GSKO split as a 10-byte value plus its trailing
/// 2 bytes in the GCKN redundancy slot, so the sealed output is a sealed GCK.
pub fn ta91(gsko: &[u8; 12], gsko_vn: u16, key: &[u8; 16]) -> [u8; SGSKO_LEN] {
    let gck: [u8; 10] = gsko[..10].try_into().expect("10 bytes");
    let gckn = [gsko[10], gsko[11]];
    ta81(&gck, gsko_vn, &gckn, key)
}

/// TA92: unseal a sealed GSKO. `Ok(gsko)` (12 bytes) when the redundancy checks
/// out, `Err(())` when the manipulation flag is set (wrong key, wrong version,
/// or a corrupted key).
pub fn ta92(sgsko: &[u8; SGSKO_LEN], gsko_vn: u16, key: &[u8; 16]) -> Result<[u8; 12], ()> {
    let (gck, tail) = ta82(sgsko, gsko_vn, key)?;
    let mut gsko = [0u8; 12];
    gsko[..10].copy_from_slice(&gck);
    gsko[10..].copy_from_slice(&tail);
    Ok(gsko)
}

#[cfg(test)]
mod tests {
    use super::*;

    // GCK reference vectors (Midnight Blue TETRA_crypto, Apache-2.0):
    // (GCK, GCK-VN, GCKN, key, sealed GCK).
    type GckVector = ([u8; 10], u16, [u8; 2], [u8; 16], [u8; 15]);
    const GCK_VECTORS: [GckVector; 4] = [
        (
            [0; 10],
            0xa397,
            [0x1f, 0x5d],
            [0x63, 0x59, 0x38, 0xac, 0xe8, 0x1f, 0x6b, 0x67, 0x82, 0xa6, 0xfa, 0x46, 0xae, 0x4f, 0x7f, 0x69],
            [0x1c, 0xcf, 0x9c, 0x6b, 0xa8, 0x5c, 0x5b, 0x45, 0x60, 0xf9, 0xcf, 0x5c, 0x63, 0xb0, 0xdc],
        ),
        (
            [0x63, 0x09, 0x5a, 0xeb, 0x26, 0xf0, 0xe7, 0x26, 0x28, 0xd0],
            0x8fbc,
            [0xe3, 0x63],
            [0x55, 0x36, 0xeb, 0x46, 0xa6, 0x02, 0xe7, 0x80, 0x49, 0x29, 0x9d, 0x82, 0xab, 0x64, 0x80, 0x45],
            [0xc9, 0x35, 0x95, 0xa5, 0x4e, 0xcd, 0x34, 0xf9, 0xb5, 0x9a, 0xfb, 0x3a, 0x0d, 0x59, 0x05],
        ),
        (
            [0x10, 0x6a, 0x40, 0xc6, 0xf7, 0xb0, 0x89, 0xb7, 0xac, 0x41],
            0xbec4,
            [0x12, 0xa6],
            [0x08, 0xf6, 0x17, 0x4e, 0xc8, 0x18, 0xd2, 0xa2, 0x14, 0xf1, 0xd7, 0x53, 0x4d, 0x31, 0x9f, 0x6c],
            [0x03, 0x52, 0x0f, 0xe9, 0x75, 0x7b, 0x66, 0x83, 0x0b, 0x36, 0xb1, 0x3b, 0x7c, 0xe5, 0xb4],
        ),
        (
            [0xc3, 0xc6, 0x82, 0xda, 0xd8, 0xaa, 0x33, 0xa2, 0xce, 0x6b],
            0x1f8b,
            [0xce, 0x89],
            [0xc2, 0x71, 0x13, 0x63, 0xd3, 0x6d, 0x4f, 0xbf, 0xc9, 0xf5, 0xcf, 0x73, 0xb8, 0xb4, 0xdd, 0x35],
            [0xc8, 0x6a, 0x1d, 0x03, 0x2c, 0x97, 0xbb, 0x86, 0x7a, 0x30, 0x2f, 0x35, 0xdf, 0x7e, 0x93],
        ),
    ];

    #[test]
    fn ta81_matches_reference_vectors_and_ta82_inverts() {
        for (gck, vn, gckn, key, sealed) in GCK_VECTORS {
            assert_eq!(ta81(&gck, vn, &gckn, &key), sealed, "TA81 sealed output mismatch");
            let (ugck, ugckn) = ta82(&sealed, vn, &key).expect("TA82 should unseal");
            assert_eq!(ugck, gck, "TA82 GCK mismatch");
            assert_eq!(ugckn, gckn, "TA82 GCKN mismatch");
        }
    }

    #[test]
    fn ta82_flags_a_wrong_key() {
        let (gck, vn, gckn, mut key, _) = GCK_VECTORS[1];
        let sealed = ta81(&gck, vn, &gckn, &key);
        key[0] ^= 0x01;
        assert!(ta82(&sealed, vn, &key).is_err());
    }

    // Independent reference vectors (Midnight Blue TETRA_crypto, Apache-2.0):
    // (SCK, SCK-VN, KSO, SCKN, SSCK).
    /// (SCK, SCK-VN, KSO, SCKN, SSCK)
    type Vector = ([u8; 10], u16, [u8; 16], u8, [u8; 15]);
    const VECTORS: [Vector; 4] = [
        (
            [0; 10],
            0x0f6d,
            [0x77, 0xe7, 0x9f, 0xee, 0x7f, 0xc6, 0x54, 0xdc, 0x65, 0x44, 0x64, 0x4f, 0xdf, 0x47, 0x68, 0x15],
            0x0f,
            [0x08, 0x3D, 0x05, 0xA7, 0x8E, 0x86, 0xFD, 0x5F, 0x46, 0xD6, 0x2B, 0x28, 0x42, 0x2B, 0x0B],
        ),
        (
            [0x56, 0x5a, 0x72, 0xd6, 0x3c, 0xce, 0xed, 0x0b, 0x6f, 0x30],
            0x790a,
            [0xc6, 0x2e, 0x22, 0x85, 0x03, 0x40, 0xbc, 0xeb, 0x55, 0x52, 0x22, 0x28, 0x60, 0x17, 0x3d, 0x7e],
            0x1b,
            [0x90, 0xB1, 0xEF, 0x3A, 0xCE, 0x5C, 0xAD, 0x1A, 0x87, 0x2A, 0x75, 0x39, 0xBC, 0xCA, 0xA4],
        ),
        (
            [0x93, 0x5e, 0x49, 0xfc, 0xdc, 0xbb, 0x47, 0x58, 0x19, 0x55],
            0x60ab,
            [0x4e, 0xbb, 0x68, 0x9d, 0x87, 0x4a, 0xd6, 0x41, 0x79, 0x05, 0xc0, 0xed, 0xaa, 0x3f, 0x90, 0xec],
            0x13,
            [0x2D, 0xDA, 0x81, 0xF9, 0x9C, 0xA3, 0x1C, 0x3E, 0xD8, 0xE6, 0xDE, 0x31, 0xF1, 0x6D, 0x58],
        ),
        (
            [0xb8, 0x24, 0xff, 0xb1, 0x37, 0xa4, 0xef, 0x87, 0xe0, 0x7a],
            0x4cad,
            [0x67, 0xfb, 0x13, 0x4d, 0xd7, 0x9c, 0x7d, 0x77, 0xf5, 0x2a, 0x5d, 0xce, 0xf2, 0x3d, 0xe6, 0xfd],
            0x03,
            [0x3E, 0x7C, 0x8E, 0x73, 0x3B, 0xC1, 0x33, 0xA7, 0x0D, 0x27, 0x83, 0x97, 0x43, 0x50, 0x30],
        ),
    ];

    #[test]
    fn ta51_matches_reference_vectors() {
        for (sck, vn, kso, sckn, ssck) in VECTORS {
            assert_eq!(ta51(&sck, vn, &kso, sckn), ssck, "sckn {sckn}");
        }
    }

    #[test]
    fn ta52_unseals_and_detects_manipulation() {
        for (sck, vn, kso, sckn, ssck) in VECTORS {
            assert_eq!(ta52(&ssck, &kso, vn), Ok((sck, sckn)));
            // Wrong version number or session key, or a flipped bit: manipulation flag.
            assert!(ta52(&ssck, &kso, vn ^ 1).is_err());
            let mut bad_kso = kso;
            bad_kso[3] ^= 0x80;
            assert!(ta52(&ssck, &bad_kso, vn).is_err());
            let mut bad = ssck;
            bad[9] ^= 0x01;
            assert!(ta52(&bad, &kso, vn).is_err());
        }
    }

    // GSKO reference vectors (Midnight Blue TETRA_crypto, Apache-2.0):
    // (GSKO, GSKO-VN, key, sealed GSKO).
    type GskoVector = ([u8; 12], u16, [u8; 16], [u8; 15]);
    const GSKO_VECTORS: [GskoVector; 4] = [
        (
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb0, 0xdc],
            0xa397,
            [0x63, 0x59, 0x38, 0xac, 0xe8, 0x1f, 0x6b, 0x67, 0x82, 0xa6, 0xfa, 0x46, 0xae, 0x4f, 0x7f, 0x69],
            [0x1c, 0xcf, 0x9c, 0x6b, 0xa8, 0x5c, 0x5b, 0xc7, 0xe0, 0x7b, 0x04, 0x21, 0xf2, 0xc3, 0x8a],
        ),
        (
            [0x63, 0x09, 0x5a, 0xeb, 0x26, 0xf0, 0xe7, 0x26, 0x28, 0xd0, 0x59, 0x05],
            0x8fbc,
            [0x55, 0x36, 0xeb, 0x46, 0xa6, 0x02, 0xe7, 0x80, 0x49, 0x29, 0x9d, 0x82, 0xab, 0x64, 0x80, 0x45],
            [0xc9, 0x35, 0x95, 0xa5, 0x4e, 0xcd, 0x34, 0x16, 0x13, 0xd0, 0xcf, 0x87, 0x03, 0xeb, 0xac],
        ),
        (
            [0x10, 0x6a, 0x40, 0xc6, 0xf7, 0xb0, 0x89, 0xb7, 0xac, 0x41, 0xe5, 0xb4],
            0xbec4,
            [0x08, 0xf6, 0x17, 0x4e, 0xc8, 0x18, 0xd2, 0xa2, 0x14, 0xf1, 0xd7, 0x53, 0x4d, 0x31, 0x9f, 0x6c],
            [0x03, 0x52, 0x0f, 0xe9, 0x75, 0x7b, 0x66, 0x9d, 0x93, 0xf6, 0x57, 0x5f, 0xee, 0x6f, 0x9c],
        ),
        (
            [0xc3, 0xc6, 0x82, 0xda, 0xd8, 0xaa, 0x33, 0xa2, 0xce, 0x6b, 0x7e, 0x93],
            0x1f8b,
            [0xc2, 0x71, 0x13, 0x63, 0xd3, 0x6d, 0x4f, 0xbf, 0xc9, 0xf5, 0xcf, 0x73, 0xb8, 0xb4, 0xdd, 0x35],
            [0xc8, 0x6a, 0x1d, 0x03, 0x2c, 0x97, 0xbb, 0x94, 0xb0, 0x01, 0x8f, 0xe5, 0x50, 0x7b, 0xa7],
        ),
    ];

    #[test]
    fn ta91_matches_reference_vectors_and_ta92_inverts() {
        for (gsko, vn, key, sealed) in GSKO_VECTORS {
            assert_eq!(ta91(&gsko, vn, &key), sealed, "TA91 sealed GSKO mismatch");
            assert_eq!(ta92(&sealed, vn, &key), Ok(gsko), "TA92 should recover the GSKO");
        }
    }

    #[test]
    fn ta92_flags_a_wrong_key_or_version() {
        let (gsko, vn, mut key, _) = GSKO_VECTORS[2];
        let sealed = ta91(&gsko, vn, &key);
        assert!(ta92(&sealed, vn ^ 1, &key).is_err(), "wrong version must flag");
        key[7] ^= 0x40;
        assert!(ta92(&sealed, vn, &key).is_err(), "wrong key must flag");
    }

    #[test]
    fn seal_round_trip_with_derived_session_key() {
        // The real flow: KSO = TA41(K, RSO), then TA51 / TA52.
        let k = [0x11u8; 16];
        let rso = [0x22u8; 10];
        let kso = crate::taa1::ta41(&k, &rso);
        let sck = [0xAB; 10];
        let sealed = ta51(&sck, 7, &kso, 1);
        assert_eq!(ta52(&sealed, &kso, 7), Ok((sck, 1)));
    }
}
