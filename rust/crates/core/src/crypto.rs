// crypto.rs -- PBKDF2 (RustCrypto sha2+hmac), CRC32, SHA-256.
// Replaces the CNG P/Invoke path in Crypto.cs; RustCrypto is stateless so the
// per-thread CNG handle cache disappears entirely.
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use sha1::Sha1;

/// PBKDF2-HMAC-SHA256, matching the RFC 7914 vectors and the C# CNG path.
pub fn pbkdf2_sha256(pwd: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    pbkdf2_hmac::<Sha256>(pwd, salt, iterations, out);
}

// ------------------------------------------------------------------
// 4-way interleaved PBKDF2-HMAC-SHA256 (the RAR5 hot path). One SHA-NI
// `_mm_sha256rnds2_epu32` chain is latency-bound (~4 cyc/instr, ~200 cyc
// per block); running 4 independent candidates round-robin turns the
// SHA unit from latency-bound to throughput-bound. Without SHA-NI (E
// cores) every call falls back to the scalar RFC path lane by lane.
#[cfg(target_arch = "x86_64")]
// cpufeatures 0.2.x's macro internally uses u8::max_value(), which newer
// std deprecated -- the call site allow does not reach the macro's inner
// items, so silence it at module level
#[allow(deprecated)]
mod sha256_x4 {
    use core::arch::x86_64::*;

    cpufeatures::new!(shani, "sha", "sse2", "ssse3", "sse4.1");

    pub fn shani_available() -> bool {
        shani::get()
    }

    pub(crate) const SHA256_IV: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
    ];

    // standard SHA-256 K table, reversed within each group of four to
    // match _mm_set_epi32's lane order (same layout as sha2's K32X4)
    const K32X4: [[u32; 4]; 16] = [
        [0xe9b5_dba5, 0xb5c0_fbcf, 0x7137_4491, 0x428a_2f98],
        [0xab1c_5ed5, 0x923f_82a4, 0x59f1_11f1, 0x3956_c25b],
        [0x550c_7dc3, 0x2431_85be, 0x1283_5b01, 0xd807_aa98],
        [0xc19b_f174, 0x9bdc_06a7, 0x80de_b1fe, 0x72be_5d74],
        [0x240c_a1cc, 0x0fc1_9dc6, 0xefbe_4786, 0xe49b_69c1],
        [0x76f9_88da, 0x5cb0_a9dc, 0x4a74_84aa, 0x2de9_2c6f],
        [0xbf59_7fc7, 0xb003_27c8, 0xa831_c66d, 0x983e_5152],
        [0x1429_2967, 0x06ca_6351, 0xd5a7_9147, 0xc6e0_0bf3],
        [0x5338_0d13, 0x4d2c_6dfc, 0x2e1b_2138, 0x27b7_0a85],
        [0x9272_2c85, 0x81c2_c92e, 0x766a_0abb, 0x650a_7354],
        [0xc76c_51a3, 0xc24b_8b70, 0xa81a_664b, 0xa2bf_e8a1],
        [0x106a_a070, 0xf40e_3585, 0xd699_0624, 0xd192_e819],
        [0x34b0_bcb5, 0x2748_774c, 0x1e37_6c08, 0x19a4_c116],
        [0x682e_6ff3, 0x5b9c_ca4f, 0x4ed8_aa4a, 0x391c_0cb3],
        [0x8cc7_0208, 0x84c8_7814, 0x78a5_636f, 0x748f_82ee],
        [0xc671_78f2, 0xbef9_a3f7, 0xa450_6ceb, 0x90be_fffa],
    ];

    #[inline(always)]
    unsafe fn schedule(v0: __m128i, v1: __m128i, v2: __m128i, v3: __m128i) -> __m128i {
        let t1 = _mm_sha256msg1_epu32(v0, v1);
        let t2 = _mm_alignr_epi8(v3, v2, 4);
        let t3 = _mm_add_epi32(t1, t2);
        _mm_sha256msg2_epu32(t3, v3)
    }

    macro_rules! rounds4 {
        ($abef:ident, $cdgh:ident, $rest:expr, $i:expr) => {{
            let k = K32X4[$i];
            let kv = _mm_set_epi32(k[0] as i32, k[1] as i32, k[2] as i32, k[3] as i32);
            let t1 = _mm_add_epi32($rest, kv);
            $cdgh = _mm_sha256rnds2_epu32($cdgh, $abef, t1);
            let t2 = _mm_shuffle_epi32(t1, 0x0E);
            $abef = _mm_sha256rnds2_epu32($abef, $cdgh, t2);
        }};
    }

    macro_rules! schedule_rounds4 {
        ($abef:ident, $cdgh:ident, $w0:expr, $w1:expr, $w2:expr, $w3:expr, $w4:expr, $i:expr) => {{
            $w4 = schedule($w0, $w1, $w2, $w3);
            rounds4!($abef, $cdgh, $w4, $i);
        }};
    }

    /// One full 64-round SHA-256 compression of `block` into `state`
    /// (SHA-NI backend, same sequence as the sha2 crate's x86 backend).
    #[allow(clippy::cast_ptr_alignment, non_snake_case)]
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    #[inline]
    pub(crate) unsafe fn compress_chain(state: &mut [u32; 8], block: &[u8; 64]) {
        #[allow(non_snake_case)]
        let MASK: __m128i = _mm_set_epi64x(0x0C0D_0E0F_0809_0A0Bu64 as i64, 0x0405_0607_0001_0203u64 as i64);

        let state_ptr = state.as_ptr() as *const __m128i;
        let dcba = _mm_loadu_si128(state_ptr.add(0));
        let efgh = _mm_loadu_si128(state_ptr.add(1));

        let cdab = _mm_shuffle_epi32(dcba, 0xB1);
        let efgh = _mm_shuffle_epi32(efgh, 0x1B);
        let mut abef = _mm_alignr_epi8(cdab, efgh, 8);
        let mut cdgh = _mm_blend_epi16(efgh, cdab, 0xF0);

        let abef_save = abef;
        let cdgh_save = cdgh;

        let data_ptr = block.as_ptr() as *const __m128i;
        let mut w0 = _mm_shuffle_epi8(_mm_loadu_si128(data_ptr.add(0)), MASK);
        let mut w1 = _mm_shuffle_epi8(_mm_loadu_si128(data_ptr.add(1)), MASK);
        let mut w2 = _mm_shuffle_epi8(_mm_loadu_si128(data_ptr.add(2)), MASK);
        let mut w3 = _mm_shuffle_epi8(_mm_loadu_si128(data_ptr.add(3)), MASK);
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

        let feba = _mm_shuffle_epi32(abef, 0x1B);
        let dchg = _mm_shuffle_epi32(cdgh, 0xB1);
        let dcba = _mm_blend_epi16(feba, dchg, 0xF0);
        let hgef = _mm_alignr_epi8(dchg, feba, 8);

        let state_ptr_mut = state.as_mut_ptr() as *mut __m128i;
        _mm_storeu_si128(state_ptr_mut.add(0), dcba);
        _mm_storeu_si128(state_ptr_mut.add(1), hgef);
    }

    /// Compress one block into each of the 4 independent states. The 4
    /// chains share no data, so the scheduler overlaps their latency
    /// chains (inlined straight-line code; LLVM interleaves what fits in
    /// the 16 XMM registers).
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    unsafe fn compress_x4(states: &mut [[u32; 8]; 4], blocks: &[[u8; 64]; 4]) {
        compress_chain(&mut states[0], &blocks[0]);
        compress_chain(&mut states[1], &blocks[1]);
        compress_chain(&mut states[2], &blocks[2]);
        compress_chain(&mut states[3], &blocks[3]);
    }

    fn state_to_block(state: &[u32; 8], block: &mut [u8; 64]) {
        // message = the 32-byte hash (big-endian words), padded: 0x80,
        // zeros, length = (64 + 32) * 8 bits -- one more compression
        // from a midstate yields HMAC(pwd, U) / U itself
        for (w, word) in state.iter().enumerate() {
            block[w * 4..w * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        block[32] = 0x80;
        block[56..64].copy_from_slice(&768u64.to_be_bytes());
    }

    /// PBKDF2 core with precomputed HMAC midstates, 4 lanes at once.
    /// Requires salt.len() + 4 <= 55 (one inner block: salt || BE32(i)).
    pub unsafe fn pbkdf2_x4_ni(pwds: &[&[u8]; 4], salt: &[u8], iters: u32, out: &mut [[u8; 32]; 4]) {
        // 1. HMAC ipad/opad blocks per lane (keys differ per lane; a key
        //    longer than the block size is hashed first, per RFC 2104)
        let mut hashed = [[0u8; 32]; 4];
        let mut ipad_blocks = [[0u8; 64]; 4];
        let mut opad_blocks = [[0u8; 64]; 4];
        for (lane, pw) in pwds.iter().enumerate() {
            let key_bytes: &[u8] = if pw.len() > 64 {
                hashed[lane] = super::sha256(pw);
                &hashed[lane]
            } else {
                pw
            };
            for j in 0..64 {
                let k = key_bytes.get(j).copied().unwrap_or(0);
                ipad_blocks[lane][j] = k ^ 0x36;
                opad_blocks[lane][j] = k ^ 0x5c;
            }
        }

        // 2. midstates: IV compressed with the ipad/opad block
        let mut inner = [SHA256_IV; 4];
        compress_x4(&mut inner, &ipad_blocks);
        let mut outer = [SHA256_IV; 4];
        compress_x4(&mut outer, &opad_blocks);

        // 3. iterations: U1 = HMAC(pwd, salt||BE32(1)), Uj = HMAC(pwd, Uj-1).
        //    Each Uj costs two compressions: the inner hash runs from the
        //    ipad midstate (block = salt||BE32(1) once, then Uj-1 per lane),
        //    the outer hash runs from the opad midstate over that 32-byte
        //    result. The salt is shared by all lanes so the first block
        //    repeats.
        let iters = iters.max(1);
        let mut first = [0u8; 64];
        first[..salt.len()].copy_from_slice(salt);
        first[salt.len()..salt.len() + 4].copy_from_slice(&1u32.to_be_bytes());
        first[salt.len() + 4] = 0x80;
        let bit_len: u64 = (64 + salt.len() as u64 + 4) * 8;
        first[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let first4 = [first, first, first, first];

        let mut ublocks = [[0u8; 64]; 4];
        let mut inner_out = inner;
        compress_x4(&mut inner_out, &first4);
        for lane in 0..4 {
            state_to_block(&inner_out[lane], &mut ublocks[lane]);
        }
        // Uj lives in u_states; the outer hash starts from the opad midstate
        let mut u_states = outer;
        compress_x4(&mut u_states, &ublocks);

        // T = U1 ^ U2 ^ ... ^ Uc (RFC 2898)
        let mut t_states = u_states;
        for _ in 2..=iters {
            for lane in 0..4 {
                state_to_block(&u_states[lane], &mut ublocks[lane]);
            }
            inner_out = inner;
            compress_x4(&mut inner_out, &ublocks);
            for lane in 0..4 {
                state_to_block(&inner_out[lane], &mut ublocks[lane]);
            }
            u_states = outer;
            compress_x4(&mut u_states, &ublocks);
            for (tl, ul) in t_states.iter_mut().zip(u_states.iter()) {
                for (tw, uw) in tl.iter_mut().zip(ul.iter()) {
                    *tw ^= *uw;
                }
            }
        }

        for (lane, o) in out.iter_mut().enumerate() {
            for (w, word) in t_states[lane].iter().enumerate() {
                o[w * 4..w * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
        }
    }
}

/// PBKDF2-HMAC-SHA256 over 4 independent passwords sharing one salt.
/// Lanes are fully independent; the result matches `pbkdf2_sha256`
/// lane-for-lane. Uses the SHA-NI 4-way kernel when available (P cores)
/// and the scalar RFC path lane by lane otherwise (E cores).
pub fn pbkdf2_sha256_x4(pwds: &[&[u8]; 4], salt: &[u8], iterations: u32, out: &mut [[u8; 32]; 4]) {
    #[cfg(target_arch = "x86_64")]
    {
        // single inner block constraint: salt || BE32(i) || padding fits
        // 64 bytes (55 = 64 - 9); RAR5's 16-byte salt is well inside
        if salt.len() + 4 <= 55 && sha256_x4::shani_available() {
            unsafe { sha256_x4::pbkdf2_x4_ni(pwds, salt, iterations.max(1), out) };
            return;
        }
    }
    for (i, pw) in pwds.iter().enumerate() {
        pbkdf2_sha256(pw, salt, iterations, &mut out[i]);
    }
}

/// PBKDF2-HMAC-SHA1 (WinZip-AES path), RFC 6070 vectors.
pub fn pbkdf2_sha1(pwd: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    pbkdf2_hmac::<Sha1>(pwd, salt, iterations, out);
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

// 7z (7zAES) key derivation.
//
// key = SHA256 over `salt || password_utf16le || LE64(round)` for
// `round` in 0 .. 2^ncp, truncated to 32 bytes. The counter is the LAST field
// and little-endian; the salt is prepended only when the archive stores one.
// ncp == 0x3F is a special value: no hashing at all, the key is
// (salt || password)[:32] zero-extended. 7-Zip drops password bytes past the
// 32-byte key there (py7zr keeps them -- it is wrong).
//
// `ncp` comes from an archive, so it is attacker-controlled: 2^31 rounds is a
// hang, not a slow check. Everything above this ceiling is refused by the
// parser (detect_note + external tool). The bound matches RAR5's `lg2 <= 24`
// and deliberately exceeds what hashcat (<32) and JtR (<=24) accept, so real
// archives still verify natively.
pub const SEVENZIP_MAX_NCP: u8 = 24;

pub fn sevenzip_derive_key(password: &str, salt: &[u8], ncp: u8) -> [u8; 32] {
    let pw: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
    if ncp == 0x3F {
        let mut key = [0u8; 32];
        for (i, &b) in salt.iter().chain(pw.iter()).take(32).enumerate() {
            key[i] = b;
        }
        return key;
    }
    let mut h = Sha256::new();
    for round in 0u64..(1u64 << ncp) {
        h.update(salt);
        h.update(&pw);
        h.update(round.to_le_bytes());
    }
    h.finalize().into()
}

/// AES-256-CBC decryption in place (7z AES streams). `data.len()` must be a
/// multiple of 16; mirrors `rar3::aes128_cbc_decrypt`.
pub fn aes256_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) -> Option<()> {
    use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
    if data.len() % 16 != 0 {
        return None;
    }
    let cipher = aes::Aes256::new(GenericArray::from_slice(key));
    let mut prev = *iv;
    for chunk in data.chunks_mut(16) {
        let cipher_text: [u8; 16] = chunk.try_into().ok()?;
        let mut block = GenericArray::clone_from_slice(&cipher_text);
        cipher.decrypt_block(&mut block);
        for (p, b) in chunk.iter_mut().zip(block.iter()) {
            *p = *b;
        }
        for (p, pv) in chunk.iter_mut().zip(prev.iter()) {
            *p ^= *pv;
        }
        prev = cipher_text;
    }
    Some(())
}

/// Standard CRC-32 (poly 0xEDB88320, reflected, pre/post inverted).
pub struct Crc32;

impl Crc32 {
    const fn build_table() -> [u32; 256] {
        let mut t = [0u32; 256];
        let mut i = 0usize;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    }

    pub const TABLE: [u32; 256] = Self::build_table();

    /// Continue a CRC over buf (pre/post inverted form).
    pub fn update(mut crc: u32, buf: &[u8]) -> u32 {
        crc ^= 0xFFFF_FFFF;
        for &b in buf {
            crc = Self::TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
        }
        crc ^ 0xFFFF_FFFF
    }

    pub fn compute(buf: &[u8]) -> u32 {
        Self::update(0, buf)
    }

    /// Raw table step without pre/post inversion -- used by the ZipCrypto
    /// key schedule, which keeps non-inverted running keys.
    #[inline]
    pub fn raw_step(c: u32, b: u8) -> u32 {
        Self::TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_sha256_rfc7914() {
        // RFC 7914 PBKDF2-HMAC-SHA-256 test vector (c=1).
        let mut out = [0u8; 32];
        pbkdf2_sha256(b"password", b"salt", 1, &mut out);
        assert_eq!(
            out,
            [
                0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
                0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b,
            ]
        );
        // c=4096 (RFC 7914 §11 / widely published PBKDF2-HMAC-SHA256 vector)
        let mut out = [0u8; 32];
        pbkdf2_sha256(b"password", b"salt", 4096, &mut out);
        assert_eq!(
            out,
            [
                0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
                0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11, 0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a,
            ]
        );
    }

    #[test]
    fn pbkdf2_sha1_rfc6070() {
        let mut out = [0u8; 20];
        pbkdf2_sha1(b"password", b"salt", 1, &mut out);
        assert_eq!(
            out,
            [0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6]
        );
        // c=4096 (RFC 6070-style vector for HMAC-SHA1)
        let mut out = [0u8; 20];
        pbkdf2_sha1(b"password", b"salt", 4096, &mut out);
        assert_eq!(
            out,
            [0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1]
        );
    }

    #[test]
    fn pbkdf2_sha256_x4_rfc7914_and_scalar_lanes() {
        // lane 0/1: RFC 7914 vectors; lane 2/3: arbitrary inputs checked
        // against the scalar implementation
        let mut out = [[0u8; 32]; 4];
        pbkdf2_sha256_x4(
            &[b"password", b"password", b"other-pw", b"third"],
            b"salt",
            1,
            &mut out,
        );
        assert_eq!(
            out[0],
            [
                0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
                0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b,
            ]
        );
        let mut ref4096 = [0u8; 32];
        pbkdf2_sha256(b"password", b"salt", 4096, &mut ref4096);
        pbkdf2_sha256_x4(
            &[b"password", b"password", b"other-pw", b"third"],
            b"salt",
            4096,
            &mut out,
        );
        assert_eq!(out[1], ref4096);
        let mut scalar = [0u8; 32];
        pbkdf2_sha256(b"other-pw", b"salt", 4096, &mut scalar);
        assert_eq!(out[2], scalar, "lane 2 must match the scalar path");
        pbkdf2_sha256(b"third", b"salt", 4096, &mut scalar);
        assert_eq!(out[3], scalar, "lane 3 must match the scalar path");
    }

    #[test]
    fn pbkdf2_sha256_x4_long_password() {
        // > 64 bytes: HMAC hashes the key first (SHA256(pwd) as the key)
        let long: &[u8] = &[b'a'; 100];
        let mut out = [[0u8; 32]; 4];
        pbkdf2_sha256_x4(&[long, b"x", b"y", b"z"], b"saltsalt16--", 7, &mut out);
        let mut scalar = [0u8; 32];
        pbkdf2_sha256(long, b"saltsalt16--", 7, &mut scalar);
        assert_eq!(out[0], scalar);
    }

    #[test]
    fn pbkdf2_sha256_x4_matches_scalar_property() {
        // correctness red line: 1000 randomized groups must agree with the
        // scalar RFC path bit-for-bit (deterministic LCG so failures replay)
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..250 {
            let mut pwds = [&[0u8][..]; 4];
            let mut pw_bufs = Vec::new();
            for _ in 0..4 {
                let len = (rnd() % 96) as usize; // covers both < 64 and >= 64
                let pw: Vec<u8> = (0..len).map(|_| (rnd() & 0xFF) as u8).collect();
                pw_bufs.push(pw);
            }
            for (i, pw) in pw_bufs.iter().enumerate() {
                pwds[i] = pw.as_slice();
            }
            let salt_len = 8 + (rnd() % 9) as usize; // RAR5 uses 16; 8..16
            let salt: Vec<u8> = (0..salt_len).map(|_| (rnd() & 0xFF) as u8).collect();
            let iters = 1 + (rnd() % 40) as u32;
            let mut out = [[0u8; 32]; 4];
            pbkdf2_sha256_x4(&pwds, &salt, iters, &mut out);
            for (i, pw) in pwds.iter().enumerate() {
                let mut scalar = [0u8; 32];
                pbkdf2_sha256(pw, &salt, iters, &mut scalar);
                assert_eq!(out[i], scalar, "lane {} diverged (iters={}, salt={:?})", i, iters, salt);
            }
        }
    }

    #[test]
    fn crc32_known() {
        assert_eq!(Crc32::compute(b"123456789"), 0xCBF4_3926);
    }

    // ---- 7z (7zAES) KDF ----------------------------------------------------
    // Every expected key below was produced by an INDEPENDENT implementation
    // (python hashlib, D:\Files\Tmp\7zverify\walk.py::calc_key) whose archives
    // 7z.exe 26.03 accepted, and none of them comes from 7z.exe's exit code --
    // research showed `7z t` still prints "Everything is Ok" for a WRONG
    // password on some archives, so it is not a gold standard.

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()).collect()
    }

    fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn sevenzip_kdf_matches_independent_vectors() {
        // (password, salt, ncp, expected key)
        let cases: [(&str, &str, u8, &str); 9] = [
            ("openwall", "", 19, "8744b794f1aa149cb618513b278a78f226696ff25fa8409f50454d554399c32a"),
            (
                "openwall",
                "1122334455667788",
                19,
                "b1cead396d7c04a1161e528f86350d14ad0ad11b2e665230ed2e4c227657e407",
            ),
            (
                "Tr0ub4dor",
                "0102030405060708090a0b0c0d0e0f10",
                19,
                "0e2c36e10b170cc1e579289dd0b21b6addc11033f559afd51663694a478bd01d",
            ),
            // ncp=0 pins "rounds = 1 << ncp", not max(1, ...) and not 2^0+1
            ("openwall", "", 0, "6b8864b369267208fca89b38e5b374febc8ee60ff998b1348045c153c1e6671b"),
            (
                "openwall",
                "1122334455667788",
                0,
                "0a5f68cd5823513e704e38a2370690aa59b099f0628e88d12e049be7ca49c3c8",
            ),
            // ncp=0x3F: key = (salt || password_utf16le || zeros)[:32], no hashing
            (
                "openwall",
                "a1a2a3a4a5a6a7a8",
                0x3F,
                "a1a2a3a4a5a6a7a86f00700065006e00770061006c006c000000000000000000",
            ),
            (
                "Tr0ub4dor",
                "0102030405060708090a0b0c0d0e0f10",
                0x3F,
                "0102030405060708090a0b0c0d0e0f1054007200300075006200340064006f00",
            ),
            // UTF-16LE is not UTF-8: 'ä' and CJK become 2 code units each
            (
                "päss中文",
                "00112233445566778899aabbccddeeff",
                10,
                "c813b17f99fcc90a4571e010b67c70ca1e2b9434945364888a2ac554a7e25c2f",
            ),
            // 48-char password at ncp=0x3F: 7-Zip TRUNCATES at 32 bytes and
            // drops the rest (py7zr keeps the tail instead -- see the spec's
            // correction to py7zr, this vector pins the 7-Zip rule)
            (
                "long-password-that-exceeds-thirty-two-bytes",
                "aabbccdd",
                0x3F,
                "aabbccdd6c006f006e0067002d00700061007300730077006f00720064002d00",
            ),
        ];
        for (pw, salt, ncp, want) in cases {
            let key = sevenzip_derive_key(pw, &from_hex(salt), ncp);
            assert_eq!(to_hex(&key), want, "pw={:?} salt={} ncp={}", pw, salt, ncp);
        }
    }

    #[test]
    fn sevenzip_kdf_counter_is_the_last_eight_little_endian_bytes() {
        // the iterated block is salt || pw_utf16le || LE64(round); spelling the
        // two rounds of ncp=1 out by hand pins both the position (last) and the
        // endianness of the counter
        let salt = from_hex("1122334455667788");
        let mut block: Vec<u8> = salt.clone();
        block.extend("openwall".encode_utf16().flat_map(u16::to_le_bytes));
        let mut h = Sha256::new();
        h.update(&block);
        h.update(0u64.to_le_bytes());
        h.update(&block);
        h.update(1u64.to_le_bytes());
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(sevenzip_derive_key("openwall", &salt, 1), want);
        // and ncp=2 must add exactly the round-2 and round-3 blocks
        let mut h = Sha256::new();
        for round in 0u64..4 {
            h.update(&block);
            h.update(round.to_le_bytes());
        }
        let want2: [u8; 32] = h.finalize().into();
        assert_eq!(sevenzip_derive_key("openwall", &salt, 2), want2);
    }

    #[test]
    fn sevenzip_kdf_ncp_ceiling_is_exposed() {
        // the caller must be able to bound 1<<ncp before it hangs the engine
        assert_eq!(SEVENZIP_MAX_NCP, 24);
    }

    #[test]
    fn aes256_cbc_nist_vector() {
        // NIST SP 800-38A F.2.5 (AES-256-CBC), the same vector the python
        // research code was validated against
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
        ];
        let iv: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut ct: Vec<u8> = from_hex(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d\
             39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
        );
        aes256_cbc_decrypt(&key, &iv, &mut ct).unwrap();
        assert_eq!(
            to_hex(&ct),
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
        );
        // a non-block-multiple length is an error, not a silent truncation
        let mut odd = [0u8; 17];
        assert!(aes256_cbc_decrypt(&key, &iv, &mut odd).is_none());
    }
}

#[cfg(test)]
mod sha256_x4_tests {
    use super::sha256_x4::*;

    #[test]
    fn compress_chain_matches_known_digest() {
        // pins the raw SHA-NI compression against SHA256("abc") before the
        // PBKDF2 layer; skipped where SHA-NI is absent (E cores)
        if !shani_available() {
            return;
        }
        let mut block = [0u8; 64];
        block[..3].copy_from_slice(b"abc");
        block[3] = 0x80;
        block[56..64].copy_from_slice(&24u64.to_be_bytes());
        let mut state = SHA256_IV;
        unsafe { compress_chain(&mut state, &block) };
        let expect: [u32; 8] = [
            0xba78_16bf, 0x8f01_cfea, 0x4141_40de, 0x5dae_2223, 0xb003_61a3, 0x9617_7a9c, 0xb410_ff61, 0xf200_15ad,
        ];
        assert_eq!(state, expect, "compress_chain diverges from SHA256(abc)");
    }
}
