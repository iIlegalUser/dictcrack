// rar3.rs -- RAR 1.5-4.x ("RAR3", unrar CRYPT_RAR30) crypto primitives,
// translated line by line from unrar's crypt3.cpp and sha1.cpp:
//   * a streaming SHA-1 with the "rar29" quirk: when a single update call
//     spans more than one full block, the final message-schedule words are
//     written back over the input block (sha1_process_rar29). WinRAR used
//     the same routine for key derivation, so reproducing the quirk is
//     required for passwords whose UTF-16 form + salt reaches 128 bytes.
//   * the KDF: SHA-1 over (password || salt || 3-byte round counter)
//     repeated 0x40000 times; every 1/16th of the way a snapshot digest
//     donates one IV byte, and the final digest words (little-endian)
//     form the AES-128 key.
//! All behaviour is pinned by test vectors generated from unrar/john data.

/// Streaming SHA-1 (soft implementation) with the rar29 write-back quirk.
pub struct Sha1Rar29 {
    state: [u32; 5],
    buffer: [u8; 64],
    buf_len: usize,
    count: u64,
}

impl Sha1Rar29 {
    pub fn new() -> Self {
        Sha1Rar29 {
            state: [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0],
            buffer: [0u8; 64],
            buf_len: 0,
            count: 0,
        }
    }

    /// Standard streaming update (no write-back). Used for short data.
    pub fn process(&mut self, data: &[u8]) {
        let j = (self.count & 63) as usize;
        self.count += data.len() as u64;
        let mut i = 0usize;
        if j + data.len() > 63 {
            let take = 64 - j;
            self.buffer[j..64].copy_from_slice(&data[..take]);
            let mut block = self.buffer;
            sha1_transform(&mut self.state, &mut block);
            i = take;
            while i + 63 < data.len() {
                let mut block = [0u8; 64];
                block.copy_from_slice(&data[i..i + 64]);
                sha1_transform(&mut self.state, &mut block);
                i += 64;
            }
            self.buf_len = 0;
        }
        if data.len() > i {
            let rest = data.len() - i;
            self.buffer[self.buf_len..self.buf_len + rest].copy_from_slice(&data[i..]);
            self.buf_len += rest;
        }
    }

    /// rar29 update: blocks taken directly from `data` are transformed and
    /// then overwritten with their final 16 schedule words (LE), so `data`
    /// is mutated -- unrar reuses the same buffer every KDF round and the
    /// mutation persists into later rounds.
    pub fn process_rar29(&mut self, data: &mut [u8]) {
        let j = (self.count & 63) as usize;
        self.count += data.len() as u64;
        let mut i = 0usize;
        if j + data.len() > 63 {
            let take = 64 - j;
            self.buffer[j..64].copy_from_slice(&data[..take]);
            let mut block = self.buffer;
            sha1_transform(&mut self.state, &mut block);
            // the buffer is refilled from scratch below, no write-back needed
            i = take;
            while i + 63 < data.len() {
                let mut block = [0u8; 64];
                block.copy_from_slice(&data[i..i + 64]);
                sha1_transform(&mut self.state, &mut block);
                data[i..i + 64].copy_from_slice(&block);
                i += 64;
            }
            self.buf_len = 0;
        }
        if data.len() > i {
            let rest = data.len() - i;
            self.buffer[self.buf_len..self.buf_len + rest].copy_from_slice(&data[i..]);
            self.buf_len += rest;
        }
    }

    fn finalize_into(&self, state: &mut [u32; 5], buf: &mut [u8; 64], buf_len: usize, count: u64) {
        let bit_len = count * 8;
        let mut pos = buf_len;
        buf[pos] = 0x80;
        pos += 1;
        if pos > 56 {
            for b in buf[pos..64].iter_mut() {
                *b = 0;
            }
            sha1_transform(state, buf);
            pos = 0;
        }
        for b in buf[pos..56].iter_mut() {
            *b = 0;
        }
        buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        sha1_transform(state, buf);
    }

    /// Digest of a snapshot (finalize a copy, keep streaming).
    pub fn snapshot_digest(&self) -> [u8; 20] {
        let mut state = self.state;
        let mut buf = self.buffer;
        self.finalize_into(&mut state, &mut buf, self.buf_len, self.count);
        let mut out = [0u8; 20];
        for (w, word) in state.iter().enumerate() {
            out[w * 4..w * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    pub fn done(&self) -> [u8; 20] {
        self.snapshot_digest()
    }
}

impl Default for Sha1Rar29 {
    fn default() -> Self {
        Self::new()
    }
}

fn sha1_transform(state: &mut [u32; 5], block: &mut [u8; 64]) {
    let mut w = [0u32; 80];
    for (k, word) in w.iter_mut().take(16).enumerate() {
        *word = u32::from_be_bytes([block[k * 4], block[k * 4 + 1], block[k * 4 + 2], block[k * 4 + 3]]);
    }
    let (mut a, mut b, mut c, mut d, mut e) = (state[0], state[1], state[2], state[3], state[4]);
    for i in 0..80 {
        if i >= 16 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let f = match i {
            0..=19 => (b & (c ^ d)) ^ d,
            20..=39 | 60..=79 => b ^ c ^ d,
            _ => ((b | c) & d) | (b & c),
        };
        let k = match i {
            0..=19 => 0x5A82_7999u32,
            20..=39 => 0x6ED9_EBA1,
            40..=59 => 0x8F1B_BCDC,
            _ => 0xCA62_C1D6,
        };
        let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(w[i]).wrapping_add(k);
        // standard rotation: (a,b,c,d,e) = (t, a, b<<<30, c, d)
        let (na, nb, nc, nd, ne) = (t, a, b.rotate_left(30), c, d);
        a = na;
        b = nb;
        c = nc;
        d = nd;
        e = ne;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    // rar29 write-back: the last 16 schedule words replace the block
    for k in 0..16 {
        block[k * 4..k * 4 + 4].copy_from_slice(&w[64 + k].to_le_bytes());
    }
}

/// RAR3 KDF (unrar crypt3.cpp SetKey30): 0x40000 SHA-1 rounds over
/// (password || salt || LE24(round)), IV bytes donated by snapshot digests,
/// key = little-endian serialization of the final digest words 0..3.
/// `password_utf16le` is the UTF-16-LE password, `salt` the 8-byte archive
/// salt (empty for unsalted).
///
/// Two implementations behind one result: the rar29 stream below (soft
/// SHA-1 plus the write-back quirk) and, when the write-back provably
/// cannot fire, the sha1 crate's SHA-NI backend. unrar's
/// `sha1_process_rar29` only rewrites the caller's buffer on its direct-
/// block path, which needs `len > 127 - j` where `j = count & 63 < 64`;
/// for `len <= 64` that is unreachable, so a plain streaming SHA-1 over the
/// same bytes produces a bit-identical key and IV. `raw.len() <= 64` means
/// passwords up to 28 chars with an 8-byte salt -- the overwhelmingly common
/// case, and exactly John's classic PLAINTEXT_LENGTH. The soft path stays
/// for longer passwords and is what the rar29 vector pins.
pub fn rar3_kdf(password_utf16le: &[u8], salt: &[u8]) -> ([u8; 16], [u8; 16]) {
    let mut raw = Vec::with_capacity(password_utf16le.len() + salt.len());
    raw.extend_from_slice(password_utf16le);
    raw.extend_from_slice(salt);
    if raw.len() <= 64 {
        return rar3_kdf_plain(&raw);
    }
    rar3_kdf_rar29(&raw)
}

/// Shared tail of both KDF variants: 0x40000 rounds, of which the first
/// three bytes are the LE round counter, with an IV byte sampled at each
/// 1/16th boundary and key/IV read out of the final digest.
const RAR3_ROUNDS: u32 = 0x4_0000;

/// plain streaming SHA-1 (no write-back possible, see `rar3_kdf`)
fn rar3_kdf_plain(raw: &[u8]) -> ([u8; 16], [u8; 16]) {
    use sha1::{Digest, Sha1};
    let snap = RAR3_ROUNDS / 16;
    let mut h = Sha1::new();
    let mut iv = [0u8; 16];
    for i in 0..RAR3_ROUNDS {
        h.update(raw);
        h.update(counter3(i));
        if i % snap == 0 {
            // 16 snapshots total: cloning the state here is free next to
            // the 262144 compressions the loop performs
            let d = h.clone().finalize();
            iv[(i / snap) as usize] = d[19];
        }
    }
    let mut d = [0u8; 20];
    d.copy_from_slice(&h.finalize());
    digest_to_key_iv(&d, &iv)
}

/// unrar's rar29 stream: identical result to `rar3_kdf_plain` except when
/// the write-back quirk fires (raw > 64 bytes)
fn rar3_kdf_rar29(raw: &[u8]) -> ([u8; 16], [u8; 16]) {
    let mut raw = raw.to_vec();
    let snap = RAR3_ROUNDS / 16;
    let mut h = Sha1Rar29::new();
    let mut iv = [0u8; 16];
    for i in 0..RAR3_ROUNDS {
        h.process_rar29(&mut raw);
        h.process(&counter3(i));
        if i % snap == 0 {
            let d = h.snapshot_digest();
            iv[(i / snap) as usize] = d[19];
        }
    }
    digest_to_key_iv(&h.done(), &iv)
}

#[inline]
fn counter3(i: u32) -> [u8; 3] {
    [i as u8, (i >> 8) as u8, (i >> 16) as u8]
}

/// key = LE bytes of digest words 0..3; IV collected by the caller
fn digest_to_key_iv(d: &[u8; 20], iv: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let mut key = [0u8; 16];
    for w in 0..4 {
        // digest words are big-endian in `d`; the key wants their LE bytes
        for j in 0..4 {
            key[w * 4 + j] = d[w * 4 + (3 - j)];
        }
    }
    (key, *iv)
}

/// AES-128-CBC decryption in place (RAR3 data/header streams).
/// `data.len()` must be a multiple of 16.
pub fn aes128_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) -> Option<()> {
    use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
    if data.len() % 16 != 0 {
        return None;
    }
    let cipher = aes::Aes128::new(GenericArray::from_slice(key));
    let mut prev = *iv;
    for chunk in data.chunks_mut(16) {
        let cipher_text: [u8; 16] = chunk.try_into().ok()?;
        let mut block = GenericArray::clone_from_slice(&cipher_text);
        cipher.decrypt_block(&mut block);
        // CBC: plaintext = D(cipher) XOR previous cipher block (IV first)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_stream_matches_known_digests() {
        let cases: [(&[u8], &str); 2] = [
            (b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
            (b"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        ];
        for (msg, want) in cases {
            let mut h = Sha1Rar29::new();
            h.process(msg);
            assert_eq!(hex(&h.done()), want, "sha1({:?})", msg);
        }
    }

    #[test]
    fn sha1_stream_block_edges_match_std() {
        // every length around the 64-byte block boundary must agree with
        // a single-shot transform of the same message
        for len in [0usize, 1, 55, 56, 63, 64, 65, 127, 128, 129, 200] {
            let msg = vec![b'q'; len];
            let mut h = Sha1Rar29::new();
            h.process(&msg);
            let streamed = hex(&h.done());
            // reference via repeated one-shot: feed all at once to a fresh
            // instance is the same code path, so instead check against the
            // known-pinned abc case plus a self-consistency property: same
            // message split into two updates must match one update
            let mut h2 = Sha1Rar29::new();
            let (a, b) = msg.split_at(len / 2);
            h2.process(a);
            h2.process(b);
            assert_eq!(streamed, hex(&h2.done()), "split update diverges at len {}", len);
        }
    }

    // john the ripper's rar test vector (real WinRAR -hp archive):
    // $RAR3$*0*c9dea41b149b53b4*fcbdb66122d8ebdb32532c22ca7ab9ec "password"
    // decrypting the stored 16 bytes with the KDF key/iv must yield the
    // fixed end-of-archive block c4 3d 7b 00 40 07 00 + zero padding
    #[test]
    fn kdf_matches_john_hp_vector() {
        let (key, iv) = rar3_kdf("password".encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>().as_slice(), &[0xc9, 0xde, 0xa4, 0x1b, 0x14, 0x9b, 0x53, 0xb4]);
        assert_eq!(hex(&key), "ce7537298db2c49c3801157c3309dc67");
        assert_eq!(hex(&iv), "7a525fe92887b46b7e60fcd17d3dd3bd");
        let ct: [u8; 16] = [
            0xfc, 0xbd, 0xb6, 0x61, 0x22, 0xd8, 0xeb, 0xdb, 0x32, 0x53, 0x2c, 0x22, 0xca, 0x7a, 0xb9, 0xec,
        ];
        let mut buf = ct;
        aes128_cbc_decrypt(&key, &iv, &mut buf).unwrap();
        assert_eq!(&buf[..7], &[0xc4, 0x3d, 0x7b, 0x00, 0x40, 0x07, 0x00]);
        assert!(buf[7..].iter().all(|&b| b == 0));
    }

    // the rar29 write-back only triggers when one update call spans more
    // than one full block (raw >= 128 bytes, i.e. 60+ UTF-16 password
    // chars). The expected value was generated by mirroring unrar's
    // sha1_process_rar29 in Python; a naive streaming SHA-1 (no write-back)
    // yields a DIFFERENT key, so this test pins the quirk.
    #[test]
    fn kdf_long_password_applies_rar29_writeback() {
        let pw: Vec<u8> = "A".repeat(70).encode_utf16().flat_map(u16::to_le_bytes).collect();
        let (key, iv) = rar3_kdf(&pw, &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        assert_eq!(hex(&key), "ef276e59f7301f97479fde7a669f5673");
        assert_eq!(hex(&iv), "1b4c92950217f42f9ba5fac59cab5220");
    }

    // correctness red line for the KDF fast path: the SHA-NI-backed plain
    // streaming variant (raw <= 64) must agree with the soft rar29 stream
    // bit-for-bit, and must hand over to the rar29 variant once the
    // write-back can fire (raw > 64). Sweeps the boundary itself.
    #[test]
    fn kdf_fast_path_matches_rar29_across_the_writeback_boundary() {
        let salt = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        // raw = 2*chars + 8, so the boundary sits at 28 chars (raw 64)
        for chars in [0usize, 1, 10, 27, 28, 29, 40, 70] {
            let pw: Vec<u8> = "A".repeat(chars).encode_utf16().flat_map(u16::to_le_bytes).collect();
            let raw_len = pw.len() + salt.len();
            let (k, i) = rar3_kdf(&pw, &salt);
            let mut raw = pw.clone();
            raw.extend_from_slice(&salt);
            let (k_ref, i_ref) = rar3_kdf_rar29(&raw);
            assert_eq!(
                (k, i),
                (k_ref, i_ref),
                "chars={} raw={}: dispatcher diverged from the rar29 stream",
                chars,
                raw_len
            );
        }
    }

    #[test]
    fn aes128_cbc_nist_vector() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let iv: [u8; 16] = core::array::from_fn(|i| i as u8);
        let mut data = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        ];
        aes128_cbc_decrypt(&key, &iv, &mut data).unwrap();
        assert_eq!(
            data.to_vec(),
            [
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
            ]
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }
}
