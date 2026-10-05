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

/// PBKDF2-HMAC-SHA1 (WinZip-AES path), RFC 6070 vectors.
pub fn pbkdf2_sha1(pwd: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    pbkdf2_hmac::<Sha1>(pwd, salt, iterations, out);
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
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
            out[..16],
            [0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37]
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
    }

    #[test]
    fn crc32_known() {
        assert_eq!(Crc32::compute(b"123456789"), 0xCBF4_3926);
    }
}
