// verifier.rs -- password verification for RAR5 (native PBKDF2 header check)
// and ZIP (native ZipCrypto / WinZip-AES). The 7z.exe fallback lives in
// tool.rs (M4). Port of Verifier.cs.
use crate::archive::{Rar4CryptInfo, Rar5CryptInfo, SevenZipCryptInfo, ZipTargetInfo};
use crate::crypto::{pbkdf2_sha1, pbkdf2_sha256, pbkdf2_sha256_x4, Crc32};
use crate::rar3;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, OnceLock, RwLock};

pub trait Verifier {
    fn verify(&self, password: &str) -> bool;
    /// Check a group of candidates in one call (multi-buffer friendly).
    /// Returns the index of the accepted password, if any. The default
    /// walks `verify` one by one; verifiers with a batched kernel override
    /// this. Per-candidate semantics (counting, cancel, hit) are kept by
    /// the caller; only the verification work is batched.
    fn verify_batch(&self, passwords: &[&str]) -> Option<usize> {
        passwords.iter().position(|p| self.verify(p))
    }
    fn native(&self) -> bool {
        false
    }
    fn describe(&self) -> String {
        "external tool".to_string()
    }
}

// ------------------------------------------------------------------
// RAR5: PswCheck = fold8(PBKDF2-HMAC-SHA256(UTF8(pwd), salt, 2^lg+32))
// (the +32 matches unrar's chain continuation for the check value)
pub struct Rar5Verifier {
    salt: [u8; 16],
    check: [u8; 8],
    iters: u32,
}

impl Rar5Verifier {
    pub fn new(ci: &Rar5CryptInfo) -> Self {
        Rar5Verifier {
            salt: ci.salt,
            check: ci.psw_check.unwrap_or([0u8; 8]),
            iters: (1u32 << ci.lg2_count) + 32,
        }
    }
}

impl Verifier for Rar5Verifier {
    fn native(&self) -> bool {
        true
    }
    fn describe(&self) -> String {
        format!("RAR5 native header check (PBKDF2-SHA256, {} iterations)", self.iters)
    }
    fn verify(&self, password: &str) -> bool {
        let pwd = password.as_bytes();
        let mut key = [0u8; 32];
        pbkdf2_sha256(pwd, &self.salt, self.iters, &mut key);
        fold8_check(key) == self.check
    }
    fn verify_batch(&self, passwords: &[&str]) -> Option<usize> {
        // the 4-way kernel only pays off with a full group: a short tail
        // group would compute 4 lanes for < 4 passwords, so the scalar
        // path is cheaper there
        if passwords.len() != 4 {
            return passwords.iter().position(|p| self.verify(p));
        }
        let pwds = [
            passwords[0].as_bytes(),
            passwords[1].as_bytes(),
            passwords[2].as_bytes(),
            passwords[3].as_bytes(),
        ];
        let mut keys = [[0u8; 32]; 4];
        pbkdf2_sha256_x4(&pwds, &self.salt, self.iters, &mut keys);
        keys.iter().position(|key| fold8_check(*key) == self.check)
    }
}

/// PswCheck = XOR-fold of the 32 PBKDF2 bytes into 8 bytes (unrar).
fn fold8_check(key: [u8; 32]) -> [u8; 8] {
    let mut check = [0u8; 8];
    for (i, b) in key.iter().enumerate() {
        check[i % 8] ^= b;
    }
    check
}

// ------------------------------------------------------------------
// RAR 1.5-4.x ("RAR3"). The KDF is 0x40000 SHA-1 rounds (rar3.rs), so one
// candidate costs ~10-16 ms; the check itself is one AES block (-hp) or a
// CRC over the decrypted stream (-p stored). Both flavours are exact, so a
// reported hit is real and needs no external confirm step.
/// The ENDARC block header, encrypted, is the -hp known plaintext (unrar
/// crypt3.cpp / john's "end-of-archive block decrypt trick"). Decrypting the
/// first CBC block of that stream must start with these bytes; the 8th is
/// the block's HeadType and is pinned too (hashcat does the same).
const RAR4_HP_PLAIN: [u8; 8] = [0xc4, 0x3d, 0x7b, 0x00, 0x40, 0x07, 0x00, 0x00];

/// upper bound on the ciphertext we will buffer per candidate; a stored file
/// in a crack target is normally small, and the header is attacker-supplied
pub const RAR4_MAX_DATA: u64 = 16 << 20;

pub struct Rar4Verifier {
    info: Rar4CryptInfo,
    archive_path: String,
}

impl Rar4Verifier {
    pub fn new(info: Rar4CryptInfo, archive_path: &str) -> Self {
        Rar4Verifier { info, archive_path: archive_path.to_string() }
    }

    /// UTF-16-LE password bytes, the form unrar feeds into the KDF
    /// (`WideToRaw`). unrar truncates at MAXPASSWORD_RAR-1 = 127 UTF-16
    /// units for compatibility with existing archives.
    fn pw_bytes(password: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(password.len() * 2);
        for c in password.chars().take(126) {
            let mut b = [0u16; 1];
            for u in c.encode_utf16(&mut b) {
                out.extend_from_slice(&u.to_le_bytes());
            }
        }
        out
    }

    /// whole encrypted pack area, or None when it is too large / unreadable
    fn read_data(&self) -> Option<Vec<u8>> {
        if self.info.pack_size == 0 || self.info.pack_size > RAR4_MAX_DATA {
            return None;
        }
        let mut fs = File::open(&self.archive_path).ok()?;
        fs.seek(SeekFrom::Start(self.info.data_offset)).ok()?;
        let mut buf = vec![0u8; self.info.pack_size as usize];
        let mut total = 0;
        while total < buf.len() {
            match fs.read(&mut buf[total..]) {
                Ok(0) | Err(_) => return None,
                Ok(n) => total += n,
            }
        }
        Some(buf)
    }

    /// -hp: decrypt the ENDARC first block, compare the fixed constant
    fn verify_hp(&self, password: &str) -> bool {
        let Some(check) = self.info.check_block else { return false };
        let (key, iv) = rar3::rar3_kdf(&Self::pw_bytes(password), &self.info.salt);
        let mut blk = check;
        if rar3::aes128_cbc_decrypt(&key, &iv, &mut blk).is_none() {
            return false;
        }
        blk[..8] == RAR4_HP_PLAIN
    }

    /// -p stored (method 0x30): CRC32 over the first UnpSize decrypted bytes
    /// must equal the header's FileCRC. A cheap tail-padding pre-filter
    /// rejects most wrong candidates with a single AES block.
    fn verify_stored(&self, password: &str) -> bool {
        let (key, iv) = rar3::rar3_kdf(&Self::pw_bytes(password), &self.info.salt);
        let Some(mut data) = self.read_data() else { return false };
        let unp = self.info.unp_size as usize;
        // padding filter (only when padding exists): the tail of the last
        // plaintext block is zeros for a correctly decrypted stored file
        if unp % 16 != 0 && data.len() >= 32 {
            let n = data.len();
            let last_iv: [u8; 16] = match data[n - 32..n - 16].try_into() {
                Ok(v) => v,
                Err(_) => return false,
            };
            let mut blk: [u8; 16] = match data[n - 16..].try_into() {
                Ok(v) => v,
                Err(_) => return false,
            };
            if rar3::aes128_cbc_decrypt(&key, &last_iv, &mut blk).is_none() {
                return false;
            }
            if blk[unp % 16..].iter().any(|&b| b != 0) {
                return false;
            }
        }
        if rar3::aes128_cbc_decrypt(&key, &iv, &mut data).is_none() {
            return false;
        }
        if unp > data.len() {
            return false;
        }
        Crc32::compute(&data[..unp]) == self.info.file_crc
    }
}

impl Verifier for Rar4Verifier {
    fn native(&self) -> bool {
        true
    }
    fn describe(&self) -> String {
        if self.info.header_encrypted {
            "RAR 1.5-4.x native header check (SHA-1 KDF + AES-128 ENDARC block)".to_string()
        } else if self.info.method == 0x30 {
            format!(
                "RAR 1.5-4.x native stored-file check (SHA-1 KDF + AES-128-CBC + CRC32, \"{}\")",
                self.info.entry_name.as_deref().unwrap_or("?")
            )
        } else {
            "RAR 1.5-4.x external tool test".to_string()
        }
    }
    fn verify(&self, password: &str) -> bool {
        if self.info.header_encrypted {
            self.verify_hp(password)
        } else if self.info.method == 0x30 {
            self.verify_stored(password)
        } else {
            // compressed -p: exact verification needs a full RAR LZ/PPMd
            // decompressor, which this engine does not have; create_native
            // never hands this case a Rar4Verifier
            false
        }
    }
}

// ------------------------------------------------------------------
// in-memory cache of the encrypted entry bytes: the confirm path runs on
// every false-positive PV hit, and at high thread counts reopening the file
// each time dominated I/O. Guarded by a size cap. Port of the ZipVerifier
// static cache.
const MAX_CACHE_BYTES: u64 = 64 << 20;

static ENTRY_CACHE: OnceLock<RwLock<Option<(String, Arc<Vec<u8>>)>>> = OnceLock::new();

fn cache_cell() -> &'static RwLock<Option<(String, Arc<Vec<u8>>)>> {
    ENTRY_CACHE.get_or_init(|| RwLock::new(None))
}

pub struct ZipVerifier {
    t: ZipTargetInfo,
    archive_path: String,
}

impl ZipVerifier {
    pub fn new(t: ZipTargetInfo, archive_path: &str) -> Self {
        // reset the cache for the new archive
        *cache_cell().write().unwrap() = None;
        ZipVerifier { t, archive_path: archive_path.to_string() }
    }

    fn get_entry_data(&self) -> Option<Arc<Vec<u8>>> {
        if self.t.comp_data_size > MAX_CACHE_BYTES {
            return None;
        }
        {
            let g = cache_cell().read().unwrap();
            if let Some((p, d)) = &*g {
                if p == &self.archive_path {
                    return Some(d.clone());
                }
            }
        }
        let mut g = cache_cell().write().unwrap();
        if let Some((p, d)) = &*g {
            if p == &self.archive_path {
                return Some(d.clone());
            }
        }
        let mut fs = File::open(&self.archive_path).ok()?;
        fs.seek(SeekFrom::Start(self.t.data_start)).ok()?;
        let mut buf = vec![0u8; self.t.comp_data_size as usize];
        let mut total = 0;
        while total < buf.len() {
            match fs.read(&mut buf[total..]) {
                Ok(0) | Err(_) => return None,
                Ok(n) => total += n,
            }
        }
        let arc = Arc::new(buf);
        *g = Some((self.archive_path.clone(), arc.clone()));
        Some(arc)
    }

    // WinZip AES: PBKDF2-HMAC-SHA1 1000 iterations over salt, deriving
    // 2*keyLen+2 bytes; the last 2 bytes are the PV. A PV match is confirmed
    // with the 10-byte HMAC-SHA1 over the WHOLE encrypted data.
    fn verify_aes(&self, password: &str) -> bool {
        let key_len = match self.t.aes_strength {
            1 => 16,
            2 => 24,
            _ => 32,
        };
        let pwd = password.as_bytes();
        let salt = &self.t.enc_header[..self.t.enc_header.len() - 2];
        let stored_pv = &self.t.enc_header[self.t.enc_header.len() - 2..];
        let mut derived = vec![0u8; 2 * key_len + 2];
        pbkdf2_sha1(pwd, salt, 1000, &mut derived);
        if derived[2 * key_len] != stored_pv[0] || derived[2 * key_len + 1] != stored_pv[1] {
            return false;
        }
        let mac_key = &derived[key_len..2 * key_len];
        let mut hmac = <Hmac<Sha1> as Mac>::new_from_slice(mac_key).expect("hmac key");
        if let Some(data) = self.get_entry_data() {
            hmac.update(&data);
        } else {
            let mut fs = match File::open(&self.archive_path) {
                Ok(f) => f,
                Err(_) => return false,
            };
            if fs.seek(SeekFrom::Start(self.t.data_start)).is_err() {
                return false;
            }
            let mut buf = vec![0u8; 1 << 16];
            let mut left = self.t.comp_data_size;
            while left > 0 {
                let want = buf.len().min(left as usize);
                match fs.read(&mut buf[..want]) {
                    Ok(0) | Err(_) => return false,
                    Ok(n) => {
                        hmac.update(&buf[..n]);
                        left -= n as u64;
                    }
                }
            }
        }
        let mac = hmac.finalize().into_bytes();
        mac[..10] == self.t.mac[..10]
    }

    // legacy ZipCrypto: 1-byte check (1/256 false positives) followed by a
    // full decrypt+inflate+CRC confirm, so reported hits are real.
    fn verify_zipcrypto(&self, password: &str) -> bool {
        let mut st = ZcState::new(password);
        let mut last = 0u8;
        for i in 0..12 {
            last = st.decrypt_byte(self.t.enc_header[i]);
        }
        if last != self.t.check_byte {
            return false;
        }
        self.confirm_full(&mut st)
    }

    fn confirm_full(&self, st: &mut ZcState) -> bool {
        let crc: u32;
        if let Some(data) = self.get_entry_data() {
            let mut plain = vec![0u8; data.len()];
            for i in 0..data.len() {
                plain[i] = st.decrypt_byte(data[i]);
            }
            crc = if self.t.method == 8 {
                match inflate_crc(&plain) {
                    Some(c) => c,
                    None => return false,
                }
            } else {
                Crc32::compute(&plain)
            };
            return crc == self.t.crc32;
        }
        // entry too large / unreadable for the cache: stream it
        let mut fs = match File::open(&self.archive_path) {
            Ok(f) => f,
            Err(_) => return false,
        };
        if fs.seek(SeekFrom::Start(self.t.data_start)).is_err() {
            return false;
        }
        let mut enc = vec![0u8; self.t.comp_data_size as usize];
        let mut total = 0;
        while total < enc.len() {
            match fs.read(&mut enc[total..]) {
                Ok(0) | Err(_) => return false,
                Ok(n) => total += n,
            }
        }
        let mut plain = vec![0u8; enc.len()];
        for i in 0..enc.len() {
            plain[i] = st.decrypt_byte(enc[i]);
        }
        crc = if self.t.method == 8 {
            match inflate_crc(&plain) {
                Some(c) => c,
                None => return false,
            }
        } else {
            Crc32::compute(&plain)
        };
        crc == self.t.crc32
    }
}

fn inflate_crc(deflated: &[u8]) -> Option<u32> {
    use flate2::read::DeflateDecoder;
    let mut d = DeflateDecoder::new(deflated);
    let mut buf = [0u8; 1 << 16];
    let mut crc = 0u32;
    loop {
        match d.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => crc = Crc32::update(crc, &buf[..n]),
            Err(_) => return None,
        }
    }
    Some(crc)
}

impl Verifier for ZipVerifier {
    fn native(&self) -> bool {
        true
    }
    fn describe(&self) -> String {
        if self.t.aes {
            format!(
                "ZIP native WinZip-AES{} check (PBKDF2-SHA1, target \"{}\")",
                self.t.aes_strength as u32 * 64 + 64,
                self.t.name
            )
        } else {
            format!("ZIP native ZipCrypto check + full CRC confirm (target \"{}\")", self.t.name)
        }
    }
    fn verify(&self, password: &str) -> bool {
        if self.t.aes {
            self.verify_aes(password)
        } else {
            self.verify_zipcrypto(password)
        }
    }
}

// ------------------------------------------------------------------
// 7z (7zAES). One candidate costs the 7z KDF (2^ncp SHA-256 rounds) plus one
// AES-256-CBC decryption of a single packed stream -- no decompressor, which is
// why this is native at all. `create_native` only ever hands over archives the
// parser proved decidable; see `SevenZipVerifier::verify` for the two shapes.
pub struct SevenZipVerifier {
    info: SevenZipCryptInfo,
    archive_path: String,
}

impl SevenZipVerifier {
    pub fn new(info: SevenZipCryptInfo, archive_path: &str) -> Self {
        SevenZipVerifier { info, archive_path: archive_path.to_string() }
    }

    /// Decrypt just the last block and report whether the PAD tail is zero.
    /// One AES block instead of the whole stream, so a wrong candidate normally
    /// stops here. Only meaningful when `pad_len() > 0`; the caller must not
    /// treat "nothing to check" as a pass.
    ///
    /// CBC needs the PREVIOUS cipher block as the IV, but a single-block stream
    /// has none inside the data -- there the archive's own IV is the right one
    /// (`7z a -m0=copy` on a <16-byte file produces exactly that: 16 packed
    /// bytes, PAD=2). Bailing out on `len < 32` would reject every password.
    fn padding_ok(&self, key: &[u8; 32], data: &[u8]) -> bool {
        let pad = self.info.pad_len() as usize;
        if pad == 0 || data.len() < 16 || data.len() % 16 != 0 {
            return false;
        }
        let n = data.len();
        let last_iv: [u8; 16] = if n >= 32 {
            match data[n - 32..n - 16].try_into() {
                Ok(v) => v,
                Err(_) => return false,
            }
        } else {
            self.info.iv
        };
        let mut blk: [u8; 16] = match data[n - 16..].try_into() {
            Ok(v) => v,
            Err(_) => return false,
        };
        if crate::crypto::aes256_cbc_decrypt(key, &last_iv, &mut blk).is_none() {
            return false;
        }
        // the padding is at the TAIL: plaintext[pack_size - pad ..]
        blk[16 - pad..].iter().all(|&b| b == 0)
    }

    /// The decisive check. Decrypts the whole packed stream and compares the
    /// CRC32 that the container stores for exactly those bytes.
    fn verify_crc(&self, password: &str, data: &[u8]) -> bool {
        let key = crate::crypto::sevenzip_derive_key(password, &self.info.salt, self.info.ncp);
        // cheap rejection before paying for the full decryption
        if self.info.padding_verifiable() && !self.padding_ok(&key, data) {
            return false;
        }
        let mut plain = data.to_vec();
        if crate::crypto::aes256_cbc_decrypt(&key, &self.info.iv, &mut plain).is_none() {
            return false;
        }
        let len = self.info.crc_len as usize;
        if len > plain.len() {
            // the CRC length must agree with what we can decrypt, or the check
            // would be vacuous; the parser rejects such archives, so reaching
            // this means the file changed under us
            return false;
        }
        Crc32::compute(&plain[..len]) == self.info.crc
    }

    /// No digest anywhere in the container: the only invariant is 7-Zip's
    /// AES-CBC zero padding at the tail. Weak (false accept 2^-8*PAD) but real;
    /// the parser refuses the PAD==0 case, where it would be vacuous.
    fn verify_padding_only(&self, password: &str, data: &[u8]) -> bool {
        let key = crate::crypto::sevenzip_derive_key(password, &self.info.salt, self.info.ncp);
        self.padding_ok(&key, data)
    }

    fn read_packed(&self) -> Option<Vec<u8>> {
        // the parser already refused anything above the cap; this is the second
        // line of defence for a hand-built info
        if self.info.pack_size == 0 || self.info.pack_size > crate::archive::SEVENZIP_MAX_PACK {
            return None;
        }
        let mut fs = File::open(&self.archive_path).ok()?;
        fs.seek(SeekFrom::Start(self.info.data_offset)).ok()?;
        let mut buf = vec![0u8; self.info.pack_size as usize];
        let mut total = 0;
        while total < buf.len() {
            match fs.read(&mut buf[total..]) {
                Ok(0) | Err(_) => return None,
                Ok(n) => total += n,
            }
        }
        Some(buf)
    }
}

/// upper bound on the packed stream we buffer per candidate. A 7z "crack
/// target" is normally small, but the size comes from the archive header, so it
/// is attacker-controlled; the parser enforces this at parse time so the
/// fallback happens before any cracking starts.
pub const SEVENZIP_MAX_PACK: u64 = crate::archive::SEVENZIP_MAX_PACK;

impl Verifier for SevenZipVerifier {
    fn native(&self) -> bool {
        true
    }
    fn describe(&self) -> String {
        if self.info.crc_kind.is_aes_out() {
            let rounds = if self.info.ncp == 0x3F {
                "no".to_string()
            } else {
                format!("{} KDF rounds", 1u64 << self.info.ncp)
            };
            format!(
                "7z native {} check (AES-256-CBC + CRC32, {})",
                if self.info.header_encrypted { "encrypted-header" } else { "content" },
                rounds
            )
        } else {
            format!(
                "7z native encrypted-header padding check ({} zero bytes at the tail)",
                self.info.pad_len()
            )
        }
    }
    fn verify(&self, password: &str) -> bool {
        let Some(data) = self.read_packed() else { return false };
        if self.info.crc_kind.is_aes_out() {
            self.verify_crc(password, &data)
        } else {
            self.verify_padding_only(password, &data)
        }
    }
}

// ------------------------------------------------------------------
pub struct ZcState {
    k0: u32,
    k1: u32,
    k2: u32,
}

impl ZcState {
    pub fn new(password: &str) -> Self {
        let mut s = ZcState { k0: 0x1234_5678, k1: 0x2345_6789, k2: 0x3456_7890 };
        for &b in password.as_bytes() {
            s.update(b);
        }
        s
    }

    fn update(&mut self, c: u8) {
        self.k0 = Crc32::raw_step(self.k0, c);
        self.k1 = self.k1.wrapping_add(self.k0 & 0xFF);
        self.k1 = self.k1.wrapping_mul(134_775_813).wrapping_add(1);
        self.k2 = Crc32::raw_step(self.k2, (self.k1 >> 24) as u8);
    }

    pub fn decrypt_byte(&mut self, c: u8) -> u8 {
        let p = c ^ self.dec_byte();
        self.update(p);
        p
    }

    fn dec_byte(&self) -> u8 {
        let temp = (self.k2 | 2) & 0xFFFF;
        ((temp.wrapping_mul(temp ^ 1) >> 8) & 0xFF) as u8
    }
}

/// Build the right native verifier for an archive, if supported.
pub fn create_native(info: &crate::archive::ArchiveInfo, archive_path: &str) -> Option<Box<dyn Verifier + Send + Sync>> {
    use crate::archive::ArchiveKind;
    match info.kind {
        ArchiveKind::Rar5 => info.rar5.as_ref().map(|r| {
            Box::new(Rar5Verifier::new(r)) as Box<dyn Verifier + Send + Sync>
        }),
        ArchiveKind::RarLegacy => info.rar4.clone().and_then(|r| {
            // -hp and stored -p verify exactly; a compressed -p file would
            // need a full RAR LZ/PPMd decoder, so it keeps the external tool
            // (parse_rar4 already reports it, but guard here too in case a
            // future caller builds the info by hand)
            if r.header_encrypted || r.method == 0x30 {
                Some(Box::new(Rar4Verifier::new(r, archive_path)) as Box<dyn Verifier + Send + Sync>)
            } else {
                None
            }
        }),
        ArchiveKind::Zip => info.zip.clone().map(|z| {
            Box::new(ZipVerifier::new(z, archive_path)) as Box<dyn Verifier + Send + Sync>
        }),
        ArchiveKind::SevenZip => info.seven_zip.clone().map(|s| {
            Box::new(SevenZipVerifier::new(s, archive_path)) as Box<dyn Verifier + Send + Sync>
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rar5_pswcheck_fold() {
        // construct a synthetic Rar5CryptInfo and check the fold logic runs
        let ci = Rar5CryptInfo {
            salt: [1u8; 16],
            lg2_count: 4,
            psw_check: Some([0u8; 8]),
            header_encrypted: false,
            entry_name: None,
        };
        let v = Rar5Verifier::new(&ci);
        assert_eq!(v.iters, (1u32 << 4) + 32);
        assert!(v.native());
    }

    #[test]
    fn rar5_verify_batch_matches_single() {
        // the stored PswCheck is derived from a known password; the batch
        // path must accept/reject exactly like the scalar verify, hit the
        // earliest index in the group, and keep working for short tail
        // groups (dict end / resume rewind) via the scalar fallback
        let salt = [7u8; 16];
        let mut key = [0u8; 32];
        pbkdf2_sha256(b"right", &salt, (1 << 2) + 32, &mut key);
        let mut check = [0u8; 8];
        for (i, b) in key.iter().enumerate() {
            check[i % 8] ^= b;
        }
        let ci = Rar5CryptInfo { salt, lg2_count: 2, psw_check: Some(check), header_encrypted: false, entry_name: None };
        let v = Rar5Verifier::new(&ci);

        assert!(!v.verify("wrong"), "scalar reject");
        assert!(v.verify("right"), "scalar accept");
        assert_eq!(v.verify_batch(&["a", "b", "c", "d"]), None, "batch reject");
        assert_eq!(v.verify_batch(&["a", "b", "right", "d"]), Some(2), "batch hit at index");
        assert_eq!(v.verify_batch(&["right", "b", "c", "d"]), Some(0), "earliest index wins");
        assert_eq!(v.verify_batch(&["a", "right"]), Some(1), "short group fallback hit");
        assert_eq!(v.verify_batch(&["a", "b", "c"]), None, "short group fallback miss");
        assert_eq!(v.verify_batch(&["right"]), Some(0), "single-candidate group");
    }

    // ---- RAR4 native path, driven from real archive bytes ------------------
    // Both fixtures are byte-for-byte the archives that 7z.exe / UnRAR.exe
    // accept with these passwords (UnRAR is the reference decryptor), so
    // these tests pin the native check against an external gold standard
    // instead of against our own implementation.

    /// minimal -hp archive: [marker][MAIN|MHD_PASSWORD][salt8][enc ENDARC]
    const RAR4_HP: &str = concat!(
        "526172211a0700ce997380000d000000000000002b91d04c6e88f71551ec4427d1525719",
        "3c8498c3f5d9a217d44725a3c16fe7b6b845e34bef23412d6fce3bbc05248fad73506e52",
        "badf2f2769f960be8d8c16903627623886af1a90c348e1358c92c40c88f5282b428f492c",
        "77e2b0a41d9c5f38626d22a5386ea6908ae7e906a91e543a"
    );
    /// minimal -p stored archive: gold.txt, 29 bytes, method 0x30
    const RAR4_P: &str = concat!(
        "526172211a0700cf907300000d000000000000005ae17404843000200000001d00000003",
        "17dabb7e000000501d30080020000000676f6c642e74787411c3a54f8e2b90d1211b0f19",
        "0c49038d823063bf4407acdd11a4a4548ae77eb1e43543531f4e3861c43d7b00400700"
    );

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    fn write_tmp(name: &str, data: &[u8]) -> std::path::PathBuf {
        use std::io::Write;
        let d = std::env::temp_dir().join(format!("dcver-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        let p = d.join(name);
        std::fs::File::create(&p).unwrap().write_all(data).unwrap();
        p
    }

    #[test]
    fn rar4_hp_matches_unrar_ground_truth() {
        // UnRAR 7.12 t -pHpGold55 -> exit 0; -pWRONGpw -> exit 3.
        // The check is one AES block against a fixed constant, so it is
        // exact: no false positives are possible from the 8-byte compare.
        let p = write_tmp("hp.rar", &from_hex(RAR4_HP));
        let info = crate::archive::parse(&p.display().to_string());
        assert!(info.native_supported(), "-hp is native");
        let v = create_native(&info, &p.display().to_string()).expect("native verifier");
        assert!(v.native());
        assert!(v.verify("HpGold55"), "correct password accepted");
        assert!(!v.verify("wrongpw"), "wrong password rejected");
        assert!(!v.verify(""), "empty password rejected");
        // one bit off must not collide
        assert!(!v.verify("HpGold5"), "prefix of the password rejected");
        assert!(!v.verify("HpGold55 "), "trailing space rejected");
    }

    #[test]
    fn rar4_p_stored_matches_unrar_ground_truth() {
        // 7z.exe t -pRar4Gold9 -> "Everything is Ok" (exit 0);
        // -ptestpw -> "CRC Failed ... Wrong password?" (exit 2).
        // Exact 32-bit CRC over the decrypted plaintext, so no false
        // positives reach the caller.
        let p = write_tmp("p.rar", &from_hex(RAR4_P));
        let info = crate::archive::parse(&p.display().to_string());
        assert!(info.native_supported(), "stored -p is native");
        let r = info.rar4.clone().expect("rar4 info");
        assert!(!r.header_encrypted, "flavour is -p");
        assert_eq!(r.method, 0x30, "stored");
        assert_eq!(r.unp_size, 29);
        assert_eq!(r.file_crc, 0x7ebb_da17, "FileCRC from the header");
        let v = create_native(&info, &p.display().to_string()).expect("native verifier");
        assert!(v.verify("Rar4Gold9"), "correct password accepted");
        assert!(!v.verify("wrongpw"), "wrong password rejected");
        assert!(!v.verify("testpw"), "the CRC-failing password from 7z.exe");
        assert!(!v.verify("Rar4Gold"), "prefix rejected");
    }

    #[test]
    fn rar4_padding_filter_does_not_reject_the_right_password() {
        // UnpSize 29 -> pad_start 13, pad 3: the tail-zero pre-filter runs
        // on the LAST block, so a correct password must survive it. This
        // guards the classic bug of testing the first block instead.
        let p = write_tmp("p2.rar", &from_hex(RAR4_P));
        let info = crate::archive::parse(&p.display().to_string());
        let r = info.rar4.clone().unwrap();
        assert_eq!(r.unp_size % 16, 13, "fixture must exercise the filter");
        assert_eq!(r.pack_size, 32, "two AES blocks");
        let v = Rar4Verifier::new(r, &p.display().to_string());
        assert!(v.verify("Rar4Gold9"), "padding filter must not eat the hit");
    }

    #[test]
    fn rar4_compressed_p_is_not_native() {        // a compressed -p file parses (so `info` explains it) but must not
        // get a native verifier: the CRC lives on the decompressed bytes and
        // this engine has no RAR LZ/PPMd decoder, so the external tool stays
        // the verifier rather than reporting an unverifiable "hit"
        let mut data = from_hex(RAR4_P);
        data[20 + 25] = 0x33; // method -> normal compression
        // re-fix the header CRC so the parse gets past the integrity check
        let crc = Crc32::compute(&data[22..20 + 48]) & 0xFFFF;
        data[20] = crc as u8;
        data[21] = (crc >> 8) as u8;
        let p = write_tmp("pc.rar", &data);
        let info = crate::archive::parse(&p.display().to_string());
        let r = info.rar4.clone().expect("still parses");
        assert_eq!(r.method, 0x33, "compressed method recorded");
        assert!(!info.native_supported(), "compressed -p is not native");
        assert!(create_native(&info, &p.display().to_string()).is_none(), "no native verifier");
        assert!(
            info.detect_note.contains("external tool"),
            "note points at the external tool, got {:?}",
            info.detect_note
        );
    }

    // ---- 7z native path, driven from real archive bytes --------------------
    // The fixtures are the exact archives 7-Zip 26.03 produced during the
    // format research, with password "openwall". They are pinned as literals so
    // `cargo test` never spawns 7z.exe -- which is also the point: research
    // showed `7z t` reports "Everything is Ok" even for a WRONG password on
    // some archives, so its verdict is not evidence. The expected CRCs come
    // from an independent python AES implementation and from the container
    // itself; the expected KDF keys from python hashlib.

    /// `7z a -mhe=on`: AES-only encoded header, folder CRC over the 106
    /// decrypted bytes, PAD=6.
    const SZ_MHE_LZMA2: &str = concat!(
        "377abcaf271c0004942906ccb0000000000000002e00000000000000ff687e1bf5e2b6e2d5dceb8d945782b2243012ba",
        "c3003b5c5535dc7b3332829a9f383b0b7ac0efe2136cb4e9df2aa0f00140c825ba30d567d29b34580a5c4ef45877dd7a",
        "ceefa33f86493fb1cf6297acb3a13bde5a447b3c0ce02a3f61f9e3d019fdc715bd9b67a9b19ca9e7a1ef8ab00586198f",
        "84be6326aab49b15a155bf4c953ce878b62f2861c83e3982b22af084ca4c076302f1c6fdf9e725b603a129316e342042",
        "29483c49288945d39d390134516a035517064001097000070b0100012406f1070112530f9ed86bd0a59e603bb03dad75",
        "d5258c930c6a0a01a87bd2950000"
    );

    /// `7z a -p` (content encryption): raw header, AES + COPY, PAD=2, substream
    /// CRC over the 46 plaintext bytes.
    const SZ_PLAIN_COPY: &str = concat!(
        "377abcaf271c0004c1a3b98730000000000000006a000000000000006cc2bfef78fb8699c48eafdfa2cc9687575c6a1e",
        "b0f99908cc41f8abe39de5f86baf9fb097259413221ce6602962943caabd5dfa0104060001093000070b0100022406f1",
        "070112530f471dc51a8fe99148ef9a5f0698275964010001000c2e2e00080a01b7782f69000005011903000000111500",
        "680065006c006c006f002e007400780074000000140a0100c6fe79b85255dd0115060100200000000000"
    );

    /// `7z a -p -m0=copy` on a 14-byte file: the packed stream is exactly ONE
    /// AES block (16) holding 14 plaintext bytes, so PAD=2 but there is no
    /// "previous cipher block" inside the data. A padding pre-filter that
    /// requires 32 bytes of ciphertext (to take the second-to-last block as the
    /// IV) must fall back to the IV from the coder properties instead of
    /// rejecting -- otherwise every password, including the right one, is
    /// refused. Regression: this archive cracked as "not found" before.
    const SZ_TINY_COPY: &str = concat!(
        "377abcaf271c00047cc4abbf10000000000000006a00000000000000cfb9e038e0a2922669c05e03328025f5b248bd66",
        "0104060001091000070b0100022406f1070112530f1b3ffeaa46ea7620e41c0579bafdd046010001000c0e0e00080a01",
        "7e1d04a6000005011903000000111300740069006e0079002e0074007800740000001900140a010071aaf8775a55dd01",
        "15060100200000000000"
    );

    /// The single-cipher-block case above: PAD > 0 but only one block, so the
    /// IV has to come from the properties.
    #[test]
    fn sevenzip_single_cipher_block_with_padding_verifies() {
        let (p, info) = sz_verify_fixture("sz_tiny.7z", SZ_TINY_COPY);
        assert!(info.native_supported(), "single-block AES+COPY content is native");
        let s = info.seven_zip.clone().expect("7z info");
        assert_eq!(s.pack_size, 16, "exactly one AES block");
        assert_eq!(s.aes_out_size, 14, "14 plaintext bytes");
        assert_eq!(s.pad_len(), 2, "PAD>0 even at one block");
        assert!(s.padding_verifiable(), "there IS a padding tail to check");
        let v = create_native(&info, &p.display().to_string()).expect("native verifier");
        assert!(v.verify("openwall"), "single-block archive must accept the right password");
        assert!(!v.verify("wrong"), "single-block archive must reject a wrong password");
        assert!(!v.verify(""), "empty rejected");
    }

    /// content encryption whose packed stream is exactly one AES block: PAD==0,    /// so only the CRC can decide. This is the fixture that would pass a naive
    /// "skip the padding check when PAD==0" implementation.
    const SZ_NOSALT: &str = concat!(
        "377abcaf271c0004b943811110000000000000005400000000000000ffb6562c8dfb4b51bb86c25b4f56e8b51d66d931",
        "010406000109100a01031d5e9e00070b0100012406f1070112530faabbccddeeff001122334455667788990c100a017b",
        "229d6d0000050111190063006f006e00740065006e0074002e00620069006e0000000000"
    );

    /// AES + LZMA2 content: the CRC is over the decompressed bytes, so no
    /// native verifier may be built.
    const SZ_PLAIN_LZMA2: &str = concat!(
        "377abcaf271c00049460db8640000000000000006a0000000000000051c3a94b34dba74b33fec983f4e31455ecb3c6d6",
        "a275584055cc0ab0a4b5bf3ec74dcd8ed8c4c80b135dae9de34aa82e082a914d8ed854819180003b77a9331298838227",
        "0104060001094000070b0100022406f1070112530f4f6ed037324f030f9480483cfa19b35e2121010001000c322e0008",
        "0a01b7782f6900000501190100111500680065006c006c006f002e007400780074000000140a0100c6fe79b85255dd01",
        "15060100200000000000"
    );

    fn sz_verify_fixture(name: &str, blob: &str) -> (std::path::PathBuf, crate::archive::ArchiveInfo) {
        let p = write_tmp(name, &from_hex(blob));
        let info = crate::archive::parse(&p.display().to_string());
        (p, info)
    }

    /// The decisive three-state test: the real password is accepted, a wrong
    /// one and an empty one are rejected, and a near-miss is not let through.
    #[test]
    fn sevenzip_mhe_accepts_right_password_only() {
        let (p, info) = sz_verify_fixture("sz_mhe.7z", SZ_MHE_LZMA2);
        assert!(info.native_supported(), "AES-only -mhe is native");
        let v = create_native(&info, &p.display().to_string()).expect("native verifier");
        assert!(v.native(), "verifier reports native");
        assert!(v.verify("openwall"), "correct password accepted");
        assert!(!v.verify("openwal"), "truncated password rejected");
        assert!(!v.verify("openwall1"), "extended password rejected");
        assert!(!v.verify("Openwall"), "case change rejected");
        assert!(!v.verify(""), "empty password rejected");
        assert!(!v.verify("wrong"), "wrong password rejected");
        // the KDF must actually be sensitive: a password differing in one byte
        // produces a different key, hence a different CRC
        assert!(!v.verify("openwalm"), "one-byte-off password rejected");
    }

    /// Content encryption, AES + COPY: same three states through the CRC path.
    #[test]
    fn sevenzip_content_copy_accepts_right_password_only() {
        let (p, info) = sz_verify_fixture("sz_copy.7z", SZ_PLAIN_COPY);
        assert!(info.native_supported(), "AES+COPY content is native");
        let v = create_native(&info, &p.display().to_string()).expect("native verifier");
        assert!(v.verify("openwall"), "correct password accepted");
        assert!(!v.verify("wrong"), "wrong password rejected");
        assert!(!v.verify(""), "empty password rejected");
    }

    /// PAD == 0 with a CRC available: the padding pre-filter is unavailable,
    /// and that must NOT make the verifier reject everything (the classic way
    /// to get this wrong is to compute the padding on an empty slice and bail).
    #[test]
    fn sevenzip_pad_zero_still_verifies_via_crc() {
        let (p, info) = sz_verify_fixture("sz_pad0.7z", SZ_NOSALT);
        assert!(info.native_supported(), "PAD==0 content archive is native");
        let s = info.seven_zip.clone().expect("7z info");
        assert_eq!(s.pad_len(), 0, "fixture must actually exercise PAD==0");
        let v = create_native(&info, &p.display().to_string()).expect("native verifier");
        assert!(v.verify("openwall"), "PAD==0 must not block a correct password");
        assert!(!v.verify("wrong"), "PAD==0 must still reject a wrong password");
    }

    /// An archive needing a decompressor gets no native verifier at all: the
    /// engine falls back to the external tool.
    #[test]
    fn sevenzip_lzma2_content_has_no_native_verifier() {
        let (p, info) = sz_verify_fixture("sz_lzma2.7z", SZ_PLAIN_LZMA2);
        assert!(!info.native_supported(), "AES+LZMA2 is not native");
        assert!(create_native(&info, &p.display().to_string()).is_none(), "no native verifier");
        assert!(info.detect_note.contains("external"), "note names the fallback");
    }

    /// The verifier must read the archive from disk, so a path that no longer
    /// resolves has to reject rather than panic or accept.
    #[test]
    fn sevenzip_missing_file_rejects_without_panicking() {
        let (p, info) = sz_verify_fixture("sz_gone.7z", SZ_MHE_LZMA2);
        let v = create_native(&info, &p.display().to_string()).expect("native verifier");
        std::fs::remove_file(&p).expect("remove fixture");
        assert!(!v.verify("openwall"), "unreadable archive must not report a hit");
    }

    /// `describe()` is what `info`/`bench` show the user; it must name the
    /// scheme and the kind of check, in the same style as the other verifiers.
    #[test]
    fn sevenzip_describe_is_informative() {
        let (p, info) = sz_verify_fixture("sz_desc.7z", SZ_MHE_LZMA2);
        let v = create_native(&info, &p.display().to_string()).expect("native verifier");
        let d = v.describe();
        assert!(d.contains("7z"), "names the format, got {:?}", d);
        assert!(d.contains("AES"), "names the cipher, got {:?}", d);
        assert!(d.contains("native"), "says it is native, got {:?}", d);
        let (p2, info2) = sz_verify_fixture("sz_desc2.7z", SZ_PLAIN_COPY);
        let d2 = create_native(&info2, &p2.display().to_string()).unwrap().describe();
        assert!(d2 != d, "header and content checks read differently: {:?}", d2);
    }

    /// batch verification: 7z keeps the trait's default (one AES pass per
    /// candidate), which must still find the right index.
    #[test]
    fn sevenzip_verify_batch_finds_the_hit() {
        let (p, info) = sz_verify_fixture("sz_batch.7z", SZ_MHE_LZMA2);
        let v = create_native(&info, &p.display().to_string()).expect("native verifier");
        assert_eq!(v.verify_batch(&["a", "b", "c"]), None, "batch miss");
        assert_eq!(v.verify_batch(&["a", "openwall", "c"]), Some(1), "batch hit index");
        assert_eq!(v.verify_batch(&["openwall", "b"]), Some(0), "earliest index");
    }

    /// Fail-closed guard for the padding-only path at PAD == 0. The parser
    /// never builds this combination (it falls back to the external tool), so
    /// this constructs the info by hand to pin the verifier's own behaviour: a
    /// zero-length tail check is VACUOUSLY true for every password, so a
    /// verifier that returned it would accept the wrong password as readily as
    /// the right one. Measured on the equivalent fixture `mhe_nocrc_pad0.7z`:
    /// with no digest AND PAD == 0, both passwords leave a zero-length tail.
    #[test]
    fn sevenzip_padding_only_at_pad_zero_rejects_everything() {
        let (p, info) = sz_verify_fixture("sz_vacuous.7z", SZ_MHE_LZMA2);
        let mut s = info.seven_zip.clone().expect("7z info");
        s.crc_kind = crate::archive::SevenZipCrcKind::None;
        s.aes_out_size = s.pack_size; // PAD == 0
        assert_eq!(s.pad_len(), 0);
        assert!(!s.padding_verifiable(), "nothing to check at PAD==0");
        let v = SevenZipVerifier::new(s, &p.display().to_string());
        assert!(!v.verify("openwall"), "the RIGHT password must not be reported at PAD==0");
        assert!(!v.verify("wrong"), "nor the wrong one: the check must fail closed");
    }

    /// The padding-only flavour (no digest anywhere, PAD > 0) end to end with a
    /// REAL password: the tail-zeros invariant must accept the correct password.
    /// Without this, a bug in the padding path would stay invisible whenever a
    /// digest happens to exist.
    #[test]
    fn sevenzip_padding_only_accepts_the_right_password() {
        let mut blob = from_hex(SZ_MHE_LZMA2);
        let nh = 32 + u64::from_le_bytes(blob[12..20].try_into().unwrap()) as usize;
        assert_eq!(blob[nh + 38], 0x0A, "kCRC record offset");
        blob.drain(nh + 38..nh + 44); // drop kCRC + allAreDefined + CRC
        blob[20..28].copy_from_slice(&40u64.to_le_bytes()); // header shrank by 6
        // re-sign both CRCs around the shortened header
        let crc = Crc32::compute(&blob[nh..nh + 40]);
        blob[28..32].copy_from_slice(&crc.to_le_bytes());
        let crc = Crc32::compute(&blob[12..32]);
        blob[8..12].copy_from_slice(&crc.to_le_bytes());
        let p = write_tmp("sz_nocrc.7z", &blob);
        let info = crate::archive::parse(&p.display().to_string());
        assert!(info.native_supported(), "padding-only header is native");
        let s = info.seven_zip.clone().expect("7z info");
        assert_eq!(s.crc_kind, crate::archive::SevenZipCrcKind::None);
        assert_eq!(s.pad_len(), 6, "PAD must still be 6");
        let v = create_native(&info, &p.display().to_string()).expect("native verifier");
        assert!(v.verify("openwall"), "padding-only path accepts the right password");
        assert!(!v.verify("wrong"), "padding-only path rejects a wrong password");
        assert!(v.describe().contains("padding"), "describe names the weak check: {}", v.describe());
    }
}
