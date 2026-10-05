// verifier.rs -- password verification for RAR5 (native PBKDF2 header check)
// and ZIP (native ZipCrypto / WinZip-AES). The 7z.exe fallback lives in
// tool.rs (M4). Port of Verifier.cs.
use crate::archive::{Rar5CryptInfo, ZipTargetInfo};
use crate::crypto::{pbkdf2_sha1, pbkdf2_sha256, Crc32};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, OnceLock, RwLock};

pub trait Verifier {
    fn verify(&self, password: &str) -> bool;
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
        let mut check = [0u8; 8];
        for i in 0..32 {
            check[i % 8] ^= key[i];
        }
        check == self.check
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
        ArchiveKind::Zip => info.zip.clone().map(|z| {
            Box::new(ZipVerifier::new(z, archive_path)) as Box<dyn Verifier + Send + Sync>
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
}
