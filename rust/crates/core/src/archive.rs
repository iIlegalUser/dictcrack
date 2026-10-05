// archive.rs -- archive format detection and parsing of the pieces needed for
// native password verification: RAR5 crypt records (salt, iteration count,
// folded PswCheck) and the best encrypted ZIP entry descriptor (ZipCrypto /
// WinZip-AES, ZIP64 aware). Port of ArchiveInfo.cs.
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    Rar5,
    RarLegacy,
    Zip,
    SevenZip,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Rar5CryptInfo {
    pub salt: [u8; 16],
    pub lg2_count: u8,
    pub psw_check: Option<[u8; 8]>,
    pub header_encrypted: bool,
    pub entry_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ZipTargetInfo {
    pub aes: bool,
    pub aes_strength: u8, // 1/2/3 -> 128/192/256
    pub enc_header: Vec<u8>, // ZipCrypto: 12 enc-header bytes; AES: salt+PV
    pub check_byte: u8,   // ZipCrypto 1-byte check
    pub mac: Vec<u8>,     // AES: stored 10-byte HMAC-SHA1
    pub data_start: u64,
    pub comp_data_size: u64, // encrypted data length (excl. salt/PV/MAC for AES)
    pub method: u16,      // 0 stored, 8 deflate
    pub crc32: u32,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct ArchiveInfo {
    pub kind: ArchiveKind,
    pub rar5: Option<Rar5CryptInfo>,
    pub zip: Option<ZipTargetInfo>,
    pub detect_note: String,
}

impl ArchiveInfo {
    pub fn native_supported(&self) -> bool {
        match self.kind {
            ArchiveKind::Rar5 => {
                matches!(&self.rar5, Some(r) if r.psw_check.is_some() && r.lg2_count <= 24)
            }
            ArchiveKind::Zip => self.zip.is_some(),
            _ => false,
        }
    }
}

fn read_head(path: &Path, count: usize) -> Vec<u8> {
    let mut buf = vec![0u8; count];
    match File::open(path) {
        Ok(mut f) => {
            let n = f.read(&mut buf).unwrap_or(0);
            buf.truncate(n);
            buf
        }
        Err(_) => Vec::new(),
    }
}

fn read_vint(buf: &[u8], pos: &mut usize) -> Result<u64, ()> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= buf.len() {
            return Err(());
        }
        let b = buf[*pos];
        *pos += 1;
        value |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift > 63 {
            return Err(());
        }
    }
}

/// hashcat -m 13000 format for RAR5:
/// $rar5$<saltlen>$<salt hex>$<lg2cnt>$<pswcheck hex>$<pswchecklen>
pub fn hashcat_rar5(ci: &Rar5CryptInfo) -> String {
    let check = ci.psw_check.unwrap_or([0u8; 8]);
    let mut s = String::from("$rar5$16$");
    for b in &ci.salt {
        s.push_str(&format!("{:02x}", b));
    }
    s.push('$');
    s.push_str(&ci.lg2_count.to_string());
    s.push('$');
    for b in &check {
        s.push_str(&format!("{:02x}", b));
    }
    s.push_str("$8");
    s
}

/// FHEXTRA_CRYPT body: version(vint) flags(vint) lg2(1) salt(16)
/// iv(16) [check(8) csum(4) when flags bit0]. The HEAD_CRYPT variant has the
/// same fields minus the IV. Port of ParseRar5CryptBody.
fn parse_rar5_crypt_body(
    body: &[u8],
    pos: usize,
    has_iv: bool,
    header_enc: bool,
    entry_name: Option<String>,
) -> Option<Rar5CryptInfo> {
    let mut p = pos;
    let version = read_vint(body, &mut p).ok()?;
    if version != 0 {
        return None;
    }
    let flags = read_vint(body, &mut p).ok()?;
    if p >= body.len() {
        return None;
    }
    let lg2 = body[p];
    p += 1;
    if lg2 > 24 {
        return None;
    }
    if p + 16 > body.len() {
        return None;
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&body[p..p + 16]);
    p += 16;
    if has_iv {
        p += 16;
    }
    let mut check = None;
    if flags & 0x0001 != 0 {
        if p + 12 > body.len() {
            return None;
        }
        let mut c = [0u8; 8];
        c.copy_from_slice(&body[p..p + 8]);
        let csum = &body[p + 8..p + 12];
        // integrity of the stored check: sha256(check)[0..3]
        let dig = crate::crypto::sha256(&c);
        for i in 0..4 {
            if dig[i] != csum[i] {
                return None;
            }
        }
        check = Some(c);
    }
    Some(Rar5CryptInfo {
        salt,
        lg2_count: lg2,
        psw_check: check,
        header_encrypted: header_enc,
        entry_name,
    })
}
