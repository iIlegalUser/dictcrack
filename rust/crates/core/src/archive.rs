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
    /// the file could not be opened at all (locked / no permission / a
    /// directory): a hard error, distinct from "parsed but nothing found".
    /// The C# build surfaces this by throwing out of ReadHead.
    pub open_error: Option<String>,
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

fn read_head(path: &Path, count: usize) -> std::io::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let mut buf = vec![0u8; count];
    let mut n = 0usize;
    while n < count {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(m) => n += m,
            Err(e) => return Err(e),
        }
    }
    buf.truncate(n);
    Ok(buf)
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

fn read_full<S: Read>(s: &mut S, buf: &mut [u8]) -> usize {
    let mut total = 0;
    while total < buf.len() {
        match s.read(&mut buf[total..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
    total
}

/// FILE header type-specific name reader (cosmetic, sanity-checked).
/// Port of TryReadFileName.
fn try_read_file_name(body: &[u8], pos: usize, extra_start: usize) -> Option<String> {
    let mut p = pos;
    let file_flags = read_vint(body, &mut p).ok()?;
    read_vint(body, &mut p).ok()?; // unpacked size
    read_vint(body, &mut p).ok()?; // attributes
    if file_flags & 0x0002 != 0 {
        p += 4; // mtime
    }
    if file_flags & 0x0004 != 0 {
        p += 4; // data CRC32
    }
    read_vint(body, &mut p).ok()?; // compression info
    read_vint(body, &mut p).ok()?; // host OS
    let name_len = read_vint(body, &mut p).ok()? as usize;
    if name_len > 0 && name_len < 1024 && p + name_len <= extra_start && p + name_len <= body.len() {
        let name = String::from_utf8_lossy(&body[p..p + name_len]).into_owned();
        let printable = !name.is_empty() && !name.chars().any(|c| (c as u32) < 0x20 || c == '\u{7F}');
        if printable {
            return Some(name);
        }
    }
    None
}

/// RAR5 header walk. Returns the first usable crypt record found. Port of ParseRar5.
fn parse_rar5(path: &Path) -> Option<Rar5CryptInfo> {
    let mut fs = File::open(path).ok()?;
    fs.seek(SeekFrom::Start(8)).ok()?;
    let file_len = fs.metadata().ok()?.len();
    let mut from_file_header: Option<Rar5CryptInfo> = None;
    loop {
        let header_start = fs.stream_position().ok()?;
        if header_start + 7 > file_len {
            return from_file_header;
        }
        let mut crc = [0u8; 4];
        if read_full(&mut fs, &mut crc) != 4 {
            return from_file_header;
        }
        // read header size vint from the stream
        let header_size = match read_vint_stream(&mut fs) {
            Some(v) => v,
            None => return from_file_header,
        };
        if header_size == 0 || header_size > 0x1000_0000 {
            return from_file_header;
        }
        let body_start = fs.stream_position().ok()?;
        let body_end = body_start + header_size;
        if body_end > file_len {
            return from_file_header;
        }
        let mut body = vec![0u8; header_size as usize];
        if read_full(&mut fs, &mut body) != body.len() {
            return from_file_header;
        }
        let mut pos = 0usize;
        let type_ = read_vint(&body, &mut pos).ok()?;
        let flags = read_vint(&body, &mut pos).ok()?;
        let extra_size = if flags & 0x0001 != 0 { read_vint(&body, &mut pos).ok()? } else { 0 };
        let data_size = if flags & 0x0002 != 0 { read_vint(&body, &mut pos).ok()? } else { 0 };

        if type_ == 5 {
            return from_file_header; // end of archive
        }
        if type_ == 4 {
            // archive encryption header (-hp): no IV, whole archive encrypted
            return parse_rar5_crypt_body(&body, pos, false, true, None);
        }
        if (type_ == 2 || type_ == 3) && extra_size > 0 && from_file_header.is_none() {
            let extra_start = body.len() - extra_size as usize;
            if extra_start >= pos {
                let mut epos = extra_start;
                let eend = body.len();
                while epos + 2 <= eend {
                    let rec_start = epos;
                    let rec_size = match read_vint(&body, &mut epos) {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    if rec_size == 0 || rec_start as u64 + rec_size > eend as u64 {
                        break;
                    }
                    let rec_end = rec_start + rec_size as usize;
                    let rec_type = match read_vint(&body, &mut epos) {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    if rec_type == 1 {
                        let name = try_read_file_name(&body, pos, extra_start);
                        if let Some(ci) = parse_rar5_crypt_body(&body, epos, true, false, name) {
                            from_file_header = Some(ci);
                            break;
                        }
                    }
                    epos = rec_end;
                }
            }
        }
        // jump to next header; data area (file payload) is skipped
        if fs.seek(SeekFrom::Start(body_end + data_size)).is_err() {
            return from_file_header;
        }
    }
}

fn read_vint_stream<S: Read>(s: &mut S) -> Option<u64> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    let mut b = [0u8; 1];
    loop {
        if s.read(&mut b).ok()? != 1 {
            return None;
        }
        value |= ((b[0] & 0x7F) as u64) << shift;
        if b[0] & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

// ---- ZIP ------------------------------------------------------------------

fn le_u16(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}
fn le_u32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}
fn le_i64(b: &[u8], i: usize) -> i64 {
    i64::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3], b[i + 4], b[i + 5], b[i + 6], b[i + 7]])
}

fn is_better(cand: &ZipTargetInfo, best: &Option<ZipTargetInfo>) -> bool {
    match best {
        None => true,
        Some(b) => {
            if cand.aes != b.aes {
                cand.aes
            } else {
                cand.comp_data_size < b.comp_data_size
            }
        }
    }
}

/// ZIP64 extra field 0x0001: 8-byte values in fixed order (original size,
/// compressed size, local header offset, disk start number); a value appears
/// only when its central-directory slot is 0xFFFFFFFF. Port of ParseZip64Extra.
fn parse_zip64_extra(extra: &[u8], uncomp: &mut i64, comp: &mut i64, local_off: &mut i64) {
    let mut i = 0usize;
    while i + 4 <= extra.len() {
        let id = le_u16(extra, i);
        let sz = le_u16(extra, i + 2) as usize;
        if id == 0x0001 {
            let mut p = i + 4;
            let end = i + 4 + sz;
            if *uncomp < 0 && p + 8 <= end {
                *uncomp = le_i64(extra, p);
                p += 8;
            }
            if *comp < 0 && p + 8 <= end {
                *comp = le_i64(extra, p);
                p += 8;
            }
            if *local_off < 0 && p + 8 <= end {
                *local_off = le_i64(extra, p);
            }
            return;
        }
        i += 4 + sz;
    }
}

/// Resolve the local header and build a ZipTargetInfo. Port of BuildZipTarget.
fn build_zip_target(
    path: &Path,
    local_offset: u64,
    flags: u16,
    method: u16,
    dostime: u16,
    crc: u32,
    comp_size: i64,
    name: String,
    central_extra: &[u8],
) -> Option<ZipTargetInfo> {
    let mut fs = File::open(path).ok()?;
    fs.seek(SeekFrom::Start(local_offset)).ok()?;
    let mut lh = [0u8; 30];
    if read_full(&mut fs, &mut lh) != 30 {
        return None;
    }
    if !(lh[0] == 0x50 && lh[1] == 0x4B && lh[2] == 0x03 && lh[3] == 0x04) {
        return None;
    }
    let local_name_len = le_u16(&lh, 26) as u64;
    let local_extra_len = le_u16(&lh, 28) as u64;
    let data_start = local_offset + 30 + local_name_len + local_extra_len;

    // AES extra field: look in the central extra first
    let mut aes = false;
    let mut strength = 0u8;
    let mut i = 0usize;
    while i + 4 <= central_extra.len() {
        let id = le_u16(central_extra, i);
        let sz = le_u16(central_extra, i + 2) as usize;
        if id == 0x9901 && sz >= 7 {
            let st = central_extra[i + 8];
            if (1..=3).contains(&st) {
                aes = true;
                strength = st;
            }
            break;
        }
        i += 4 + sz;
    }

    if aes {
        let salt_len = match strength {
            1 => 8usize,
            2 => 12,
            _ => 16,
        };
        if comp_size < (salt_len + 12) as i64 {
            return None;
        }
        let mut head = vec![0u8; salt_len + 2];
        fs.seek(SeekFrom::Start(data_start)).ok()?;
        if read_full(&mut fs, &mut head) != head.len() {
            return None;
        }
        let comp_data_size = (comp_size as u64) - salt_len as u64 - 12;
        let mut mac = vec![0u8; 10];
        fs.seek(SeekFrom::Start(data_start + salt_len as u64 + 2 + comp_data_size)).ok()?;
        if read_full(&mut fs, &mut mac) != 10 {
            return None;
        }
        Some(ZipTargetInfo {
            aes: true,
            aes_strength: strength,
            enc_header: head, // salt(8/12/16)+PV(2)
            check_byte: 0,
            mac,
            data_start: data_start + salt_len as u64 + 2,
            comp_data_size,
            method,
            crc32: crc,
            name,
        })
    } else {
        if method != 0 && method != 8 {
            return None;
        }
        let mut eh = [0u8; 12];
        fs.seek(SeekFrom::Start(data_start)).ok()?;
        if read_full(&mut fs, &mut eh) != 12 {
            return None;
        }
        // bit3 (data descriptor): CRC in the header is zero, check byte uses DOS time
        let check_byte = (if flags & 0x0008 != 0 {
            (dostime >> 8) as u32
        } else {
            crc >> 24
        } & 0xFF) as u8;
        Some(ZipTargetInfo {
            aes: false,
            aes_strength: 0,
            enc_header: eh.to_vec(),
            check_byte,
            mac: Vec::new(),
            data_start: data_start + 12,
            comp_data_size: comp_size as u64 - 12,
            method,
            crc32: crc,
            name,
        })
    }
}

/// Port of ParseZip: locate the best encrypted entry (ZIP64 aware).
fn parse_zip(path: &Path) -> Option<ZipTargetInfo> {
    let mut fs = File::open(path).ok()?;
    let flen = fs.metadata().ok()?.len();
    if flen < 22 {
        return None;
    }
    let mut tail = vec![0u8; 66000];
    let tail_start = flen.saturating_sub(tail.len() as u64);
    fs.seek(SeekFrom::Start(tail_start)).ok()?;
    let tail_len = fs.read(&mut tail).ok()?;
    let mut eocd = -1i64;
    let mut i = tail_len as i64 - 22;
    while i >= 0 {
        let u = i as usize;
        if tail[u] == 0x50 && tail[u + 1] == 0x4B && tail[u + 2] == 0x05 && tail[u + 3] == 0x06 {
            eocd = i;
            break;
        }
        i -= 1;
    }
    if eocd < 0 {
        return None;
    }
    let eocd = eocd as usize;
    let mut entry_count = le_u16(&tail, eocd + 10) as u32;
    let mut cd_size = le_u32(&tail, eocd + 12) as u64;
    let eocd_file_pos = tail_start + eocd as u64;
    let mut cd_offset = le_u32(&tail, eocd + 16) as u64;

    // ZIP64 locator 20 bytes before the EOCD
    let mut used_zip64_eocd = false;
    if eocd >= 20
        && tail[eocd - 20] == 0x50
        && tail[eocd - 19] == 0x4B
        && tail[eocd - 18] == 0x06
        && tail[eocd - 17] == 0x07
    {
        let z64_pos = le_i64(&tail, eocd - 20 + 8);
        if z64_pos >= 0 && z64_pos as u64 + 56 <= flen {
            let mut z64 = [0u8; 56];
            if fs.seek(SeekFrom::Start(z64_pos as u64)).is_ok()
                && read_full(&mut fs, &mut z64) == 56
                && z64[0] == 0x50
                && z64[1] == 0x4B
                && z64[2] == 0x06
                && z64[3] == 0x06
            {
                let entries64 = le_i64(&z64, 32);
                let cd_size64 = le_i64(&z64, 40);
                let cd_offset64 = le_i64(&z64, 48);
                if entry_count == 0xFFFF {
                    entry_count = entries64.min(u32::MAX as i64) as u32;
                }
                if cd_size == 0xFFFF_FFFF {
                    cd_size = cd_size64 as u64;
                }
                if cd_offset == 0xFFFF_FFFF {
                    cd_offset = cd_offset64 as u64;
                }
                used_zip64_eocd = cd_size64 > 0 || cd_offset64 > 0;
            }
        }
    }
    let mut base_offset = 0u64;
    if !used_zip64_eocd {
        let bo = eocd_file_pos as i64 - (cd_size as i64 + cd_offset as i64);
        base_offset = if bo < 0 { 0 } else { bo as u64 };
        cd_offset += base_offset;
    }

    let mut best: Option<ZipTargetInfo> = None;
    let mut pos = cd_offset;
    for _ in 0..entry_count {
        if pos + 46 > flen {
            break;
        }
        if fs.seek(SeekFrom::Start(pos)).is_err() {
            break;
        }
        let mut cde = [0u8; 46];
        if read_full(&mut fs, &mut cde) != 46 {
            break;
        }
        if !(cde[0] == 0x50 && cde[1] == 0x4B && cde[2] == 0x01 && cde[3] == 0x02) {
            break;
        }
        let flags = le_u16(&cde, 8);
        let method = le_u16(&cde, 10);
        let dostime = le_u16(&cde, 12);
        let crc = le_u32(&cde, 16);
        let uncomp_size = le_u32(&cde, 24);
        let comp_size = le_u32(&cde, 20);
        let name_len = le_u16(&cde, 28) as usize;
        let extra_len = le_u16(&cde, 30) as usize;
        let comment_len = le_u16(&cde, 32) as usize;
        let local_offset = le_u32(&cde, 42);
        let mut name_buf = vec![0u8; name_len];
        if read_full(&mut fs, &mut name_buf) != name_len {
            break;
        }
        let mut extra_buf = vec![0u8; extra_len];
        if extra_len > 0 && read_full(&mut fs, &mut extra_buf) != extra_len {
            break;
        }
        let name = String::from_utf8_lossy(&name_buf).into_owned();

        let mut comp_l: i64 = if comp_size == 0xFFFF_FFFF { -1 } else { comp_size as i64 };
        let mut local_off_l: i64 = if local_offset == 0xFFFF_FFFF { -1 } else { local_offset as i64 };
        if uncomp_size == 0xFFFF_FFFF || comp_l < 0 || local_off_l < 0 {
            let mut uncomp_l: i64 = if uncomp_size == 0xFFFF_FFFF { -1 } else { uncomp_size as i64 };
            parse_zip64_extra(&extra_buf, &mut uncomp_l, &mut comp_l, &mut local_off_l);
            if comp_l < 0 {
                comp_l = 0;
            }
            if local_off_l < 0 {
                local_off_l = local_offset as i64;
            }
        }

        if flags & 0x0001 != 0 && comp_l > 0 {
            if let Some(cand) = build_zip_target(
                path,
                base_offset + local_off_l as u64,
                flags,
                method,
                dostime,
                crc,
                comp_l,
                name,
                &extra_buf,
            ) {
                if is_better(&cand, &best) {
                    best = Some(cand);
                }
            }
        }
        pos += 46 + (name_len + extra_len + comment_len) as u64;
        if cd_size > 0 && pos > cd_offset + cd_size {
            break;
        }
    }
    best
}

/// Top-level sniff + parse. Port of ArchiveParser.Parse. Never throws for
/// damaged data: failures surface as a null rar5/zip plus a detect_note, and
/// the engine falls back to the external tool. A file that cannot be opened
/// at all is the one hard failure: it lands in open_error (the C# build
/// throws out of ReadHead and the CLI turns that into exit 2).
pub fn parse(path: &str) -> ArchiveInfo {
    let p = Path::new(path);
    let mut info = ArchiveInfo {
        kind: ArchiveKind::Unknown,
        rar5: None,
        zip: None,
        detect_note: String::new(),
        open_error: None,
    };
    // a locked/unreadable path must not become "unknown format" - that
    // would send crack off to burn the whole dictionary against a verifier
    // that can never succeed
    let head = match read_head(p, 8) {
        Ok(h) => h,
        Err(e) => {
            info.open_error = Some(e.to_string());
            return info;
        }
    };
    if head.len() >= 8
        && head[0] == 0x52 && head[1] == 0x61 && head[2] == 0x72 && head[3] == 0x21
        && head[4] == 0x1A && head[5] == 0x07 && head[6] == 0x01 && head[7] == 0x00
    {
        info.kind = ArchiveKind::Rar5;
        info.rar5 = parse_rar5(p);
        if info.rar5.is_none() {
            info.detect_note = "RAR5: no password check data found in headers".into();
        }
        return info;
    }
    if head.len() >= 7
        && head[0] == 0x52 && head[1] == 0x61 && head[2] == 0x72 && head[3] == 0x21
        && head[4] == 0x1A && head[5] == 0x07 && head[6] == 0x00
    {
        info.kind = ArchiveKind::RarLegacy;
        info.detect_note = "RAR 1.5-4.x format (native header check not supported)".into();
        return info;
    }
    if head.len() >= 6
        && head[0] == 0x37 && head[1] == 0x7A && head[2] == 0xBC && head[3] == 0xAF
        && head[4] == 0x27 && head[5] == 0x1C
    {
        info.kind = ArchiveKind::SevenZip;
        info.detect_note = "7z format (native check requires LZMA; using external tool)".into();
        return info;
    }
    if head.len() >= 4 && head[0] == 0x50 && head[1] == 0x4B {
        info.kind = ArchiveKind::Zip;
        info.zip = parse_zip(p);
        if info.zip.is_none() {
            info.detect_note = "ZIP: no encrypted entry found (or archive is empty/unreadable)".into();
        }
        return info;
    }
    info.detect_note = "unrecognized signature; will try external tool anyway".into();
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("dcarch-{}-{}", tag, std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        d
    }

    fn write_temp(tag: &str, name: &str, data: &[u8]) -> std::path::PathBuf {
        let p = temp_dir(tag).join(name);
        File::create(&p).unwrap().write_all(data).unwrap();
        p
    }

    // little-endian byte writer, the stand-in for C#'s BinaryWriter
    #[derive(Default)]
    struct W(Vec<u8>);
    impl W {
        fn u16(&mut self, x: u16) -> &mut Self {
            self.0.extend_from_slice(&x.to_le_bytes());
            self
        }
        fn u32(&mut self, x: u32) -> &mut Self {
            self.0.extend_from_slice(&x.to_le_bytes());
            self
        }
        fn i64(&mut self, x: i64) -> &mut Self {
            self.0.extend_from_slice(&x.to_le_bytes());
            self
        }
        fn b(&mut self, x: u8) -> &mut Self {
            self.0.push(x);
            self
        }
        fn bytes(&mut self, x: &[u8]) -> &mut Self {
            self.0.extend_from_slice(x);
            self
        }
    }

    // minimal encrypted-ZipCrypto ZIP with all classic fields at 0xFFFFFFFF
    // and the real values in ZIP64 records/extra fields (C# BuildZip64Fixture)
    fn build_zip64_fixture() -> Vec<u8> {
        let mut w = W::default();
        w.u32(0x0403_4b50).u16(20).u16(0x0001).u16(8).u16(0).u16(0x5A00);
        w.u32(0x1234_5678); // crc
        w.u32(0xFFFF_FFFF).u32(0xFFFF_FFFF); // comp/uncomp size (zip64)
        w.u16(1).u16(20); // name len, extra len (zip64: 4+16)
        w.b(b'a');
        w.u16(0x0001).u16(16).i64(262_144).i64(100);
        let data = vec![0x5Au8; 100]; // contents not verified by the parser
        w.bytes(&data);
        let cd_offset = w.0.len() as u64;
        w.u32(0x0201_4b50).u16(20).u16(20).u16(0x0001).u16(8).u16(0).u16(0x5A00);
        w.u32(0x1234_5678);
        w.u32(0xFFFF_FFFF).u32(0xFFFF_FFFF);
        w.u16(1).u16(28).u16(0).u16(0).u16(0).u32(0);
        w.u32(0xFFFF_FFFF); // local offset (zip64)
        w.b(b'a');
        w.u16(0x0001).u16(24).i64(262_144).i64(100).i64(0);
        let cd_size = w.0.len() as u64 - cd_offset;
        let z64_pos = w.0.len() as u64;
        w.u32(0x0606_4b50).i64(44).u16(45).u16(45).u32(0).u32(0);
        w.i64(1).i64(1).i64(cd_size as i64).i64(cd_offset as i64);
        w.u32(0x0706_4b50).u32(0).i64(z64_pos as i64).u32(1);
        w.u32(0x0605_4b50).u16(0xFFFF).u16(0xFFFF).u16(0xFFFF).u16(0xFFFF);
        w.u32(0xFFFF_FFFF).u32(0xFFFF_FFFF).u16(0);
        w.0
    }

    #[test]
    fn zip64_fixture_parses() {
        let p = write_temp("z64", "z64.zip", &build_zip64_fixture());
        let info = parse(&p.display().to_string());
        assert_eq!(info.kind, ArchiveKind::Zip, "detected as zip");
        let z = info.zip.expect("zip64 entry parsed");
        assert_eq!(z.name, "a", "zip64 name");
        assert!(!z.aes, "zip64 not aes");
        assert_eq!(z.comp_data_size, 88, "comp size 100-12 enc header");
        assert_eq!(z.data_start, 63, "30+1+20 local header + 12 enc header");
        assert_eq!(z.check_byte, 0x12, "crc>>24");
    }

    // ZIP64 with more than 65535 entries: the classic EOCD count field holds
    // 0xFFFF and the real count lives in the ZIP64 EOCD record. Regression:
    // a count truncated to u16 made a 65536-entry archive parse as 0 entries.
    fn build_zip64_many_entries(n: usize) -> Vec<u8> {
        let mut w = W::default();
        w.u32(0x0403_4b50).u16(20).u16(0x0001).u16(8).u16(0).u16(0x5A00);
        w.u32(0x1234_5678).u32(100).u32(100).u16(1).u16(0);
        w.b(b'e');
        w.bytes(&vec![0u8; 12 + 100]); // 12-byte enc header + payload
        let cd_offset = w.0.len() as u64;
        for i in 0..n {
            let last = i == n - 1;
            w.u32(0x0201_4b50).u16(20).u16(20).u16(if last { 0x0001 } else { 0 }).u16(8);
            w.u16(0).u16(0x5A00).u32(0x1234_5678).u32(100).u32(100);
            w.u16(1).u16(0).u16(0).u16(0).u16(0).u32(0);
            w.u32(0); // local offset (only 'last' is opened)
            w.b(if last { b'e' } else { b'x' });
        }
        let cd_size = w.0.len() as u64 - cd_offset;
        let z64_pos = w.0.len() as u64;
        w.u32(0x0606_4b50).i64(44).u16(45).u16(45).u32(0).u32(0);
        w.i64(n as i64).i64(n as i64).i64(cd_size as i64).i64(cd_offset as i64);
        w.u32(0x0706_4b50).u32(0).i64(z64_pos as i64).u32(1);
        w.u32(0x0605_4b50).u16(0xFFFF).u16(0xFFFF).u16(0xFFFF).u16(0xFFFF);
        w.u32(0xFFFF_FFFF).u32(0xFFFF_FFFF).u16(0);
        w.0
    }

    #[test]
    fn zip64_many_entries_65536() {
        let p = write_temp("many", "many.zip", &build_zip64_many_entries(65536));
        let info = parse(&p.display().to_string());
        assert_eq!(info.kind, ArchiveKind::Zip, "many-entry zip64 detected");
        let z = info.zip.expect("encrypted entry found despite 65536 entries");
        assert_eq!(z.name, "e", "many-entry target name");
        assert_eq!(z.comp_data_size, 88, "many-entry comp size");
    }

    #[test]
    fn hashcat_rar5_format() {
        let ci = Rar5CryptInfo {
            salt: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            lg2_count: 15,
            psw_check: Some([0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7]),
            header_encrypted: false,
            entry_name: None,
        };
        assert_eq!(
            hashcat_rar5(&ci),
            "$rar5$16$000102030405060708090a0b0c0d0e0f$15$a0a1a2a3a4a5a6a7$8"
        );
    }

    // a RAR5 file whose header chain is truncated mid-vint must parse
    // gracefully (no crypt record) instead of erroring
    #[test]
    fn rar5_truncated_header_tolerated() {
        let mut data = vec![0x52u8, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];
        data.extend_from_slice(&[0, 0, 0, 0, 0x80, 0x80, 0x80, 0x80, 0x80]); // CRC + unterminated vint
        let p = write_temp("trunc", "trunc.rar", &data);
        let info = parse(&p.display().to_string());
        assert_eq!(info.kind, ArchiveKind::Rar5, "detected as rar5");
        assert!(info.rar5.is_none(), "no crypt record, no error");
    }

    // a path that cannot be opened (a directory on Windows) is a hard
    // open_error, not "unknown format" - mirrors the C# build, where
    // ReadHead throws and the CLI reports exit 2
    #[test]
    fn unreadable_path_sets_open_error() {
        let d = temp_dir("lock");
        let info = parse(&d.display().to_string());
        assert!(info.open_error.is_some(), "directory open must surface as open_error");
        assert_eq!(info.kind, ArchiveKind::Unknown);
        assert!(info.rar5.is_none() && info.zip.is_none());
        let _ = std::fs::remove_dir_all(&d);
    }
}
