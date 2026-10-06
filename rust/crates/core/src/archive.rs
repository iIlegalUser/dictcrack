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

/// RAR 1.5-4.x ("RAR3") crypt info. Two flavours:
///   * header-encrypted (-hp): the archive ends with [salt(8)][encrypted
///     end-of-archive block(16)]; the end block decrypts to a fixed 16-byte
///     pattern, which is the password check.
///   * plain headers (-p): the first encrypted file header carries its own
///     8-byte salt (LHD_SALT); the check runs on the file data.
#[derive(Debug, Clone)]
pub struct Rar4CryptInfo {
    pub header_encrypted: bool,
    pub salt: [u8; 8],
    /// -hp only: the 16-byte encrypted end-of-archive block from the tail.
    pub check_block: Option<[u8; 16]>,
    /// -p only: absolute offset of the encrypted data area.
    pub data_offset: u64,
    pub pack_size: u64,
    pub unp_size: u64,
    pub file_crc: u32,
    /// 0x30 = stored (full native check), 0x31..=0x35 = compressed
    /// (native pre-check + external-tool confirm).
    pub method: u8,
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

/// Where the CRC that decides a 7z password comes from. Only these two
/// layouts put a CRC over the AES coder's own output stream, which is the one
/// thing a decrypt-only verifier can recompute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SevenZipCrcKind {
    /// kUnPackInfo's folder digest: opaque over the final folder output, so it
    /// is only usable when AES is the last coder in the chain.
    Folder,
    /// kSubStreamsInfo's digest for a single-substream folder. 7-Zip emits a
    /// folder digest here too, and it equals the substream digest.
    SubStream,
    /// No digest in the streams info at all (multi-file folders typically keep
    /// their CRCs in kFilesInfo instead): nothing to compare against.
    None,
}

impl SevenZipCrcKind {
    /// Both digest kinds sit on the bytes the AES coder produced, and only when
    /// no further coder transforms them.
    pub fn is_aes_out(self) -> bool {
        matches!(self, SevenZipCrcKind::Folder | SevenZipCrcKind::SubStream)
    }
}

/// 7z (7zAES) password-check data for the FIRST pack stream of the archive.
///
/// Built only when the password can be decided without a decompressor; see
/// `parse_sevenzip`. Deliberately holds no compression information: everything
/// this struct describes is checkable by AES-decrypting `pack_size` bytes at
/// `data_offset` and looking at the result.
#[derive(Debug, Clone)]
pub struct SevenZipCryptInfo {
    /// kEncodedHeader (0x17, the "-mhe" flavour) rather than a raw kHeader.
    /// Note this flag alone says nothing about encryption: a plain `7z a` also
    /// produces 0x17. The AES coder id is the real gate, and `parse_sevenzip`
    /// only builds this struct once it has found one.
    pub header_encrypted: bool,
    pub salt: Vec<u8>,
    pub iv: [u8; 16],
    pub ncp: u8,
    /// absolute file offset of the packed stream (32 + PackPos)
    pub data_offset: u64,
    pub pack_size: u64,
    /// the AES coder's OWN out-stream UnPackSize: the plaintext length before
    /// 7-Zip's zero padding, i.e. what the CRC is computed over
    pub aes_out_size: u64,
    pub crc: u32,
    pub crc_kind: SevenZipCrcKind,
    /// expected CRC input length; equals `aes_out_size` for the layouts that
    /// can be verified natively (kept explicit because it is what the check
    /// must assert, not derive)
    pub crc_len: u64,
    /// coder ids following AES in the chain; empty or [COPY] means the CRC
    /// covers the AES output itself
    pub trailing_coders: Vec<Vec<u8>>,
}

impl SevenZipCryptInfo {
    /// PAD = PackSize - AES out-stream UnPackSize: the number of zero bytes
    /// 7-Zip appended to reach an AES block boundary. 0..15.
    pub fn pad_len(&self) -> u64 {
        self.pack_size.saturating_sub(self.aes_out_size)
    }

    /// Cheap rejection: decrypt the last block only and require the PAD tail to
    /// be zero (false accept 2^(-8*PAD)). Useless when PAD == 0 -- it must NOT
    /// be treated as a pass then, see `SevenZipVerifier::verify`.
    pub fn padding_verifiable(&self) -> bool {
        self.pad_len() > 0
    }
}

#[derive(Debug, Clone)]
pub struct ArchiveInfo {
    pub kind: ArchiveKind,
    pub rar5: Option<Rar5CryptInfo>,
    pub rar4: Option<Rar4CryptInfo>,
    pub zip: Option<ZipTargetInfo>,
    pub seven_zip: Option<SevenZipCryptInfo>,
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
            ArchiveKind::RarLegacy => {
                // -hp and stored -p have exact native checks; a compressed
                // -p file needs a full RAR LZ/PPMd decoder, so it stays on
                // the external tool
                matches!(&self.rar4, Some(r) if r.header_encrypted || r.method == 0x30)
            }
            ArchiveKind::Zip => self.zip.is_some(),
            ArchiveKind::SevenZip => self.seven_zip.is_some(),
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

// ---- RAR 1.5-4.x ("RAR3") --------------------------------------------------

/// RAR4 header CRC16: the low 16 bits of the CRC32 over the header bytes
/// from HEAD_TYPE through the end of the header (verified against unrar).
fn rar4_crc_ok(body: &[u8], stored: u16) -> bool {
    (crate::crypto::Crc32::compute(body) & 0xFFFF) as u16 == stored
}

const RAR4_MARK: usize = 7; // "Rar!\x1a\x07\x00" marker block
const RAR4_FIXED_MAIN: usize = 13; // crc(2)+type(1)+flags(2)+size(2)+HighPosAV(2)+PosAv(4)
const RAR4_FIXED_FILE: usize = 32; // ..+pack(4)+unp(4)+host(1)+crc(4)+ftime(4)+ver(1)+method(1)+name_len(2)+attr(4)
/// RAR3 salt is always 8 bytes (unrar SIZE_SALT30), for -hp and -p alike.
const RAR4_SALT_LEN: usize = 8;
/// the -hp tail is [salt(8)][first ciphertext block(16)]; decrypting that
/// block must yield the fixed ENDARC header (john's "end-of-archive block
/// decrypt trick", unrar crypt3.cpp)
const RAR4_HP_TAIL: u64 = (RAR4_SALT_LEN + 16) as u64;

/// RAR4 walk. -hp archives keep plaintext MAIN (flags bit 0x0080 =
/// MHD_PASSWORD) and end with [salt(8)][encrypted end block(16)]; plain
/// archives expose the first encrypted file header with its own salt
/// (LHD_SALT). Anything unusual returns None and the engine falls back to
/// the external tool (SpawnVerifier), which stays the ground truth.
fn parse_rar4(path: &Path) -> Option<Rar4CryptInfo> {
    let mut fs = File::open(path).ok()?;
    let file_len = fs.metadata().ok()?.len();

    // the marker block precedes MAIN; both offsets below are relative to
    // the real block start (the header CRC covers MAIN from HeadType on)
    let mut mark = [0u8; RAR4_MARK];
    if read_full(&mut fs, &mut mark) != RAR4_MARK || mark != [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00] {
        return None;
    }

    // MAIN header (plaintext, even for -hp)
    let mut main = [0u8; RAR4_FIXED_MAIN];
    if read_full(&mut fs, &mut main) != RAR4_FIXED_MAIN || main[2] != 0x73 {
        return None;
    }
    // block layout: +0 CRC(2) +2 Type(1) +3 Flags(2) +5 HeadSize(2) +7 HighPosAV(2) +9 PosAV(4)
    let main_flags = u16::from_le_bytes([main[3], main[4]]);
    if !rar4_crc_ok(&main[2..], u16::from_le_bytes([main[0], main[1]])) {
        return None;
    }

    if main_flags & 0x0080 != 0 {
        // -hp: [salt(8)][encrypted ENDARC first block(16)] are the last 24
        // bytes (john rar2john seeks -24 from EOF). The block's plaintext is
        // a fixed constant, so this is the whole password check.
        if file_len < RAR4_MARK as u64 + RAR4_FIXED_MAIN as u64 + RAR4_HP_TAIL {
            return None;
        }
        let mut tail = [0u8; RAR4_HP_TAIL as usize];
        fs.seek(SeekFrom::Start(file_len - RAR4_HP_TAIL)).ok()?;
        if read_full(&mut fs, &mut tail) != tail.len() {
            return None;
        }
        let mut salt = [0u8; RAR4_SALT_LEN];
        let mut check = [0u8; 16];
        salt.copy_from_slice(&tail[..RAR4_SALT_LEN]);
        check.copy_from_slice(&tail[RAR4_SALT_LEN..]);
        return Some(Rar4CryptInfo {
            header_encrypted: true,
            salt,
            check_block: Some(check),
            data_offset: 0,
            pack_size: 0,
            unp_size: 0,
            file_crc: 0,
            method: 0,
            entry_name: None,
        });
    }

    // plain headers: walk blocks to the first encrypted file. The walk
    // starts after the marker + MAIN (the MAIN block's own HeadSize is
    // authoritative; >13 means an embedded old-style comment follows)
    let main_head_size = u16::from_le_bytes([main[5], main[6]]) as usize;    if main_head_size < RAR4_FIXED_MAIN {
        return None;
    }
    let mut pos: u64 = (RAR4_MARK + main_head_size) as u64;
    loop {
        if pos + 7 > file_len {
            return None;
        }
        fs.seek(SeekFrom::Start(pos)).ok()?;
        let mut head = [0u8; RAR4_FIXED_FILE];
        // read the fixed part; a short read here means a truncated/garbage tail
        if read_full(&mut fs, &mut head[..7]) != 7 {
            return None;
        }
        let block_type = head[2];
        let head_size = u16::from_le_bytes([head[5], head[6]]) as usize;
        if head_size < 7 {
            return None;
        }
        if block_type == 0x7b {
            return None; // end of archive, no encrypted file found
        }
        if block_type != 0x74 && block_type != 0x7a {
            // sub-blocks (comments, AV, recovery): skip via size; LONG_BLOCK
            // data area is skipped too via pack_size below only for files,
            // so for unknown types just bail out to the external tool
            return None;
        }
        if read_full(&mut fs, &mut head[7..]) != RAR4_FIXED_FILE - 7 {
            return None;
        }
        if head_size < RAR4_FIXED_FILE || pos + head_size as u64 > file_len {
            return None;
        }
        let flags = u16::from_le_bytes([head[3], head[4]]);
        // read the whole header body for the CRC (type..end of header)
        let mut body = vec![0u8; head_size - 2];
        fs.seek(SeekFrom::Start(pos + 2)).ok()?;
        if read_full(&mut fs, &mut body) != body.len() {
            return None;
        }
        if !rar4_crc_ok(&body, u16::from_le_bytes([head[0], head[1]])) {
            return None;
        }
        if flags & 0x0100 != 0 {
            return None; // LHD_LARGE (>4 GB entries): external tool
        }
        let pack_size = u32::from_le_bytes([head[7], head[8], head[9], head[10]]) as u64;
        let unp_size = u32::from_le_bytes([head[11], head[12], head[13], head[14]]) as u64;
        let file_crc = u32::from_le_bytes([head[16], head[17], head[18], head[19]]);
        let unp_ver = head[24];
        let method = head[25];
        let name_len = u16::from_le_bytes([head[26], head[27]]) as usize;
        let name_pos = RAR4_FIXED_FILE;
        let salt_pos = name_pos + name_len;
        if flags & 0x0400 != 0 {
            if salt_pos + 8 > head_size {
                return None;
            }
        } else if name_pos + name_len > head_size {
            return None;
        }

        if flags & 0x0004 != 0 {
            // first encrypted file: this is the crack target
            if flags & 0x0003 != 0 {
                return None; // split across volumes: external tool
            }
            if unp_ver != 29 {
                return None; // RAR 2.x crypto, not the RAR3 AES scheme
            }
            if flags & 0x0400 == 0 {
                return None; // no salt stored: keep the external tool path
            }
            // the encrypted data area must actually be present, or the
            // verifier would read past EOF (truncated / corrupt archive)
            let data_offset = pos + head_size as u64;
            if data_offset + pack_size > file_len {
                return None;
            }
            let mut salt = [0u8; RAR4_SALT_LEN];
            salt.copy_from_slice(&body[salt_pos - 2..salt_pos - 2 + RAR4_SALT_LEN]);
            let name = String::from_utf8_lossy(&body[name_pos - 2..name_pos - 2 + name_len])
                .trim_end_matches('\0')
                .to_string();
            let name = if name.chars().any(|c| (c as u32) < 0x20) { None } else { Some(name) };
            return Some(Rar4CryptInfo {
                header_encrypted: false,
                salt,
                check_block: None,
                data_offset,
                pack_size,
                unp_size,
                file_crc,
                method,
                entry_name: name,
            });
        }

        // unencrypted file: skip header + data area, try the next block
        pos += head_size as u64 + pack_size;
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

// ---- 7z --------------------------------------------------------------------

const SEVENZIP_SIG: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
const SEVENZIP_SIG_HEADER: usize = 32;
/// the one and only 7z AES codec id (7zHeader.h k_AES = 0x6F10701, stored
/// big-endian)
const SEVENZIP_AES: [u8; 4] = [0x06, 0xF1, 0x07, 0x01];
/// upper bound on the packed stream buffered per candidate. The size comes from
/// the archive header, so it is attacker-controlled; past this the archive is
/// declared non-native (parse time) rather than verified unsafely.
pub const SEVENZIP_MAX_PACK: u64 = 16 << 20;
/// k_Copy: a no-op, so it does not disturb a CRC over the AES output
const SEVENZIP_COPY: [u8; 1] = [0x00];
/// coders that need a decompressor whose output is what the CRC covers.
/// Names are only used for the detect_note the user reads.
const SEVENZIP_UNSUPPORTED: [(&[u8], &str); 16] = [
    (&[0x03, 0x01, 0x01], "LZMA1"),
    (&[0x21], "LZMA2"),
    (&[0x03], "Delta"),
    (&[0x0A], "ARM64"),
    (&[0x0B], "RISCV"),
    (&[0x03, 0x04, 0x01], "PPMd"),
    (&[0x04, 0x01, 0x08], "Deflate"),
    (&[0x04, 0x01, 0x09], "Deflate64"),
    (&[0x04, 0x02, 0x02], "BZip2"),
    (&[0x03, 0x03, 0x01, 0x03], "BCJ"),
    (&[0x03, 0x03, 0x01, 0x1B], "BCJ2"),
    (&[0x03, 0x03, 0x02, 0x05], "PPC"),
    (&[0x03, 0x03, 0x04, 0x01], "IA64"),
    (&[0x03, 0x03, 0x05, 0x01], "ARM"),
    (&[0x03, 0x03, 0x07, 0x01], "ARMT"),
    (&[0x03, 0x03, 0x08, 0x05], "SPARC"),
];

fn sevenzip_coder_name(id: &[u8]) -> String {
    if id == SEVENZIP_AES {
        return "7zAES".to_string();
    }
    if id == SEVENZIP_COPY {
        return "COPY".to_string();
    }
    for (want, name) in SEVENZIP_UNSUPPORTED {
        if id == want {
            return name.to_string();
        }
    }
    id.iter().map(|b| format!("{:02x}", b)).collect()
}

/// 7z's variable-length UINT64 (distinct from RAR5's vint, which is why
/// `read_vint` above cannot be reused): the count of leading one bits in the
/// first byte gives the number of following bytes, and the remaining low bits
/// are the high part of the value.
fn read_7z_num(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *buf.get(*pos)?;
    *pos += 1;
    if first < 0x80 {
        return Some(first as u64);
    }
    let mut i = 1usize;
    while i <= 7 {
        if first & (0x80 >> i) == 0 {
            let high = (first & (0x7F >> i)) as u64;
            let mut val = 0u64;
            for k in 0..i {
                val |= (*buf.get(*pos + k)? as u64) << (8 * k);
            }
            *pos += i;
            return Some(val | (high << (8 * i)));
        }
        i += 1;
    }
    // 0xFF: eight raw little-endian bytes
    let mut val = 0u64;
    for k in 0..8 {
        val |= (*buf.get(*pos + k)? as u64) << (8 * k);
    }
    *pos += 8;
    Some(val)
}

fn read_7z_u32(buf: &[u8], pos: &mut usize) -> Option<u32> {
    let b = buf.get(*pos..*pos + 4)?;
    *pos += 4;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_7z_bytes<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Option<&'a [u8]> {
    let b = buf.get(*pos..*pos + n)?;
    *pos += n;
    Some(b)
}

/// All-are-defined byte, then a CRC for each defined entry (7zFormat.txt).
fn read_7z_digests(buf: &[u8], pos: &mut usize, count: usize) -> Option<Vec<Option<u32>>> {
    let all = *buf.get(*pos)?;
    *pos += 1;
    let mut defined = vec![true; count];
    if all == 0 {
        let mut mask = 0u8;
        let mut v = 0u8;
        for slot in defined.iter_mut().take(count) {
            if mask == 0 {
                v = *buf.get(*pos)?;
                *pos += 1;
                mask = 0x80;
            }
            *slot = v & mask != 0;
            mask >>= 1;
        }
    }
    let mut out = Vec::with_capacity(count);
    for d in defined {
        out.push(if d { Some(read_7z_u32(buf, pos)?) } else { None });
    }
    Some(out)
}

struct SzCoder {
    id: Vec<u8>,
    num_out: u64,
    props: Vec<u8>,
}

struct SzFolder {
    coders: Vec<SzCoder>,
    /// out-stream UnPackSizes in coder order (the AES coder's own out size is
    /// the first entry of `[AES, ...]` chains -- reading the LAST entry here
    /// instead is what corrupts the PAD computation)
    out_sizes: Vec<u64>,
}

fn parse_7z_folder(buf: &[u8], pos: &mut usize) -> Option<SzFolder> {
    let num_coders = read_7z_num(buf, pos)?;
    // an archive claiming thousands of coders in one folder is not something
    // 7-Zip produces; refuse before allocating
    if num_coders == 0 || num_coders > 64 {
        return None;
    }
    let mut coders = Vec::with_capacity(num_coders as usize);
    let (mut total_in, mut total_out) = (0u64, 0u64);
    for _ in 0..num_coders {
        let flags = *buf.get(*pos)?;
        *pos += 1;
        if flags & 0x80 != 0 {
            return None; // "more alternative methods": not used anymore
        }
        let id_size = (flags & 0x0F) as usize;
        if id_size == 0 {
            return None;
        }
        let id = read_7z_bytes(buf, pos, id_size)?.to_vec();
        let (num_in, num_out) = if flags & 0x10 != 0 {
            (read_7z_num(buf, pos)?, read_7z_num(buf, pos)?)
        } else {
            (1, 1)
        };
        if num_in == 0 || num_out == 0 || num_in > 64 || num_out > 64 {
            return None;
        }
        total_in += num_in;
        total_out += num_out;
        let props = if flags & 0x20 != 0 {
            let n = read_7z_num(buf, pos)?;
            if n > 1 << 12 {
                return None;
            }
            read_7z_bytes(buf, pos, n as usize)?.to_vec()
        } else {
            Vec::new()
        };
        coders.push(SzCoder { id, num_out, props });
    }
    // bind pairs: every out-stream but one is bound to an in-stream
    let num_bind = total_out.checked_sub(1)?;
    for _ in 0..num_bind {
        read_7z_num(buf, pos)?; // in index
        read_7z_num(buf, pos)?; // out index
    }
    let num_packed = total_in.checked_sub(num_bind)?;
    if num_packed == 0 {
        return None;
    }
    // with exactly one packed stream its index is implicit; with more, they
    // are listed and the first one is no longer necessarily our AES input
    if num_packed > 1 {
        for _ in 0..num_packed {
            read_7z_num(buf, pos)?;
        }
        return None;
    }
    Some(SzFolder { coders, out_sizes: Vec::new() })
}

/// 7z AES coder properties (spec §B.2): mirror of
/// `CEncoder::WriteCoderProperties` / `SetDecoderProperties2`.
fn decode_aes_props(props: &[u8]) -> Option<(Vec<u8>, [u8; 16], u8)> {
    let b0 = *props.first()?;
    let ncp = b0 & 0x3F;
    if b0 & 0xC0 == 0 {
        // no salt, no IV; exactly one byte, so a decoder that reads props[1]
        // unconditionally would eat the next stream byte
        return if props.len() == 1 { Some((Vec::new(), [0u8; 16], ncp)) } else { None };
    }
    let b1 = *props.get(1)?;
    // the two extra bits are worth +1, NOT +16 (max 16 = 1 + 15)
    let salt_size = ((b0 >> 7) & 1) as usize + (b1 >> 4) as usize;
    let iv_size = ((b0 >> 6) & 1) as usize + (b1 & 0x0F) as usize;
    if props.len() != 2 + salt_size + iv_size {
        return None;
    }
    let salt = props[2..2 + salt_size].to_vec();
    let raw_iv = &props[2 + salt_size..2 + salt_size + iv_size];
    let mut iv = [0u8; 16];
    // a short IV is right-zero-padded at use time; the +1 bits mean both
    // fields can also be empty
    let n = raw_iv.len().min(16);
    iv[..n].copy_from_slice(&raw_iv[..n]);
    Some((salt, iv, ncp))
}

/// One `kPackInfo`/`kUnPackInfo` block pair: enough of the 7z header grammar to
/// reach the first folder's coder chain, its out-stream sizes and its digest.
/// Everything unknown stops the walk (None) rather than being skipped
/// heuristically -- a misread header must not turn into a bogus password check.
fn parse_7z_streams(buf: &[u8], pos: &mut usize) -> Option<(u64, Vec<u64>, Vec<SzFolder>, Vec<Option<u32>>)> {
    let mut pack_sizes: Vec<u64> = Vec::new();
    let mut folders: Vec<SzFolder> = Vec::new();
    let mut digests: Vec<Option<u32>> = Vec::new();
    if *buf.get(*pos)? != 0x06 {
        return None; // kPackInfo is mandatory
    }
    *pos += 1;
    let pack_pos = read_7z_num(buf, pos)?;
    let num_streams = read_7z_num(buf, pos)?;
    if num_streams == 0 || num_streams > 1 << 16 {
        return None;
    }
    match *buf.get(*pos)? {
        0x00 => {}
        0x09 => {
            *pos += 1;
            for _ in 0..num_streams {
                pack_sizes.push(read_7z_num(buf, pos)?);
            }
            match *buf.get(*pos)? {
                0x00 => {}
                0x0A => {
                    *pos += 1;
                    // pack stream CRCs cover the ciphertext: useless as a
                    // password check, but the field has to be walked
                    read_7z_digests(buf, pos, num_streams as usize)?;
                    if *buf.get(*pos)? != 0x00 {
                        return None;
                    }
                }
                _ => return None,
            }
        }
        _ => return None,
    }
    *pos += 1; // kEnd of kPackInfo
    if pack_sizes.len() != num_streams as usize {
        return None;
    }
    if *buf.get(*pos)? != 0x07 {
        return None; // kUnPackInfo is mandatory
    }
    *pos += 1;
    if *buf.get(*pos)? != 0x0B {
        return None; // kFolder
    }
    *pos += 1;
    let num_folders = read_7z_num(buf, pos)?;
    if num_folders == 0 || num_folders > 1 << 16 {
        return None;
    }
    if *buf.get(*pos)? != 0x00 {
        return None; // external folder data: not supported
    }
    *pos += 1;
    for _ in 0..num_folders {
        folders.push(parse_7z_folder(buf, pos)?);
    }
    if *buf.get(*pos)? != 0x0C {
        return None; // kCodersUnPackSize
    }
    *pos += 1;
    for f in folders.iter_mut() {
        for c in f.coders.iter() {
            for _ in 0..c.num_out {
                f.out_sizes.push(read_7z_num(buf, pos)?);
            }
        }
    }
    match *buf.get(*pos)? {
        0x00 => {}
        0x0A => {
            *pos += 1;
            digests = read_7z_digests(buf, pos, num_folders as usize)?;
            if *buf.get(*pos)? != 0x00 {
                return None;
            }
        }
        _ => return None,
    }
    *pos += 1; // kEnd of kUnPackInfo
    Some((pack_pos, pack_sizes, folders, digests))
}

/// `kSubStreamsInfo` (0x08), optional. For the single-substream, one-coder
/// layouts that can be verified natively the digest here equals the folder
/// digest; multi-substream folders are rejected by the caller.
fn parse_7z_substreams(
    buf: &[u8],
    pos: &mut usize,
    folder_total: u64,
    digest_defined: bool,
) -> Option<(Vec<u64>, Vec<Option<u32>>)> {
    let mut nums = vec![1u64];
    let mut sizes = vec![folder_total];
    let mut digests = Vec::new();
    let mut next = *buf.get(*pos)?;
    *pos += 1;
    if next == 0x0D {
        nums[0] = read_7z_num(buf, pos)?;
        if nums[0] == 0 || nums[0] > 1 << 16 {
            return None;
        }
        next = *buf.get(*pos)?;
        *pos += 1;
    }
    if next == 0x09 {
        // n-1 sizes follow; the last substream's size is implied
        let mut acc = 0u64;
        sizes.clear();
        for _ in 1..nums[0] {
            let s = read_7z_num(buf, pos)?;
            sizes.push(s);
            acc += s;
        }
        sizes.push(folder_total.checked_sub(acc)?);
        next = *buf.get(*pos)?;
        *pos += 1;
    }
    // 7zFormat.txt: the digest list holds the substreams whose CRC the folder
    // digest did NOT already define, in order.
    let num_digests: usize = if !digest_defined { nums[0] as usize } else { 0 };
    if next == 0x0A {
        digests = read_7z_digests(buf, pos, num_digests)?;
        next = *buf.get(*pos)?;
        *pos += 1;
    }
    if next != 0x00 {
        return None;
    }
    Some((sizes, digests))
}

/// 7z container walk. Returns the crypt info when the archive's password can
/// be decided by AES-decrypting and comparing a CRC32, and None otherwise --
/// with `note` explaining which case it was, because the engine falls back to
/// the external tool on None and the user has to see why.
fn parse_sevenzip(path: &Path, note: &mut String) -> Option<SevenZipCryptInfo> {
    let mut fs = File::open(path).ok()?;
    let file_len = fs.metadata().ok()?.len();
    if file_len < SEVENZIP_SIG_HEADER as u64 {
        *note = "7z format (file is shorter than the signature header)".into();
        return None;
    }
    let mut sig = [0u8; SEVENZIP_SIG_HEADER];
    if read_full(&mut fs, &mut sig) != SEVENZIP_SIG_HEADER {
        *note = "7z format (signature header truncated)".into();
        return None;
    }
    if crate::crypto::Crc32::compute(&sig[12..32]) != le_u32(&sig, 8) {
        *note = "7z format (signature header CRC mismatch; file is damaged)".into();
        return None;
    }
    if sig[..6] != SEVENZIP_SIG {
        *note = "7z format (bad signature)".into();
        return None;
    }
    // NextHeaderOffset/Size are REAL_UINT64 (fixed little-endian), unlike
    // everything inside the header
    let nh_off = u64::from_le_bytes(sig[12..20].try_into().ok()?);
    let nh_size = u64::from_le_bytes(sig[20..28].try_into().ok()?);
    let nh_crc = le_u32(&sig, 28);
    if nh_size == 0 {
        *note = "7z format (no header: empty archive)".into();
        return None;
    }
    let nh_start = SEVENZIP_SIG_HEADER as u64 + nh_off;
    if nh_size > 1 << 24 || nh_start.checked_add(nh_size)? > file_len {
        *note = "7z format (next header is outside the file; truncated or damaged)".into();
        return None;
    }
    let mut nh = vec![0u8; nh_size as usize];
    fs.seek(SeekFrom::Start(nh_start)).ok()?;
    if read_full(&mut fs, &mut nh) != nh.len() || crate::crypto::Crc32::compute(&nh) != nh_crc {
        *note = "7z format (next header CRC mismatch; file is damaged)".into();
        return None;
    }

    // kEncodedHeader means "the header is stored as a folder's stream", NOT
    // "encrypted": a plain `7z a` produces it too (next_header[0] == 0x17 with
    // no password). And for content encryption the header is a raw kHeader
    // (0x01), readable without a password. Hence: parse the streams info
    // either way, then require an AES coder.
    let encoded_header = nh[0] == 0x17;
    let mut pos = 1usize;
    if !encoded_header {
        // raw kHeader: [kArchiveProperties] [kAdditionalStreamsInfo] [kMainStreamsInfo]
        loop {
            match *nh.get(pos)? {
                0x02 => {
                    pos += 1;
                    while *nh.get(pos)? != 0x00 {
                        pos += 1;
                        let n = read_7z_num(&nh, &mut pos)?;
                        read_7z_bytes(&nh, &mut pos, n as usize)?;
                    }
                    pos += 1;
                }
                0x04 => {
                    pos += 1;
                    break;
                }
                _ => {
                    *note = "7z format (header has no main streams info)".into();
                    return None;
                }
            }
        }
    }
    let (pack_pos, pack_sizes, folders, folder_digests) = parse_7z_streams(&nh, &mut pos)?;
    let folder = folders.first()?;

    // the AES coder must be the FIRST coder of the chain: it consumes the
    // packed stream, so everything after it transforms the decrypted bytes
    let aes = match folder.coders.first().filter(|c| c.id == SEVENZIP_AES) {
        Some(c) => c,
        None => {
            // kEncodedHeader is NOT encryption: a plain `7z a` produces 0x17
            // too. Reporting "no password" (via the SpawnVerifier probe) relies
            // on getting this distinction right.
            //
            // The wording here must stay DOUBTFUL, not assertive. When the
            // header is itself compressed (LZMA1/LZMA2 -- the default for an
            // archive with many files), the real coder chain lives INSIDE the
            // compressed stream and its AES id is not visible from the outside
            // at all: a content-encrypted archive can therefore contain zero
            // occurrences of 06F10701 while still being encrypted (measured on
            // plain_many.7z: `7z t -popenwall` succeeds and `-pwrongpw` fails,
            // yet the AES id never appears in the file). Do not "improve" this
            // into a claim that the archive is unencrypted.
            *note =
                "7z format (header has no AES coder; the header itself may be compressed -> using external tool)"
                    .into();
            return None;
        }
    };
    let (salt, iv, ncp) = decode_aes_props(&aes.props)?;
    let aes_out_size = *folder.out_sizes.first()?;
    let pack_size = *pack_sizes.first()?;
    // PAD is the zero padding 7-Zip appended; the AES out-stream size is what
    // it recorded before padding
    if aes_out_size > pack_size {
        *note = "7z format (AES stream size exceeds its packed size; header is inconsistent)".into();
        return None;
    }
    let pad = pack_size - aes_out_size;
    let trailing: Vec<Vec<u8>> = folder.coders[1..].iter().map(|c| c.id.clone()).collect();
    let has_copy = trailing.iter().any(|id| *id == SEVENZIP_COPY);
    let has_other = trailing.iter().any(|id| *id != SEVENZIP_COPY);
    if has_other {
        // the CRC covers the decompressed/filtered bytes, so a decrypt-only
        // check cannot decide the password. Deliberately not attempted: a
        // "hit" here would be a lie.
        let names: Vec<String> = trailing
            .iter()
            .filter(|id| **id != SEVENZIP_COPY)
            .map(|id| sevenzip_coder_name(id))
            .collect();
        *note = format!(
            "7z format ({}: password check needs a decompressor; using external tool)",
            names.join("+")
        );
        return None;
    }
    if has_copy && trailing.len() != 1 {
        // 0x00 is a no-op, so several COPYs in a row are still identity, but a
        // mix we do not expect means we misread the chain
        *note = "7z format (unexpected coder chain; using external tool)".into();
        return None;
    }
    // 0x3F is not "many rounds": it is 7-Zip's special value meaning NO hashing
    // at all (key = (salt||password)[:32]), so it must not trip the ceiling.
    if ncp != 0x3F && ncp > crate::crypto::SEVENZIP_MAX_NCP {
        *note = format!(
            "7z format (key derivation needs 2^{} rounds, above the native limit 2^{}; using external tool)",
            ncp,
            crate::crypto::SEVENZIP_MAX_NCP
        );
        return None;
    }

    // Where does the decisive CRC come from? With AES as the last coder both
    // digests describe the AES output exactly; with a trailing COPY the CRC
    // still covers those same bytes (COPY is identity), but only if the sizes
    // agree.
    let mut crc_kind = SevenZipCrcKind::None;
    let mut crc = 0u32;
    let mut crc_len = aes_out_size;
    let folder_digest = folder_digests.first().copied().flatten();
    match *nh.get(pos)? {
        0x00 => {
            // no kSubStreamsInfo; the folder digest is all there is
            if let Some(c) = folder_digest {
                crc = c;
                crc_kind = SevenZipCrcKind::Folder;
            }
        }
        0x08 => {
            pos += 1;
            let (sizes, sub_digests) =
                parse_7z_substreams(&nh, &mut pos, *folder.out_sizes.last()?, folder_digest.is_some())?;
            // only a lone substream can be checked against a decrypt-only
            // buffer: with several, the CRC covers an arbitrary byte range and
            // 7-Zip may not even have stored it here
            if sizes.len() != 1 {
                *note = format!(
                    "7z format (folder holds {} substreams; password check needs the external tool)",
                    sizes.len()
                );
                return None;
            }
            crc_len = sizes[0];
            if let Some(c) = sub_digests.first().copied().flatten() {
                crc = c;
                crc_kind = SevenZipCrcKind::SubStream;
            } else if let Some(c) = folder_digest {
                crc = c;
                crc_kind = SevenZipCrcKind::Folder;
            }
        }
        _ => return None,
    }
    // A trailing COPY keeps working only when no size was rewritten, otherwise
    // the digest's length is unknown to us.
    if has_copy && crc_kind.is_aes_out() && crc_len != aes_out_size {
        *note = "7z format (CRC length does not match the AES output; using external tool)".into();
        return None;
    }

    // A digest over the AES output makes the check exact. For an ENCODED
    // header that digest exists whenever AES is the only coder -- 7-Zip stores
    // the AES out-stream CRC in kUnPackInfo's folder list (measured on real
    // -mhe archives: folder CRC == CRC32 of the decrypted AES output). Without
    // any digest the only invariant left is the tail zero padding, which is
    // weak (2^-8*PAD) but non-vacuous; at PAD == 0 there is nothing to check at
    // all. Content encryption is different: there the CRC is the normal case
    // and PAD is merely a free pre-filter, so PAD == 0 must NOT force a
    // fallback there (see the note on SevenZipCryptInfo::padding_verifiable).
    if crc_kind.is_aes_out() {
        *note = if encoded_header {
            "7z format (encrypted header: AES-only, native CRC check)".into()
        } else {
            "7z format (AES-encrypted content: native CRC check)".into()
        };
    } else if encoded_header {
        if pad == 0 {
            *note = "7z format (encrypted header: no CRC and no padding to check; using external tool)"
                .into();
            return None;
        }
        *note = format!("7z format (encrypted header: only the {}-byte zero padding is checkable)", pad);
    } else {
        // Content encryption with no digest anywhere: a decrypt-only verifier
        // has nothing to compare against, and guessing would be worse than
        // falling back.
        *note = "7z format (no CRC over the stream; using external tool)".into();
        return None;
    }

    // The ciphertext must be inside the file, or every candidate would read
    // garbage past EOF and be rejected for the wrong reason. The size cap is
    // checked FIRST and here rather than in the verifier: a declared PackSize
    // above the cap means this engine will never buffer the stream, so the
    // archive is non-native no matter what else the header says -- and an
    // archive we cannot check must fall back, not silently reject every
    // password (which the engine would report as a fully searched dictionary).
    if pack_size > SEVENZIP_MAX_PACK {
        *note = format!(
            "7z format (packed stream is {} MiB, above the native {} MiB limit; using external tool)",
            pack_size >> 20,
            SEVENZIP_MAX_PACK >> 20
        );
        return None;
    }
    let data_offset = (SEVENZIP_SIG_HEADER as u64).checked_add(pack_pos)?;
    if pack_size == 0 || data_offset.checked_add(pack_size)? > file_len {
        *note = "7z format (packed stream is outside the file; truncated or damaged)".into();
        return None;
    }

    Some(SevenZipCryptInfo {
        header_encrypted: encoded_header,
        salt,
        iv,
        ncp,
        data_offset,
        pack_size,
        aes_out_size,
        crc,
        crc_kind,
        crc_len,
        trailing_coders: trailing,
    })
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
        rar4: None,
        zip: None,
        seven_zip: None,
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
        info.rar4 = parse_rar4(p);
        if info.rar4.is_none() {
            info.detect_note = "RAR 1.5-4.x format (no usable native check data found)".into();
        } else if !info.native_supported() {
            // a compressed -p file parses fine, but verifying it needs a
            // full RAR LZ/PPMd decoder (the CRC covers the decompressed
            // bytes), so the external tool stays the verifier
            info.detect_note =
                "RAR 1.5-4.x format (compressed file needs the external tool; native check covers -hp and stored -p)".into();
        }
        return info;
    }
    if head.len() >= 6
        && head[0] == 0x37 && head[1] == 0x7A && head[2] == 0xBC && head[3] == 0xAF
        && head[4] == 0x27 && head[5] == 0x1C
    {
        info.kind = ArchiveKind::SevenZip;
        info.seven_zip = parse_sevenzip(p, &mut info.detect_note);
        if info.detect_note.is_empty() {
            info.detect_note = "7z format (no password check data found)".into();
        }
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

    // ---- 7z gold samples ---------------------------------------------------
    // Real archives produced by 7-Zip 26.03 during the format research
    // (D:\Files\Tmp\7zverify), frozen as hex literals so `cargo test` never
    // needs 7z.exe. The password is "openwall" for every one of them, and the
    // expected CRC/KDF values below were cross-checked with an independent
    // python implementation (see docs/7z-verification-spec.md).

    /// `7z a -mhe=on` with an AES-only encoded header: PAD=6.
    const SZ_MHE_LZMA2: &str = concat!(
        "377abcaf271c0004942906ccb0000000000000002e00000000000000ff687e1bf5e2b6e2d5dceb8d945782b2243012ba",
        "c3003b5c5535dc7b3332829a9f383b0b7ac0efe2136cb4e9df2aa0f00140c825ba30d567d29b34580a5c4ef45877dd7a",
        "ceefa33f86493fb1cf6297acb3a13bde5a447b3c0ce02a3f61f9e3d019fdc715bd9b67a9b19ca9e7a1ef8ab00586198f",
        "84be6326aab49b15a155bf4c953ce878b62f2861c83e3982b22af084ca4c076302f1c6fdf9e725b603a129316e342042",
        "29483c49288945d39d390134516a035517064001097000070b0100012406f1070112530f9ed86bd0a59e603bb03dad75",
        "d5258c930c6a0a01a87bd2950000"
    );

    /// `7z a -mhe=on -mhc=on`: encoded header with TWO coders (AES + LZMA1),
    /// so the AES out-stream size (485) is not the final size (1634) and the
    /// CRC covers the LZMA1 output: no native check without a decompressor.
    const SZ_MHE_MANY: &str = concat!(
        "377abcaf271c0004fce544fd70020000000000003f000000000000005a82fa919b8cc11517bc3bfc3f9aedac4da54467",
        "e5b5c54662dda62d2e66c102a6cf057e853e7f167e252a8c91909e77327ac1470addf97fd75cf5c701f1da222b12a776",
        "8eb7fbc14319cda4fcb12b74de72faa3ca5dc1c1c2829ee4f3fa28e659f7fecba27566d965d940205ee8b8bf434a7d3a",
        "dbd91e1590f8c608668e3805b5dca39523a6aac5cd81fd059d5661699f6a5e721cbb1b1b9f2b175156c47b48b303802a",
        "85e4e0ce5f9b4a8a7a7e103e7f48ef6c693ddf920a38ea3d004cf00b5a8bd4dc7aa1425444b81cce83d370d807bed0cd",
        "5e69c429f3ecc9c66aa5728c81c0379f1ddffc52b3f969d829e0be6791ff10251595b91dae12c4177f6598d431dc0694",
        "62c9d2f103f90072caddc7569c34db0c719110ab041ef437efbffd05ae8b636d7e3ae804e63e834aaa4c21f51ba53ed6",
        "03af29164ab69c45fbcb928cae1bfffeb6626c260176606c0a3221307b6adbbe51053f6ec2d7e73443e9efad634d8e9e",
        "299c4934bf847c7519d00184e996ed0f067fcd7fb0d05914647792d5673d879fcfa87554ed575fc99d02c3961eeadd19",
        "9b2ebb06d6205e57e19af310b65b224d39f220b0f54037a0e3a6847f66a4eea5dbe258bb81c587b1d9ce0de440bc759c",
        "fc3caa904fcc7843cafa9aa85c44ec4529b3b2795308e9ed1a71102938fe6a43c6da93fba5e9a22b284071f90e5c2d1a",
        "8a09cc0f0b3931591a10bce2241a88fa66e312e21a89bfacbfb8df0bf5b301ddbf1ff78d17d6debcdcdbd139a8f24726",
        "5c1593cb76bf33acd61a90f6b7f6e20f6814941e3e80ac6113535617237fb30ed01a8a232024afbdccdf80c9af772b3a",
        "b80fafa1b723bfa29fae31dba00ad2541ab806ef26ecd3a9eb079b34a5f7b00617068080010981f000070b0100022406",
        "f1070112530fc2424b3a61ffc513be75fc075a49380823030101055d0010000001000c81e586620a01387501300000"
    );

    /// `7z a -p` (content encryption, plain header): AES + COPY, PAD=2, and a
    /// kSubStreamsInfo CRC over the 46 plaintext bytes.
    const SZ_PLAIN_COPY: &str = concat!(
        "377abcaf271c0004c1a3b98730000000000000006a000000000000006cc2bfef78fb8699c48eafdfa2cc9687575c6a1e",
        "b0f99908cc41f8abe39de5f86baf9fb097259413221ce6602962943caabd5dfa0104060001093000070b0100022406f1",
        "070112530f471dc51a8fe99148ef9a5f0698275964010001000c2e2e00080a01b7782f69000005011903000000111500",
        "680065006c006c006f002e007400780074000000140a0100c6fe79b85255dd0115060100200000000000"
    );

    /// `7z a -p -m0=lzma2`: AES + LZMA2, needs the decompressor.
    const SZ_PLAIN_LZMA2: &str = concat!(
        "377abcaf271c00049460db8640000000000000006a0000000000000051c3a94b34dba74b33fec983f4e31455ecb3c6d6",
        "a275584055cc0ab0a4b5bf3ec74dcd8ed8c4c80b135dae9de34aa82e082a914d8ed854819180003b77a9331298838227",
        "0104060001094000070b0100022406f1070112530f4f6ed037324f030f9480483cfa19b35e2121010001000c322e0008",
        "0a01b7782f6900000501190100111500680065006c006c006f002e007400780074000000140a0100c6fe79b85255dd01",
        "15060100200000000000"
    );

    /// Plain `7z a` with the default compressed header: kEncodedHeader (0x17)
    /// WITHOUT any AES coder. This is the sample that proves 0x17 != encrypted.
    const SZ_PLAIN_MANY: &str = concat!(
        "377abcaf271c000447260507650200000000000023000000000000004072468f0af1413e2d4375f4cf08556615761029",
        "8fa177e6316867838cf6bc5b31518a858126a1f6ed290ae5720041768a06be4aa771398f2e3e956f3b7aa6f4323ec369",
        "306962c0da262d37a5a6df6b0b340c5e205b9a03aac08030b709d9abfd8ad2e0fafc79c80b2ed48294d6c7d4064e16b0",
        "dfa6b21336db10412a3cbae2a6ae15c30000813307ae0fd53527b1693e3ad3ce1000747a718deff518aa1a43476ae8b3",
        "0485ae24cf42eee1cd02bf730c9614ae9083bf06c1955e3e2deb25649f88693a4d800794312f52e8f528a231bb301bbe",
        "c6ee7ec05ed26bbd2b5a1fab2e340cbcdb37cc9f4c078e2bb710e28204da1a12f8f6d7d90b248e6f99f5d2b30b4a4e4a",
        "fdddba9203b5eeb389a2bc26ea1d7d3e05c5ea5907a572ba9acd1fb0cc4ab18388a9a7aa71481a3d5594397753cbccbb",
        "390578adb9a1527725f0eb1d496a5ea3d532acae218052d7469d880652695a2c1400efa66ed5ea43f15becce7d41f1dc",
        "627b2081d383c0b40bf8a57a31e53b2d83fd0ec8352d6bfd9894fb90c5623bac6d586c86394b6cc064d0c64d97ce420e",
        "dce580f7863ccc8cfe4309567728c32a0a4e89c9ba9b5810befbdceba9980d984444a0a6a93361be20ae31cee88e4fba",
        "4735e23744cee7bfd55cf6e9e1fc16a5149b746b3c53dc922a2053fe1e9ae97ac9c27d1324eba03fc840c5191560ea5e",
        "c0742ef047f1e23362350162bad7e61daa47f8ef283bbf4eaea3f2ea2875d1b04b5689ab836ae468ba59f7fb4cb89ab0",
        "81ab13f7af0ad825cd4306abadfb38f198cc5a5bca7ec3846faea95b1a21825ed65f3207b2f92ca3ef9bdfc210471c06",
        "621000a7b915e6999961d1b834d6456971a13e1e2f17068080010981e500070b01000123030101055d001000000c8662",
        "0a0113098b8c0000"
    );

    /// Synthetic content-encrypted archive (salt=0, iv=16, ncp=19) whose
    /// packed stream is exactly one AES block: PAD == 0, so the pad pre-filter
    /// is unavailable and only the folder CRC can decide. 7z.exe accepts it.
    const SZ_NOSALT: &str = concat!(
        "377abcaf271c0004b943811110000000000000005400000000000000ffb6562c8dfb4b51bb86c25b4f56e8b51d66d931",
        "010406000109100a01031d5e9e00070b0100012406f1070112530faabbccddeeff001122334455667788990c100a017b",
        "229d6d0000050111190063006f006e00740065006e0074002e00620069006e0000000000"
    );

    /// Stored, single-file, unencrypted `7z a` (7-Zip reports `Encrypted = -`):
    /// raw kHeader and `k_Copy` as the only coder.
    const SZ_PLAIN_COPY_ONLY: &str = concat!(
        "377abcaf271c0004e8cc8ead0e000000000000004200000000000000ff28b8624142434445464748494a4b4c4d4e0104",
        "060001090e00070b01000101000c0e00080a0145ef25ab00000501110d0070002e007400780074000000140a01007c4c",
        "ed475b55dd0115060100200000000000"
    );

    fn from_hex(s: &str) -> Vec<u8> {        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()).collect()
    }

    fn sz_temp(name: &str, data: &[u8]) -> std::path::PathBuf {
        write_temp("sz", name, data)
    }

    /// Flip one byte of a fixture, asserting the old value so that a drifting
    /// fixture cannot silently turn a test into a no-op.
    fn patch_byte(blob: &mut [u8], at: usize, old: u8, new: u8) {
        assert_eq!(blob[at], old, "fixture drifted at offset {}", at);
        blob[at] = new;
    }

    /// Recompute both CRCs after mutating a 7z header, so the parser reaches
    /// the field under test instead of bailing out on the integrity check.
    fn refix_sevenzip_crcs(blob: &mut [u8]) {
        let nh_off = u64::from_le_bytes(blob[12..20].try_into().unwrap()) as usize;
        let nh_size = u64::from_le_bytes(blob[20..28].try_into().unwrap()) as usize;
        let nh = 32 + nh_off;
        let crc = crate::crypto::Crc32::compute(&blob[nh..nh + nh_size]);
        blob[28..32].copy_from_slice(&crc.to_le_bytes());
        let crc = crate::crypto::Crc32::compute(&blob[12..32]);
        blob[8..12].copy_from_slice(&crc.to_le_bytes());
    }

    /// `-mhe` with an AES-only header: the encoded header is one AES stream, so
    /// the folder CRC covers the AES out-stream and no decompressor is needed.
    #[test]
    fn sevenzip_mhe_aes_only_header_is_native() {
        let p = sz_temp("mhe.7z", &from_hex(SZ_MHE_LZMA2));
        let info = parse(&p.display().to_string());
        assert_eq!(info.kind, ArchiveKind::SevenZip, "detected as 7z");
        assert!(info.native_supported(), "AES-only encoded header is native");
        let s = info.seven_zip.clone().expect("7z crypt info parsed");
        assert!(s.header_encrypted, "kEncodedHeader flavour");
        assert_eq!(s.ncp, 19, "numCyclesPower");
        assert_eq!(s.salt, Vec::<u8>::new(), "no salt in the props");
        assert_eq!(
            s.iv,
            [0x9e, 0xd8, 0x6b, 0xd0, 0xa5, 0x9e, 0x60, 0x3b, 0xb0, 0x3d, 0xad, 0x75, 0xd5, 0x25, 0x8c, 0x93],
            "IV comes from the coder properties, not from a digest"
        );
        assert_eq!(s.pack_size, 112, "PackSize");
        assert_eq!(s.aes_out_size, 106, "AES coder's own out-stream UnPackSize");
        assert_eq!(s.pad_len(), 6, "PAD = PackSize - AES out");
        assert_eq!(s.data_offset, 96, "32 + PackPos(64)");
        assert_eq!(s.crc, 0x95d2_7ba8, "folder CRC over the 106 plaintext bytes");
        assert_eq!(s.crc_len, 106, "CRC length is the AES out-stream size");
        assert_eq!(s.crc_kind, SevenZipCrcKind::Folder, "folder digest");
        assert!(s.trailing_coders.is_empty(), "AES is the only coder");
    }

    /// AES followed by anything that transforms the bytes: the stored CRC is
    /// over the DECOMPRESSED output, so the cheap check is gone.
    #[test]
    fn sevenzip_multi_coder_header_needs_decompressor() {
        let p = sz_temp("mhemany.7z", &from_hex(SZ_MHE_MANY));
        let info = parse(&p.display().to_string());
        assert_eq!(info.kind, ArchiveKind::SevenZip);
        assert!(info.seven_zip.is_none(), "AES+LZMA1 header cannot be verified natively");
        assert!(!info.native_supported());
        assert!(
            info.detect_note.contains("LZMA") && info.detect_note.contains("external"),
            "note must name the missing decompressor and the fallback, got {:?}",
            info.detect_note
        );
    }

    /// The one PAD==0 case that genuinely has no criterion: an encoded header
    /// with no digest at all. Generated from SZ_MHE_LZMA2 by deleting the
    /// folder kCRC and setting UnPackSize == PackSize (see
    /// D:\Files\Tmp\7zverify\gen_edge_fixtures.py); the container stays
    /// self-consistent -- only the criterion is gone.
    ///
    /// The fallback is not caution for its own sake. Measured on the equivalent
    /// fixture `mhe_nocrc_pad0.7z`: with PAD == 0 the tail padding is empty, so
    /// "the last PAD bytes are zero" holds VACUOUSLY and BOTH the correct and
    /// the wrong password "pass" it. Any future "optimisation" that lets PAD==0
    /// through this branch would accept every password at once.
    #[test]
    fn sevenzip_encoded_header_without_any_criterion_falls_back() {
        let mut blob = from_hex(SZ_MHE_LZMA2);
        let nh = 32 + u64::from_le_bytes(blob[12..20].try_into().unwrap()) as usize;
        assert_eq!(blob[nh + 38], 0x0A, "kCRC record offset");
        blob.drain(nh + 38..nh + 44); // drop kCRC + allAreDefined + CRC
        patch_byte(&mut blob, nh + 37, 0x6a, 0x70); // 106 -> 112: PAD == 0
        blob[20..28].copy_from_slice(&(46u64 - 6).to_le_bytes());
        refix_sevenzip_crcs(&mut blob);
        let info = parse(&sz_temp("nocrcpad0.7z", &blob).display().to_string());
        assert!(info.seven_zip.is_none(), "no CRC and no padding must not be native");
        assert!(
            info.detect_note.contains("no CRC") && info.detect_note.contains("padding"),
            "note explains both missing criteria, got {:?}",
            info.detect_note
        );
    }

    /// Encoded header with the digest removed but PAD > 0: the tail padding is
    /// still a real (if weak) invariant, so it stays native -- and the note has
    /// to say how weak.
    #[test]
    fn sevenzip_encoded_header_padding_only_is_native_but_noted() {
        let mut blob = from_hex(SZ_MHE_LZMA2);
        let nh = 32 + u64::from_le_bytes(blob[12..20].try_into().unwrap()) as usize;
        blob.drain(nh + 38..nh + 44); // drop kCRC + allAreDefined + CRC
        blob[20..28].copy_from_slice(&(46u64 - 6).to_le_bytes());
        refix_sevenzip_crcs(&mut blob);
        let p = sz_temp("nocrc.7z", &blob);
        let info = parse(&p.display().to_string());
        assert!(info.native_supported(), "padding-only header is still native");
        let s = info.seven_zip.clone().expect("7z crypt info parsed");
        assert_eq!(s.pad_len(), 6, "PAD survives");
        assert_eq!(s.crc_kind, SevenZipCrcKind::None, "no digest in this variant");
        assert!(
            info.detect_note.contains("zero padding"),
            "note warns the check is padding-only, got {:?}",
            info.detect_note
        );
    }

    /// AES-only encoded header with PAD == 0 but its CRC intact: still native.
    /// The folder CRC is over the AES output, so padding is not needed --
    /// treating PAD==0 as "unverifiable" here would push a decidable archive
    /// onto the external tool.
    #[test]
    fn sevenzip_encoded_header_pad_zero_with_crc_stays_native() {
        let mut blob = from_hex(SZ_MHE_LZMA2);
        let nh = 32 + u64::from_le_bytes(blob[12..20].try_into().unwrap()) as usize;
        patch_byte(&mut blob, nh + 37, 0x6a, 0x70); // 106 -> 112: PAD == 0
        // CRC32 of the 112 decrypted bytes, from the independent python AES
        blob[nh + 40..nh + 44].copy_from_slice(&0xbd0a_e8f7u32.to_le_bytes());
        refix_sevenzip_crcs(&mut blob);
        let p = sz_temp("pad0crc.7z", &blob);
        let info = parse(&p.display().to_string());
        assert!(info.native_supported(), "PAD==0 with a CRC is native");
        let s = info.seven_zip.clone().expect("7z crypt info parsed");
        assert_eq!(s.pad_len(), 0);
        assert_eq!(s.crc, 0xbd0a_e8f7);
        assert_eq!(s.crc_len, 112, "the CRC covers the whole AES output");
        assert_eq!(s.crc_kind, SevenZipCrcKind::Folder);
    }

    /// Content encryption with AES+COPY: the CRC is the decisive check and the
    /// padding is only a free pre-filter, so PAD > 0 is not required.
    #[test]
    fn sevenzip_content_encrypted_copy_uses_crc_fast_path() {
        let p = sz_temp("copy.7z", &from_hex(SZ_PLAIN_COPY));
        let info = parse(&p.display().to_string());
        assert!(info.native_supported(), "AES+COPY content is native");
        let s = info.seven_zip.clone().expect("7z crypt info parsed");
        assert!(!s.header_encrypted, "raw kHeader flavour");
        assert_eq!(s.pack_size, 48);
        assert_eq!(s.aes_out_size, 46);
        assert_eq!(s.pad_len(), 2);
        assert_eq!(s.data_offset, 32, "PackPos 0 is relative to offset 32");
        assert_eq!(s.crc, 0x692f_78b7, "substream CRC");
        assert_eq!(s.crc_len, 46, "first substream size");
        assert_eq!(s.crc_kind, SevenZipCrcKind::SubStream, "CRC came from kSubStreamsInfo");
        assert_eq!(s.trailing_coders, vec![vec![0x00u8]], "AES + COPY");
    }

    /// PAD == 0 with a CRC available: still native. The padding filter is
    /// simply skipped -- refusing here would push a perfectly verifiable
    /// archive onto the external tool.
    #[test]
    fn sevenzip_content_encrypted_pad_zero_still_native() {
        let p = sz_temp("nosalt.7z", &from_hex(SZ_NOSALT));
        let info = parse(&p.display().to_string());
        assert!(info.native_supported(), "PAD==0 content archive is native via CRC");
        let s = info.seven_zip.clone().expect("7z crypt info parsed");
        assert_eq!(s.pad_len(), 0, "one AES block, no padding");
        assert_eq!(s.crc, 0x6d9d_227b);
        assert_eq!(s.crc_len, 16);
        assert_eq!(s.crc_kind, SevenZipCrcKind::Folder);
        assert_eq!(s.iv, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99]);
    }

    #[test]
    fn sevenzip_content_encrypted_lzma2_needs_decompressor() {
        let p = sz_temp("lzma2.7z", &from_hex(SZ_PLAIN_LZMA2));
        let info = parse(&p.display().to_string());
        assert!(info.seven_zip.is_none(), "AES+LZMA2 content is not native");
        assert!(!info.native_supported());
        assert!(info.detect_note.contains("external"), "got {:?}", info.detect_note);
    }

    /// An encoded header whose coder chain has no AES id must NOT be reported
    /// natively, and the note must not CLAIM the archive is unencrypted.
    ///
    /// The fixture is a content-encrypted archive (`7z t -popenwall` succeeds,
    /// `-pwrongpw` fails) whose header is LZMA1-compressed, so the AES coder
    /// sits inside the compressed stream and `06F10701` appears ZERO times in
    /// the file. A note that asserted "not encrypted" would therefore be a
    /// false statement about a password-protected archive; the wording has to
    /// stay doubtful. (`crack` correctness does not depend on this note: the
    /// archive falls back to the external tool either way.)
    #[test]
    fn sevenzip_encoded_header_without_aes_coder_falls_back_with_doubtful_note() {
        let p = sz_temp("many.7z", &from_hex(SZ_PLAIN_MANY));
        assert_eq!(
            from_hex(SZ_PLAIN_MANY).windows(4).filter(|w| *w == [0x06, 0xF1, 0x07, 0x01]).count(),
            0,
            "fixture must genuinely hide the AES coder (compressed header)"
        );
        let info = parse(&p.display().to_string());
        assert_eq!(info.kind, ArchiveKind::SevenZip);
        assert!(info.seven_zip.is_none(), "no AES coder -> nothing to verify");
        assert!(!info.native_supported());
        assert!(
            info.detect_note.contains("may be compressed"),
            "note must hedge: the header may be compressed, got {:?}",
            info.detect_note
        );
        assert!(
            !info.detect_note.contains("not encrypted"),
            "note must not assert the archive is unencrypted, got {:?}",
            info.detect_note
        );
    }

    /// A stored, single-file, unencrypted `7z a` (7-Zip reports
    /// `Encrypted = -` for it): raw kHeader, and the only coder is `k_Copy`,
    /// so the AES id never appears. This is the shape where "no AES coder"
    /// genuinely means "no encryption" -- the counterpart to the compressed
    /// header case above, where the same absence proves nothing.
    #[test]
    fn sevenzip_unencrypted_raw_header_falls_back() {
        let info = parse(&sz_temp("plaincopy.7z", &from_hex(SZ_PLAIN_COPY_ONLY)).display().to_string());
        assert_eq!(info.kind, ArchiveKind::SevenZip);
        assert!(info.seven_zip.is_none(), "unencrypted archive has nothing to verify");
        assert!(!info.native_supported(), "must not claim native support");
        assert!(
            info.detect_note.contains("no AES coder"),
            "note names the cause, got {:?}",
            info.detect_note
        );
    }

    /// ncp is attacker-controlled; 2^31 rounds would hang the engine, so the
    /// ceiling has to be enforced in the parser and explained in the note.
    #[test]
    fn sevenzip_ncp_above_ceiling_falls_back() {
        let mut blob = from_hex(SZ_MHE_LZMA2);
        let nh = 32 + u64::from_le_bytes(blob[12..20].try_into().unwrap()) as usize;
        patch_byte(&mut blob, nh + 18, 0x53, 0x59); // ncp 19 -> 25
        refix_sevenzip_crcs(&mut blob);
        let info = parse(&sz_temp("ncp.7z", &blob).display().to_string());
        assert!(info.seven_zip.is_none(), "ncp above the ceiling is not native");
        assert!(info.detect_note.contains("25"), "note names the value, got {:?}", info.detect_note);
    }

    /// ncp = 0x3F is the documented 7-Zip special value: the key is
    /// (salt || password)[:32] with NO hashing at all, so it is the cheapest
    /// possible case and must not be mistaken for "too many rounds".
    #[test]
    fn sevenzip_ncp_special_value_0x3f_is_native() {
        let mut blob = from_hex(SZ_MHE_LZMA2);
        let nh = 32 + u64::from_le_bytes(blob[12..20].try_into().unwrap()) as usize;
        // props[0] = 0x53 = ncp 0x13 | iv-present bit 0x40; set ncp to 0x3F
        // while keeping the IV bit, i.e. 0x3F | 0x40 = 0x7F
        patch_byte(&mut blob, nh + 18, 0x53, 0x7F);
        refix_sevenzip_crcs(&mut blob);
        let info = parse(&sz_temp("ncp3f.7z", &blob).display().to_string());
        assert!(info.native_supported(), "ncp=0x3F needs no hashing, so it is native");
        let s = info.seven_zip.clone().expect("7z crypt info parsed");
        assert_eq!(s.ncp, 0x3F);
        assert_eq!(s.salt.len(), 0, "0x53 also encodes saltSize=0; still no salt");
        assert_eq!(s.iv.len(), 16, "the IV bit must survive the ncp change");
    }

    /// A packed stream larger than the per-candidate buffer cap must fall back
    /// AT PARSE TIME. Deciding it at verify time instead would turn "cannot
    /// check this archive" into "every password is wrong", which the engine
    /// would report as an exhausted dictionary rather than as a limitation.
    #[test]
    fn sevenzip_oversized_pack_stream_falls_back_at_parse_time() {
        let mut blob = from_hex(SZ_MHE_LZMA2);
        let nh = 32 + u64::from_le_bytes(blob[12..20].try_into().unwrap()) as usize;
        assert_eq!(blob[nh + 5], 0x70, "PackSize encoding (112)");
        // PackSize = 0x1000001 (16 MiB + 1) encodes as e1 01 00 00: 0xE1 means
        // three following LE bytes, high part 1
        blob[nh + 5] = 0xE1;
        blob.insert(nh + 6, 0x01);
        blob.insert(nh + 7, 0x00);
        blob.insert(nh + 8, 0x00);
        blob[20..28].copy_from_slice(&49u64.to_le_bytes()); // 46 + 3
        refix_sevenzip_crcs(&mut blob);
        let info = parse(&sz_temp("bigpack.7z", &blob).display().to_string());
        assert!(info.seven_zip.is_none(), "oversized pack stream must not claim native support");
        assert!(!info.native_supported());
        assert!(
            info.detect_note.contains("external"),
            "note points at the external tool, got {:?}",
            info.detect_note
        );
    }

    #[test]
    fn sevenzip_aes_out_larger_than_pack_size_falls_back() {
        let mut blob = from_hex(SZ_MHE_LZMA2);
        let nh = 32 + u64::from_le_bytes(blob[12..20].try_into().unwrap()) as usize;
        patch_byte(&mut blob, nh + 37, 0x6a, 0x78); // 106 -> 120 > PackSize 112
        refix_sevenzip_crcs(&mut blob);
        let info = parse(&sz_temp("negative.7z", &blob).display().to_string());
        assert!(info.seven_zip.is_none(), "PAD < 0 means the header is corrupt");
        assert!(!info.native_supported());
    }

    /// Truncation, a broken signature header CRC and a broken next-header CRC
    /// must all end in "fall back", never in a panic or a wrong "native".
    #[test]
    fn sevenzip_damaged_containers_fall_back() {
        let good = from_hex(SZ_MHE_LZMA2);
        for cut in [6usize, 16, 31, 40, 200, 240] {
            let p = sz_temp(&format!("cut{}.7z", cut), &good[..cut.min(good.len())]);
            let info = parse(&p.display().to_string());
            assert!(!info.native_supported(), "truncated at {} must not be native", cut);
        }
        let mut bad_start = good.clone();
        bad_start[8] ^= 0xFF;
        assert!(
            parse(&sz_temp("badstart.7z", &bad_start).display().to_string()).seven_zip.is_none(),
            "bad StartHeaderCRC must not parse"
        );
        let mut bad_nh = good.clone();
        bad_nh[240] ^= 0xFF;
        assert!(
            parse(&sz_temp("badnh.7z", &bad_nh).display().to_string()).seven_zip.is_none(),
            "bad NextHeaderCRC must not parse"
        );
    }

    /// The properties bit packing, including the two traps: the two extra bits
    /// are worth +1 (not +16) and the whole array may be a single byte.
    #[test]
    fn sevenzip_aes_props_bit_unpacking() {
        // real -mhe props: ncp=19, saltSize=0, ivSize=16
        let (salt, iv, ncp) = decode_aes_props(&from_hex("530f8e45617a6034f50691dc43d5a0a7784e")).unwrap();
        assert_eq!(ncp, 19);
        assert!(salt.is_empty(), "no salt");
        assert_eq!(iv.to_vec(), from_hex("8e45617a6034f50691dc43d5a0a7784e"));
        let (salt, iv, ncp) = decode_aes_props(&[0x13]).unwrap();
        assert_eq!((salt.len(), ncp), (0, 19));
        assert_eq!(iv, [0u8; 16], "an absent IV reads as zeros");
        // bit7/bit6 + 1: saltSize 16 (0xd3 0xff) and ivSize 16
        let mut props = from_hex("d3ff");
        props.extend(0u8..16);
        props.extend(16u8..32);
        let (salt, iv, ncp) = decode_aes_props(&props).unwrap();
        assert_eq!((ncp, salt.len(), iv.len()), (19, 16, 16));
        assert_eq!(iv[0], 16);
        // the +1 is not +16: saltSize = bit7 + high nibble
        let mut props = from_hex("d30f");
        props.push(0xAA); // saltSize = 1 + 0 = 1
        props.extend(0u8..16);
        let (salt, iv, _) = decode_aes_props(&props).unwrap();
        assert_eq!(salt, vec![0xAA], "saltSize 1");
        assert_eq!(iv.len(), 16);
        // a short IV is right-zero-padded to 16 at use time (real ivSize=8 props)
        let mut props = from_hex("5307");
        props.extend(from_hex("0102030405060708"));
        let (salt, iv, ncp) = decode_aes_props(&props).unwrap();
        assert_eq!((ncp, salt.len()), (19, 0));
        assert_eq!(iv, [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0], "zero-padded on the right");
        // length mismatches, and a 2-byte array claiming no salt/IV, are errors
        assert!(decode_aes_props(&from_hex("530f00")).is_none(), "truncated iv");
        assert!(decode_aes_props(&[0x13, 0x08]).is_none(), "2 bytes but no salt/iv bits");
        assert!(decode_aes_props(&[]).is_none(), "empty props");
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

    // ---- RAR4 gold samples -------------------------------------------------
    // Byte-for-byte minimal RAR 4.x archives generated offline and verified
    // against the gold standard (7z.exe t and UnRAR.exe t both accept the
    // right password and reject wrong ones). WinRAR 7.12 cannot create RAR4,
    // so the fixtures are embedded as hex literals.

    fn rar4_p_sample() -> Vec<u8> {
        const HEX: &str = concat!(
            "526172211a0700cf907300000d000000000000005ae17404843000200000001d00000003",
            "17dabb7e000000501d30080020000000676f6c642e74787411c3a54f8e2b90d1211b0f19",
            "0c49038d823063bf4407acdd11a4a4548ae77eb1e43543531f4e3861c43d7b00400700"
        );
        (0..HEX.len() / 2)
            .map(|i| u8::from_str_radix(&HEX[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    fn rar4_hp_sample() -> Vec<u8> {
        const HEX: &str = concat!(
            "526172211a0700ce997380000d000000000000002b91d04c6e88f71551ec4427d1525719",
            "3c8498c3f5d9a217d44725a3c16fe7b6b845e34bef23412d6fce3bbc05248fad73506e52",
            "badf2f2769f960be8d8c16903627623886af1a90c348e1358c92c40c88f5282b428f492c",
            "77e2b0a41d9c5f38626d22a5386ea6908ae7e906a91e543a"
        );
        (0..HEX.len() / 2)
            .map(|i| u8::from_str_radix(&HEX[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rar4_p_sample_parses() {
        let p = write_temp("rar4p", "gold.rar", &rar4_p_sample());
        let info = parse(&p.display().to_string());
        assert_eq!(info.kind, ArchiveKind::RarLegacy, "detected as rar4");
        let r = info.rar4.clone().expect("rar4 crypt info parsed");
        assert!(!r.header_encrypted, "-p flavour");
        assert_eq!(r.salt, [0x11, 0xc3, 0xa5, 0x4f, 0x8e, 0x2b, 0x90, 0xd1], "per-file salt");
        assert_eq!(r.data_offset, 68, "7 marker + 13 main + 48 file header");
        assert_eq!(r.pack_size, 32);
        assert_eq!(r.unp_size, 29);
        assert_eq!(r.file_crc, 0x7ebbda17);
        assert_eq!(r.method, 0x30, "stored");
        assert_eq!(r.entry_name.as_deref(), Some("gold.txt"));
        assert!(info.native_supported(), "rar4 -p is native");
    }

    #[test]
    fn rar4_hp_sample_parses() {
        let p = write_temp("rar4hp", "goldhp.rar", &rar4_hp_sample());
        let info = parse(&p.display().to_string());
        assert_eq!(info.kind, ArchiveKind::RarLegacy, "detected as rar4");
        let r = info.rar4.clone().expect("rar4 crypt info parsed");
        assert!(r.header_encrypted, "-hp flavour");
        assert_eq!(r.salt, [0x77, 0xe2, 0xb0, 0xa4, 0x1d, 0x9c, 0x5f, 0x38], "tail salt");
        let check = r.check_block.expect("encrypted end block captured");
        assert_eq!(&check[..], &rar4_hp_sample()[132 - 16..], "check block = last 16 bytes");
        assert!(info.native_supported(), "rar4 -hp is native");
    }

    #[test]
    fn rar4_garbage_falls_back_to_external() {
        // truncated / corrupted RAR4 must parse to None (spawn fallback),
        // never panic or misreport native support
        for cut in [7usize, 10, 19, 40, 90] {
            let data = &rar4_p_sample()[..cut.min(rar4_p_sample().len())];
            let p = write_temp("rar4bad", format!("cut{}.rar", cut).as_str(), data);
            let info = parse(&p.display().to_string());
            assert!(info.rar4.is_none(), "cut {} must not parse", cut);
            assert!(!info.native_supported(), "cut {} not native", cut);
        }
        // corrupted MAIN CRC
        let mut bad = rar4_p_sample();
        bad[7] ^= 0xFF;
        let p = write_temp("rar4bad", "crc.rar", &bad);
        assert!(parse(&p.display().to_string()).rar4.is_none(), "bad main crc");
    }
}
