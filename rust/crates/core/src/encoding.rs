// encoding.rs -- dictionary encoding plan: BOM detection, strict UTF-8 probe,
// GBK dual-pass. Port of the DictEncoding logic in Attacks.cs.
//
// .NET side used Encoding.GetEncoding(936) (GBK). encoding_rs has no plain
// "GBK"; its GBK label maps to the GB18030 decoder, which is a superset that
// accepts the same GBK byte range we sweep, so it is a drop-in for the
// dictionary decode path. The (rare) mapping differences are covered by the
// e2e encoding matrix.
use std::fs::File;
use std::io::Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enc {
    Utf8,
    Utf16Le,
    Utf16Be,
    Gbk,
}

impl Enc {
    pub fn label(self) -> &'static str {
        match self {
            Enc::Utf8 => "UTF-8",
            Enc::Utf16Le => "UTF-16LE",
            Enc::Utf16Be => "UTF-16BE",
            Enc::Gbk => "ANSI(GBK)",
        }
    }
    pub fn is_utf16(self) -> bool {
        matches!(self, Enc::Utf16Le | Enc::Utf16Be)
    }
}

pub struct Plan {
    pub encs: Vec<Enc>,
    pub note: String,
    pub bom_skip: u64,
}

/// Plans which encodings a dictionary should be tried under. A BOM pins the
/// encoding; without a BOM the first 256 KB are strict-decoded as UTF-8 -
/// valid text sweeps UTF-8 + ANSI(GBK), anything else runs GBK only. The
/// probe can only add encodings, never skip one a hit could appear in.
/// Port of DictEncoding.Plan (stream variant).
pub fn plan_bytes(head: &[u8], total_len: u64) -> Plan {
    let b = |i: usize| head.get(i).copied().unwrap_or(0);
    if b(0) == 0xEF && b(1) == 0xBB && b(2) == 0xBF {
        return Plan { encs: vec![Enc::Utf8], note: "UTF-8 (BOM)".into(), bom_skip: 3 };
    }
    if b(0) == 0xFF && b(1) == 0xFE {
        return Plan { encs: vec![Enc::Utf16Le], note: "UTF-16LE (BOM)".into(), bom_skip: 0 };
    }
    if b(0) == 0xFE && b(1) == 0xFF {
        return Plan { encs: vec![Enc::Utf16Be], note: "UTF-16BE (BOM)".into(), bom_skip: 0 };
    }
    // no BOM: strict-decode the probe as UTF-8; trim trailing high bytes so a
    // cut inside a multibyte sequence cannot fake an illegal one.
    let probe_len = head.len().min(262144);
    let mut buf = &head[..probe_len];
    if (probe_len as u64) < total_len {
        let mut valid = probe_len;
        while valid > 0 && buf[valid - 1] >= 0x80 {
            valid -= 1;
        }
        buf = &buf[..valid];
    }
    if std::str::from_utf8(buf).is_ok() {
        return Plan { encs: vec![Enc::Utf8, Enc::Gbk], note: "UTF-8 + ANSI(GBK)".into(), bom_skip: 0 };
    }
    Plan { encs: vec![Enc::Gbk], note: "ANSI(GBK)".into(), bom_skip: 0 }
}

/// Convenience: plan from a file path by reading its head.
pub fn plan_file(path: &str) -> Plan {
    match File::open(path) {
        Ok(mut f) => {
            let total = f.metadata().map(|m| m.len()).unwrap_or(0);
            let mut head = vec![0u8; 262144.min(total as usize)];
            let _ = f.read(&mut head);
            plan_bytes(&head, total)
        }
        Err(_) => Plan { encs: vec![Enc::Gbk], note: "ANSI(GBK)".into(), bom_skip: 0 },
    }
}

/// Decode one raw line under the given encoding. Returns None when the
/// encoding strictly rejects the bytes (the next planned encoding still runs).
pub fn decode(enc: Enc, bytes: &[u8]) -> Option<String> {
    match enc {
        Enc::Utf8 => std::str::from_utf8(bytes).ok().map(|s| s.to_string()),
        Enc::Utf16Le => decode_utf16(bytes, false),
        Enc::Utf16Be => decode_utf16(bytes, true),
        Enc::Gbk => {
            let (cow, _, had_errors) = encoding_rs::GBK.decode(bytes);
            if had_errors {
                // a strict encoding may reject foreign bytes; treat as no-decode
                // for this line (mirrors the .NET strict-throw fallback)
                None
            } else {
                Some(cow.into_owned())
            }
        }
    }
}

fn decode_utf16(bytes: &[u8], be: bool) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| {
            if be {
                u16::from_be_bytes([c[0], c[1]])
            } else {
                u16::from_le_bytes([c[0], c[1]])
            }
        })
        .collect();
    String::from_utf16(&units).ok()
}

/// UTF-16 body with a leading BOM removed. The C# path decodes UTF-16
/// dictionaries through StreamReader, which consumes the BOM itself; plan()
/// reports bom_skip=0 for UTF-16 (the byte-level splitter never sees those
/// files), so the UTF-16 branches must strip it here instead - otherwise the
/// first line carries a U+FEFF and can never match.
pub fn strip_utf16_bom(bytes: &[u8]) -> &[u8] {
    if bytes.len() >= 2
        && ((bytes[0] == 0xFF && bytes[1] == 0xFE) || (bytes[0] == 0xFE && bytes[1] == 0xFF))
    {
        &bytes[2..]
    } else {
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bom_utf8() {
        let p = plan_bytes(&[0xEF, 0xBB, 0xBF, b'a'], 4);
        assert_eq!(p.encs, vec![Enc::Utf8]);
        assert_eq!(p.bom_skip, 3);
    }

    #[test]
    fn gbk_decode() {
        // "密码" in GBK
        let gbk = encoding_rs::GBK.encode("密码").0;
        assert_eq!(decode(Enc::Gbk, &gbk), Some("密码".to_string()));
    }

    #[test]
    fn utf8_then_gbk_plan() {
        let p = plan_bytes("hello world".as_bytes(), 11);
        assert_eq!(p.encs, vec![Enc::Utf8, Enc::Gbk]);
    }
}
