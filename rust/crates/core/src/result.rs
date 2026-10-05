// result.rs -- result file writing: GBK(936) preferred with a lossless check,
// falling back to UTF-8 with BOM. Never depends on the machine's ANSI code
// page, so en-US CI regions cannot corrupt a Chinese password. Port of
// WriteResultText in Engine.cs.
use std::fs;
use std::path::PathBuf;

/// Writes the found password to `path`. GBK is preferred so a Chinese
/// Notepad reads it directly, but a password GBK cannot represent (emoji,
/// rare chars) is written as UTF-8 with BOM instead. The body is exactly
/// `password + CRLF`, matching the C# WriteResultText byte-for-byte.
pub fn write_result_text(path: &PathBuf, password: &str) -> std::io::Result<()> {
    let body = format!("{}\r\n", password);
    let bytes = match encode_gbk_lossless(&body) {
        Some(b) => b,
        None => {
            let mut b = vec![0xEF, 0xBB, 0xBF]; // UTF-8 BOM
            b.extend_from_slice(body.as_bytes());
            b
        }
    };
    fs::write(path, bytes)
}

/// GBK-encode, returning None when any character is not representable
/// (encoding_rs reports had_errors on unmappable chars).
fn encode_gbk_lossless(s: &str) -> Option<Vec<u8>> {
    let (cow, _, had_errors) = encoding_rs::GBK.encode(s);
    if had_errors {
        None
    } else {
        Some(cow.into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chinese_goes_gbk() {
        let dir = std::env::temp_dir().join(format!("dcres-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("r.txt");
        write_result_text(&p, "密码abc123").unwrap();
        let bytes = std::fs::read(&p).unwrap();
        // GBK: no UTF-8 BOM, and decodes back via GBK
        assert!(!(bytes.starts_with(&[0xEF, 0xBB, 0xBF])));
        let (dec, _, _) = encoding_rs::GBK.decode(&bytes);
        assert!(dec.contains("密码abc123"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emoji_falls_back_utf8() {
        let dir = std::env::temp_dir().join(format!("dcres2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("r.txt");
        write_result_text(&p, "pw🎉").unwrap();
        let bytes = std::fs::read(&p).unwrap();
        assert!(bytes.starts_with(&[0xEF, 0xBB, 0xBF]));
        let text = String::from_utf8_lossy(&bytes[3..]).into_owned();
        assert!(text.contains("pw🎉"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn trailing_backslash_survives_gbk() {
        // backslash is GBK-representable and must not be eaten or doubled
        let dir = std::env::temp_dir().join(format!("dcres3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("r.txt");
        write_result_text(&p, "abc\\").unwrap();
        let bytes = std::fs::read(&p).unwrap();
        assert!(!bytes.starts_with(&[0xEF, 0xBB, 0xBF]), "stays GBK (no BOM)");
        let (dec, _, had_errors) = encoding_rs::GBK.decode(&bytes);
        assert!(!had_errors);
        assert!(dec.contains("abc\\"), "roundtrips: {:?}", dec);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
