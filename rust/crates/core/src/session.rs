// session.rs -- session.json load/save, fingerprint validation, rewind margin.
// Port of SessionState in Engine.cs. JSON field names must match the C#
// hand-rolled format exactly for cross-implementation --resume.
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionState {
    pub archive: String,
    pub params: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dictfp: Option<String>,
    #[serde(rename = "tried", default)]
    pub tried_all: i64,
    #[serde(rename = "fileIdx", default)]
    pub file_idx: i64,
    #[serde(rename = "lineIdx", default)]
    pub line_idx: i64,
    #[serde(default)]
    pub seg: i64,
    #[serde(default)]
    pub counter: u64,
    #[serde(rename = "idxA", default)]
    pub idx_a: i64,
    #[serde(rename = "idxB", default)]
    pub idx_b: i64,
    #[serde(rename = "saveTime", default)]
    pub save_time_text: String,
}

impl SessionState {
    pub fn matches(&self, archive: &str, params_hash: &str, dict_fp: Option<&str>) -> bool {
        if !self.archive.eq_ignore_ascii_case(archive) || self.params != params_hash {
            return false;
        }
        match dict_fp {
            // fingerprint unavailable: keep the old lenient behavior
            None => true,
            // sessions saved before this field existed fail for dict runs
            // (safe restart), mirroring the C# semantics
            Some(fp) => self.dictfp.as_deref() == Some(fp),
        }
    }

    /// Serialises the session atomically (write .tmp, then replace). The JSON
    /// is hand-built so the field order matches the C# hand-rolled writer
    /// exactly (archive, params, dictfp, tried, fileIdx, lineIdx, seg,
    /// counter, idxA, idxB, saveTime), UTF-8 no BOM. Returns false when the
    /// exe directory is not writable.
    pub fn save(&self, path: &PathBuf) -> bool {
        let mut sb = String::from("{\n");
        append_kv(&mut sb, "archive", &self.archive);
        sb.push_str(",\n");
        append_kv(&mut sb, "params", &self.params);
        sb.push_str(",\n");
        append_kv(&mut sb, "dictfp", self.dictfp.as_deref().unwrap_or(""));
        sb.push_str(",\n");
        sb.push_str(&format!("  \"tried\": {},\n", self.tried_all));
        sb.push_str(&format!("  \"fileIdx\": {},\n", self.file_idx));
        sb.push_str(&format!("  \"lineIdx\": {},\n", self.line_idx));
        sb.push_str(&format!("  \"seg\": {},\n", self.seg));
        sb.push_str(&format!("  \"counter\": {},\n", self.counter));
        sb.push_str(&format!("  \"idxA\": {},\n", self.idx_a));
        sb.push_str(&format!("  \"idxB\": {},\n", self.idx_b));
        append_kv(&mut sb, "saveTime", &self.save_time_text);
        sb.push('\n');
        sb.push_str("}\n");
        let tmp = path.with_extension("json.tmp");
        if fs::write(&tmp, sb).is_err() {
            return false;
        }
        if fs::rename(&tmp, path).is_err() {
            let _ = fs::copy(&tmp, path);
            let _ = fs::remove_file(&tmp);
        }
        true
    }

    /// Reads back a file written by save; tolerant of a missing/corrupt file -
    /// returns None, callers treat that as "no session" and start over.
    pub fn load(path: &PathBuf) -> Option<SessionState> {
        let text = fs::read_to_string(path).ok()?;
        let s: SessionState = serde_json::from_str(&text).ok()?;
        if s.archive.is_empty() {
            return None;
        }
        Some(s)
    }
}

/// session.json lives next to the executable - every crack-time artifact
/// stays next to the exe, never on C:.
pub fn session_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("session.json")
}

/// JSON string-value append with the same escaping as the C# AppendKv:
/// backslash/quote escaped, control chars as \uXXXX.
fn append_kv(sb: &mut String, key: &str, val: &str) {
    sb.push_str("  \"");
    sb.push_str(key);
    sb.push_str("\": \"");
    for c in val.chars() {
        match c {
            '\\' | '"' => {
                sb.push('\\');
                sb.push(c);
            }
            c if (c as u32) < 0x20 => {
                sb.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => sb.push(c),
        }
    }
    sb.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("dcsess-{}-{}", tag, std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        d
    }

    // C# TestSessionRoundTrip: backslash+CJK path, embedded quote, i64/u64
    // extremes, control char in saveTime - and the exact JSON escaping the
    // C# hand-rolled writer produces.
    #[test]
    fn roundtrip() {
        let dir = temp_dir("rt");
        let p = dir.join("session.json");
        let s = SessionState {
            archive: "D:\\test\\\u{6863}\u{6848}.rar".into(), // backslash + CJK
            params: "ab\"cd".into(),                          // quote escape
            dictfp: Some("123:456;".into()),
            tried_all: 12_345_678_901,
            file_idx: 2,
            line_idx: 34567,
            seg: 4,
            counter: u64::MAX,
            idx_a: 9,
            idx_b: 10,
            save_time_text: "12:00:00\nx".into(), // control char escape
        };
        assert!(s.save(&p));
        let l = SessionState::load(&p).unwrap();
        assert_eq!(l.archive, s.archive);
        assert_eq!(l.params, s.params);
        assert_eq!(l.dictfp, s.dictfp);
        assert_eq!(l.tried_all, s.tried_all);
        assert_eq!(l.file_idx, 2);
        assert_eq!(l.line_idx, 34567);
        assert_eq!(l.seg, 4);
        assert_eq!(l.counter, u64::MAX);
        assert_eq!(l.idx_a, 9);
        assert_eq!(l.idx_b, 10);
        assert_eq!(l.save_time_text, "12:00:00\nx");

        // the escaping matches the C# AppendKv byte-for-byte (cross-impl
        // resume only needs value equality, but the shape keeps diffs sane)
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("\"archive\": \"D:\\\\test\\\\\u{6863}\u{6848}.rar\""), "{}", text);
        assert!(text.contains("\"params\": \"ab\\\"cd\""), "{}", text);
        assert!(text.contains("\"saveTime\": \"12:00:00\\u000ax\""), "{}", text);
        assert!(!text.starts_with("\u{FEFF}"), "UTF-8 no BOM");

        // garbage is not a session
        std::fs::write(&p, "this is not json {{{").unwrap();
        assert!(SessionState::load(&p).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn matches_semantics() {
        let s = SessionState {
            archive: "D:\\x.rar".into(),
            params: "abc".into(),
            dictfp: Some("fp".into()),
            ..Default::default()
        };
        // archive compares case-insensitively (C# OrdinalIgnoreCase)
        assert!(s.matches("d:\\X.rar", "abc", Some("fp")));
        assert!(!s.matches("d:\\X.rar", "abc", Some("other")), "dictfp mismatch rejects");
        assert!(!s.matches("d:\\X.rar", "different", Some("fp")), "params mismatch rejects");
        assert!(!s.matches("d:\\other.rar", "abc", Some("fp")), "archive mismatch rejects");
        // fingerprint unavailable: lenient (C# dictFp == null branch)
        assert!(s.matches("d:\\X.rar", "abc", None));
    }
}
