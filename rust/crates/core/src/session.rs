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

    #[test]
    fn roundtrip() {
        let dir = std::env::temp_dir().join(format!("dcsess-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("session.json");
        let s = SessionState {
            archive: "D:\\x.rar".into(),
            params: "abc".into(),
            dictfp: Some("fp".into()),
            tried_all: 42,
            file_idx: 1,
            line_idx: 7,
            seg: 3,
            counter: 99,
            idx_a: 5,
            idx_b: 6,
            save_time_text: "2026-10-05".into(),
        };
        assert!(s.save(&p));
        let l = SessionState::load(&p).unwrap();
        assert_eq!(l.tried_all, 42);
        assert_eq!(l.counter, 99);
        assert_eq!(l.line_idx, 7);
        assert!(l.matches("d:\\X.rar", "abc", Some("fp")));
        assert!(!l.matches("d:\\X.rar", "abc", Some("other")));
        assert!(!l.matches("d:\\X.rar", "different", Some("fp")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
