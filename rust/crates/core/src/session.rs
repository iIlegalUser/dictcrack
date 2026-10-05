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

    /// Serialises the session atomically (write .tmp, then replace). Returns
    /// false when the exe directory is not writable - the engine turns that
    /// into a visible warning instead of silently losing resume support.
    pub fn save(&self, path: &PathBuf) -> bool {
        // field order matches the C# hand-rolled JSON exactly
        let mut map = serde_json::Map::new();
        map.insert("archive".into(), serde_json::Value::String(self.archive.clone()));
        map.insert("params".into(), serde_json::Value::String(self.params.clone()));
        if let Some(fp) = &self.dictfp {
            map.insert("dictfp".into(), serde_json::Value::String(fp.clone()));
        }
        map.insert("tried".into(), self.tried_all.into());
        map.insert("fileIdx".into(), self.file_idx.into());
        map.insert("lineIdx".into(), self.line_idx.into());
        map.insert("seg".into(), self.seg.into());
        map.insert("counter".into(), self.counter.into());
        map.insert("idxA".into(), self.idx_a.into());
        map.insert("idxB".into(), self.idx_b.into());
        map.insert("saveTime".into(), serde_json::Value::String(self.save_time_text.clone()));
        let text = serde_json::to_string_pretty(&serde_json::Value::Object(map)).unwrap_or_default() + "\n";
        let tmp = path.with_extension("json.tmp");
        if fs::write(&tmp, text).is_err() {
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
