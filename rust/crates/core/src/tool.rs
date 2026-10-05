// tool.rs -- 7z.exe / rar.exe location, per-tool command-line quoting, and the
// spawn verifier for everything the native paths cannot handle (RAR4, 7z,
// -hp without check data, ...). Port of ToolLocator / WinArg / SpawnVerifier.
use crate::verifier::Verifier;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

// ------------------------------------------------------------------
// command-line quoting. There is no single correct quoting: 7z.exe parses
// the RAW command line itself (backslashes always literal, "" collapses to
// one quote, trailing backslash must NOT be doubled), while rar.exe/unrar.exe
// are standard CRT argv programs (\" escapes a quote and backslash runs
// before a quote must be doubled). Port of WinArg.
pub struct WinArg;

impl WinArg {
    /// 7z family (7z.exe/7za/7zr/7zG): self-parsing, doubling rules.
    pub fn simple_quote(s: &str) -> String {
        format!("\"{}\"", s.replace('"', "\"\""))
    }

    /// standard CRT/CommandLineToArgvW escaping. Port of WinArg.Quote.
    pub fn quote(s: &str) -> String {
        let mut sb = String::with_capacity(s.len() + 8);
        sb.push('"');
        let mut slashes = 0usize;
        for c in s.chars() {
            if c == '\\' {
                slashes += 1;
                continue;
            }
            if c == '"' {
                for _ in 0..(slashes * 2 + 1) {
                    sb.push('\\');
                }
                slashes = 0;
            } else if slashes > 0 {
                for _ in 0..slashes {
                    sb.push('\\');
                }
                slashes = 0;
            }
            sb.push(c);
        }
        for _ in 0..(slashes * 2) {
            sb.push('\\');
        }
        sb.push('"');
        sb
    }

    /// one-stop helper: quote value for the tool being spawned.
    pub fn quote_for_tool(tool_path: &str, value: &str) -> String {
        let name = Path::new(tool_path)
            .file_name()
            .map(|s| s.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if name.starts_with("7z") {
            Self::simple_quote(value)
        } else {
            Self::quote(value)
        }
    }
}

// ------------------------------------------------------------------
pub struct ToolLocator;

impl ToolLocator {
    /// returns a 7z.exe/rar.exe for the spawn fallback; the native paths
    /// never need it. Port of ToolLocator.FindExtractor.
    pub fn find_extractor() -> Option<String> {
        if let Ok(env) = std::env::var("DICTCRACK_TOOL") {
            if !env.is_empty() && Path::new(&env).exists() {
                return Some(env);
            }
        }
        let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
        let pf86 = std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| r"C:\Program Files (x86)".into());
        let candidates = [
            r"D:\Software\Scoop\shims\7z.exe".to_string(),
            Path::new(&pf).join(r"7-Zip\7z.exe").display().to_string(),
            Path::new(&pf).join(r"WinRAR\rar.exe").display().to_string(),
            Path::new(&pf86).join(r"7-Zip\7z.exe").display().to_string(),
            r"D:\Software\WinRAR\rar.exe".to_string(),
        ];
        for c in &candidates {
            if Path::new(c).exists() {
                return Some(c.clone());
            }
        }
        for name in ["7z.exe", "rar.exe", "unrar.exe"] {
            if let Some(p) = Self::probe(name) {
                return Some(p);
            }
        }
        None
    }

    fn probe(exe: &str) -> Option<String> {
        let path_var = std::env::var("PATH").unwrap_or_default();
        for dir in path_var.split(';') {
            if dir.is_empty() {
                continue;
            }
            let p = PathBuf::from(dir.trim()).join(exe);
            if p.exists() {
                return Some(p.display().to_string());
            }
        }
        None
    }
}

// ------------------------------------------------------------------
// everything the native paths cannot handle goes through `7z t -p<pwd>`.
pub struct SpawnVerifier {
    tool: String,
    archive_path: String,
}

impl SpawnVerifier {
    pub fn new(tool: String, archive_path: String) -> Self {
        SpawnVerifier { tool, archive_path }
    }
}

impl Verifier for SpawnVerifier {
    fn describe(&self) -> String {
        let name = Path::new(&self.tool).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        format!("external tool test ({})", name)
    }

    fn verify(&self, password: &str) -> bool {
        if password.contains('\r') || password.contains('\n') {
            return false;
        }
        // pass each argument raw with the tool's own quoting applied: 7z.exe
        // re-parses the raw command line itself (doubling form) while
        // rar.exe is a CRT argv program, so std's automatic escaping (which
        // follows neither rule) must be bypassed with raw_arg
        let pwd_arg = format!("-p{}", WinArg::quote_for_tool(&self.tool, password));
        let arch_arg = WinArg::quote_for_tool(&self.tool, &self.archive_path);
        let status = Command::new(&self.tool)
            .arg("t")
            .arg("-y")
            .raw_arg(&pwd_arg)
            .raw_arg(&arch_arg)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match status {
            Ok(s) => s.success(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_quote_doubles_quotes() {
        assert_eq!(WinArg::simple_quote("a\"b"), "\"a\"\"b\"");
        assert_eq!(WinArg::simple_quote("endbs\\"), "\"endbs\\\"");
    }

    #[test]
    fn crt_quote_trailing_backslash() {
        // abc\ must arrive as "abc\\" so the child receives abc\
        assert_eq!(WinArg::quote("abc\\"), "\"abc\\\\\"");
        assert_eq!(WinArg::quote("a\"b"), "\"a\\\"b\"");
    }

    #[test]
    fn per_tool_selection() {
        assert_eq!(WinArg::quote_for_tool(r"C:\7-Zip\7z.exe", "x\\"), "\"x\\\"");
        assert_eq!(WinArg::quote_for_tool(r"C:\WinRAR\rar.exe", "x\\"), "\"x\\\\\"");
    }

    // full matrix from the C# TestWinArgQuote (rules verified against the
    // real 7z.exe/rar.exe by round-tripping actual passwords)
    #[test]
    fn seven_zip_family_doubling_form() {
        assert_eq!(WinArg::quote_for_tool(r"C:\t\7z.exe", "plain"), "\"plain\"");
        assert_eq!(WinArg::quote_for_tool(r"C:\t\7z.exe", "with space"), "\"with space\"");
        assert_eq!(WinArg::quote_for_tool(r"C:\t\7z.exe", "a\"b"), "\"a\"\"b\"");
        assert_eq!(WinArg::quote_for_tool(r"C:\t\7z.exe", "a\\b"), "\"a\\b\"");
        // trailing backslash stays literal: 7z parses the raw line itself
        assert_eq!(WinArg::quote_for_tool(r"C:\t\7z.exe", "abc\\"), "\"abc\\\"");
    }

    #[test]
    fn rar_family_argv_escaping() {
        assert_eq!(WinArg::quote_for_tool(r"C:\t\rar.exe", "plain"), "\"plain\"");
        assert_eq!(WinArg::quote_for_tool(r"C:\t\rar.exe", "a\"b"), "\"a\\\"b\"");
        assert_eq!(WinArg::quote_for_tool(r"C:\t\rar.exe", "a\\b"), "\"a\\b\"");
        // a trailing backslash escapes the closing quote unless doubled
        assert_eq!(WinArg::quote_for_tool(r"C:\t\rar.exe", "abc\\"), "\"abc\\\\\"");
        assert_eq!(WinArg::quote_for_tool(r"C:\t\rar.exe", "a\\\""), "\"a\\\\\\\"\"");
    }

    #[test]
    fn unknown_tool_uses_conservative_argv_escaping() {
        assert_eq!(WinArg::quote_for_tool(r"C:\t\other.exe", "abc\\"), "\"abc\\\\\"");
    }

    #[test]
    fn raw_quote_keeps_crt_rules() {
        assert_eq!(WinArg::quote("plain"), "\"plain\"");
        assert_eq!(WinArg::quote("with space"), "\"with space\"");
    }
}
