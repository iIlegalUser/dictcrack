//! Console-aware output for the CLI. Rust's std writes UTF-8 bytes straight
//! at the console handle; on a console whose output code page is not 65001
//! (zh-CN Windows defaults to 936/GBK) every Chinese message renders as
//! mojibake. The C# build instead encodes with the console code page, so its
//! messages display fine. When the stream is a real console, hand the text
//! to WriteConsoleW as UTF-16 (the CPython PEP 528 approach): rendering is
//! then correct regardless of the console code page, with no global
//! SetConsoleOutputCP side effects on the user's session. Redirected or
//! piped output keeps plain UTF-8 bytes (the standard for non-console
//! consumers, e.g. PowerShell 7 and the e2e suite).
//!
//! Covers the whole binary via the out!/outln!/err!/errln! macros; the core
//! crate never prints. clap's rendered help/error text goes through the
//! same writers (main reroutes `try_parse_from` errors), since the help
//! text is Chinese too.

use std::io::Write;
use std::sync::OnceLock;

#[cfg(windows)]
const STD_OUTPUT_HANDLE: u32 = (-11i32) as u32;
#[cfg(windows)]
const STD_ERROR_HANDLE: u32 = (-12i32) as u32;

#[cfg(windows)]
extern "system" {
    fn GetStdHandle(which: u32) -> *mut core::ffi::c_void;
    fn GetConsoleMode(handle: *mut core::ffi::c_void, mode: *mut u32) -> i32;
    fn WriteConsoleW(
        handle: *mut core::ffi::c_void,
        chars: *const u16,
        count: u32,
        written: *mut u32,
        reserved: *mut core::ffi::c_void,
    ) -> i32;
}

/// true when the standard handle is a console (and must go through
/// WriteConsoleW); decided once per stream, the way .NET and CPython do
#[cfg(windows)]
fn handle_is_console(which: u32, cache: &OnceLock<bool>) -> bool {
    *cache.get_or_init(|| unsafe {
        let h = GetStdHandle(which);
        if h.is_null() || h as isize == -1 {
            return false;
        }
        let mut mode = 0u32;
        GetConsoleMode(h, &mut mode) != 0
    })
}

/// UTF-16 via WriteConsoleW; false = fall back to raw bytes (also covers a
/// failed or partial write, which for a console means something is wrong
/// beyond encoding anyway)
#[cfg(windows)]
fn write_console(which: u32, s: &str) -> bool {
    unsafe {
        let h = GetStdHandle(which);
        if h.is_null() || h as isize == -1 {
            return false;
        }
        let chars: Vec<u16> = s.encode_utf16().collect();
        let mut off = 0usize;
        while off < chars.len() {
            let mut written = 0u32;
            let ok = WriteConsoleW(
                h,
                chars.as_ptr().add(off),
                (chars.len() - off) as u32,
                &mut written,
                std::ptr::null_mut(),
            );
            if ok == 0 || written == 0 {
                return false;
            }
            off += written as usize;
        }
        true
    }
}

/// write to stdout: WriteConsoleW when it is a console, UTF-8 bytes
/// otherwise (write errors ignored -- a closed pipe must not panic the CLI
/// mid-report the way a failing println! would)
pub fn write_out(s: &str) {
    #[cfg(windows)]
    {
        static IS_CONSOLE: OnceLock<bool> = OnceLock::new();
        if handle_is_console(STD_OUTPUT_HANDLE, &IS_CONSOLE) && write_console(STD_OUTPUT_HANDLE, s) {
            return;
        }
    }
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(s.as_bytes());
    let _ = out.flush();
}

/// write to stderr, same rules as [`write_out`]
pub fn write_err(s: &str) {
    #[cfg(windows)]
    {
        static IS_CONSOLE: OnceLock<bool> = OnceLock::new();
        if handle_is_console(STD_ERROR_HANDLE, &IS_CONSOLE) && write_console(STD_ERROR_HANDLE, s) {
            return;
        }
    }
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(s.as_bytes());
    let _ = err.flush();
}

#[macro_export]
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::console::write_out(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! outln {
    () => {
        $crate::console::write_out("\n")
    };
    ($($arg:tt)*) => {
        $crate::console::write_out(&format!("{}\n", format_args!($($arg)*)))
    };
}

#[macro_export]
macro_rules! err {
    ($($arg:tt)*) => {
        $crate::console::write_err(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! errln {
    ($($arg:tt)*) => {
        $crate::console::write_err(&format!("{}\n", format_args!($($arg)*)))
    };
}
