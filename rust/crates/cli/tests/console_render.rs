//! Console rendering regression test (ignored by default: needs a real
//! console and spawns a visible cmd window for a moment).
//!
//! Run with: cargo test --test console_render -- --ignored
//!
//! Redirected output can only prove the byte stream; what a CP936 console
//! actually RENDERS lives in its screen buffer. This test spawns the CLI in
//! a NEW console, attaches to that console and reads the buffer back via
//! ReadConsoleOutputCharacterW. Pre-fix, std's raw UTF-8 bytes were stored
//! as GBK-misdecoded garbage characters in the buffer; with WriteConsoleW
//! the buffer holds the true Unicode text, which is what this asserts.
//!
//! Spawn mechanics matter here: Rust's Command always sets
//! STARTF_USESTDHANDLES, so a CREATE_NEW_CONSOLE child would inherit the
//! harness's pipes and render nothing on screen. Going through PowerShell's
//! Start-Process (ShellExecute) gives the inner cmd fresh console handles,
//! like a real user's terminal would.

#![cfg(windows)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_SHARE_WRITE: u32 = 0x2;
const OPEN_EXISTING: u32 = 3;

type Handle = *mut core::ffi::c_void;

#[repr(C)]
#[derive(Clone, Copy)]
struct Coord {
    x: i16,
    y: i16,
}

#[repr(C)]
struct SmallRect {
    left: i16,
    top: i16,
    right: i16,
    bottom: i16,
}

#[repr(C)]
struct ScreenBufferInfo {
    dw_size: Coord,
    dw_cursor: Coord,
    attributes: u16,
    window: SmallRect,
    max_window: Coord,
}

extern "system" {
    fn FreeConsole() -> i32;
    fn AttachConsole(pid: u32) -> i32;
    fn GetLastError() -> u32;
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *mut core::ffi::c_void,
        disposition: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn CloseHandle(h: Handle) -> i32;
    fn GetConsoleScreenBufferInfo(h: Handle, info: *mut ScreenBufferInfo) -> i32;
    fn ReadConsoleOutputCharacterW(
        h: Handle,
        chars: *mut u16,
        count: u32,
        coord: Coord,
        read: *mut u32,
    ) -> i32;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// read the visible portion of the attached console's screen buffer;
/// returns (text, diagnostics)
fn read_screen_text() -> (String, String) {
    let mut diag = String::new();
    unsafe {
        let conout = CreateFileW(
            wide("CONOUT$").as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        if conout as isize == -1 {
            return (String::new(), "CreateFileW(CONOUT$) failed".into());
        }
        let mut info = ScreenBufferInfo {
            dw_size: Coord { x: 0, y: 0 },
            dw_cursor: Coord { x: 0, y: 0 },
            attributes: 0,
            window: SmallRect { left: 0, top: 0, right: 0, bottom: 0 },
            max_window: Coord { x: 0, y: 0 },
        };
        if GetConsoleScreenBufferInfo(conout, &mut info) == 0 {
            CloseHandle(conout);
            return (String::new(), "GetConsoleScreenBufferInfo failed".into());
        }
        diag.push_str(&format!(
            "size={}x{} cursor_y={} win={}..={}",
            info.dw_size.x, info.dw_size.y, info.dw_cursor.y, info.window.top, info.window.bottom
        ));
        let width = info.dw_size.x.max(1);
        let top = info.window.top.max(0);
        let bottom = info.window.bottom.min(info.dw_size.y - 1);
        let mut text = String::new();
        for y in top..=bottom {
            let mut row = vec![0u16; width as usize];
            let mut read = 0u32;
            let ok = ReadConsoleOutputCharacterW(
                conout,
                row.as_mut_ptr(),
                width as u32,
                Coord { x: 0, y },
                &mut read,
            );
            if y == top {
                diag.push_str(&format!(" first-read ok={} read={}", ok, read));
            }
            if ok != 0 && read > 0 {
                text.push_str(&String::from_utf16_lossy(&row[..read as usize]));
            }
            text.push('\n');
        }
        CloseHandle(conout);
        (text, diag)
    }
}

#[test]
#[ignore]
fn console_renders_chinese_as_unicode_not_mojibake() {
    let exe = std::path::Path::new(env!("CARGO_BIN_EXE_dictcrack")).display().to_string();
    // the chain is single-quoted inside a PowerShell -ArgumentList: no spaces
    // in the paths, no single quotes anywhere
    assert!(!exe.contains(' ') && !exe.contains('\''), "unexpected target path: {}", exe);

    // fixtures: a nonexistent path exercises the stderr (errln) route, a
    // 0-byte file the stdout (outln) route of `info`; both outputs are short
    // so nothing scrolls off the visible screen
    let probe = std::env::temp_dir().join(format!("dc-console-probe-{}.bin", std::process::id()));
    std::fs::write(&probe, b"").unwrap();
    let probe_path = probe.display().to_string();
    assert!(!probe_path.contains(' ') && !probe_path.contains('\''));

    let pid_file = std::env::temp_dir().join(format!("dc-console-pid-{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&pid_file);
    let pid_file_str = pid_file.display().to_string();

    // `ping -n 30` keeps the inner cmd (and its console) alive long enough
    // for us to attach and read, with nothing to clean up interactively
    // (a `pause` would wait for a keypress on the console input buffer)
    let chain = format!(
        "{} info __dc_no_such__.rar & {} info {} & echo __DC_END__ & ping -n 30 127.0.0.1 >nul",
        exe, exe, probe_path
    );
    let script = format!(
        "$p = Start-Process cmd -ArgumentList '/c','{}' -PassThru; Set-Content -LiteralPath '{}' -Value $p.Id; Start-Sleep -Seconds 60",
        chain, pid_file_str
    );
    let mut spawner = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &script])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn powershell helper");

    // wait for the helper to report the inner cmd's pid
    let deadline = Instant::now() + Duration::from_secs(15);
    let inner_pid: u32 = loop {
        if let Ok(s) = std::fs::read_to_string(&pid_file) {
            if let Ok(pid) = s.trim().parse::<u32>() {
                break pid;
            }
        }
        assert!(Instant::now() < deadline, "helper never wrote the inner pid");
        assert!(spawner.try_wait().ok().flatten().is_none(), "helper exited early");
        std::thread::sleep(Duration::from_millis(200));
    };

    // detach from our own console (if any) and attach to the child's; give
    // the child a moment to boot cmd and run the chain
    std::thread::sleep(Duration::from_millis(1200));
    let mut attach_diag = String::new();
    let attached = (0..25).find(|_| {
        unsafe { FreeConsole() };
        if unsafe { AttachConsole(inner_pid) } != 0 {
            return true;
        }
        attach_diag = format!("GetLastError={}", unsafe { GetLastError() });
        std::thread::sleep(Duration::from_millis(200));
        false
    });
    let _ = std::fs::remove_file(&pid_file);
    assert!(attached.is_some(), "could not attach to the child console [{}]", attach_diag);

    // poll the buffer until the chain finished writing, then read it back
    let deadline = Instant::now() + Duration::from_secs(15);
    let (text, diag) = loop {
        let (t, d) = read_screen_text();
        if t.contains("__DC_END__") || Instant::now() > deadline {
            break (t, d);
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    unsafe { FreeConsole() };
    let _ = Command::new("taskkill").args(["/PID", &inner_pid.to_string(), "/T", "/F"]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    let _ = spawner.kill();
    let _ = spawner.wait();
    let _ = std::fs::remove_file(&probe);

    assert!(text.contains("__DC_END__"), "child output never appeared [{}]:\n{}", diag, text);
    // stdout route (outln): the 0-byte probe file's info output
    assert!(text.contains("字节"), "stdout Chinese garbled:\n{}", text);
    assert!(text.contains("验证路径"), "stdout Chinese garbled:\n{}", text);
    // stderr route (errln): the missing-file error from cmd_info
    assert!(text.contains("文件不存在"), "stderr Chinese garbled:\n{}", text);
}
