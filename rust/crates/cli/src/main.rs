// dictcrack CLI (Rust rewrite of Cli.cs).
use clap::{Parser, Subcommand};
use dictcrack_core::archive::{self, ArchiveKind};
use dictcrack_core::engine::{self, CrackConfig, CrackEngine};
use dictcrack_core::tool::{ToolLocator, WinArg};
use dictcrack_core::verifier;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

// console-aware output macros (out!/outln!/err!/errln!) must be in scope
// before any call site below
#[macro_use]
mod console;

#[derive(Parser)]
#[command(name = "dictcrack", version, about = "DictCrack - 压缩包密码字典/掩码破解工具（原生引擎）", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// 查看格式 / 加密方式 / 验证路径（--hashcat 导出 hashcat 格式）
    Info {
        /// 压缩包路径
        archive: String,
        /// 导出 hashcat -m 13000 格式 hash
        #[arg(long)]
        hashcat: bool,
    },
    /// 基准测速（需要 RAR5 或加密 ZIP）
    Bench {
        #[arg(short = 'a', long)]
        archive: String,
        /// 并行线程（0=自动）
        #[arg(short = 't', long, default_value_t = 0)]
        threads: u32,
        /// 测速秒数
        #[arg(long, default_value_t = 3)]
        seconds: u32,
    },
    /// 破解（字典 / 掩码 / 组合）
    Crack {
        /// 压缩包路径
        #[arg(short = 'a', long)]
        archive: String,
        /// 字典文件（可多个；-w - 从 stdin 读）
        #[arg(short = 'w', long = "dict")]
        dicts: Vec<String>,
        /// 组合攻击的字典 B
        #[arg(long = "w2")]
        dict_b: Option<String>,
        /// 变异规则（years,digits,leet,rev,cap,double）
        #[arg(long, value_delimiter = ',')]
        rule: Vec<String>,
        /// 掩码（如 "前缀?d?d?d?d"）
        #[arg(short = 'm', long)]
        mask: Option<String>,
        /// 自定义字符集 1..4
        #[arg(short = '1')]
        c1: Option<String>,
        #[arg(short = '2')]
        c2: Option<String>,
        #[arg(short = '3')]
        c3: Option<String>,
        #[arg(short = '4')]
        c4: Option<String>,
        /// 掩码最小长度
        #[arg(long, default_value_t = 1)]
        min: usize,
        /// 掩码最大长度（-1=完整掩码长度）
        #[arg(long, default_value_t = -1)]
        max: i64,
        /// 并行线程（0=自动）
        #[arg(short = 't', long, default_value_t = 0)]
        threads: u32,
        /// 最多尝试 N 个候选后停止
        #[arg(long, default_value_t = -1)]
        max_tries: i64,
        /// 后备验证工具路径
        #[arg(long)]
        tool: Option<String>,
        /// 结果文件路径
        #[arg(long)]
        out: Option<String>,
        /// 找到密码后自动解压到该目录
        #[arg(long)]
        extract_to: Option<String>,
        /// 从上次中断处继续
        #[arg(long)]
        resume: bool,
        /// 不写会话文件
        #[arg(long)]
        no_checkpoint: bool,
        /// 字典模式跨行去重
        #[arg(long)]
        dedupe: bool,
        /// 不输出进度行
        #[arg(short = 'q', long)]
        quiet: bool,
    },
}

// File.Exists in C# is "exists and is a regular file": a directory must
// take the same "文件不存在" branch the C# frontend reports.
fn path_missing(p: &Path) -> bool {
    !p.exists() || p.is_dir()
}

fn cmd_info(archive_path: &str, hashcat: bool) -> i32 {
    if path_missing(Path::new(archive_path)) {
        errln!("文件不存在: {}", archive_path);
        return 2;
    }
    let info = archive::parse(archive_path);
    if let Some(err) = &info.open_error {
        errln!("无法读取该文件（可能被占用或权限不足）: {}", err);
        return 2;
    }
    let full = std::fs::canonicalize(archive_path)
        .map(|p| {
            let s = p.display().to_string();
            s.strip_prefix(r"\\?\").map(|x| x.to_string()).unwrap_or(s)
        })
        .unwrap_or_else(|_| archive_path.to_string());
    outln!("文件: {}", full);
    let size = std::fs::metadata(archive_path).map(|m| m.len()).unwrap_or(0);
    outln!("大小: {} 字节", size);
    match info.kind {
        ArchiveKind::Rar5 => {
            outln!("格式: RAR 5.x");
            match &info.rar5 {
                None => outln!("加密: 无（未发现加密头记录）"),
                Some(r) => {
                    outln!("加密: {}", if r.header_encrypted { "RAR5 头加密（-hp）" } else { "RAR5 文件数据加密" });
                    if let Some(n) = &r.entry_name {
                        outln!("目标条目: {}", n);
                    }
                    outln!("KDF: PBKDF2-HMAC-SHA256, {} 轮", 1u64 << r.lg2_count);
                    outln!("密码校验: {}", if r.psw_check.is_some() { "有（可原生快速验证）" } else { "无（回退外部工具）" });
                    if hashcat {
                        if r.psw_check.is_some() {
                            outln!("Hashcat (-m 13000): {}", archive::hashcat_rar5(r));
                        } else {
                            outln!("Hashcat: 该压缩包没有可导出的校验数据");
                        }
                    }
                }
            }
        }
        ArchiveKind::RarLegacy => outln!("格式: RAR 1.5-4.x"),
        ArchiveKind::Zip => {
            outln!("格式: ZIP");
            match &info.zip {
                None => outln!("加密: 未检测到加密条目"),
                Some(z) => {
                    outln!("目标条目: {}", z.name);
                    outln!(
                        "加密方式: {}",
                        if z.aes { format!("WinZip AES-{}", z.aes_strength as u32 * 64 + 64) } else { "传统 ZipCrypto".to_string() }
                    );
                }
            }
        }
        ArchiveKind::SevenZip => outln!("格式: 7z"),
        ArchiveKind::Unknown => outln!("格式: 无法识别（{}）", info.detect_note),
    }
    outln!("验证路径: {}", if info.native_supported() { "原生引擎 (native)" } else { "外部工具 (external)" });
    0
}

fn cmd_bench(archive_path: &str, threads: u32, seconds: u32) -> i32 {
    if path_missing(Path::new(archive_path)) {
        errln!("文件不存在: {}", archive_path);
        return 2;
    }
    let info = archive::parse(archive_path);
    if let Some(err) = &info.open_error {
        errln!("无法读取该文件（可能被占用或权限不足）: {}", err);
        return 2;
    }
    if !info.native_supported() {
        errln!("该压缩包不支持原生验证（{}），基准测速需要 RAR5 或加密 ZIP。", info.detect_note);
        return 2;
    }
    let v: Arc<dyn verifier::Verifier + Send + Sync> = match verifier::create_native(&info, archive_path) {
        Some(v) => v.into(),
        None => {
            errln!("无法创建原生验证器。");
            return 2;
        }
    };
    outln!("{}", v.describe());
    let single = engine::bench_measure(&v, 1, seconds);
    outln!("单线程: {:.1} 个/秒", single);
    let all = engine::bench_measure(&v, threads, seconds);
    outln!(
        "{}: {:.1} 个/秒",
        if threads > 0 { format!("{} 线程", threads) } else { "自动线程".to_string() },
        all
    );
    0
}

fn format_time(sec: f64) -> String {
    if sec < 0.0 || sec.is_nan() || sec.is_infinite() {
        return "--:--".into();
    }
    let s = sec.floor() as u64;
    let h = s / 3600;
    let m = (s % 3600) / 60;
    let sec = s % 60;
    if h >= 1 {
        format!("{:02}:{:02}:{:02}", h, m, sec)
    } else {
        format!("{:02}:{:02}", m, sec)
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_crack(
    archive: String,
    dicts: Vec<String>,
    dict_b: Option<String>,
    rule: Vec<String>,
    mask: Option<String>,
    c1: Option<String>,
    c2: Option<String>,
    c3: Option<String>,
    c4: Option<String>,
    min: usize,
    max: i64,
    threads: u32,
    max_tries: i64,
    tool: Option<String>,
    out: Option<String>,
    extract_to: Option<String>,
    resume: bool,
    no_checkpoint: bool,
    last_checkpoint: Option<bool>,
    dedupe: bool,
    quiet: bool,
) -> i32 {
    let mode = if mask.is_some() {
        "mask".to_string()
    } else if dict_b.is_some() {
        "comb".to_string()
    } else {
        "dict".to_string()
    };
    if mode == "dict" && dicts.is_empty() {
        errln!("错误: 字典模式需要 -w <字典文件>（或使用 --mask）。");
        return 2;
    }
    let presets: Vec<String> = rule
        .iter()
        .flat_map(|r| r.split(','))
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty() && dictcrack_core::attacks::Rules::PRESET_NAMES.contains(&s.as_str()))
        .collect();

    let cfg = CrackConfig {
        archive_path: archive.clone(),
        mode,
        dict_files: dicts,
        dict_file_b: dict_b,
        presets,
        mask,
        custom_sets: [
            c1.unwrap_or_default(),
            c2.unwrap_or_default(),
            c3.unwrap_or_default(),
            c4.unwrap_or_default(),
        ],
        mask_min: min,
        mask_max: max,
        threads,
        // C# ParseCrackArgs applies --resume/--no-checkpoint in argv order
        // (the last one wins); last_checkpoint carries that order, defaulting
        // to the flags' plain semantics when neither appears
        checkpoint_enabled: last_checkpoint.unwrap_or(!no_checkpoint),
        resume_requested: resume,
        max_tries,
        user_tool: tool,
        quiet,
        out_file: out,
        dedupe,
    };

    // Ctrl+C: first graceful stop, second force exit
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel2 = cancel.clone();
    let _ = ctrlc_set_handler(move || {
        static COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        if COUNT.fetch_add(1, Ordering::SeqCst) >= 1 {
            errln!("强制退出。");
            std::process::exit(3);
        }
        cancel2.store(true, Ordering::SeqCst);
        errln!("... 正在停止（再次 Ctrl+C 强制退出）");
    });

    outln!("DictCrack 原生引擎 v1.0");
    let engine = CrackEngine::new(cfg.clone());
    let stats = engine.stats.clone();

    // progress printer thread
    let progress = if quiet {
        None
    } else {
        Some(std::thread::spawn(move || {
            let mut prev_tried = 0i64;
            let mut prev_time = Instant::now();
            let mut rate = 0.0f64;
            while !stats.done.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(500));
                let tried = stats.tried.load(Ordering::Relaxed) + stats.base_tried.load(Ordering::Relaxed);
                let now = Instant::now();
                let dt = now.duration_since(prev_time).as_secs_f64();
                if dt > 0.4 {
                    let r = (tried - prev_tried) as f64 / dt;
                    if r > 0.0 {
                        rate = r;
                    }
                    prev_tried = tried;
                    prev_time = now;
                }
                let total = stats.total.load(Ordering::Relaxed);
                let mut eta = String::new();
                if total > 0 && rate > 0.0 {
                    let remain = total - tried;
                    if remain > 0 {
                        eta = format!(" 剩余 {}", format_time(remain as f64 / rate));
                    }
                }
                let phase = stats.phase.lock().unwrap().clone();
                let cur = stats.current.lock().unwrap().clone();
                let tag = stats.current_tag.lock().unwrap().clone();
                let cur = if !tag.is_empty() { format!("[{}] {}", tag, cur) } else { cur };
                let mut line = format!(
                    "{} | 已试 {}{} | {:.1} 个/秒{} | 当前: {}",
                    phase,
                    tried,
                    if total > 0 { format!("/{}", total) } else { String::new() },
                    rate,
                    eta,
                    cur
                );
                if line.chars().count() > 110 {
                    line = line.chars().take(110).collect();
                }
                out!("\r{:<width$}\r", line, width = 118);
            }
        }))
    };

    let res = engine.run(cancel);
    if let Some(p) = progress {
        let _ = p.join();
    }

    if let Some(e) = &res.error {
        errln!("错误: {}", e);
        return 2;
    }
    if let Some(w) = &res.warning {
        errln!("警告: {}", w);
    }
    let rate = if res.elapsed_sec > 0.2 { res.tried as f64 / res.elapsed_sec } else { 0.0 };
    if res.found {
        outln!();
        outln!("=== 找到密码: {} ===", res.password);
        outln!("尝试 {} 个, 用时 {}, 平均 {:.1} 个/秒", res.tried, format_time(res.elapsed_sec), rate);
        if let Some(f) = &res.result_file {
            outln!("结果已保存: {}", f);
        }
        if let Some(dir) = extract_to {
            return do_extract(&archive, &res.password, &dir);
        }
        return 0;
    }
    if res.cancelled {
        outln!("已取消（进度已保存, 下次加 --resume 继续）。");
        return 3;
    }
    if res.maxed_out {
        outln!("达到 --max-tries 上限, 已停止（进度已保存, 加 --resume 继续）。");
        return 3;
    }
    outln!();
    let note = engine.log_note.lock().unwrap().clone();
    outln!("未找到密码。{}", if !note.is_empty() { format!("（编码方案: {}）", note) } else { String::new() });
    outln!("共尝试 {} 个, 用时 {}, 平均 {:.1} 个/秒", res.tried, format_time(res.elapsed_sec), rate);
    1
}

// minimal Ctrl+C handler without an extra crate: use SetConsoleCtrlHandler via
// a tiny inline binding. Falls back to a no-op when unavailable.
fn ctrlc_set_handler<F: Fn() + Send + Sync + 'static>(f: F) -> Result<(), ()> {
    use std::sync::OnceLock;
    static HANDLER: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();
    let _ = HANDLER.set(Box::new(f));
    #[cfg(windows)]
    unsafe {
        extern "system" fn ctrl_handler(_: u32) -> i32 {
            if let Some(h) = HANDLER.get() {
                h();
            }
            1 // TRUE: handled
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn SetConsoleCtrlHandler(handler: Option<extern "system" fn(u32) -> i32>, add: i32) -> i32;
        }
        if SetConsoleCtrlHandler(Some(ctrl_handler), 1) != 0 {
            return Ok(());
        }
    }
    Err(())
}

// ------------------------------------------------------------------
// --extract-to: after a hit, unpack with 7z.exe/rar.exe. Port of Cli.DoExtract:
// `x -y -p<pwd> -o<dir> <archive>` with per-tool quoting (7z self-parses the
// raw line, rar.exe is a CRT argv program - see tool::WinArg).
fn do_extract(archive: &str, password: &str, dir: &str) -> i32 {
    let tool = match ToolLocator::find_extractor() {
        Some(t) => t,
        None => {
            errln!("错误: 找不到 7z.exe, 无法解压。");
            return 2;
        }
    };
    if let Err(e) = std::fs::create_dir_all(dir) {
        // C# DoExtract lets Directory.CreateDirectory throw (an unhandled
        // crash); report the real cause instead of blaming the extractor
        errln!("错误: 无法创建目录 {}: {}", dir, e);
        return 2;
    }
    outln!("正在解压到 {} ...", dir);
    let status = std::process::Command::new(&tool)
        .arg("x")
        .arg("-y")
        .raw_arg(format!("-p{}", WinArg::quote_for_tool(&tool, password)))
        .raw_arg(format!("-o{}", WinArg::quote_for_tool(&tool, dir)))
        .raw_arg(WinArg::quote_for_tool(&tool, archive))
        .status();
    match status {
        Ok(s) if s.success() => {
            outln!("解压完成。");
            0
        }
        Ok(s) => {
            outln!("解压失败（退出码 {}）。", s.code().unwrap_or(-1));
            2
        }
        Err(e) => {
            outln!("解压失败（{}）。", e);
            2
        }
    }
}

// ------------------------------------------------------------------
// The C# frontend warns about and IGNORES unrecognized options
// (ParseCrackArgs) instead of failing; anything that is not info/bench/help
// even runs the crack parser without a subcommand. clap hard-errors on both,
// so pre-scan the crack argv: drop unknown "-..." tokens with the same
// warning, drop stray positionals (C# silently ignores them), and inject the
// implicit "crack" subcommand.
const OPTS_WITH_VALUE: &[&str] = &[
    "-a", "--archive", "-w", "--dict", "--w2", "--rule", "--rules", "--mask", "-m",
    "-1", "-2", "-3", "-4", "--min", "--max", "-t", "--threads", "--max-tries",
    "--tool", "--out", "--extract-to",
];
const OPT_FLAGS: &[&str] = &["--resume", "--no-checkpoint", "-q", "--quiet", "--dedupe"];

fn normalize_w2(s: &str) -> String {
    if s == "-w2" {
        "--w2".to_string()
    } else if let Some(rest) = s.strip_prefix("-w2=") {
        format!("--w2={}", rest)
    } else {
        s.to_string()
    }
}

fn is_recognized(token: &str) -> Option<bool> {
    // Some(true): recognized with a value; Some(false): flag; None: unknown
    let t = normalize_w2(token);
    if OPTS_WITH_VALUE.contains(&t.as_str()) {
        return Some(true);
    }
    if OPT_FLAGS.contains(&t.as_str()) {
        return Some(false);
    }
    if OPTS_WITH_VALUE.iter().any(|n| t.starts_with(&format!("{}=", n))) {
        return Some(false); // attached-value form, e.g. --out=x.rar
    }
    None
}

/// Rewrites the crack invocation the way C# would parse it:
/// unknown "-..." options warn and get dropped, stray positionals are
/// silently dropped, and the leading "crack" may be implicit.
fn crack_argv(args: Vec<std::ffi::OsString>) -> Vec<std::ffi::OsString> {
    // decide the subcommand like C# Main does
    let first = args.get(1).and_then(|a| a.to_str()).map(|s| s.to_lowercase());
    let pass_through = matches!(
        first.as_deref(),
        Some("info") | Some("bench") | Some("help") | Some("--help") | Some("-h") | Some("--version") | Some("-v")
    ) || args.len() <= 1;
    if pass_through {
        return args;
    }
    // tokens after the (optional, dropped) "crack" subcommand word
    let rest: Vec<std::ffi::OsString> = if first.as_deref() == Some("crack") {
        args.into_iter().skip(2).collect()
    } else {
        args.into_iter().skip(1).collect()
    };

    let mut out = vec![std::ffi::OsString::from("dictcrack"), std::ffi::OsString::from("crack")];
    let mut skip_next = false; // next token is a consumed option value
    for a in rest {
        if skip_next {
            out.push(a);
            skip_next = false;
            continue;
        }
        let s = a.to_string_lossy().into_owned();
        if s.len() > 1 && s.starts_with('-') {
            match is_recognized(&s) {
                Some(true) => {
                    out.push(a);
                    skip_next = true;
                }
                Some(false) => out.push(a),
                None => errln!("警告: 无法识别的选项 {}（已忽略）", s),
            }
        }
        // else: a stray positional (or a bare "-"): C# silently ignores it
    }
    out
}

/// Recovers the C# argv-order semantics of --resume/--no-checkpoint (the
/// last flag wins; `--resume` implies checkpointing on). Scans the rewritten
/// crack argv and skips option *values*: C# consumes "-a --resume" as the
/// archive value, so a flag-looking token in value position must not count.
fn last_checkpoint(args: &[std::ffi::OsString]) -> Option<bool> {
    let mut last: Option<bool> = None;
    let mut skip_next = false;
    for a in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        match a.to_str() {
            Some("--resume") => last = Some(true),
            Some("--no-checkpoint") => last = Some(false),
            Some(s) if is_recognized(s) == Some(true) => skip_next = true,
            _ => {}
        }
    }
    last
}

fn main() {
    // clap cannot express the single-dash multi-char option "-w2" (the C#
    // combinator flag); rewrite it to the long form "--w2" before parsing so
    // the CLI contract stays byte-compatible with the C# frontend.
    let args: Vec<std::ffi::OsString> = std::env::args_os()
        .map(|a| {
            let s = a.to_str().map(|s| s.to_string());
            match s.as_deref().map(normalize_w2) {
                Some(n) if n != a.to_string_lossy() => std::ffi::OsString::from(n),
                _ => a,
            }
        })
        .collect();
    let args = crack_argv(args);
    // clap loses the argv order of the --resume / --no-checkpoint flags, but
    // the C# frontend applies them in order, so the last one decides
    // whether the session file is written; recover that order here
    let checkpoint_order = last_checkpoint(&args);
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            // clap writes its rendered text straight to stderr/stdout, which
            // would mojibake the Chinese help on a CP936 console; route it
            // through the same console-aware writers
            let mut text = e.render().to_string();
            if !text.ends_with('\n') {
                text.push('\n');
            }
            if e.use_stderr() {
                err!("{}", text);
            } else {
                out!("{}", text);
            }
            std::process::exit(e.exit_code());
        }
    };
    let code = match cli.command {
        Some(Commands::Info { archive, hashcat }) => cmd_info(&archive, hashcat),
        Some(Commands::Bench { archive, threads, seconds }) => cmd_bench(&archive, threads, seconds),
        Some(Commands::Crack {
            archive, dicts, dict_b, rule, mask, c1, c2, c3, c4, min, max, threads,
            max_tries, tool, out, extract_to, resume, no_checkpoint, dedupe, quiet,
        }) => cmd_crack(
            archive, dicts, dict_b, rule, mask, c1, c2, c3, c4, min, max, threads,
            max_tries, tool, out, extract_to, resume, no_checkpoint, checkpoint_order, dedupe, quiet,
        ),
        None => {
            errln!("用法见 dictcrack --help");
            2
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<std::ffi::OsString> {
        v.iter().map(|s| std::ffi::OsString::from(*s)).collect()
    }

    #[test]
    fn normalize_w2_forms() {
        assert_eq!(normalize_w2("-w2"), "--w2");
        assert_eq!(normalize_w2("-w2=d.txt"), "--w2=d.txt");
        assert_eq!(normalize_w2("--w2"), "--w2");
        // lookalikes stay untouched (C# TryOpt matches "-w2"/"-w2=" exactly)
        assert_eq!(normalize_w2("-w"), "-w");
        assert_eq!(normalize_w2("-w22"), "-w22");
        assert_eq!(normalize_w2("--dict"), "--dict");
    }

    #[test]
    fn is_recognized_matrix() {
        // value-taking options
        for t in [
            "-a", "--archive", "-w", "--dict", "--w2", "--rule", "--rules", "--mask", "-m",
            "-1", "-2", "-3", "-4", "--min", "--max", "-t", "--threads", "--max-tries",
            "--tool", "--out", "--extract-to",
        ] {
            assert_eq!(is_recognized(t), Some(true), "{} takes a value", t);
        }
        // flags
        for t in ["--resume", "--no-checkpoint", "-q", "--quiet", "--dedupe"] {
            assert_eq!(is_recognized(t), Some(false), "{} is a flag", t);
        }
        // attached-value form: recognized, but consumes no following token
        assert_eq!(is_recognized("--out=x.rar"), Some(false));
        assert_eq!(is_recognized("--w2=d.txt"), Some(false));
        assert_eq!(is_recognized("--mask=ab?d"), Some(false));
        // unknown -> the C# warning-and-ignore path
        for t in ["--masi", "-v", "-x", "-w22", "--dictx", "-"] {
            assert_eq!(is_recognized(t), None, "{} unknown", t);
        }
    }

    #[test]
    fn crack_argv_rewrites_implicit_crack_and_drops_junk() {
        // no subcommand -> implicit "crack"; unknown options warn and are
        // dropped; stray positionals are silently dropped
        assert_eq!(
            crack_argv(os(&["dictcrack", "--masi", "-a", "x.rar", "-w", "d.txt", "junk"])),
            os(&["dictcrack", "crack", "-a", "x.rar", "-w", "d.txt"])
        );
        // explicit "crack" is consumed exactly once
        assert_eq!(
            crack_argv(os(&["dictcrack", "crack", "-a", "x.rar", "-q"])),
            os(&["dictcrack", "crack", "-a", "x.rar", "-q"])
        );
    }

    #[test]
    fn crack_argv_values_may_look_like_options() {
        // an option value is consumed even if it starts with "-"
        assert_eq!(
            crack_argv(os(&["dictcrack", "crack", "-a", "-weird.rar", "-q"])),
            os(&["dictcrack", "crack", "-a", "-weird.rar", "-q"])
        );
        // attached-value options consume nothing
        assert_eq!(
            crack_argv(os(&["dictcrack", "crack", "--out=x.rar", "--mask=ab?d", "-q"])),
            os(&["dictcrack", "crack", "--out=x.rar", "--mask=ab?d", "-q"])
        );
    }

    #[test]
    fn crack_argv_passes_through_non_crack_invocations() {
        assert_eq!(crack_argv(os(&["dictcrack", "info", "x.rar"])), os(&["dictcrack", "info", "x.rar"]));
        assert_eq!(
            crack_argv(os(&["dictcrack", "bench", "-a", "x.rar"])),
            os(&["dictcrack", "bench", "-a", "x.rar"])
        );
        assert_eq!(crack_argv(os(&["dictcrack", "--help"])), os(&["dictcrack", "--help"]));
        assert_eq!(crack_argv(os(&["dictcrack", "-h"])), os(&["dictcrack", "-h"]));
        assert_eq!(crack_argv(os(&["dictcrack", "--version"])), os(&["dictcrack", "--version"]));
        assert_eq!(crack_argv(os(&["dictcrack"])), os(&["dictcrack"]));
    }

    #[test]
    fn last_checkpoint_last_flag_wins() {
        // the C# frontend applies both flags in argv order: last one decides
        assert_eq!(last_checkpoint(&os(&["--resume"])), Some(true));
        assert_eq!(last_checkpoint(&os(&["--no-checkpoint"])), Some(false));
        assert_eq!(last_checkpoint(&os(&["--resume", "--no-checkpoint"])), Some(false));
        assert_eq!(last_checkpoint(&os(&["--no-checkpoint", "--resume"])), Some(true));
        assert_eq!(last_checkpoint(&os(&["-a", "x.rar", "-w", "d.txt"])), None);
        assert_eq!(last_checkpoint(&os(&[])), None);
    }

    #[test]
    fn last_checkpoint_skips_option_values() {
        // "-a --resume" consumes "--resume" as the archive value: C# never
        // sees a flag there, so neither may the pre-scan
        assert_eq!(last_checkpoint(&os(&["-a", "--resume", "-w", "d.txt"])), None);
        assert_eq!(
            last_checkpoint(&os(&["-a", "x.rar", "--out=--resume", "-w", "d.txt"])),
            None
        );
        // ... while a real flag after a consumed value still counts
        assert_eq!(last_checkpoint(&os(&["-a", "--resume", "--no-checkpoint"])), Some(false));
    }

    #[test]
    fn path_missing_matches_file_exists() {
        let dir = std::env::temp_dir();
        assert!(path_missing(&dir.join("dictcrack-no-such-path-test")), "missing path");
        // C# File.Exists: a directory is not a file -> "不存在" branch
        assert!(path_missing(&dir), "directory counts as missing");
        let f = dir.join(format!("dictcrack-file-{}.tmp", std::process::id()));
        std::fs::write(&f, b"x").unwrap();
        assert!(!path_missing(&f), "regular file exists");
        let _ = std::fs::remove_file(&f);
    }
}
