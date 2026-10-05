// dictcrack CLI (Rust rewrite of Cli.cs).
use clap::{Parser, Subcommand};
use dictcrack_core::archive::{self, ArchiveKind};
use dictcrack_core::engine::{self, CrackConfig, CrackEngine};
use dictcrack_core::verifier;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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

fn cmd_info(archive_path: &str, hashcat: bool) -> i32 {
    if !Path::new(archive_path).exists() {
        eprintln!("文件不存在: {}", archive_path);
        return 2;
    }
    let info = archive::parse(archive_path);
    let full = std::fs::canonicalize(archive_path)
        .map(|p| {
            let s = p.display().to_string();
            s.strip_prefix(r"\\?\").map(|x| x.to_string()).unwrap_or(s)
        })
        .unwrap_or_else(|_| archive_path.to_string());
    println!("文件: {}", full);
    let size = std::fs::metadata(archive_path).map(|m| m.len()).unwrap_or(0);
    println!("大小: {} 字节", size);
    match info.kind {
        ArchiveKind::Rar5 => {
            println!("格式: RAR 5.x");
            match &info.rar5 {
                None => println!("加密: 无（未发现加密头记录）"),
                Some(r) => {
                    println!("加密: {}", if r.header_encrypted { "RAR5 头加密（-hp）" } else { "RAR5 文件数据加密" });
                    if let Some(n) = &r.entry_name {
                        println!("目标条目: {}", n);
                    }
                    println!("KDF: PBKDF2-HMAC-SHA256, {} 轮", 1u64 << r.lg2_count);
                    println!("密码校验: {}", if r.psw_check.is_some() { "有（可原生快速验证）" } else { "无（回退外部工具）" });
                    if hashcat {
                        if r.psw_check.is_some() {
                            println!("Hashcat (-m 13000): {}", archive::hashcat_rar5(r));
                        } else {
                            println!("Hashcat: 该压缩包没有可导出的校验数据");
                        }
                    }
                }
            }
        }
        ArchiveKind::RarLegacy => println!("格式: RAR 1.5-4.x"),
        ArchiveKind::Zip => {
            println!("格式: ZIP");
            match &info.zip {
                None => println!("加密: 未检测到加密条目"),
                Some(z) => {
                    println!("目标条目: {}", z.name);
                    println!(
                        "加密方式: {}",
                        if z.aes { format!("WinZip AES-{}", z.aes_strength as u32 * 64 + 64) } else { "传统 ZipCrypto".to_string() }
                    );
                }
            }
        }
        ArchiveKind::SevenZip => println!("格式: 7z"),
        ArchiveKind::Unknown => println!("格式: 无法识别（{}）", info.detect_note),
    }
    println!("验证路径: {}", if info.native_supported() { "原生引擎 (native)" } else { "外部工具 (external)" });
    0
}

fn cmd_bench(archive_path: &str, threads: u32, seconds: u32) -> i32 {
    if !Path::new(archive_path).exists() {
        eprintln!("文件不存在: {}", archive_path);
        return 2;
    }
    let info = archive::parse(archive_path);
    if !info.native_supported() {
        eprintln!("该压缩包不支持原生验证（{}），基准测速需要 RAR5 或加密 ZIP。", info.detect_note);
        return 2;
    }
    let v: Arc<dyn verifier::Verifier + Send + Sync> = match verifier::create_native(&info, archive_path) {
        Some(v) => v.into(),
        None => {
            eprintln!("无法创建原生验证器。");
            return 2;
        }
    };
    println!("{}", v.describe());
    let single = engine::bench_measure(&v, 1, seconds);
    println!("单线程: {:.1} 个/秒", single);
    let all = engine::bench_measure(&v, threads, seconds);
    println!(
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
        eprintln!("错误: 字典模式需要 -w <字典文件>（或使用 --mask）。");
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
        checkpoint_enabled: !no_checkpoint,
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
            eprintln!("强制退出。");
            std::process::exit(3);
        }
        cancel2.store(true, Ordering::SeqCst);
        eprintln!("... 正在停止（再次 Ctrl+C 强制退出）");
    });

    println!("DictCrack 原生引擎 v1.0");
    let engine = CrackEngine::new(cfg.clone());
    let stats = engine.stats.clone();

    // progress printer thread
    let progress_cancel = cancel.clone();
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
                print!("\r{:<width$}\r", line, width = 118);
                let _ = progress_cancel;
            }
        }))
    };

    let res = engine.run(cancel);
    if let Some(p) = progress {
        let _ = p.join();
    }

    if let Some(e) = &res.error {
        eprintln!("错误: {}", e);
        return 2;
    }
    if let Some(w) = &res.warning {
        eprintln!("警告: {}", w);
    }
    let rate = if res.elapsed_sec > 0.2 { res.tried as f64 / res.elapsed_sec } else { 0.0 };
    if res.found {
        println!();
        println!("=== 找到密码: {} ===", res.password);
        println!("尝试 {} 个, 用时 {}, 平均 {:.1} 个/秒", res.tried, format_time(res.elapsed_sec), rate);
        if let Some(f) = &res.result_file {
            println!("结果已保存: {}", f);
        }
        if extract_to.is_some() {
            eprintln!("提示: --extract-to 依赖 7z.exe，外部工具集成在 M4 实现；密码已给出。");
        }
        return 0;
    }
    if res.cancelled {
        println!("已取消（进度已保存, 下次加 --resume 继续）。");
        return 3;
    }
    if res.maxed_out {
        println!("达到 --max-tries 上限, 已停止（进度已保存, 加 --resume 继续）。");
        return 3;
    }
    println!();
    let note = engine.log_note.lock().unwrap().clone();
    println!("未找到密码。{}", if !note.is_empty() { format!("（编码方案: {}）", note) } else { String::new() });
    println!("共尝试 {} 个, 用时 {}, 平均 {:.1} 个/秒", res.tried, format_time(res.elapsed_sec), rate);
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

fn main() {
    // clap cannot express the single-dash multi-char option "-w2" (the C#
    // combinator flag); rewrite it to the long form "--w2" before parsing so
    // the CLI contract stays byte-compatible with the C# frontend.
    let args: Vec<std::ffi::OsString> = std::env::args_os()
        .map(|a| {
            if a == "-w2" {
                std::ffi::OsString::from("--w2")
            } else if let Some(s) = a.to_str() {
                if let Some(rest) = s.strip_prefix("-w2=") {
                    std::ffi::OsString::from(format!("--w2={}", rest))
                } else {
                    a.clone()
                }
            } else {
                a.clone()
            }
        })
        .collect();
    let cli = Cli::parse_from(args);
    let code = match cli.command {
        Some(Commands::Info { archive, hashcat }) => cmd_info(&archive, hashcat),
        Some(Commands::Bench { archive, threads, seconds }) => cmd_bench(&archive, threads, seconds),
        Some(Commands::Crack {
            archive, dicts, dict_b, rule, mask, c1, c2, c3, c4, min, max, threads,
            max_tries, tool, out, extract_to, resume, no_checkpoint, dedupe, quiet,
        }) => cmd_crack(
            archive, dicts, dict_b, rule, mask, c1, c2, c3, c4, min, max, threads,
            max_tries, tool, out, extract_to, resume, no_checkpoint, dedupe, quiet,
        ),
        None => {
            eprintln!("用法见 dictcrack --help");
            2
        }
    };
    std::process::exit(code);
}
