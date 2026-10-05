// dictcrack CLI (Rust rewrite of Cli.cs).
use clap::{Parser, Subcommand};
use dictcrack_core::archive::{self, ArchiveKind};
use dictcrack_core::{engine, verifier};
use std::path::Path;
use std::sync::Arc;

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
        /// 压缩包路径
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
        // TODO(M3): -w/-w2/--rule/--mask/-1..-4/--min/--max/--max-tries/--tool/
        // --out/--extract-to/--resume/--no-checkpoint/--dedupe/-q
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
            // canonicalize prepends the \\?\ verbatim prefix on Windows; the
            // C# Path.GetFullPath output has no such prefix, strip it to keep
            // the info output byte-identical.
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
                    println!(
                        "加密: {}",
                        if r.header_encrypted { "RAR5 头加密（-hp）" } else { "RAR5 文件数据加密" }
                    );
                    if let Some(n) = &r.entry_name {
                        println!("目标条目: {}", n);
                    }
                    println!("KDF: PBKDF2-HMAC-SHA256, {} 轮", 1u64 << r.lg2_count);
                    println!(
                        "密码校验: {}",
                        if r.psw_check.is_some() { "有（可原生快速验证）" } else { "无（回退外部工具）" }
                    );
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
                        if z.aes {
                            format!("WinZip AES-{}", z.aes_strength as u32 * 64 + 64)
                        } else {
                            "传统 ZipCrypto".to_string()
                        }
                    );
                }
            }
        }
        ArchiveKind::SevenZip => println!("格式: 7z"),
        ArchiveKind::Unknown => println!("格式: 无法识别（{}）", info.detect_note),
    }
    println!(
        "验证路径: {}",
        if info.native_supported() { "原生引擎 (native)" } else { "外部工具 (external)" }
    );
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

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Some(Commands::Info { archive, hashcat }) => cmd_info(&archive, hashcat),
        Some(Commands::Bench { archive, threads, seconds }) => cmd_bench(&archive, threads, seconds),
        Some(Commands::Crack { archive }) => {
            println!("crack: {} (TODO M3)", archive);
            0
        }
        None => {
            eprintln!("用法见 dictcrack --help");
            2
        }
    };
    std::process::exit(code);
}
