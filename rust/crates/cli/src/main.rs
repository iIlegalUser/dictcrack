// dictcrack CLI (Rust rewrite of Cli.cs).
use clap::{Parser, Subcommand};

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

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Info { archive, hashcat: _ }) => {
            println!("info: {}", archive);
            // TODO(M1)
        }
        Some(Commands::Bench { archive, threads, seconds }) => {
            println!("bench: {} t={} s={}", archive, threads, seconds);
            // TODO(M2)
        }
        Some(Commands::Crack { archive }) => {
            println!("crack: {}", archive);
            // TODO(M3)
        }
        None => {
            eprintln!("用法见 dictcrack --help");
            std::process::exit(2);
        }
    }
}
