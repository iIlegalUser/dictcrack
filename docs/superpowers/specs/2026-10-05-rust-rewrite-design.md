# dictcrack Rust 重写（CLI 引擎）设计文档

日期：2026-10-05
状态：待评审

## 1. 目标与范围

把 dictcrack 的**核心破解引擎（CLI 侧）**用 Rust 重写为独立交付物 `dictcrack.exe`，
行为与现有 C# 版逐点对齐。**GUI（src\Gui.cs）完全不动**，继续调用 C# 版
`dist\dictcrack.exe`；Rust 产物先输出到 `rust\target\release\`，与 C# 产物并存、
互不覆盖。

动机：跨平台潜力（Linux/macOS）、零运行时单 exe 静态分发、热路径性能
（PBKDF2 / CRC / ZipCrypto）、顺带消除 CNG「共享句柄内部串行、须每线程一开」的坑。

### 1.1 非目标（明确不做）

- GUI 不用 Rust 重写，本期也不改 GUI 任何代码。
- RAR 1.5-4.x / 7z 原生化（C# 版也未做，仍走 7z.exe 进程回退）。
- GPU 加速（README 定位明确为纯 CPU；需要 GPU 用 hashcat）。
- tokio / 异步化（引擎是显式生产者-消费者 + 断点模型，无收益）。
- 改动 `src\` 下任何 C# 文件、`build\build.ps1`、`tests\*.ps1` 脚本本体
  （e2e 只新增一个可选参数 `-ExePath`，见 §9.2）。

## 2. 环境准备

- 工具链：`scoop install rust-gnu`（1.99.0，`x86_64-pc-windows-gnu`），已装好并验证可编译运行。
- **链接器决策（2026-10-05 定）**：本机无 MSVC Build Tools（无 link.exe、无 vswhere），MSVC target 无法
  链接；改用 GNU 工具链（rust-gnu 自带 MinGW 链接器）。为防其他已装 rust 包抢占 target，
  在 `rust\.cargo\config.toml` 钉 `target = "x86_64-pc-windows-gnu"`，任何机器/CI 行为一致。
- 产物形态：GNU target 静态链接 libgcc/libstdc++（Rust 运行时本身静态），单 exe 免安装，
  与现有形态一致。
- 构建：`cargo build --release`（在 `rust\` 下），MSRV 以 lockfile 记录的 stable 版本为准。
- CI（`.github\workflows` 现有自动编译发布工作流）后续加 rust target；
  本期可先用本地构建验收，CI 接入列入里程碑 M4 可选项。

## 3. 仓库布局与 crate 结构

现有 `src\`（C# 版）原样保留，作为行为对照基准。新增：

```
rust\
  Cargo.toml                # workspace: 成员 core 与 cli
  Cargo.lock                # 入库，保证可复现构建
  crates\
    core\                   # dictcrack-core（lib crate，引擎全部逻辑，无 UI/CLI 依赖）
      Cargo.toml
      src\
        lib.rs
        crypto.rs           # PBKDF2(sha2+hmac)、CRC32、SHA-256、ZipCrypto 密钥调度
        archive.rs          # RAR5 头链解析（vint/加密头记录）、ZIP 中央目录（含 ZIP64）
        verifier.rs         # Rar5 / Zip(ZipCrypto + WinZip-AES confirm) / Spawn(7z 回退)
        attacks.rs          # Dictionary / Mask / Combinator 候选源 + 链式变异
        engine.rs           # 生产者-消费者编排、断点会话、统计、基准
        encoding.rs         # BOM 探测、严格 UTF-8 探测、GBK 遍历计划
        session.rs          # session.json 读写、指纹校验、回退余量
        result.rs           # 结果文件写出（GBK 优先无损校验，回退 UTF-8 BOM）
        tool.rs             # 7z/rar 定位与按工具命令行转义（ToolLocator/WinArg 等价物）
    cli\
      Cargo.toml
      src\main.rs           # dictcrack 二进制：clap 解析，crack/info/bench 子命令
```

关键决策：引擎做成 `dictcrack-core` lib crate，CLI 只是薄壳。后续若要换 GUI
（egui/Tauri）或暴露 FFI，不必再动引擎；`cargo test` 直接测 lib。

## 4. 依赖选型（编译期 crate，全部纯 Rust，无 C 依赖）

| 功能 | crate（锁定大版本） | 替代与理由 |
|---|---|---|
| CLI 解析 | `clap` 4（derive） | 标准选择；help 文本贴齐 C# 版中文输出 |
| 序列化 | `serde` 1 + `serde_json` 1 | session.json；字段名与 C# 手写 JSON 完全一致 |
| SHA-256 / HMAC / PBKDF2 | `sha2` 0.10 + `hmac` 0.12 + `pbkdf2` 0.12 | RustCrypto 纯 Rust、有 SIMD 路径；预期与 CNG 持平或更快，且天然无线程串行坑 |
| AES-CTR（WinZip-AES） | `aes` 0.8 + `ctr` 0.9 | WinZip-AES 用 AES-CTR |
| Deflate 解压（确认路径） | `flate2` 1（`rust_backend` = miniz_oxide，纯 Rust） | 替代 C# DeflateStream |
| GBK | `encoding_rs` 0.8 | GB18030 解码器是 GBK 超集；与 .NET 936 的少量码位差异由编码矩阵测试兜底 |
| 通道 | `crossbeam-channel` 0.5 | 生产者-消费者 M/N 通道，贴 C# 版语义 |
| CRC32 | 自实现查表（照抄 C# 版表驱动 + RawStep） | 约 30 行，不值得引 crate |

不引：`zip` crate（其加密支持不符合头部校验路径）、`rayon`（引擎是显式
生产者-消费者+断点，模型不合）、tokio。

PBKDF2 实现视为可替换：`crypto.rs` 只暴露 `pbkdf2_sha256(pwd,salt,iters,bytes)` /
`pbkdf2_sha1(...)` 两个函数。若 M2 基准显示慢于 C# 版 CNG 超过 10%，评估切换
`ring` 或 `openssl` crate，接口不变。

## 5. 模块映射（C# → Rust）

| C# | Rust | 说明 |
|---|---|---|
| `Crypto.cs`（CNG P/Invoke） | `crypto.rs` | 纯 Rust PBKDF2；`[ThreadStatic]` 句柄缓存**整体删除**（RustCrypto 无状态） |
| `ArchiveInfo.cs` | `archive.rs` | RAR5 vint/加密头记录、ZIP 中央目录/ZIP64——纯字节解析，`&[u8]` + 显式游标 |
| `Verifier.cs` | `verifier.rs` | `trait Verifier { fn verify(&self, pwd:&str)->bool; fn native(&self)->bool; fn describe(&self)->String }`；ZipVerifier 的 ≤64MB 静态条目缓存保留（`OnceLock<RwLock<Option<(PathBuf, Arc<Vec<u8>>)>>>`） |
| `Attacks.cs` | `attacks.rs` | `trait CandidateSource`（`next(&mut self) -> Option<Candidate>` + `position()`/`seek()`）；Dictionary/Mask/Combinator 三实现 + 链式变异；RawLines 缓冲区复用用生命周期/`Cow<[u8]>` 表达 |
| `Engine.cs` | `engine.rs` | `CancellationToken` → `Arc<AtomicBool>`；`Interlocked` → `AtomicI64`/`AtomicBool`；checkpoint 每 3s 一存的循环照搬 |
| `Cli.cs` | `cli/main.rs` | 子命令 crack/info/bench；退出码 0/1/2/3 不变；选项全集保留 |
| 编码遍历（`DictEncoding`） | `encoding.rs` | BOM 识别 → 严格 UTF-8 探测 → UTF-8+GBK 双遍历去重 |
| 结果文件写出 | `result.rs` | GBK(936) 优先无损校验，失败改写 UTF-8 with BOM；不依赖系统区域 |
| 7z/rar 定位与转义 | `tool.rs` | `DICTCRACK_TOOL` 环境变量、常见安装路径探测、`QuoteForTool` 等价逻辑 |

## 6. CLI 契约（与 C# 版逐字对齐）

### 6.1 子命令与选项

- `dictcrack crack -a <包> -w <字典> [-w 更多]... [-w2 <字典B>] [--rule years,digits,leet,rev,cap,double]
  [--mask "..."] [-1..-4 自定义字符集] [--min N --max N] [-t 线程] [--max-tries N]
  [--tool exe] [--out 文件] [--extract-to 目录] [--resume] [--no-checkpoint]
  [--dedupe] [-q/--quiet]`
- `dictcrack info <包> [--hashcat]`
- `dictcrack bench -a <包> [-t 线程] [--seconds 秒]`
- `-w -` 从 stdin 读字典；`-w2` 存在且非 mask 时自动切 comb 模式；
  无法识别的 `-x` 选项打印「警告: 无法识别的选项 …（已忽略）」并忽略。

### 6.2 输出与退出码

- 启动横幅：`DictCrack 原生引擎 v1.0`（Rust 版保持同字符串，便于脚本比对）。
- 进度行：`\r` 覆写单行，格式 `{阶段} | 已试 {n}[/{total}] | {rate} 个/秒[ 剩余 hh:mm:ss] | 当前: [tag] cur`，
  截断 110 列、PadRight 118；`-q` 关闭。
- 找到：`=== 找到密码: <pwd> ===` + 尝试数/用时/均速 + `结果已保存: <path>`；
  未找到：`未找到密码。（编码方案: …）` + 统计；取消/达上限打印可 `--resume` 提示。
- 退出码：`0` 找到 / `1` 未找到 / `2` 出错 / `3` 已停止（可 `--resume`）。
- Ctrl+C：第一次优雅停止（进度已保存），第二次强制退出（exit 3）。

### 6.3 info / bench 输出

- `info` 逐行格式与 C# 版一致（文件/大小/格式/加密/目标条目/KDF 轮数/密码校验/验证路径），
  `--hashcat` 时输出 `Hashcat (-m 13000): <hash>`。
- `bench` 输出 `…Describe()…` + `单线程: X 个/秒` + `N 线程: Y 个/秒`；自动线程 = 核数-2、封顶 32。

## 7. session.json 兼容性

### 7.1 格式（与 C# 手写 JSON 完全同构）

```json
{
  "archive": "…", "params": "…", "dictfp": "…",
  "tried": 0, "fileIdx": 0, "lineIdx": 0, "seg": 0,
  "counter": 0, "idxA": 0, "idxB": 0,
  "saveTime": "…"
}
```

- 字段名、顺序、UTF-8 无 BOM、原子写（`.tmp` 再 replace）与 C# 一致。
- 位置：exe 同级 `session.json`（`current_exe()` 所在目录），不写 C 盘。
- 匹配规则：`archive` 不区分大小写比较 + `params` 严格相等 + `dictfp`（size+mtime 指纹）
  相等；旧会话无 `dictfp` 字段时对字典跑判定为不匹配（安全重跑，行为同 C#）。

### 7.2 跨实现续跑

- **必须能**：Rust 版 `--resume` 读取 C# 版保存的 session.json 并继续（反向亦然）。
  这是 e2e 断点续跑用例的一部分。

## 8. 行为对齐清单（魔法常量逐项钉死）

| 行为 | 值 / 规则 |
|---|---|
| 变异规则 | 按 `--rule` 顺序**链式叠加**；单行候选扇出上限 **100000** |
| years 范围 | 1980 ..= 当前年份+1（动态） |
| resume 回退余量 | `threads*8 + threads + 16` 个候选 |
| checkpoint 间隔 | 3 秒 |
| ZIP 条目内存缓存上限 | 64MB（`MaxCacheBytes = 64<<20`） |
| ZipCrypto 误报处理 | 1 字节检查值命中后全量解密+解压+CRC 确认 |
| WinZip-AES HMAC | 对**全部密文流式**计算（非前 1024 字节） |
| RAR5 PswCheck | `fold8(PBKDF2-HMAC-SHA256(UTF8(pwd), salt16, 2^Lg2Cnt + 32))`；解析头内存储的 8 字节 check 时，须先验 `SHA256(check)[0..4]` 与紧随的 4 字节 csum 一致（不一致视为无有效校验数据） |
| 编码计划 | BOM → 严格 UTF-8 探测；合法则 UTF-8+GBK 双遍历去重，否则仅 GBK |
| 结果文件编码 | GBK(936) 优先无损校验，失败改写 UTF-8 with BOM |
| 外部工具回退 | RAR4/7z/无校验数据 → 7z.exe/rar.exe；候选含 `\r`/`\n` 跳过；引号/反斜杠/空格按工具转义 |

## 9. 测试策略（现有资产全复用）

### 9.1 单元测试（`cargo test`）

`tests\unittests.cs` 的 51 项逻辑逐条翻译到 `dictcrack-core` 的 `#[cfg(test)]`：
PBKDF2 RFC 6070/7914 向量、会话序列化往返、ZIP64 合成样本（含 >65535 条目回归）、
掩码/规则/行切分/编码计划、结果文件编码策略、外部工具参数转义。

### 9.2 端到端（`tests\run-tests.ps1`）

- 脚本本体不动，**新增可选参数 `-ExePath <path>`**（默认仍指向 `dist\dictcrack.exe`），
  验收 Rust 版时：`powershell -File tests\run-tests.ps1 -ExePath rust\target\release\dictcrack.exe`。
- 18 项全绿即对齐（WinRAR/7z 现场造真样本，是最强等价性验证）。
- 额外加一项：C# 版跑一半中断 → Rust 版 `--resume` 续跑命中（§7.2）。

### 9.3 性能基准

同机 22 线程跑 `bench` 子命令，对照 C# 版三条路径。验收线：**RAR5 / ZIP-AES /
ZipCrypto 三条路径均不慢于 C# 版**；ZipCrypto 预期明显更快。PBKDF2 若慢于 CNG
超过 10%，触发 §4 的实现替换评估。

## 10. 里程碑（每步独立可验收）

- **M1 骨架+解析**：workspace 搭好；`archive.rs` + `info` 子命令可对真包输出
  格式/加密方式/KDF 轮数，与 C# 版 `info` 逐字段一致。
- **M2 原生验证**：`crypto.rs` + `verifier.rs`（RAR5 + ZIP 双路径）；PBKDF2 RFC
  向量过、真包密码命中；`bench` 初版跑出并与 C# 版对比。
- **M3 攻击+引擎**：`attacks.rs` + `engine.rs` + `encoding.rs` + `session.rs` +
  `result.rs`；crack/bench 全功能、断点续跑、编码矩阵 e2e 全绿、跨实现续跑用例过。
- **M4 收尾**：`tool.rs`（7z 回退）、`--hashcat` 导出、性能对比报告；可选接入
  GitHub Actions rust target。

## 11. 风险与对策

| 风险 | 对策 |
|---|---|
| GBK 映射差异（encoding_rs 是 GB18030 解码器，与 .NET 936 少量码位不同） | 编码矩阵 e2e 已有 GBK 中文密码用例；若踩到，为该码位集写显式映射表 |
| PBKDF2 慢于 CNG 超 10% | `crypto.rs` 接口隔离，切换 `ring`/`openssl` 不动调用方（M2 末尾判定） |
| RAR5 头解析边界样本（vint 溢出、加密头嵌套） | 逐行对照 C# 版移植 + 现有真包样本回归 |
| 行为漂移（§8 魔法常量） | 全部抽 `const`，值与 C# 版逐项核对；e2e 断点续跑用例兜底 |
| session.json 跨实现不兼容 | §7.2 列为硬验收项；serde_json 字段名对齐 C# 手写格式 |

## 12. 验收标准

1. `cargo test` 全绿（51 项单测逻辑全数落地）。
2. `tests\run-tests.ps1 -ExePath rust\target\release\dictcrack.exe` 18 项全绿。
3. C#→Rust / Rust→C# 双向 `--resume` 续跑命中。
4. 同机 bench：三条原生路径均不慢于 C# 版。
5. Rust 产物为单 exe 静态链接（GNU target，libgcc/libstdc++ 静态），
   `rust\target\release\dictcrack.exe` 双击/命令行可用，不依赖外部 DLL。
