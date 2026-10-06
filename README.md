# DictCrack — 压缩包密码字典/掩码破解工具

Windows 下的压缩包密码恢复工具：直接解析 RAR5 / RAR 4.x / 7z / ZIP 加密头，用密码
校验值离线验证候选密码，不产生任何子进程；无法原生校验的变体（需要解压器的 7z、
RAR 4.x 压缩条目等）自动回退到 7-Zip / WinRAR 进程测试。支持字典 / 掩码 / 组合攻击、
中文场景变异规则、字典编码自动遍历（UTF-8 / UTF-16 / GBK）与断点续跑。

双引擎：

- **Rust 引擎**（`rust\`）：命令行，单 exe 静态分发、零运行时依赖；原生路径性能
  全面更快（RAR5 约 2.9×、ZIP AES 约 7.6×、ZipCrypto 约 4.0×，RAR 4.x / 7z 见下）。
- **C# 引擎**（`src\`）：WinForms 图形界面 + 命令行，运行无需安装 .NET
  （Windows 8+ 自带 .NET Framework 4.x）。
- 两个引擎的 CLI 契约逐点一致，`session.json` 断点续跑双向互通。

## 实测性能（24 逻辑核，默认 22 线程）

端到端 `crack` 实测（含候选源开销，不是绕过管道的 bench 数字）：

| 加密方式 | 引擎路径 | C# 引擎 | Rust 引擎 |
|---|---|---|---|
| RAR5（PBKDF2-SHA256 2^15 轮） | 原生头部校验 | ~1 500 个/秒 | 约 2.9× |
| ZIP WinZip AES-256 | 原生 PBKDF2-SHA1 + HMAC | ~5 000 个/秒 | 约 7.6× |
| ZIP ZipCrypto | 原生流密码 + CRC 全量确认 | ~5 000 000 个/秒 | 约 4.0× |
| RAR 4.x（-hp / -p 存储） | Rust 原生 SHA-1 KDF + AES；C# 无此路径走 7z 进程 | ~124-130 个/秒（7z 进程） | **~1 300-1 400 个/秒** |
| 7z（-mhe / AES+COPY 内容） | Rust 原生 SHA-256 KDF + AES；C# 无此路径走 7z 进程 | ~118 个/秒（7z 进程） | **~950 个/秒** |
| RAR 4.x 压缩条目 / 7z 需解压器 | 7z 进程回退（两引擎相同） | ~120 个/秒 | 同回退路径 |

RAR5 的 PBKDF2（2^15 轮）、RAR 4.x 的 SHA-1 KDF（0x40000 轮）与 7z 的 SHA-256 KDF
（默认 2^19 轮）都是**格式强制的 KDF**，纯 CPU 即为上述量级；ZIP 可达每秒数百万候选。
换句话说，RAR 4.x / 7z 原生化省掉的是**进程启动开销**（每次 ~40 ms），而不是 KDF
成本——所以收益是 ~10× 量级而非数量级突破。

7z 能否原生校验**由 coder 链决定、与扩展名无关**：加密头仅含 AES、或内容为
AES+COPY（存储）时 CRC 可直接比对；一旦需要 LZMA/LZMA2/BCJ 解压器，校验就必须
解码数据，本工具不做，自动回退外部工具并在 `info` 里说明原因。详见
[docs/rar4-native-verification.md](docs/rar4-native-verification.md)、
[docs/7z-native-verification.md](docs/7z-native-verification.md)。

## 环境要求

- Rust 引擎：单 exe，无运行时依赖，解压即用。
- C# 引擎：Windows 7 / Server 2008 R2 或更高（原生 PBKDF2 走系统 CNG
  `bcrypt.dll`），运行无需安装 .NET；编译用系统自带的 csc（见下）。无任何
  第三方依赖。
- 仅外部工具回退路径（7z 需解压器的变体、RAR 4.x 压缩条目等）需要 7-Zip 的
  `7z.exe` 或 WinRAR 的 `rar.exe`，可用 `--tool` 或环境变量 `DICTCRACK_TOOL` 指定；
  原生路径完全不需要。

## 构建

### Rust 引擎

```powershell
cd rust
cargo build --release   # 产出 rust\target\x86_64-pc-windows-gnu\release\dictcrack.exe
```

工具链为 `x86_64-pc-windows-gnu`（`rust\.cargo\config.toml` 已钉死，任意机器
行为一致）；产物单 exe 静态链接，无外部 DLL 依赖。

### C# 引擎

无第三方依赖，用系统自带 .NET Framework 4.8 编译器：

```powershell
powershell -ExecutionPolicy Bypass -File build\build.ps1
# 产出 dist\dictcrack.exe（命令行）与 dist\dictcrack-gui.exe（图形界面）
```

CI（`.github\workflows\release.yml`）在 Windows runner 上分别构建并测试两个
引擎，tag 推送时聚合双 zip 发布 Release。

## 使用

### 图形界面

直接运行 `dist\dictcrack-gui.exe`。支持拖入压缩包/字典、三种攻击模式、变异规则、
断点续跑、基准测速；找到密码自动复制到剪贴板、写结果文件，可一键解压或把密码
提前到字典首行。命令行参数可自动启动：`dictcrack-gui.exe -a <包> -w <字典> [-t N] [--mask ...]`，
传 `-w` + `-w2` 则自动切换到组合模式并填入 A/B 两个字典。

**双引擎自动选择**：GUI 启动时自动探测 Rust 引擎（`--version` 握手判别，探测顺序：
同目录 `dictcrack-rs.exe` → 同目录 `dictcrack.exe` → 开发目录
`rust\target\x86_64-pc-windows-gnu\release\dictcrack.exe`）。找到则破解与基准测速走
Rust 引擎进程模式——Rust CLI 以 `--progress` JSON 行协议上报进度、`--cancel-event`
命名内核事件优雅停止、`--session-file` 与 C# 引擎共享断点文件，界面会标注
"Rust 进程模式"；找不到自动回退内置 C# 引擎，行为与旧版完全一致。把 Rust 发布包
里的 `dictcrack-rs.exe` 复制到 `dictcrack-gui.exe` 旁边即可启用。

### 命令行（两个引擎契约一致）

```
dictcrack crack -a <压缩包> -w <字典> [--rule years,digits,leet,rev,cap,double] [-t 线程]
                [--out 结果文件] [--dedupe]
dictcrack crack -a <压缩包> -w -                              # 从 stdin 读字典
dictcrack crack -a <压缩包> --mask "前缀?d?d?d?d" [-1 自定义字符集] [--min N --max N]
dictcrack crack -a <压缩包> -w <字典A> -w2 <字典B>          # 组合攻击
dictcrack info  <压缩包> [--hashcat]   # 格式 / 加密方式 / KDF 轮数 / 验证路径
                                       # --hashcat: 导出 hashcat -m 13000（RAR5）格式 hash
dictcrack bench -a <压缩包>   # 基准测速（RAR5 / RAR 4.x / 7z 快路径 / 加密 ZIP）
```

常用选项：`--resume`（从中断处继续）、`--max-tries N`（限次停止，测试用）、
`--extract-to <目录>`（命中后自动解压）、`--out <文件>`（结果文件路径，默认
`<压缩包名>_password.txt`）、`--dedupe`（字典模式跨行去重，内存换时间）、
`--tool <exe>`（后备验证工具路径，也可用环境变量 `DICTCRACK_TOOL` 指定
7z.exe/rar.exe）、`-q`（静默）。字典可给多个 `-w`，`-w -` 从标准输入读入。
退出码：`0` 找到密码，`1` 未找到，`2` 出错，`3` 已停止（可 `--resume`）。
被占用 / 无权限的压缩包是一等错误：`info`/`bench` 报
「无法读取该文件（可能被占用或权限不足）」并 exit 2，`crack` 报
「解析压缩包失败: …」exit 2，不会静默当作未知格式；目录按 `File.Exists`
语义报「文件不存在」。

变异规则按选择顺序**链式叠加**：每个预设也会变异前面预设的输出，如
`--rule years,digits` 会产出 `词+年份` 与 `词+年份+数字` 两层形态，覆盖
"词+年份+数字"类组合；单行候选扇出上限 100000，防止组合爆炸。`years` 的
年份范围为 1980 到当前年份+1（动态）。

掩码占位符：`?l` 小写 `?u` 大写 `?d` 数字 `?s` 特殊 `?a` 全部 `?h/?H` 十六进制
`?1..?4` 自定义字符集。

`info` 会打印格式、加密方式与**验证路径**，无法原生的包还会说明回落原因：

```
$ dictcrack info game.rar
文件: D:\...\game.rar
大小: 70544822 字节
格式: RAR 5.x
加密: RAR5 头加密（-hp）
KDF: PBKDF2-HMAC-SHA256, 32768 轮
密码校验: 有（可原生快速验证）
验证路径: 原生引擎 (native)

$ dictcrack info photos.7z
格式: 7z
说明: 7z format (LZMA2: password check needs a decompressor; using external tool)
验证路径: 外部工具 (external)
```

示例：

```powershell
# 字典 + 年份/数字变异（链式：词+年份、词+年份+数字都会试到）
dictcrack crack -a game.rar -w cnwords.txt --rule years,digits

# 结果写到指定文件
dictcrack crack -a game.rar -w cnwords.txt --out D:\found.txt

# 管道喂字典
type words.txt | dictcrack crack -a game.rar -w -

# 六位纯数字掩码
dictcrack crack -a game.rar --mask "?d?d?d?d?d?d" -t 24

# 中断后继续（会话保存在软件目录 session.json）
dictcrack crack -a game.rar -w big.txt --resume
```

`--resume` 说明：恢复时会回退一个安全余量（约 threads×8+threads+16 个候选），
覆盖取消瞬间仍在队列中的候选；会话记录字典 size+mtime 指纹，字典被编辑过则
自动忽略旧会话重跑；会话文件写入失败会给出警告，不再静默。无法识别的命令行
选项会打印警告并忽略（防止拼写错误静默跑错模式）。Ctrl+C 第一次优雅
停止（进度已保存），第二次强制退出。

## 架构

```
src\                     C# 引擎（GUI 唯一实现 + 命令行）
  Crypto.cs      托管/原生 PBKDF2（每线程 CNG 句柄）、CRC32
  ArchiveInfo.cs RAR5 头链解析（vint/加密头记录）、ZIP 中央目录解析（含 ZIP64，支持
                 >4GB / >65535 条目）、格式识别
  Verifier.cs    Rar5Verifier / ZipVerifier（含 ZipCrypto 全量确认；确认阶段将目标
                 条目缓存进内存，≤64MB，减少高线程数下的重复磁盘 I/O）/ 7z 进程回退
                 （C# 引擎按设计只保留 7z.exe 回退，无 RAR4/7z 原生路径）
  Attacks.cs     字典（多编码遍历+链式变异，支持 stdin）、掩码、组合三种候选源（可序列化进度）
  Engine.cs      生产者-消费者线程编排、断点会话、统计、基准
  Cli.cs         命令行前端
  Gui.cs         WinForms 前端（扁平设计、拖放、DPI 缩放）
rust\                    Rust 引擎（命令行）
  crates\core\src\
    archive.rs    RAR5 头链（vint/加密头记录）、RAR 1.5-4.x 头链、7z 容器、ZIP 中央
                  目录（含 ZIP64）解析与格式识别
    verifier.rs   RAR5 / RAR 4.x / 7z / ZIP 原生验证器（含 ZipCrypto 全量确认）
    crypto.rs     PBKDF2-HMAC-SHA256（含 4 路 SHA-NI 交错内核）/ SHA1、7z SHA-256 KDF、
                  AES-128/256-CBC、CRC32
    rar3.rs       RAR 1.5-4.x 原语：带 rar29 写回的流式 SHA-1、0x40000 轮 KDF、
                  AES-128-CBC（密码 ≤28 字符时走 SHA-NI 快路径，结果逐位相同）
    attacks.rs    字典 / 掩码 / 组合三种候选源（多编码遍历 + 链式变异）
    encoding.rs   字典编码探测（BOM / 严格 UTF-8 / GBK）
    engine.rs     生产者-消费者编排、断点会话、checkpoint、基准
    result.rs     结果文件（GBK 优先无损回退 UTF-8 BOM）
    session.rs    session.json 序列化（字段序与 C# 逐字节一致）
    tool.rs       外部工具定位与参数转义（7z 自解析 vs rar CRT argv 两套规则）
  crates\cli\src\
    main.rs       CLI 前端（crack / info / bench）
    console.rs    Windows 控制台输出（真控制台 WriteConsoleW，重定向保持 UTF-8）
build\build.ps1   csc 编译脚本（CLI + GUI）
tests\run-tests.ps1    端到端测试（38 项，WinRAR/7z 现场造样本 + RAR4 字节字面量样本）
tests\unit-tests.ps1   C# 纯单元测试（无外部工具依赖）
```

实现要点：

- **RAR5 校验值算法**（对照 unrar `crypt5.cpp` 用真实样本验证）：
  `PswCheck(8B) = fold8(PBKDF2-HMAC-SHA256(UTF8(pwd), salt16, 2^Lg2Cnt + 32))`，
  头里另存 `SHA256(PswCheck)[0..4]` 做完整性。-hp 头加密包的校验数据在明文的
  加密头记录里，**同样可原生破解**。
- **RAR5 多缓冲 PBKDF2**：一次算 4 个候选，4 条独立 `sha256rnds2` 链交替发射，
  把 SHA 单元从延迟受限转为接近吞吐受限（实测单线程 1.64×，8 线程 1.62×）；
  无 SHA-NI 的核（如 E 核）自动逐路回退标量路径。
- **RAR 4.x 原生化**：`-hp` 用归档末尾 24 字节 `[salt(8)][ENDARC 首块(16)]` 解密
  比对固定常量；`-p` 存储用全量解密后前 `UnpSize` 字节的 CRC32 比对文件头
  `FileCRC`——两条路径都是精确校验，命中的密码一定正确。KDF 是 0x40000 轮 SHA-1，
  密码 ≤28 字符时 rar29 写回不可能触发，可安全走 SHA-NI 快路径（单线程再快 2.1×）。
- **7z 原生化**：判据**由 coder 链决定，与扩展名无关**。加密头仅含 AES、或内容为
  AES+COPY（存储）时，CRC32 可直接比对（PAD==0 也是原生）；一旦 AES 之后还有
  LZMA/LZMA2/BCJ 等解压器，CRC 覆盖的是解压后字节，就必须解码，本工具不做，自动
  回退外部工具。加密头无任何 CRC 时只剩 AES-CBC 尾部零填充可查，PAD==0 时无判据，
  同样回退——这条边界刻意与前者不同，理由见实现说明。
- **CNG 并行化**（C# 引擎）：`BCryptDeriveKeyPBKDF2` 共享算法句柄时内部串行，
  每线程各开一个句柄后恢复近线性扩展。
- **ZipCrypto 误报**：1 字节检查值有 1/256 误报率，命中后再做全量解密+解压+CRC
  校验，保证报出的密码一定正确。

支持格式：RAR5（-p 与 -hp）、RAR 1.5-4.x（-hp 与 `-p` 存储）、7z（加密头仅 AES /
内容 AES+COPY）与加密 ZIP（ZipCrypto / AES-128/192/256）走原生快速路径；其余变体
（RAR 4.x 压缩条目、7z 需解压器的 folder、无密码校验数据的 RAR5 等）自动回退外部
工具测试，`info` 会说明回落原因。

字典编码：按 BOM 识别 UTF-8/UTF-16（UTF-8 BOM 正确剥离，首行候选不带 U+FEFF）；
无 BOM 时先做严格 UTF-8 探测，合法则 UTF-8 + GBK 双遍历（同一行去重），否则只跑
GBK——GBK 字典不会浪费 UTF-8 遍。组合攻击对字典 A、B 都执行同一套编码扫描
（UTF-8/GBK 遍历），UTF-8 的字典 B 不会再被当 GBK 读成乱码。

设计文档与验收报告见 `docs\superpowers\specs\`。

## 测试

```powershell
# 端到端，默认测 C# 引擎（需要 7-Zip 造 ZIP/7z 样本，WinRAR 的 rar.exe 造 RAR5 样本）
powershell -ExecutionPolicy Bypass -File tests\run-tests.ps1

# 端到端测 Rust 引擎（GUI 2 项跳过；RAR4/7z 原生路径的断言只在 -ExePath 模式执行）
powershell -ExecutionPolicy Bypass -File tests\run-tests.ps1 -ExePath rust\target\x86_64-pc-windows-gnu\release\dictcrack.exe

# C# 纯单元测试（无外部工具依赖）
powershell -ExecutionPolicy Bypass -File tests\unit-tests.ps1

# Rust 单元测试
cd rust
cargo test
# 真控制台渲染测试需手动跑（要真实 conhost 窗口）：
cargo test --test console_render -- --ignored
```

run-tests.ps1 需要 7-Zip 造 ZIP/7z 样本、WinRAR 的 `rar.exe` 造 RAR5 样本。RAR 4.x
样本**不需要外部工具**：WinRAR 7 已不能生成 RAR4（`-ma4` 报未知选项），两个最小样本
以字节字面量固化在脚本与单测里，固化前已用 `UnRAR.exe` / `7z.exe` 双向验证过。
覆盖：各加密路径的字典命中与错密码穷尽、未加密报错、掩码/组合/规则、UTF-8 BOM /
UTF-16LE / GBK 中文密码矩阵、断点续跑（含 RAR4）、基准、GUI 自动启动、open_error
（缺失/目录/被锁文件三入口 exit 2）、**早返回路径不挂起**、7z 分档路由、单密文块
边界。`Run-Cli` 带 120 秒看门狗：任何"不返回"变成测试失败，而不是卡死整个套件。

断言分两种：**结果类**（命中/拒绝/退出码）两个引擎都跑；**能力与路由类**
（"这条路径应为原生"）只在 `-ExePath` 模式下断言 native，否则断言 external 或跳过
——C# 引擎按设计只有 7z.exe 回退，不做区分会让 CI 的两个 job 必然有一个假红或假绿。

unit-tests.ps1 把引擎源码与 unittests.cs 编译成独立程序集直接跑，覆盖 PBKDF2
已知向量、会话序列化往返、ZIP64 合成样本（含 >65535 条目回归）、掩码/规则/
行切分/编码计划、结果文件编码策略、外部工具参数转义等。

cargo test 覆盖 PBKDF2（含 4 路内核对拍标量）、RAR3 KDF 向量与快路径边界、
7z KDF 与容器解析、RAR4 头解析与校验三态、ZIP64 合成样本、各候选源与转义矩阵、
CLI 预扫描纯函数、session 双向序列化、engine 完成标志等。

## 运行期生成的文件

所有生成物都落在 exe 所在目录，不往系统其他位置写文件：

| 文件 | 说明 |
|---|---|
| `session.json` | 断点续跑会话（进度 + 参数指纹），命中/跑完自动删除 |
| `<压缩包名>_password.txt` | 默认结果文件（可用 `--out` 改路径） |
| `dictcrack-gui.cfg` | GUI 记住的上次输入（含个人路径，已在 .gitignore 排除） |

结果文件编码：优先显式 GBK(936)（中文环境记事本直接可读），但先做无损校验，
GBK 表示不了的密码（emoji、生僻字等）自动改写 UTF-8 with BOM；从不依赖机器
的 `Encoding.Default`，en-US 等 CI 区域不会写坏中文密码。

## 合规与授权

本工具仅用于**已获得明确授权**的口令审计、密码恢复测试与安全学习场景（例如
恢复自己的档案、企业内部获授权的口令强度评估）。对未授权的账户/档案使用本
工具可能违反当地法律；使用者需自行承担合规责任。

## 已知限制

- 纯 CPU：RAR5 的 PBKDF2（默认 2^15 轮）是格式强制的，有 GPU 请用 hashcat
  （`dictcrack info <压缩包> --hashcat` 可直接导出 hashcat -m 13000 格式 hash）。
  RAR 4.x 的 SHA-1 KDF（0x40000 轮）与 7z 的 SHA-256 KDF（默认 2^19 轮）同理，
  速率天花板由格式决定。
- 外部工具回退路径的候选不能含换行（\r/\n 会被跳过）；引号、反斜杠、空格等
  特殊字符已做完整的命令行转义，原生路径无任何字符限制。
- 组合攻击会把字典 B 整体载入内存。
- **RAR 4.x 压缩条目**（method 0x31-0x35）不能原生校验：CRC 在**解压后**的字节上，
  需要完整 RAR LZ/PPMd 解码器，本工具不做，自动回退外部工具。
- **7z 需要解压器的 folder**（AES 之后还有 LZMA/LZMA2/BCJ 等）同样回退外部工具；
  多 folder / 多 PackStream、BCJ2、KDF 轮数超过 2^24 的包也一律回退（`info` 说明原因）。
- RAR 4.x `-p` 存储的原生校验要把整段密文读进内存，数据区上限 16 MiB，超过则回退。
- Rust 引擎重定向输出的字节流恒为 UTF-8（真控制台走 WriteConsoleW 按 UTF-16
  渲染），与 C# 引擎按控制台代码页输出不同。
