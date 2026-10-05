# dictcrack Rust 重写 — 验收与性能报告

日期：2026-10-05（同日收尾轮更新）
状态：M1-M4 全部完成，验收通过；设计文档全部验收项闭合

## 交付物

- `rust\target\x86_64-pc-windows-gnu\release\dictcrack.exe`：单 exe（约 1.4 MB），
  GNU target 静态链接，无外部 DLL 依赖；已验证拷到干净目录独立运行。
- 源码：`rust\crates\core`（引擎 lib）+ `rust\crates\cli`（CLI 薄壳）。
- 工具链：`scoop install rust-gnu` 1.99.0，`rust\.cargo\config.toml` 钉死
  `x86_64-pc-windows-gnu`。构建：`cargo build --release`（在 `rust\` 下）。

## 里程碑

| 里程碑 | 内容 | 验证 |
|---|---|---|
| M0 | rust-gnu 工具链 | 编译运行 OK |
| M1 | archive.rs（RAR5 头链 + ZIP64）+ info | info 与 C# 版逐字节一致 |
| M2 | crypto.rs + verifier.rs + bench | 三条原生路径命中/拒绝全对 |
| M3 | attacks/engine/encoding/session/result + crack CLI | 字典/掩码/组合/规则/编码矩阵 + 断点续跑 |
| M4 | tool.rs（7z 回退）+ hashcat 导出 | 7z 命中、尾部反斜杠密码、hashcat 逐字一致 |

## 验收结果（对照 spec §12）

1. `cargo test`：**55 项单测全绿** —— unittests.cs 的 15 组逻辑全数落地
   （PBKDF2 RFC 向量 ×4、会话往返含 JSON 转义逐字节断言、字典指纹与匹配语义、
   规则/掩码/组合/去重、RawLines 含 3MB 长行、编码计划 ×4、ZIP64 合成样本、
   65536 条目回归、hashcat 格式、RAR5 截断容忍、UTF-16 字典变异、结果文件
   GBK/UTF-8 回退、WinArg 全矩阵、不可读路径 open_error、CLI 预扫描纯函数
   crack_argv/is_recognized/normalize_w2/last_checkpoint/path_missing）。✔
2. `tests\run-tests.ps1 -ExePath <rust dictcrack.exe>`：**19 项 PASS、0 失败**
   （2 项 GUI 测试按 spec 属 GUI 范围跳过——Rust 无 GUI）。覆盖 RAR5 -p/-hp、
   ZipCrypto 全量确认、AES-256 HMAC、7z 回退、掩码、组合、规则、UTF-8 BOM /
   UTF-16LE / GBK 中文密码矩阵、断点续跑、bench、尾部反斜杠密码、
   引号+反斜杠密码、`--extract-to` 解压。✔（C# 侧同套件 21 项全过）
3. C#↔Rust **双向 `--resume` 续跑命中**，且已验证会话真实生效（非从头重跑）：
   C# 存会话 → Rust 续跑尝试数 = 会话进度 + 回退余量后命中；反向亦然。
   依赖下文「dictfp 对齐」修复。✔
4. 同机 bench：三条原生路径均不慢于 C# 版（见下表，全部大幅超过）。✔
5. 单 exe 静态链接，独立运行不依赖外部 DLL（拷贝到干净目录验证）。✔
6. CI：`.github\workflows\release.yml` 新增 `rust` job（stable GNU 工具链 →
   `cargo test --locked` → `cargo build --release` → e2e `-ExePath` 对阵 Rust
   exe → 打包上传）；tag 时 `release` job 聚合 C# + Rust 两个 zip 发 Release。✔

## 性能对比（同机，release vs release，单线程 / 自动线程，候选/秒）

| 路径 | C# | Rust | 提升（单 / 多） |
|---|---|---|---|
| RAR5 PBKDF2-SHA256 (2^15+32) | 155 / 1 344 | 333 / 3 885 | 2.1× / 2.9× |
| ZIP AES-256 PBKDF2-SHA1 | 647 / 4 683 | 2 929 / 35 728 | 4.5× / 7.6× |
| ZipCrypto | 2 828 111 / 10 875 818 | 4 930 879 / 43 176 561 | 1.7× / 4.0× |

收益来源：RustCrypto 的纯 Rust PBKDF2 省掉了 P/Invoke 封送开销，且天然无
CNG「共享句柄内部串行」的坑（C# 版须每线程独立开句柄）；ZipCrypto 的 CRC /
密钥调度热循环内联更彻底。

## 行为对齐要点

- CLI 选项/输出文案/退出码 0-1-2-3 与 C# 版逐字一致；`-w2` 单横杠多字符选项
  在 clap 解析前重写为 `--w2` 保持契约兼容。
- session.json：手写 JSON，字段名/顺序/UTF-8 无 BOM/原子写与 C# 完全一致。
- 魔法常量逐项对齐：链式变异扇出上限 100000、years 1980..=今年+1、resume
  回退 `threads*8+threads+16`、checkpoint 3s、ZIP 缓存 64MB、RAR5 csum 校验、
  GBK 无损校验回退 UTF-8 BOM、WinArg 按工具转义。
- info 的 `\\?\` canonicalize 前缀已剥离，与 C# `Path.GetFullPath` 输出一致。

## 踩坑记录（重写中新踩的）

1. **crossbeam bounded channel 死锁**：worker 在命中 / --max-tries 后退出，
   producer 仍向已满 channel 阻塞发送 → join 永不返回。C# 版靠
   `queue.Add(cand, ct)` 的取消令牌抛异常跳出。修复：emit 先查 cancel/
   external 标志跳过发送 + `send_timeout` 100ms 兜底。
2. **clap 无法表达 `-w2`**：单横杠多字符选项 clap 不原生支持，解析前重写。
3. **clap `color` feature** 拉 `windows-sys`，GNU target 需 `dlltool.exe`（rust-gnu
   未带）；关掉 default features 解决。
4. **serde_json 字段顺序**：默认 Map 按字母序，与 C# 手写顺序不符；改为手工
   拼接 JSON 保证字段序一致（C# 的容错按键读取其实也能兼容，但严格对齐更稳）。

## 已知限制 / 后续

- GUI 未动（spec 明确不做）：GUI 仍用 `dist\dictcrack.exe`（C# 版）。若要让 GUI
  用 Rust 引擎，需加 `--progress` 机器可读进度协议 + GUI 改进程模式（二期）。
- RAR 1.5-4.x / 7z 仍走 7z.exe 进程回退（与 C# 版一致，未原生化）。

## 收尾轮（同日）补齐的设计文档缺口

- **`--extract-to` 落地**：此前 Rust CLI 只打印"集成在 M4 实现"的提示。
  现已对齐 C# DoExtract：找工具（ToolLocator）→ 建目录 → `x -y -p<pwd>
  -o<dir> <archive>`（per-tool raw_arg 转义）→ 解压完成/失败文案与退出码 0/2。
- **未知选项警告**（spec §6.1）：crack argv 预扫描，未知 `-...` 打印
  「警告: 无法识别的选项 …（已忽略）」并丢弃，多余位置参数静默忽略，
  无子命令时按 C# 语义默认走 crack；info/bench/help/--help/--version 直通。
- **checkpoint 时间戳**：`secs % 1000000` 垃圾值改为 GetLocalTime 的
  `HH:mm:ss`，与 C# `DateTime.Now.ToString("HH:mm:ss")` 一致（"续跑: …"展示）。
- **dictfp 跨实现对齐（真 bug 修复）**：C# 指纹用 `LastWriteTimeUtc.Ticks`
  （100ns 自 0001-01-01），Rust 原用 UNIX epoch 纳秒 —— 两边对同一字典算出的
  字符串永不相等，跨实现 `--resume` 时会话必被"已忽略不匹配的历史会话"静默
  丢弃、从头重跑。Rust 改为 `UNIX 纳秒/100 + 621355968000000000` 与 .NET Ticks
  逐位一致（Windows filetime 本身 100ns 分辨率），双向续跑实测通过。
- **UTF-16 字典 BOM 剥离（移植缺陷）**：C# 用 StreamReader 自动消费 BOM，
  Rust 直接解码导致首行带 U+FEFF（首行即密码时永远打不中）。e2e 未抓到是
  因为 BOM 行只是个错误候选；单测 `utf16_dict_runs_mutation_presets` 现已钉死。
- **单测补齐**：17 → 47 项，unittests.cs 全部 15 组逻辑落地（原报告的
  17 项远少于 spec §9.1 要求的 51 项/80 断言）。
- **CI rust target**：见验收结果第 6 条。

## 审查修复轮（同日，代码审查发现后补齐）

- **不可读文件成为一等错误态**：`archive::read_head` 原先吞掉 open 错误返回
  空头，被锁/无权限的压缩包被归为 Unknown——`info` 误导性地报"无法识别"且
  exit 0，`crack` 会静默烧完整个字典报"未找到"。现 `ArchiveInfo.open_error`
  承载该错误：`info`/`bench` 输出与 C# 一致的
  「无法读取该文件（可能被占用或权限不足）」并 exit 2，`crack` 引擎短路为
  「解析压缩包失败: …」exit 2（对齐 C# Engine 的 catch 文案）；
  目录路径也按 C# `File.Exists` 语义报「文件不存在」。实测被锁文件探针
  两侧行为一致。单测 `unreadable_path_sets_open_error` 钉死。
- **e2e 补 `--extract-to` 与引号密码覆盖**：新增 test 20（7z 引号+尾反斜杠
  密码 `pw"q\` 的 spawn 验证命中，fixture 用 ProcessStartInfo 直拼 7z 原始
  命令行——PowerShell 自身的参数编码传不了含引号密码）与 test 21
  （`--extract-to` 解压到含空格目录并校验产物），补上审查发现的命中后解压
  主流程零覆盖。
- **`--resume`/`--no-checkpoint` 顺序语义**：C# 按 argv 顺序应用两开关
  （后者覆盖前者，`--resume` 隐含启用 checkpoint）；clap 丢失顺序，Rust 现
  预扫描 argv 恢复"最后一个生效"的语义，四种组合实测与 C# 一致。
- **checkpoint 线程 sleep 分段**：`sleep(3000)` 在 join 之后才被唤醒，
  每次结尾给 elapsed 加 0-3 s 尾巴；改 30×100 ms 分段检查 stop，尾巴消除
  （实测"用时 00:00"）。
- **死代码清理**：SpawnVerifier 里从未使用的 `args` 字符串与矛盾注释、
  `write_result_text` 恒为空的 `note` 参数（C# 只写 `password + CRLF`）、
  engine 里空 `if` 语句；`Cli.cs` 的 `Hashcat` 字段缩进对齐文件标准。
- **CI**：rust job 增加 `Swatinem/rust-cache@v2`。

## 收尾审查修复轮（同日第二次双审查员审查后）

针对《2026-10-05-review-uncommitted-changes.md》逐条核实（14 项全部属实）后修复：

- **C# bench open_error 对齐**：`CmdBench` 补 info 同款 try/catch，
  被锁/无权限文件 exit 2 而非未处理异常崩溃（Cli.cs）。
- **e2e open_error 回归**：新增 test 22（缺失/目录路径在 info/bench/crack
  下 exit 2）与 test 23（FileShare.None 锁定文件三入口 exit 2），两侧套件
  均通过；`New-7zRaw` 补 7z 退出码检查；全套件钉死
  `DICTCRACK_TOOL=$sz`（finally 恢复），杜绝外部环境变量把 7z 路径测试
  悄悄切到 rar 分支。
- **producer 丢候选修复**：`send_timeout(100ms)` 的 `let _ =` 会静默丢候选
  （worker 卡顿 >100ms 时），且 live_pos 已先行推进导致 `--resume` 永久
  跳过——改为 cancel 感知重试循环（Timeout → 查 cancel 后重试，
  Disconnected → 返回），不退回裸 `send()`（避免复现 M3 的 cancel 死锁）。
- **编码方案输出链路接通**：`CandidateSource::plan_note()`（默认 None，
  DictionarySource 覆写）经共享槽位从 producer 搬回，run 收尾覆写
  log_note（对齐 C# Engine.cs:318 的无条件覆写语义）；
  `（编码方案: …）` 分支两侧输出实测逐字一致。
- **CLI 预扫描单测**：`last_checkpoint` 提为独立函数并顺带修掉
  "选项值恰好叫 --resume" 的误判（跳过被消费的选项值，对齐 C#）；
  表驱动单测 ×8 覆盖粘连短选项、attached 值、bare `-`、pass-through、
  位置参数与 `path_missing`。
- **杂项**：`do_extract` 对 `create_dir_all` 失败给出明确错误（C# 同路径
  是未处理崩溃）；删除 `progress_cancel` 死代码与 engine 的
  `_BenchVerifier`/`_AtomicU64`/`_Duration` 别名；README 补 open_error
  文案说明；release.yml `rustup default` → `rustup override set`；
  `New-Rar` 注释说明为何仅 7z 侧需要 ProcessStartInfo。
- 修复后验证：`cargo test --locked` 55 项全绿、release 构建零警告、
  C# `tests\unit-tests.ps1` ALL PASS、e2e 两侧 0 失败
  （C# 23 项全过，Rust 21 过 + 2 GUI 跳过）。

### 与 C# 版的已知行为差异（登记）

- **数值选项解析**：`-t/--seconds/--max-tries/--min/--max` 传非数字时，
  C# `ParseInt/ParseLong` 静默回退默认值继续跑；Rust clap 严格报错
  exit 2（含负数 `--min`，C# 会接受负值）。选严格侧：`--max-tries` 打错字
  静默失去限次语义比报错更危险。
- **`--version`/`-v`**：Rust 直通打印版本 exit 0；C# 视为未知选项走
  crack → 警告 + 缺 `-a` usage + exit 2。保留 Rust 行为（标准 CLI 语义）。
- **缺 `-a` 的 usage 文案**：C# 打完整中文 usage；Rust 打 clap 英文错误
  （两侧退出码均 2）。
- **`--extract-to` 目标目录创建失败**：C# `Directory.CreateDirectory`
  未处理崩溃（致命错误 + 异常退出码）；Rust 打「错误: 无法创建目录 …」
  并 exit 2。
- **控制台中文编码**：~~Rust 版 stdout 恒为 UTF-8，代码页 936 的传统控制台
  里中文会乱码~~ **已修复**（见下节「控制台中文乱码修复」）；剩余偏差仅
  重定向场景：Rust 输出恒为 UTF-8 字节，C# 按 console CP（GBK）编码——
  PowerShell 7/现代消费者按 UTF-8 解码，Rust 侧反而是正确姿势，保留。
  两侧源字符串逐字一致。

## 控制台中文乱码修复（审查外发现，2026-10-06 单独立项）

- **问题**：Rust std 对控制台句柄直接写 UTF-8 字节；代码页 936（zh-CN
  默认）的 conhost 把字节按 GBK 解释，CLI 的全部中文（进度行、错误、
  help）渲染为乱码。C# `Console.WriteLine` 按 console CP 编码所以正常。
- **方案**：`WriteConsoleW`（CPython PEP 528 同款）而非
  `SetConsoleOutputCP(65001)`——后者会持久改动用户控制台代码页、影响
  后续命令。新模块 `cli/src/console.rs`：句柄是真控制台时把 UTF-8 转
  UTF-16 走 `WriteConsoleW`（`GetConsoleMode` 探测，每流缓存一次）；
  重定向/管道保持 UTF-8 字节。全二进制经 `out!/outln!/err!/errln!` 宏
  输出（core crate 无打印，51 处调用点全在 CLI 壳层）；clap 的中文
  help/error 经 `try_parse_from` 拿到渲染文本后走同一出口。
- **回归测试**：`cli/tests/console_render.rs`（`#[ignore]`，因需真控制台）
  ——spawn 子进程跑 CLI，`AttachConsole` + `ReadConsoleOutputCharacterW`
  读回真实屏幕缓冲区，断言 stdout/stderr 两条路径的中文均为正确 Unicode。
  运行：`cargo test --test console_render -- --ignored`。
  测试自身的坑（值得记住）：Rust `Command` 恒设 `STARTF_USESTDHANDLES`，
  CREATE_NEW_CONSOLE 子进程的 std 句柄继承的是父进程管道——输出全进管道、
  控制台空白；须经 PowerShell `Start-Process`（ShellExecute）spawn 才能拿
  到真控制台句柄。`pause` 读 stdin 句柄，继承的 EOF 管道会使其秒退，用
  `ping -n 30` 保活。
- **验证**：`cargo test --locked` 55 项全绿 + 渲染回归测试通过、release
  构建零警告、`--help`/`--version`/缺参退出码 0/0/2 与改造前一致、
  e2e Rust 侧 23 项 0 失败（重定向路径字节行为不变）。C# 侧未改动。
