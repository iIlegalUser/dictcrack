# dictcrack 未提交代码审查报告（2026-10-05 收尾轮）

- **审查对象**：工作区未提交修改 vs HEAD `f399aa6`（20 个文件，+1458/-200）
- **审查方式**：双审查员并行（Rust 侧 / C#+CI+e2e 侧）+ 逐条技术核实
- **实测验证**：`cargo test --locked` 47 项全绿、`cargo build --release --locked` 零警告、C# `tests\unit-tests.ps1` ALL PASS、C#↔Rust 关键路径交叉核对
- **审查日期**：2026-10-05

## 总体结论：**With fixes**（无 Critical）

本轮修复（open_error 一等错误态、e2e test 20/21、argv 顺序语义、checkpoint 分段 sleep、死代码清理）整体质量高，但验收报告声称的「info/bench/crack 全部 exit 2 且文案对齐」在 C# bench 上未达成，且有若干 HEAD 遗留问题被审查捎出。

---

## 做得好的地方

- **open_error 一等错误态（Rust）实现干净**：`ArchiveInfo.open_error` 与「解析但没找到」严格区分（archive.rs:46、629-640）；`path_missing` 把目录归入「文件不存在」与 C# `File.Exists` 语义一致（main.rs:105-107）；info/bench/crack 统一 exit 2，单测 `unreadable_path_sets_open_error` 钉死。
- **dictfp .NET Ticks 对齐是真 bug 修复**：`UNIX纳秒/100 + 621355968000000000` 公式正确，含 1970 前 `saturating_sub` 分支（engine.rs:140-151），双向 `--resume` 实测真实生效。
- **checkpoint 竞态两侧都堵住**：Rust 30×100ms 分段 sleep（engine.rs:477-482）消除结尾 3s 尾巴；C# `Dispose(WaitHandle)+WaitOne(2000)`（Engine.cs:483-487）堵住 DeleteSession 后 stale session 写回，是 .NET 推荐姿势。
- **WinArg 双规则转义收敛**：7z 自解析（`""` 折叠、尾反斜杠不翻倍）vs rar CRT argv（`\"` 转义、尾反斜杠翻倍），Cli/Gui/SpawnVerifier/Rust do_extract 四处统一走 `QuoteForTool`；Rust 测试矩阵完整（tool.rs:186-216），C# unittests 同矩阵 PASS。
- **`--resume`/`--no-checkpoint` 末位生效语义**：clap 丢 argv 顺序，main.rs:562-572 预扫描恢复（含「--resume 隐含启用 checkpoint、resume_requested 不被复位」细节），与 C# ParseCrackArgs 逐条应用（Cli.cs:159-160）行为一致。
- **e2e test 20/21 设计正确**：`ProcessStartInfo` 直拼 7z 原始命令行是绕过 PowerShell 参数编码的唯一正解；断言验证真实行为（结果文件内容 == `pw"q\`、解压产物 262144 字节）而非仅退出码。
- **ZIP64 >65535 条目截断修复**：C# `ushort`→`uint`/`long`（ArchiveInfo.cs:318+），Rust archive.rs:497-524 已同步，65536 条目回归测试两侧齐备。
- **WriteResultText 字符串级 roundtrip**（Engine.cs:528-530）：逮住 GBK best-fit `'?'`（字节级比较逮不到）；Rust result.rs 语义对齐、三单测覆盖（含尾反斜杠）。
- **CI rust job 结构完整**：工具链钉版匹配 `rust/.cargo/config.toml`、`cargo test/build --locked`、rust-cache `workspaces: rust`、WinRAR fixture、e2e `-ExePath`、独立 artifact；release job `needs: [build, rust]` + `merge-multiple` + `dist/*.zip` 聚合双 zip 正确；C# job 新增 unit-tests 步骤指向真实存在的 tests/unit-tests.ps1。
- **exit code 表完整对齐**：0 命中 / 1 未找到 / 2 错误 / 3 cancel+maxed-out，两侧逐点一致（main.rs:385-392 ↔ Cli.cs:230-231），cancel/max-tries 时 session 保存时机也一致。
- **Gui.cs 改动克制**：MaxedOut 不再误报「未找到密码」（Gui.cs:1066-1073），只动状态文案，未碰 150% DPI 布局控件树。
- **session.json 手写 JSON 字段序/转义/tmp 名与 C# 逐字节一致**，`counter=u64::MAX` 可被 C# `ulong.TryParse` 解析；`strip_utf16_bom` 幂等且三处调用齐全。

---

## Issues

### Important（建议提交前修）

#### 1. C# bench 裸调 `ArchiveParser.Parse`，open_error 契约未对齐

- **位置**：[src/Cli.cs:112](src/Cli.cs#L112)
- **问题**：`CmdBench` 未包 try/catch，被锁/无权限文件让进程以未处理异常崩溃（exit 非 2、喷 .NET 栈）。Rust bench 输出「无法读取该文件（可能被占用或权限不足）」exit 2；C# info 本轮已包（Cli.cs:52-55）。本轮主打目标「info/bench/crack 全部 exit 2 且文案对齐」只完成 1/3，验收报告措辞对 bench 失准。
- **修法**：复制 info 的 try/catch（3 行）；同步修正验收报告措辞。
- **注**：crack 路径（Engine.cs:128「解析压缩包失败: …」）两侧文案已逐字对齐，且 pre-flight 顺序保证不可读文件不会误报「没有密码保护」，无需改模型。

#### 2. e2e 缺 open_error 回归用例

- **位置**：tests/run-tests.ps1（21 项无一覆盖）
- **问题**：#1 正是因此漏网。
- **修法**：目录当 `-a` 参数可稳定触发「文件不存在」分支（两侧语义已一致）；测试内用锁占用文件可触发「无法读取」分支。

#### 3. New-7zRaw 不检查 7z 退出码

- **位置**：[tests/run-tests.ps1:131](tests/run-tests.ps1#L131)
- **问题**：仅靠 `Test-Path` 判成败，7z 失败但目录有同名残留会静默通过，且无任何诊断输出。
- **修法**：`$p.WaitForExit(); if ($p.ExitCode -ne 0) { throw "7z exited $($p.ExitCode)" }`。

#### 4. test 20/21 未钉死 `DICTCRACK_TOOL`

- **位置**：[tests/run-tests.ps1:373](tests/run-tests.ps1#L373)、388
- **问题**：`ToolLocator.FindExtractor()` 环境变量优先（Verifier.cs:456）；若用户 `DICTCRACK_TOOL` 指向 rar.exe，test 21 实际覆盖 CRT 转义路径而非注释声称的 7z 自解析路径，断言两边都过但测试意图落空。
- **修法**：Run-Cli 前显式 `$env:DICTCRACK_TOOL = $sz`，finally 恢复原值。

#### 5. `send_timeout(100ms)` 静默丢候选且 `live_pos` 在 send 前更新【HEAD 遗留】

- **位置**：[rust/crates/core/src/engine.rs:396-399](rust/crates/core/src/engine.rs#L396)
- **问题**：worker 集体卡住 >100ms（如杀软拖慢 SpawnVerifier）时 `let _ =` 吞掉 Timeout，候选被静默跳过；而 live_pos 在 send 前已更新，resume 会从被跳过的位置续跑，密码永久漏试。C# 语义是 `queue.Add(cand, ct)` 无限阻塞必送达（Engine.cs:210）。HEAD 已有非本轮回归，但属审查明确要求的 crossbeam 死锁项。
- **修法**：cancel 感知重试循环（`Err(Timeout) → 查 cancel 后 continue`，`Err(Disconnected) → return`）。**不能退回裸 `send()`**——会重新引入 M3 修过的「cancel 后 producer 阻塞」死锁。

#### 6. 「编码方案」输出链路断裂【HEAD 遗留】

- **位置**：[rust/crates/core/src/attacks.rs:380](rust/crates/core/src/attacks.rs#L380)、engine.rs、main.rs:394-395
- **问题**：`DictionarySource.last_plan_note` 被赋值后无人搬运进 `engine.log_note`（log_note 只写「已忽略不匹配的历史会话」），main.rs:395 的 `（编码方案: …）` 分支永不触发；C# 在 Engine.cs:318 有搬运。验收报告「输出逐字一致」声明对此不成立。
- **修法**：engine 收尾照 C# 搬一行（`if source is DictionarySource → log_note = last_plan_note` 的 Rust 等价）。

#### 7. 数值选项容错偏差【行为差异未登记】

- **位置**：C# [src/Cli.cs:331-341](src/Cli.cs#L331) vs Rust clap 严格解析
- **问题**：C# `ParseInt/ParseLong` 对 `-t abc`/`--seconds abc`/`--max-tries abc` 静默回退默认值继续跑；clap 严格解析报错 exit 2。
- **修法**：clap `value_parser` 换容错解析（对齐 C#），或在验收报告登记该偏差。

#### 8. 本轮新增 CLI 预扫描纯函数零单元测试

- **位置**：[rust/crates/cli/src/main.rs:462-572](rust/crates/cli/src/main.rs#L462)
- **问题**：`crack_argv`/`is_recognized`/`normalize_w2`/`last_checkpoint`/`path_missing` 只有 e2e 兜底；均为纯函数，测试成本极低。粘连短选项、attached 值（`--out=x`）、bare `-`、stray positional 等分支已核对与 C# TryOpt 一致，但无测试钉死。
- **修法**：补一组表驱动单测。

### Minor（登记即可）

| # | 问题 | 位置 |
|---|------|------|
| 9 | Rust do_extract 吞 `create_dir_all` 错误：只读父目录下报「解压失败（退出码 2）」而非「目录创建失败」，与 C# `Directory.CreateDirectory` 直接抛有出入 | main.rs:437 |
| 10 | `--version`/`-v`：Rust 直通 exit 0 打版本；C# 视为未知走 crack → 警告+exit 2。不一致，未登记 | main.rs:509 |
| 11 | 缺 `-a` 时 C# 打中文 usage、Rust 打 clap 英文错误（退出码均 2） | main.rs |
| 12 | `progress_cancel` 捕获后只 `let _ =` 丢弃——本轮死代码清理的漏网之鱼 | main.rs:309/355 |
| 13 | `_BenchVerifier`/`_AtomicU64`/`_Duration` 别名怪味（HEAD 遗留），本轮清理 engine.rs 时顺手可收 | engine.rs:631-676 |
| 14 | README 未提 open_error 错误文案；验收报告「17→46 项」实为 47；release.yml:67 `rustup default` 可换 `rustup override set`（GitHub-hosted runner 影响小，洁癖项）；`New-Rar` 可加一行注释说明仅 7z 侧需 ProcessStartInfo | 各处 |

---

## 提交建议

1. **必修（本轮目标内，改动均小）**：#1、#2、#3、#4。
2. **建议同修（验收报告「逐点对齐」声明相关）**：#6（一行搬运）、#8（纯函数单测）。
3. **可单独立项**：#5（HEAD 遗留并发正确性问题，需配回归测试）、#7（行为差异登记或容错解析）。
4. Minor 随手清。

## 附：审查过程记录

- 双审查员并行：Rust 侧（9 文件 + 验收报告）、C#+CI+e2e 侧（7 C# 文件 + release.yml + README + run-tests.ps1）。
- 审查员全部发现经逐条技术核实（读代码/grep/对照 HEAD/跑测试），无盲信；其中「crack open_error 需改字段模型」一条经核实后判定**非必需**（两侧文案已逐字对齐），从 Important 降级为知情决策项。
- Rust 侧 4 项 Important（#5-#8）经 `git show f399aa6` 核实均为 HEAD 遗留，非本轮回归，但 #6 与验收声明直接冲突、#5 属审查明确要求项，故保留 Important 级别。

---

## 修复记录（2026-10-05，逐条核实后全部确认属实）

14 项指控经代码逐条复核**全部成立**，按审查建议修复/登记：

| # | 处置 | 说明 |
|---|------|------|
| 1 | 已修 | Cli.cs CmdBench 补 info 同款 try/catch，exit 2 |
| 2 | 已修 | e2e 新增 test 22（缺失/目录）与 test 23（FileShare.None 锁文件），info/bench/crack 三入口 exit 2 |
| 3 | 已修 | New-7zRaw 检查 7z 退出码并 throw 带诊断 |
| 4 | 已修 | 套件钉死 `DICTCRACK_TOOL=$sz`，finally 恢复原值 |
| 5 | 已修 | emit 改 cancel 感知重试循环（Timeout→查 cancel 重试，Disconnected→return），未退回裸 send() |
| 6 | 已修 | trait 增 `plan_note()`（DictionarySource 覆写），producer 经共享槽位搬回，run 收尾覆写 log_note；两侧「（编码方案: …）」输出实测逐字一致 |
| 7 | 登记 | 保留 clap 严格解析（--max-tries 打错字静默失去限次语义更危险），登记进验收报告「已知行为差异」 |
| 8 | 已修 | 预扫描纯函数表驱动单测 ×8；last_checkpoint 提函数并顺带修掉「选项值恰为 --resume」误判（跳过被消费值，对齐 C#） |
| 9 | 已修 | do_extract 对 create_dir_all 失败打明确错误 exit 2（C# 同路径是未处理崩溃，差异登记） |
| 10 | 登记 | 保留 Rust `--version` 直通（标准语义），登记 |
| 11 | 登记 | usage 文案差异登记 |
| 12 | 已修 | 删 progress_cancel 死代码 |
| 13 | 已修 | 删三别名与 `_BenchVerifierUsed` 桩，bench 用正常 `AtomicU64`/`Duration` |
| 14 | 已修 | README 补 open_error 文案；验收报告 46→实数；release.yml `rustup override set`；New-Rar 注释 |

验证：`cargo test --locked` 55 项全绿（47+8）、`cargo build --release --locked` 零警告、
C# `tests\unit-tests.ps1` ALL PASS、e2e 双侧 0 失败（C# 23 项全过；Rust 21 过 + 2 GUI 跳过）。
偏差登记全文见验收报告「与 C# 版的已知行为差异（登记）」一节。

审查外新发现：Rust 版 stdout 恒为 UTF-8，代码页 936 的传统控制台中文会
乱码（C# 按 console CP 正常）——2026-10-06 已单独立项修复（WriteConsoleW
方案 + 真控制台屏幕缓冲区回归测试），详见验收报告「控制台中文乱码修复」
一节；重定向输出保持 UTF-8 字节（与 C# 的 console CP 字节不同，已登记为
有意保留的偏差）。
