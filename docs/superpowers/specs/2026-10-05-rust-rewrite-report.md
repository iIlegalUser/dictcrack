# dictcrack Rust 重写 — 验收与性能报告

日期：2026-10-05
状态：M1-M4 全部完成，验收通过

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

1. `cargo test`：17 项单测全绿（PBKDF2 RFC 向量、CRC32、编码计划、掩码/规则、
   session 往返、result GBK/UTF-8 回退、WinArg 转义）。✔
2. `tests\run-tests.ps1 -ExePath <rust dictcrack.exe>`：**17 项 PASS、0 失败**
   （2 项 GUI 测试按 spec 属 GUI 范围跳过——Rust 无 GUI）。覆盖 RAR5 -p/-hp、
   ZipCrypto 全量确认、AES-256 HMAC、7z 回退、掩码、组合、规则、UTF-8 BOM /
   UTF-16LE / GBK 中文密码矩阵、断点续跑、bench、尾部反斜杠密码。✔
3. C#↔Rust **双向 `--resume` 续跑命中**（session.json 字段名/顺序/params hash
   字节级一致）。✔
4. 同机 bench：三条原生路径均不慢于 C# 版（见下表，全部大幅超过）。✔
5. 单 exe 静态链接，独立运行不依赖外部 DLL。✔

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
- CI 的 GitHub Actions rust target 未接入（spec M4 可选项），本地构建已验收。
