# 二期实施验收记录（2026-10-06）

> 对应 `docs/superpowers/specs/2026-10-06-perf-phase2-plan.md`。
> 记录实测数字、回归结果、以及**交付前的独立验证**（Lead 亲自复跑，不采信实现者自述）。

## 1. #2 多缓冲 PBKDF2（RAR5 4 路 SHA-NI 交错）

同一归档（`b5.rar`：RAR5 `-p`，PBKDF2 2^15+32 轮），`bench` 命令直接对比
**未改动的 commit `d313463` 二进制**与本次改动：

| | 单线程 | 8 线程 |
|---|---|---|
| commit `d313463`（标量 `pbkdf2_hmac`） | 331.7 个/秒 | 2309.7 个/秒 |
| 本次（`pbkdf2_sha256_x4`） | **545.4 个/秒** | **3743.4 个/秒** |
| 倍数 | **1.64×** | **1.62×** |

无 SHA-NI 时（本机 E 核）逐路回落标量路径，行为与改动前一致。

## 2. #3 RAR4 原生化

### 速率：spawn vs native（同一归档）

| 路径 | 单线程 | 8 线程 |
|---|---|---|
| spawn `7z.exe t`（原回退路径，实测 37.8 ms/次进程启动） | 26.5 个/秒 | — |
| 原生 `-hp` | 130.1 个/秒 | 958.3 个/秒 |
| 原生 `-p` 存储 | 131.0 个/秒 | 948.0 个/秒 |

单线程 **~36×**（原生为 8 线程对比 spawn 单线程口径；同口径下单线程为 4.9×）。
KDF 快路径（`raw<=64` 走 SHA-NI）把单线程从 62 → 131 个/秒（2.1×）。

### 正确性：与外部参考解密器逐例对拍

`verifier.rs` 与 `archive.rs` 的单测直接用字节字面量样本，样本在固化前经外部验证：

| 样本 | 密码 | 外部验证结果 |
|---|---|---|
| `rar4hp.rar`（-hp） | `HpGold55` | `UnRAR.exe t` exit 0；错密码 exit 3 |
| `rar4p.rar`（-p 存储） | `Rar4Gold9` | `7z.exe t` "Everything is Ok" exit 0；错密码 "CRC Failed" exit 2 |

单测覆盖的正/反例：正确密码、错误密码、空密码、正确密码的前缀、正确密码加尾空格、
以及 7z.exe 报 CRC 失败的那个密码。**10/10 全部与外部金标准一致**（Lead 独立复跑）。

## 3. #3 7z 原生化

7z 是否能原生校验**由 coder 链决定，与扩展名无关**。实现按"先看有没有决定性判据、
再看 PAD 能否兜底"分档：

| 归档形态 | 判据 | 路径 |
|---|---|---|
| `-mhe` 加密头，header folder 仅 AES | `CRC32(AES 明文)` == folder CRC（2⁻³²） | 原生（PAD 无关） |
| `-mhe` 加密头，无任何 digest，PAD>0 | AES-CBC 尾部零填充（2⁻⁸·ᴾᴬᴰ） | 原生，note 注明仅零填充可查 |
| `-mhe` 加密头，无 digest 且 PAD==0 | **无判据** | 外部工具 |
| 内容加密 AES+COPY（存储） | `CRC32(明文) == 存储 CRC` | 原生（PAD 无关） |
| 内容加密 AES+LZMA/LZMA2/BCJ | CRC 在解压后字节上，需解压器 | 外部工具 |
| BCJ2 / 多 folder / 多 PackStream | 不可验证 | 外部工具 |

### 速率

| 路径 | 单线程 | 8 线程 |
|---|---|---|
| spawn `7z.exe t`（39.8 ms/次） | 25.1 个/秒 | — |
| 原生 `-mhe`（AES-only 头，2^19 KDF 轮） | 78.4 个/秒 | 526.3 个/秒 |

7z KDF 是 SHA-256 迭代 `2^ncp` 次（默认 2^19），单候选本身就是主要成本天花板；
原生化收益 = 省 spawn + 原生多线程，**8 线程约 21×**。

（注：7z 实现者本人未测性能并明确要求不要在报告里替他编数字；上表由 Lead 用其
release 产物在同一台机器上补测。）

### 正确性：Lead 独立复验

- **23 个真实/构造样本**：真密码字典命中 21/23、错密码字典 **23/23 全部"未找到密码"、
  零假阳性**。两个例外各有正当理由：`mhe_nocrc_pad0.7z` 是设计上无判据的那档
  （**7z.exe 自己也无法处理**），`plaincopy.7z` 是真正的未加密包（7z 报 `Encrypted = -`）。
- **决定性证明"确实是原生"**：把 `DICTCRACK_TOOL` 指向不存在的路径（spawn 兜底失效）
  后，`mhe_lzma2 / mhe_pad0 / plain_copy / nosalt / ncp3f / salt16_a / mhe_nocrc` 七个样本
  仍然全部命中正确密码 —— 命中只可能来自原生路径。

## 4. 本轮修复的三个既有缺陷（均先复现、后修复、再回归）

| 缺陷 | 影响 | 归属 |
|---|---|---|
| `engine.run` 的早返回（6 处）不置 `done` 标志 | **非 `-q` 下 `crack` 永久挂起**（进度线程 `while !done` + 无条件 `join`），未加密归档/缺失文件/目录全部中招 | Lead 修（漏斗式：`run()` 拆 `run_inner()`，置位在唯一出口） |
| **C# 引擎同一 bug**（`Engine.Run` 的 6 个早返回绕过 `Stats.Done = true`） | 同上，C# CLI 与 GUI 同样挂起 | Lead 修（同一漏斗式改法：`Run()` try/finally 包 `RunCore()`） |
| 7z AES+COPY **单密文块** + PAD>0 时取不到 CBC IV | **假阴性**：正确密码被否决、报"未找到" | sevenzip-dev 修（单块时 IV 取 coder properties 的 IV） |
| 压缩头加密包的 note 断言"未加密" | `info` 误导（`crack` 仍正确） | sevenzip-dev 修（改为存疑表述并双向断言） |

前两个都是**e2e 原有盲区**导致的长期潜伏：挂起只在去掉 `-q` 时可见（而所有既有
crack 用例都带 `-q`），假阴性只在小于 16 字节的载荷上出现。现已分别补
`test 22b`（去 `-q` 跑 4 条早返回路径）与 `test 6f`（1 B / 14 B 单块载荷），
并给 `Run-Cli` 加了 120 s 看门狗 —— 任何"不返回"从此变成测试失败而非卡死整个套件。

**C# 侧同 bug 的发现过程**：写完后意识到 CI 有两个 e2e job（一个跑 C# 构建、
一个用 `-ExePath` 跑 Rust），于是拿 C# 二进制复跑同样的挂起场景 —— 果然也挂。
这也暴露出**新增的原生路径断言必须区分引擎**：C# 引擎按设计只有 7z.exe 回退，
所以 `test 3a/6a/6d`（路由与"无外部工具仍命中"）改为 `-ExePath` 时断言 native、
否则断言 external 或 SKIP，命中/拒绝类用例（3b/3c/3d/6b/6c/6e/6f）两个引擎都跑。

## 5. 全量回归

| 项目 | 结果 |
|---|---|
| `cargo test` | **core 98 + cli 11 passed, 0 failed**（+1 ignored 控制台渲染测试）；基线 67 |
| `cargo build --release` | **零警告** |
| e2e（Rust 引擎，`-ExePath`） | **0 failure（38 项，native 断言全部执行）** |
| e2e（C# 引擎，无 `-ExePath`，CI job 1） | **0 failure**（仅 Rust 独有的 6a/6d/24-26 按设计 SKIP） |
| C# 编译 | `build\build.ps1` 两个 exe 均 OK（`src\Engine.cs` 仅 +12 行） |

新增 e2e 用例（11 项）：

- `test 3a` RAR4 路由断言（Rust=native / C#=external）
- `test 3b`–`3d` RAR4：`-hp` 命中、`-p` 存储命中、错误字典穷尽
- `test 6a` 7z 分支路由（native vs external 三种 coder 形态，仅 Rust）
- `test 6b`/`6c` 7z 命中（`-mhe` AES-only 头 / AES+COPY 内容，两个引擎都跑）
- `test 6d` **无外部工具时仍命中**（证明走的是原生路径，且错密码不产生结果文件，仅 Rust）
- `test 6e` AES+LZMA2 回落外部工具且仍能命中
- `test 6f` 单密文块 AES+COPY 假阴性回归（1 B 与 14 B 载荷）
- `test 15b` RAR4 断点续跑
- `test 22b` 早返回路径不挂起（4 条路径，**刻意不加 `-q`**）

## 6. 跨引擎会话互通（关键回归）

二期把候选改成**每 8 个一批**过 channel，并依赖不变量
`(cap + threads) × 8 ≤ threads*8 + threads + 16`（resume margin）保证 C#↔Rust 会话
互通不被破坏。该不变量有 t=1..64 的单测钉死，但**必须实测双向**：

| 方向 | 步骤 | 结果 |
|---|---|---|
| Rust → C# | Rust `-t 1 --max-tries 50 --session-file` 写会话 → C# `--resume` | ✅ 命中 `Interop42`（尝试 300 个，跳过已试前缀） |
| C# → Rust | C# `-t 1 --max-tries 50` 写 `dist\session.json` → Rust 同目录 `--resume` | ✅ 命中 `Interop42`（尝试 317 个） |

（`--session-file` 是 Rust 独有选项，C# 会"警告并忽略"，反向测试因此走默认 exe 旁
`session.json` 路径。）

## 7. 真实目标实测

用户的一个实际目标归档（RAR5 `-hp`，70.5 MB，PBKDF2 2^15 轮，含 PswCheck）用本地
字典 839 行在 8 线程下跑到第 1012 个候选命中：

```
=== 找到密码: <已隐去> ===
尝试 1012 个, 用时 00:00, 平均 2511.5 个/秒
```

**独立验证**：拿命中的密码跑 `UnRAR.exe t -p<密码> <归档>` → 全部文件解压正常，
exit 0（即原生校验报出的密码经外部参考解密器确认为真，不是假阳性）。

> 密码本身不写入仓库：本仓库是公开的，而这是一位用户真实归档的密码。上面保留了
> 命中位置、速率与外部验证结论——这些才是本次改动的证据。

## 8. 实测推翻的方案原文（三处，详见方案文档"实施纠正"）

1. RAR4 `-p` 的校验不是"前 16 字节明文比 CRC 低 3 字节"，而是全量解密 + 对前
   `UnpSize` 字节算 CRC32；"百万/s"差 4 个数量级（KDF 是 0x40000 轮 SHA-1）。
2. RAR4 `-hp` 不是"解密文件头校验结构 CRC"，而是末尾 24 字节里 ENDARC 首块
   解密比固定常量。
3. 7z `-mhe` 加密头明文不是前导零，而是以 `kHeader(0x01)` 开头；可判真伪的是
   **AES-CBC 尾部零填充**或 **folder CRC**（有 digest 时），二者都不是"前 N 字节零"。

这些纠正均由独立调研（hashcat/John/unrar/7-Zip 源码 + 实测样本）确认，并在实现
前落地到 `docs/rar3-password-check-spec.md` 与 `docs/7z-verification-spec.md`。
