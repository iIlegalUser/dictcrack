# 性能二期方案：多缓冲 PBKDF2（#2）与 RAR4/7z 原生化（#3）

> 背景：2026-10-06 瓶颈分析（对话实测，i7-12800HX 8P+8E）确认三处瓶颈。第一处
> （真实 crack 管道反扩展）已当日修复：候选按 8 个一批过 channel + 每 worker 独立
> "当前密码"槽位，ZipCrypto t=22 从 43 万/s → 245 万/s，反扩展消失，RAR5 无回归。
> 本文档是剩余两处的实施方案。
>
> **状态（2026-10-06 晚）：#2 与 #3-RAR4 已实现并实测通过。#3-7z 实施中。**
> 实施中发现本文档原有的若干技术判断有误，**以实测纠正为准**，纠正清单见下方
> "实施纠正"一节；RAR4 的完整规格与实测见 `docs/rar4-native-verification.md`，
> 7z 的权威字节级规格见 `docs/7z-verification-spec.md`。

## 实施纠正（实测推翻原方案的部分）

### #2：成立，收益略超预期

原方案预期 1.4-1.6×。实测 RAR5（PBKDF2-SHA256 32800 轮）：

| | 单线程 | 8 线程 |
|---|---|---|
| 原标量 PBKDF2 | 331.7 个/秒 | 2309.7 个/秒 |
| 4 路 SHA-NI 交错内核 | **545.4 个/秒（1.64×）** | **3743.4 个/秒（1.62×）** |

无 SHA-NI 时（E 核）逐路回落标量路径，与现状一致。

### #3 RAR4：原方案的三处技术判断全错

| 原方案 | 实测 |
|---|---|
| "解密文件数据前 16 字节，明文第 13-15 字节 == 文件头 CRC32 低 3 字节" | **错**。`-p` 存储的对前 `UnpSize` 字节算标准 CRC32 与 `FileCRC` 比 4 字节；无 3 字节截断，无"明文比 CRC 字段"这种校验。廉价预筛是**末块填充零**。 |
| "单候选成本 = KDF + 1 个 AES 块，速率落在 ZipCrypto 量级（百万/s）" | **错，差 4 个数量级**。RAR3 KDF = **0x40000 轮 SHA-1**（262144 压缩/候选），实测 16.1 ms/候选。 |
| "`-hp` 解密文件头校验其结构 CRC" | **错**。`-hp` 头是密文读不到；校验是归档末尾 24 字节 `[salt(8)][ENDARC 首块(16)]` 解密比对**固定常量**。 |

纠正后实际收益：spawn `7z.exe` 26.5 个/秒 → 原生 **958 个/秒（8 线程，~36×）**；另加
KDF 快路径（`raw<=64` 时 rar29 写回不可达，可走 SHA-NI）把单线程从 62 → 131 个/秒。
**压缩的 `-p` 不做**（需完整 RAR LZ/PPMd 解压器），回落外部工具。

### #3 7z：原方案的校验判据也错

| 原方案 | 实测 |
|---|---|
| "加密头（-mhe）解密头流前 32 字节应全零" | **错**。明文开头是 `kHeader` 的 `0x01`，不是零。真正的不变量是 **AES-CBC 尾部零填充**：`PAD = PackSize - AES出流UnPackSize`，明文**末尾** PAD 字节全零；PAD==0 时无快路径（实测 PAD=6/11/14/2/14）。 |
| （未提及）`kEncodedHeader(0x17)` 即加密 | **错**。无密码的 `7z a` 也产生 0x17（dummy 场景）；必须先查 coder 链里有无 AES id `06F10701`。 |
| （未提及）IV 来自摘要剩余字节 | **错**。SHA-256 全部 32 字节都是 AES-256 密钥；IV 存在 coder properties 里（短则右侧补零）。 |

7z 分档实证结论：**AES+COPY（存储）有纯 CRC32 快路径**（CRC 决定性，无需解压器，PAD
仅作预过滤）；**AES+LZMA/LZMA2/BCJ 必须跑解压器**，本期不做，回落外部工具。

## #2 多缓冲 PBKDF2-HMAC-SHA256（RAR5，实测 1.64×）


### 现状与依据

RAR5 验证 = 32800 轮 PBKDF2-HMAC-SHA256 ≈ 65600 次 SHA256 块压缩，纯依赖链。
sha2 0.10.9 的 SHA-NI 后端（运行时检测，已确认启用）单流受 `sha256rnds2`
延迟限制（4 cyc/指令 × 32 指令/块 ≈ 200 cyc/块实测），SHA 单元吞吐上限约
2 cyc/指令 ≈ 64-100 cyc/块，单流只吃到单元的一半不到。SMT 双流部分填补：
实测 P 核 SMT 下 ~420 候选/s/核，理论单元上限 ~1000/s/核。

### 方案

新增 4 路交错 PBKDF2 内核：一次处理 4 个独立候选，指令级 round-robin 发射
4 条独立 rnds2 链，把 SHA 单元从延迟受限转为接近吞吐受限。

1. `core/src/crypto.rs` 新增 `pbkdf2_sha256_x4`：
   - 输入 `pwds: &[&[u8]; 4]`、salt、iters，输出 `&mut [[u8; 32]; 4]`。
   - 每路独立预计算 HMAC ipad/opad 状态（密码不同），迭代体每轮 2 次压缩
     （U1 = HMAC(pwd, salt‖BE32(i))，Uj = HMAC(pwd, Uj-1)；输入 ≤32 字节，
     inner/outer 各 1 块）。
   - 核心 `compress4`：4 个状态 × 64 轮，`_mm_sha256rnds2_epu32` 每轮 4 路
     背靠背发射。`cpufeatures` 运行时检测（sha/sse4.1/sse2/ssse3），无
     SHA-NI 时回退现有 `pbkdf2_hmac` 逐路调用（本机 12800HX 的 E 核走回退，
     与现状相同）。
2. `core/src/verifier.rs`：`Rar5Verifier` 增加
   `verify_batch(&self, pwds: &[&str]) -> Option<usize>`（命中返回组内下标），
   逐候选 fold8/PswCheck 比较不变。
3. `core/src/engine.rs` worker：本地聚合 4 个候选为一组调用 `verify_batch`；
   add_tried/note_current/取消/命中/上限检查逐候选语义不变（取消粒度变为一组，
   RAR5 下 ≤12ms，GUI 15s kill 兜底与 Ctrl+C 桥接均不受影响）；组不足 4 个
   （字典尾部/resume 回退区）回退单路 `verify`。
4. Verifier trait 加 `verify_batch` 默认实现（逐个调 verify），其他验证器
   不动；ZIP AES 暂不做多缓冲（1000 轮 SHA1 本身便宜，确认路径 HMAC 占比大，
   列为可选扩展）。

### 测试

- RFC 7914 向量按 4 路不同密码/salt 各跑一遍；
- property test：随机 1000 组与标量 `pbkdf2_hmac` 对拍（核心正确性红线）；
- cargo test 全量 + e2e 全量（RAR5 用例不变）；
- bench：`bench -a <RAR5>` 预期 3851 → 5300-6000/s；真实 crack 掩码抽查。

### 风险

- intrinsics 手写正确性：对拍测试兜底；
- GNU 工具链编 SHA-NI：sha2 已证明可行（同一构建里在用）；
- 收益不及预期：上限受 E 核回退路与调度影响，实测低于 1.3× 时保留（无害）。

工作量：约 1 天。

### 实施结果（已完成）

按上述方案实现，与方案一致，未走样。相关改动：`crypto.rs` 的 `sha256_x4` 模块
（SHA-NI `compress_chain` + 4 路 `compress_x4`）、`Rar5Verifier::verify_batch`、
`Verifier::verify_batch` 默认实现、engine worker 的 4 候选分组、`bench_measure`
按 4 组驱动。

测试：RFC 7914 向量、长密码（>64 字节走 HMAC 先哈希密码那条分支）、以及
1000 组确定性 LCG 随机对拍（250 组 × 4 路，覆盖 <64 与 ≥64 字节密码、8..16 字节 salt、
1..40 轮）——LANE 逐位等于标量实现。另加 `compress_chain` 对 `SHA256("abc")` 的
已知摘要钉测（无 SHA-NI 时自动跳过）。

实测见上方"实施纠正"表：单线程 1.64×，8 线程 1.62×。

## #3 RAR4 / 7z 原生化（数量级收益）

### 现状

RAR4/7z 每次验证 spawn 一个 7z.exe/rar.exe（~50-100ms/次，22 线程聚合
~10-40 候选/s，CPU 大量空转）。这是唯一「验证成本比 RAR5 还贵」的路径。

### RAR4（优先做）— ✅ 已完成

> 下面这段原文的**校验判据与收益估计都是错的**（见开头"实施纠正"表）。
> 实际实现与实测见 `docs/rar4-native-verification.md`，摘要：
> `-hp` = 末尾 `[salt8][ENDARC首块16]` 解密比固定常量；`-p` 存储 = 全量解密 +
> 对前 `UnpSize` 字节算 CRC32 比 `FileCRC`；`-p` 压缩**不做**（需 LZ/PPMd 解压器）。
> KDF 是 0x40000 轮 SHA-1，实测 131 个/秒单线程（不是"百万/s"）；原生化后
> 8 线程 958 个/秒 vs spawn 26.5 个/秒。

- KDF：unrar `crypt.cpp` 的 SHA1 迭代 KDF（固定迭代数与展开方式，**实现时以
  unrar 源码逐行核对常数**，不凭记忆写），AES-128-CBC。
- 校验：`-p`（头不加密）解密文件数据**前 16 字节**，明文第 13-15 字节 ==
  文件头 CRC32 低 3 字节（rar2john 同款）；`-hp`（头加密）解密文件头校验其
  结构 CRC。校验发生在压缩数据流上，**无需实现任何解压算法**——单候选成本
  = KDF（一次）+ 1 个 AES 块，速率落在 ZipCrypto 量级（百万/s）。
- 改动面：`archive.rs` 解析 RAR4 主头/文件头（salt 8 字节、文件 CRC32、数据
  偏移、加密标志）；`verifier.rs` 新增 `Rar4Verifier`（Verifier trait 原样）；
  `create_native` 接入；`info` 输出对齐 C# ArchiveInfo 文案；检测到不支持的
  变体（如多卷、非常规 coder）自动回落 SpawnVerifier。
- 测试样本缺口：本机 WinRAR 7.12 只能造 RAR5 造不了 RAR4。需先确认 e2e 现在
  如何构造 RAR4 样本（现有外部工具用例的数据来源）；若无造法，把一个最小
  RAR4 样本以字节字面量固化进 e2e/单测（金标准 = 7z.exe 能解）。
  → 已按此路执行：两个最小样本（`-hp` 132 B / `-p` 存储 107 B）以字节字面量
  固化，固化前用 UnRAR.exe 与 7z.exe 双向验证过。
- 收益：~10-40/s → ~10⁶/s。
  → 实测 ~10-40/s → **958/s（8 线程）**；"10⁶/s"不可能，KDF 是硬下限。

### 7z（其次，收益分情形）— 🚧 实施中

> 下面这段原文的**校验判据也是错的**（加密头明文不是前导零），见开头"实施纠正"
> 表；权威字节级规格见 `docs/7z-verification-spec.md`。

- 7z 没有独立密码校验字段，验证必须解码数据，分两档：
  - **加密头（-mhe）**：解密头流前 32 字节应全零（7z 编码头固定前缀，
    hashcat/john 同款快速校验）→ 快路径，可用。
  - **内容加密**：CRC 在明文上，必须 AES-256-CBC 全解密 + LZMA 解码 + CRC；
    且 7z KDF 是 SHA256 迭代 2^numCyclesPower 次（常见 2^19，单候选本身
    ~0.5-2s，比 RAR5 的 PBKDF2 还重）。原生化收益 = 省 spawn 开销 + 原生
    多线程，但速率天花板由 KDF 决定，到不了快路径量级。
- 改动面：`archive.rs` 解析 7z 容器（kHeader/kEncodedHeader、folder 的
  coder 链、salt/IV/numCyclesPower 的 u64 properties 打包）——格式繁琐是
  主要工作量；`verifier.rs` 新增 `SevenZipVerifier`（两档校验）；KDF 用现有
  sha2。带 BCJ/多 coder 链等复杂 folder 检测到就走 SpawnVerifier 兜底。

### 顺序与验收

1. RAR4 先（现实收益大、实现面小）：e2e 新增原生 RAR4 命中/拒绝/续跑用例，
   bench 表加 RAR4 行（spawn vs native 对比），info 输出与 C# 对齐。
   ✅ e2e test 3a–3d + 15b；bench 行见 `docs/rar4-native-verification.md` 对比表。
2. 7z 后：e2e 新增加密头快速校验用例 + 内容加密用例（容忍慢）；检测到
   KDF 轮数过大时照常可跑（GUI 有取消兜底）。🚧
3. 两条路径都不删 SpawnVerifier——它保留为未知变体的兜底。✅

工作量：RAR4 约 1-2 天（大头在头解析与样本构造），7z 约 2-3 天。

## 附：不做的事

- 不改 C# 引擎管道（它只是 GUI 回退引擎，同样的 per-candidate 队列开销在
  C# 侧是次要问题）。
  → 例外（不违反本条的意图）：实施中修了 C# 的一个**既有挂起 bug**——
  `Engine.Run` 的 6 个早返回绕过 `Stats.Done = true`，而 `Cli.cs` 无条件
  `progress.Join()`，导致所有错误路径永久挂起（Rust 侧同一 bug 一并修复）。
  改动只是 `Run()` 用 try/finally 包住 `RunCore()`（`src\Engine.cs` +12 行），
  **没有触碰 per-candidate 队列/管道逻辑**。详见验收报告第 4 节。
- 不动 resume margin 公式 `threads*8+threads+16`——批处理的不变量
  （(cap+threads)×8 ≤ margin，t=1..64 单测钉死）保证 C#↔Rust 会话互通继续成立。
  ✅ 已实测双向互通（Rust↔C# 各一次，见验收报告第 6 节）。
- 不做 GPU（hashcat 路线），超出本项目定位。
