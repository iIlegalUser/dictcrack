# 7z 原生校验实现说明（task-1）

对应权威规格：`docs/7z-verification-spec.md`（调研+实测稿）。本文只记录**实现侧**的决策、
分档理由与验证证据，格式细节不重复抄规格。

代码位置：
- `rust/crates/core/src/archive.rs` — `SevenZipCryptInfo` / `SevenZipCrcKind` / `parse_sevenzip()`
- `rust/crates/core/src/crypto.rs` — `sevenzip_derive_key()` / `aes256_cbc_decrypt()` / `SEVENZIP_MAX_NCP`
- `rust/crates/core/src/verifier.rs` — `SevenZipVerifier` / `create_native()` 接入

---

## 1. 判据分档（本实现的核心决策）

**原则：先看有没有决定性判据，再决定尾部零填充能不能兜底。**

| # | 容器形态 | 判据 | 结果 |
|---|---|---|---|
| 1 | AES 是链尾（或后跟 COPY），且有 digest | `CRC32(AES 明文[:crc_len]) == 存储 CRC` **且** `crc_len == AES 出流 UnPackSize` | **原生**（PAD 无关，PAD=0 也原生）；PAD>0 时先做 1 个 AES 块的尾部零填充预过滤 |
| 2 | AES 是链尾但**容器里没有任何 digest** | 仅 AES-CBC 尾部零填充，假阳率 `2^-8·PAD` | **PAD>0 → 原生**（note 注明只查了 N 字节零填充）；**PAD==0 → 回落** |
| 3 | AES 后还有解压器/过滤器（LZMA/LZMA2/BCJ/PPMD/…） | CRC 覆盖的是**解压后**字节，本引擎无解压器 | **回落** |
| 4 | 链里根本没有 AES coder | 无密码保护 | **回落**（note 说明未加密；引擎空密码探测后报"无需破解"） |

### 为什么第 1 档 PAD==0 仍算原生，第 2 档 PAD==0 必须回落

这两处**故意不同**，注释里也写死了理由，防止以后被人"统一"掉：

- 第 1 档有 CRC32，是 **2^-32** 的判据，PAD 只是省一个 AES 块的预过滤。PAD==0 只意味着
  "没有预过滤"，判据仍在 ⇒ 回落到外部工具属于**能力倒退**。
- 第 2 档除尾部零填充外**没有任何判据**。PAD==0 时"末尾 0 字节全为零"是**空真（vacuous）**：
  实测 `mhe_nocrc_pad0.7z`（无 digest + PAD=0）**正确密码和错误密码都通过**该检查。若放行，
  等于"任意密码都命中"。⇒ 必须回落。

### 与任务书原描述的偏差（已经 Lead 复核同意）

任务书原文把"PAD==0 的内容加密"列为必须回落。实测发现 **AES-only 的 `-mhe` 加密头也有
folder CRC，且恰好等于 AES 出流的 CRC32**（5 个真实样本全中：`mhe_lzma2`/`mhe_copy`/`mhe_lzma1`/
`mhe_many_nohc` 命中，`mhe_many` 因多 coder 本就回落）。因此按"有无决定性判据"分档，
比"按 PAD 一刀切"多覆盖一类真实加密头，且不放松任何红线。Lead 已确认采纳。

---

## 2. 三条纠正版要点的落地位置

1. **加密头明文不是前导零** —— 实现里根本没有"前导零"检查；`mhe_*` 样本解出的前 16 字节是
   `01 04 06 00 01 09 40 00 07 0b 01 00 ...`（`kHeader` 开头），单测断言的是 CRC 与尾部填充。
2. **`0x17` ≠ 加密** —— `parse_sevenzip()` 解析完 StreamsInfo 后**要求链首 coder id ==
   `06 F1 07 01`**；无 AES 时返回 None 并把 note 写成未加密。`sevenzip_encoded_header_without_aes_coder_is_not_encrypted`
   用真实无密码 `-mhe` 样本（`plain_many.7z`）钉住这条。
3. **IV 来自 coder properties（右侧补零）** —— `decode_aes_props()` 返回 `[u8;16]`，
   `raw_iv` 短于 16 时右补零；`ivpart_a.7z`（ivSize=8）单测断言补零结果。

---

## 3. 安全/健壮性防护

| 防护 | 位置 | 理由 |
|---|---|---|
| `SEVENZIP_MAX_NCP = 24`（`0x3F` 例外放行） | `crypto.rs` + `archive.rs` | `ncp` 来自攻击者可控的头：`2^31` 轮是**挂死**不是慢。`0x3F` 是 7-Zip 的"无哈希"特例（最便宜），必须放行。 |
| `SEVENZIP_MAX_PACK = 16 MiB` | `archive.rs` **parse 期** | 打包流大小来自头。超限在**解析期**判为不可原生 ⇒ 回落；若留到校验期才拒，会把"无法校验"变成"每个密码都错"，引擎会报成"字典跑完了"。 |
| 全部长度/边界检查走 `.get()` / `checked_add` | `archive.rs` | 攻击者构造的截断容器只能得到 `None`，不得 panic。 |
| `crc_len > plain.len()` ⇒ reject | `verifier.rs` | 防止 CRC 检查退化成"对空/短切片算 CRC"。 |
| 打包流必须完整落在文件内 | `archive.rs` | 否则每个候选都读到 EOF 之后的垃圾，因错误的原因被拒。 |
| 未知/不支持的 coder 一律 `None` | `archive.rs` | 宁可回落外部工具，绝不让"无法校验"被当成"校验失败"或"校验通过"。 |

---

## 4. 测试与证据

`cd rust; cargo test` → **core 98 passed / cli 11 passed / 1 ignored / 0 failed**（基线 67，新增 30 项）。
`cargo build --release` → 零警告。

### 4.1 KDF 向量来源（**不以 7z.exe 退出码为金标准**）
调研阶段已证明：密码错误时 `7z t`/`7z x` 仍可能报 "Everything is Ok" 并把垃圾明文写盘
（见规格文末 Verification log）。因此所有期望值来自**独立实现**：
python `hashlib`（`D:\Files\Tmp\7zverify\walk.py::calc_key`），其产物已被 7z.exe 接受。
9 条向量覆盖：ncp=0（钉死 `rounds = 1<<ncp`，不是 `max(1,..)`）、ncp=0x3F、salt 0/8/16、
UTF-16LE 非 ASCII（`päss中文`）、48 字符密码在 0x3F 下的**32 字节截断**（钉 7-Zip 规则，
不是 py7zr 的保留尾部）。

### 4.2 变异测试（确认测试真的能失败）
临时 harness 注入 15 处缺陷，**全部**被现有测试抓到（无存活）：padding 查头而非尾、
PAD==0 当通过、单块 IV 不从 props 取、`0x17` 当加密、saltSize `+16`、IV 左补零、
AES 出流取最后一项、counter 大端/位置提前/截断 u32、`0x3F` 误判超限、ncp 上限删除、
PackSize 上限删除等。
过程中因此发现并修掉三个真 bug：`ncp=0x3F` 被上限误杀、PackSize 超限时 note 优先级错误、
以及**单 AES 块 + PAD>0 时正确密码被否决**（见 §5 第 6 条）。
harness 用完即删，未留在仓库。
> 踩坑记录：harness 最初用 `` `n `` 写多行匹配模式，静默得到 "pattern not found"，
> 看起来像"测试没覆盖"，浪费两轮排查。原因**不是**"本仓库是 CRLF"（那是错的结论）——
> 工作区行尾是**混合**的：`.gitattributes` 是 `* text=auto` + `core.autocrlf=true`，
> git blob 一律 LF，工作区则取决于该文件是 git 检出的（CRLF）还是被 Edit/Write 刚改过的（LF）。
> 同一 crate 内实测：`crypto.rs`/`verifier.rs` 是 CRLF，`archive.rs` 是 LF。
> **通用修法（与文件当前状态无关）**：先归一化再匹配 ——
> `$t = ([IO.File]::ReadAllText($f)) -replace "`r`n","`n"`，模式里统一写 `` `n ``。
> 单行模式不受影响。（Lead 复核时纠正了我的初版结论，此处已按实测改正。）

### 4.3 真实样本实测（`release\dictcrack.exe`）
16 个样本 `info` 文案与"原生/外部"判定全部符合分档；`crack` 正反两向：
15 个样本真密码命中（`openwall` / `Tr0ub4dor`）、错误密码字典**全部**"未找到密码"；
唯一不命中的 `mhe_nocrc_pad0.7z` 正是设计上回落的第 2 档（**7z.exe 自己也无法处理它**，
真密码同样报 `Headers Error`）。

---

## 5. 已知未验证 / 待办
1. **note 文案对"压缩头"保持存疑表述**（已按 Lead 确认的措辞修正）：
   `plain_many.7z` 实为内容加密（`7z t -popenwall` → Ok，`-pwrongpw` → Fail），但文件里
   `06F10701` 出现 **0 次** —— 它的头是 LZMA1 **压缩**的，真实 coder 链在压缩体内，需解压头
   才能看到。因此 note 不能断言"未加密"，现为：
   `7z format (header has no AES coder; the header itself may be compressed -> using external tool)`；
   代码注释与测试都写死了这条理由（`sevenzip_encoded_header_without_aes_coder_falls_back_with_doubtful_note`
   同时断言"出现 0 次 AES id"和"文案不许含 not encrypted"）。另用真实未加密样本
   （`Encrypted = -`、raw header、仅 COPY）覆盖了"无 AES id 确实等于未加密"的反例。
   `crack` 正确性不依赖该文案（两条路都回落外部工具）。
2. `-mhe` 无 digest 但 PAD>0 的档（`mhe_nocrc.7z`）为构造样本，未见真实 7-Zip 产物。
3. 多 folder / `NumPackStreams > 1` 的真实样本未覆盖，代码逻辑上直接回落。
4. BCJ2 等**真实**样本未覆盖（只覆盖 id 表与回落路径）。
5. 性能**由 Lead 补测**（本任务刻意没跑，避免与其 e2e 撞车），`mhe_lzma2.7z`（AES-only 头、
   `2^19` KDF 轮）：spawn `7z.exe t` 25.1 个/秒（39.8 ms/次）、原生单线程 78.4 个/秒、
   8 线程 **526.3 个/秒**，即 8 线程约 **21×**。天花板是格式强制的 SHA-256 `2^19` KDF，
   不是实现问题。**这些数字不是我的实测**，引用时请注明来源为 Lead 的二期验收报告。
6. **单 AES 块 + PAD>0** 的样本（`7z a -m0=copy` 且文件 <16 字节）**已覆盖**并修掉一个真 bug：
   原先 padding 预过滤要求密文 ≥ 32 字节（为取倒数第二个块当 IV），单块流没有任何"前一块"，
   导致**正确密码也被否决**（实测 `tiny.7z` 报"未找到密码"，而 7z.exe 报 Everything is Ok）。
   修法：单块时 IV 取 coder properties 里的 IV。见
   `sevenzip_single_cipher_block_with_padding_verifies`。
7. 与 7z 无关的**既有 bug**（已由 Lead 修复，不在本任务范围）：
   `engine.rs` 的 `run()` 只在 `run_inner` 正常返回后置 `stats.done`，而 `run_inner` 的 7 个提前
   `return res`（不存在的文件、解析失败、未找到解压工具、无密码保护 ×3、构造攻击计划失败）
   绕过了置位；`main.rs` 又无条件 `join()` 进度线程（`while !stats.done`），于是这些
   **错误路径全部永久挂起**（基线二进制同样复现）。现已由单一漏斗出口修复并实测：
   missing file / 目录 / 未加密 7z / 未加密 zip 全部正常退出（exit 2），`--progress` 正确发
   `{"ev":"done","status":"error"}`。

最后验证: 2026-10-06（`cargo test` 98 core + 11 cli 全绿 + release 零警告 + 16 真实样本双向实测；
性能数字由 Lead 补测；工作区行尾"混合"的结论经 Lead 复核后改正）
