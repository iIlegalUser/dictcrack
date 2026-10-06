# RAR 1.5–4.x（"RAR4"/"RAR3"）原生化实现记录

> 对应方案 `docs/superpowers/specs/2026-10-06-perf-phase2-plan.md` 的 **#3 RAR4 部分**。
> 实现日期 2026-10-06。本文档记录**实测纠正后**的真实规格，方案文档里关于 RAR4 的
> 校验方式描述有误，以本文为准。
>
> 字节级外部权威规格见 `docs/rar3-password-check-spec.md`（独立调研产出，逐条引用 hashcat
> `module_12500/23700/23800.c`、John `rar_common.h`、unrar `crypt3.cpp`/`arcread.cpp` 源码）。

## 方案文档的三处错误（已纠正）

| 方案原文 | 实测结论 |
|---|---|
| "`-p` 解密文件数据**前 16 字节**，明文第 13-15 字节 == 文件头 CRC32 低 3 字节（rar2john 同款）" | **错误**。`-p` stored 的校验是**解密全部数据、对前 `UnpSize` 字节算标准 CRC32 与 `FileCRC` 比 4 字节**。不存在"低 3 字节"截断，也没有任何实现拿明文比 CRC 字段。便宜的预筛是**末尾填充零**（最后一块），不是前 16 字节。 |
| "单候选成本 = KDF（一次）+ 1 个 AES 块，速率落在 ZipCrypto 量级（百万/s）" | **错误，差 4 个数量级**。RAR3 KDF 是 **0x40000 轮 SHA-1**（262144 次压缩/候选），实测软实现 16.1 ms/候选 ≈ 62/s，优化后 7.6 ms ≈ 131/s 单线程。与 ZipCrypto 的 CRC 流密码完全不是一个量级。 |
| "`-hp`（头加密）解密文件头校验其结构 CRC" | **错误**。`-hp` 头本身是加密的，读不到。校验用的是归档**末尾 24 字节**：`[salt(8)][ENDARC 首块密文(16)]`，解密后比对**固定常量** `c4 3d 7b 00 40 07 00 00`（john 的 "end-of-archive block decrypt trick"）。 |

附带纠正：`-p` 压缩（method 0x31–0x35）**没有**廉价的精确前缀校验。CRC 在**解压后**的
字节上，必须跑完整 RAR LZ/PPMd 解压。前 16 字节只能做概率预筛（LZ Huffman / PPMd 头
位检查，john 注释称拒绝 >96% 错误候选），不能确认密码。本实现**不做解压器**，这类
归档继续走外部工具。

## 最终实现

### 校验方式

| 场景 | 校验 | 精确性 |
|---|---|---|
| `-hp` 头加密 | `AES128-CBC_decrypt(key, iv, ENDARC首块)[0..8] == c4 3d 7b 00 40 07 00 00` | 精确（8 字节常量，2⁻⁶⁴ 假阳） |
| `-p` 存储（method 0x30） | `CRC32(plaintext[0..UnpSize]) == FileCRC`（小端 u32，文件头 +16） | 精确（2⁻³² 假阳，与格式本身同等强度） |
| `-p` 压缩（0x31–0x35） | 需要完整 RAR LZ/PPMd 解压器 → **回落外部工具** | — |

两条原生路径都是精确校验，因此**不需要**像 ZipCrypto 那样的"确认"二次步骤，报告命中
即为真。

### KDF

`unrar crypt3.cpp SetKey30`，逐行核对：

```
raw = UTF16LE(password) ‖ salt(8)
h = SHA1_INIT
for I in 0..0x40000:
    sha1_process_rar29(h, raw, len(raw))     # 仅这一段带 rar29 写回 quirk
    sha1_process(h, [I&0xFF, (I>>8)&0xFF, (I>>16)&0xFF])   # 普通 SHA-1
    if I % 0x4000 == 0:
        iv[I / 0x4000] = sha1_final_copy(h)[19]
d = sha1_final_copy(h)
key = le32(d[0..3]) ‖ le32(d[4..7]) ‖ le32(d[8..11]) ‖ le32(d[12..15])
```

要点：
- **salt 恒为 8 字节**（unrar `SIZE_SALT30`），`-hp` 与 `-p` 相同；16 字节是 RAR5 的事。
- IV 取自摘要**字节下标 19**（= big-endian 摘要最后一个字节 = `digest[4]` 低字节），
  共 16 次采样。
- `rar29` 写回 quirk 只作用于 `password‖salt` 那一次 update，**不作用于 3 字节计数器**。

### 关键优化：KDF 快路径（2.1×）

`sha1_process_rar29` 只在"单次 update 跨过一个以上完整块"时才把展开的消息调度字写回
调用方缓冲区，条件是其循环入口 `j + len > 63` 且 `len > 128 - j`，其中 `j = count & 63 < 64`。
**`len <= 64` 时该写回不可达**，因此普通流式 SHA-1 与 rar29 流产生逐位相同的 key/IV。

`raw.len() <= 64` 即"密码 ≤ 28 字符 + 8 字节 salt"——绝大多数真实场景，也正好是 John
经典构建的 `PLAINTEXT_LENGTH`。这条路径直接用 `sha1` crate 的 **SHA-NI** 后端（运行时
检测，`sha1` 0.10.7 的 `compress/x86.rs` 用 `_mm_sha1rnds4_epu32`）：

| 实现 | 单候选耗时 | 单线程速率 |
|---|---|---|
| rar29 软 SHA-1（原） | 16.1 ms | 62 个/秒 |
| SHA-NI 快路径（现） | 7.6 ms | **131 个/秒** |

超过 64 字节的密码自动回落到软 rar29 流（quirk 必须保留）。分支切换点由
`rar3::tests::kdf_fast_path_matches_rar29_across_the_writeback_boundary` 扫描 0/1/10/27/28/29/40/70
字符两侧钉死，两路结果必须逐位一致。

### 与外部工具的实测对比

同一归档（`rar4p.rar`，7z.exe 与 UnRAR 均确认 `Rar4Gold9` 正确）：

| 路径 | 单线程 | 8 线程 |
|---|---|---|
| spawn `7z.exe t`（原回退路径） | 26.5 个/秒（37.8 ms/次进程启动） | — |
| 原生 `-hp` | 130.1 个/秒 | 958.3 个/秒 |
| 原生 `-p` 存储 | 131.0 个/秒 | 948.0 个/秒 |

即 **~36×（单线程）**，且不再依赖外部 exe。

## 测试与金标准

WinRAR 7.12 **不能造 RAR4**（`-ma4` 报未知选项），因此两个最小样本以**字节字面量**固化，
并在固化前用外部参考解密器验证过：

| 样本 | 密码 | 外部验证 |
|---|---|---|
| `rar4hp.rar`（-hp，132 B） | `HpGold55` | `UnRAR.exe t` 正确密码 exit 0，错误密码 exit 3 |
| `rar4p.rar`（-p 存储，107 B） | `Rar4Gold9` | `7z.exe t` 正确密码 "Everything is Ok" exit 0，错误密码 "CRC Failed" exit 2 |

固化位置：
- 单测：`archive.rs`（解析）+ `verifier.rs`（校验三态、填充预筛、压缩回落）+
  `rar3.rs`（KDF 向量与快路径对拍）
- e2e：`tests/run-tests.ps1` test 3a–3d（info 文案 / `-hp` 命中 / `-p` 命中 / 错误字典穷尽）
  与 test 15b（RAR4 断点续跑）

单测覆盖的拒绝态包括：错误密码、空密码、正确密码的前缀、正确密码加尾空格，以及
7z.exe 报 CRC 失败的那个密码。

## 已知限制

- **压缩的 `-p` 文件不是原生路径**：需要 RAR LZ/PPMd 解压器，本实现不做。`info` 会给出
  `compressed file needs the external tool` 说明并回落 `SpawnVerifier`。
- **`-p` 数据区上限 16 MiB**（`verifier::RAR4_MAX_DATA`）：原生校验要把整段密文读进内存
  解密。超过则回退外部工具，避免每候选分配巨量内存。仅影响"存储 + 超大"的归档。
- **多卷 / `LHD_LARGE`（>4 GB）/ 无 salt / RAR 2.x 加密（UnpVer != 29）** 一律
  `parse_rar4` 返回 `None` → 外部工具兜底。
- `-hp` 的校验常量是归档格式的固有已知明文，不是本实现的假设：hashcat 与 John
  用的是同一个 8 字节序列。

## 文件清单

| 文件 | 改动 |
|---|---|
| `rust/crates/core/src/rar3.rs` | 新增（RAR3 SHA-1/KDF/AES-CBC 原语 + 快路径分派） |
| `rust/crates/core/src/archive.rs` | `Rar4CryptInfo` + `parse_rar4` + 探测接线 |
| `rust/crates/core/src/verifier.rs` | `Rar4Verifier`（-hp / -p 存储）+ `create_native` 接入 |
| `rust/crates/cli/src/main.rs` | `info` 的 RAR4 文案 |
| `tests/run-tests.ps1` | test 3a–3d、test 15b |

最后验证: 2026-10-06（cargo test 全绿、e2e 0 failure、bench 实测如上表）
