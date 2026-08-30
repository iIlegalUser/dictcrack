# DictCrack — 压缩包密码字典/掩码破解工具（原生引擎版）

Windows 下的压缩包密码恢复工具。核心是 **C# 原生验证引擎**：直接解析 RAR5 / ZIP
加密头，用密码校验值离线验证候选密码，不产生任何子进程；RAR 4.x、7z 等格式自动
回退到 7-Zip / WinRAR 进程测试。带 WinForms 图形界面与功能完整的命令行。

## 与市面工具的对比

| 能力 | hashcat / John | ARCHPR 等 | DictCrack |
|---|---|---|---|
| 原生头部校验（不启动子进程） | ✔ | ✔ | ✔（RAR5/ZIP） |
| 字典 / 掩码 / 组合攻击 | ✔ | 部分 | ✔ |
| 规则变异（年份、数字、leet…） | ✔（规则语言） | 部分 | 内置 6 种中文场景预设 |
| 断点续跑（checkpoint/restore） | ✔ | ✔ | ✔（自动保存、可交互续跑） |
| 基准测速 | ✔ | ✗ | ✔（按真实压缩包测 H/s） |
| 中文密码 / GBK 字典处理 | 需自行转换 | 部分 | ✔ 编码自动遍历（UTF-8/UTF-16/GBK） |
| 图形界面 | ✗ | ✔ | ✔ |
| GPU 加速 | ✔ | ✗ | ✗（纯 CPU，见下） |

定位：无 GPU 依赖、免安装、面向中文口令场景的 CPU 破解器。RAR5 走 PBKDF2 头部
校验（这是格式强制的 KDF，GPU 与否都省不掉），ZIP 可达每秒数百万候选。

## 实测性能（24 逻辑核，默认 22 线程）

| 加密方式 | 引擎路径 | 速率 | 旧版（PS + 7z 进程） |
|---|---|---|---|
| RAR5（PBKDF2-SHA256 2^15 轮） | 原生头部校验 | ~1 500 个/秒 | ~100–160 个/秒 |
| ZIP WinZip AES-256 | 原生 PBKDF2-SHA1 + HMAC | ~5 000 个/秒 | 同上 |
| ZIP ZipCrypto | 原生流密码 + CRC 全量确认 | ~5 000 000 个/秒 | 同上 |
| RAR 4.x / 7z | 7z 进程回退 | ~150 个/秒 | 同上 |

三个工程要点（踩过坑的）：

1. **RAR5 校验值算法**（对照 unrar `crypt5.cpp` 用真实样本验证）：
   `PswCheck(8B) = fold8(PBKDF2-HMAC-SHA256(UTF8(pwd), salt16, 2^Lg2Cnt + 32))`，
   头里另存 `SHA256(PswCheck)[0..4]` 做完整性。-hp 头加密包的校验数据在明文的
   加密头记录里，**同样可原生破解**。
2. **CNG 并行化**：`BCryptDeriveKeyPBKDF2` 共享算法句柄时内部串行（实测 4 线程
   后吞吐平台期），每线程各开一个句柄后恢复近线性扩展。
3. **ZipCrypto 误报**：1 字节检查值有 1/256 误报率，命中后再做全量解密+解压+CRC
   校验，保证报出的密码一定正确。

## 构建

无第三方依赖，用系统自带 .NET Framework 4.8 编译器：

```powershell
powershell -ExecutionPolicy Bypass -File build\build.ps1
# 产出 dist\dictcrack.exe（命令行）与 dist\dictcrack-gui.exe（图形界面）
```

## 使用

### 图形界面

直接运行 `dist\dictcrack-gui.exe`。支持拖入压缩包/字典、三种攻击模式、变异规则、
断点续跑、基准测速；找到密码自动复制到剪贴板、写结果文件，可一键解压或把密码
提前到字典首行。命令行参数可自动启动：`dictcrack-gui.exe -a <包> -w <字典> [-t N] [--mask ...]`，
传 `-w` + `-w2` 则自动切换到组合模式并填入 A/B 两个字典。

### 命令行

```
dictcrack crack -a <压缩包> -w <字典> [--rule years,digits,leet,rev,cap,double] [-t 线程]
dictcrack crack -a <压缩包> --mask "前缀?d?d?d?d" [-1 自定义字符集] [--min N --max N]
dictcrack crack -a <压缩包> -w <字典A> -w2 <字典B>          # 组合攻击
dictcrack info  <压缩包>      # 格式 / 加密方式 / KDF 轮数 / 验证路径
dictcrack bench -a <压缩包>   # 基准测速（需要 RAR5 或加密 ZIP）
```

常用选项：`--resume`（从中断处继续）、`--max-tries N`（限次停止，测试用）、
`--extract-to <目录>`（命中后自动解压）、`--out <文件>`（结果文件路径）、`-q`（静默）。
退出码：`0` 找到密码，`1` 未找到，`2` 出错，`3` 已停止（可 `--resume`）。

掩码占位符：`?l` 小写 `?u` 大写 `?d` 数字 `?s` 特殊 `?a` 全部 `?h/?H` 十六进制
`?1..?4` 自定义字符集。

示例：

```powershell
# 字典 + 年份/数字变异
dictcrack crack -a game.rar -w cnwords.txt --rule years,digits

# 六位纯数字掩码
dictcrack crack -a game.rar --mask "?d?d?d?d?d?d" -t 24

# 中断后继续（会话保存在软件目录 session.json）
dictcrack crack -a game.rar -w big.txt --resume
```

## 架构

```
src\
  Crypto.cs      托管/原生 PBKDF2（每线程 CNG 句柄）、CRC32
  ArchiveInfo.cs RAR5 头链解析（vint/加密头记录）、ZIP 中央目录解析、格式识别
  Verifier.cs    Rar5Verifier / ZipVerifier（含 ZipCrypto 全量确认）/ 7z 进程回退
  Attacks.cs     字典（多编码遍历+变异）、掩码、组合三种候选源（可序列化进度）
  Engine.cs      生产者-消费者线程编排、断点会话、统计、基准
  Cli.cs         命令行前端
  Gui.cs         WinForms 前端（扁平设计、拖放、DPI 缩放）
build\build.ps1  csc 编译脚本（CLI + GUI）
tests\run-tests.ps1  端到端测试（17 项，WinRAR/7z 现场造样本）
legacy\          旧版 PowerShell GUI 套件（已被原生引擎版取代，保留备查）
```

支持格式：RAR5（-p 与 -hp）与加密 ZIP（ZipCrypto / AES-128/192/256）走原生快速
路径；RAR 1.5-4.x、7z 及其他 7-Zip 认识的格式自动回退外部工具测试。不支持的
RAR5（无密码校验数据）同样回退。

字典编码：按 BOM 识别 UTF-8/UTF-16；无 BOM 时先做严格 UTF-8 探测，合法则
UTF-8 + GBK 双遍历（同一行去重），否则只跑 GBK——GBK 字典不会浪费 UTF-8 遍。

## 测试

```powershell
powershell -ExecutionPolicy Bypass -File tests\run-tests.ps1
```

需要 7-Zip（造 ZIP/7z 样本）与 WinRAR 的 `rar.exe`（造 RAR5 样本；RAR 7 已不能
生成 RAR4 格式）。测试覆盖：五种加密路径的字典命中、未加密报错、掩码/组合/规则、
UTF-8 BOM / UTF-16LE / GBK 中文密码矩阵、断点续跑、基准、GUI 自动启动。

## 已知限制

- 纯 CPU：RAR5 的 PBKDF2（默认 2^15 轮）是格式强制的，有 GPU 请用 hashcat（可
  用 `info` 查看轮数自行提取 hash）。
- 外部工具回退路径的候选不能含换行/引号（命令行传参限制）；原生路径无此限制。
- 组合攻击会把字典 B 整体载入内存。
