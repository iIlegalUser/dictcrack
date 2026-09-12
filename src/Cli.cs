// Cli.cs -- dictcrack.exe console frontend. ASCII only source.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace DictCrack
{
    internal static class Cli
    {
        private static int Main(string[] args)
        {
            AppDomain.CurrentDomain.UnhandledException += delegate(object s, UnhandledExceptionEventArgs e)
            {
                try { Console.Error.WriteLine("致命错误: " + e.ExceptionObject); } catch { }
            };
            try
            {
                if (args.Length == 0) { PrintUsage(); return 2; }
                string cmd = args[0].ToLowerInvariant();
                if (cmd == "info") return CmdInfo(Rest(args, 1));
                if (cmd == "bench") return CmdBench(Rest(args, 1));
                if (cmd == "help" || cmd == "--help" || cmd == "-h" || cmd == "/?") { PrintUsage(); return 0; }
                return CmdCrack(args);
            }
            catch (ApplicationException ex)
            {
                Console.Error.WriteLine("错误: " + ex.Message);
                return 2;
            }
        }

        private static string[] Rest(string[] args, int n)
        {
            string[] r = new string[args.Length - n];
            Array.Copy(args, n, r, 0, r.Length);
            return r;
        }

    // ----------------------------------------------------------------
    private static bool Hashcat;

    private static int CmdInfo(string[] args)
    {
        if (args.Length < 1) { Console.Error.WriteLine("用法: dictcrack info <archive> [--hashcat]"); return 2; }
        string path = args[0];
        if (!File.Exists(path)) { Console.Error.WriteLine("文件不存在: " + path); return 2; }
        Hashcat = Array.IndexOf(args, "--hashcat") >= 0;
        ArchiveInfo info = ArchiveParser.Parse(path);
            Console.WriteLine("文件: " + Path.GetFullPath(path));
            Console.WriteLine("大小: " + new FileInfo(path).Length + " 字节");
            switch (info.Kind)
            {
                case ArchiveKind.Rar5:
                    Console.WriteLine("格式: RAR 5.x");
                    if (info.Rar5 == null) { Console.WriteLine("加密: 无（未发现加密头记录）"); }
                    else
                    {
                        Console.WriteLine("加密: " + (info.Rar5.HeaderEncrypted ? "RAR5 头加密（-hp）" : "RAR5 文件数据加密"));
                        if (info.Rar5.EntryName != null) Console.WriteLine("目标条目: " + info.Rar5.EntryName);
                        Console.WriteLine("KDF: PBKDF2-HMAC-SHA256, " + (1L << info.Rar5.Lg2Count) + " 轮");
                        Console.WriteLine("密码校验: " + (info.Rar5.PswCheck != null ? "有（可原生快速验证）" : "无（回退外部工具）"));
                        if (Hashcat)
                        {
                            if (info.Rar5.PswCheck != null)
                                Console.WriteLine("Hashcat (-m 13000): " + ArchiveParser.HashcatRar5(info.Rar5));
                            else
                                Console.WriteLine("Hashcat: 该压缩包没有可导出的校验数据");
                        }
                    }
                    break;
                case ArchiveKind.RarLegacy:
                    Console.WriteLine("格式: RAR 1.5-4.x");
                    break;
                case ArchiveKind.Zip:
                    Console.WriteLine("格式: ZIP");
                    if (info.Zip == null) Console.WriteLine("加密: 未检测到加密条目");
                    else
                    {
                        Console.WriteLine("目标条目: " + info.Zip.Name);
                        Console.WriteLine("加密方式: " + (info.Zip.Aes ? "WinZip AES-" + (info.Zip.AesStrength * 64 + 64) : "传统 ZipCrypto"));
                    }
                    break;
                case ArchiveKind.SevenZip:
                    Console.WriteLine("格式: 7z");
                    break;
                default:
                    Console.WriteLine("格式: 无法识别（" + info.DetectNote + "）");
                    break;
            }
            bool native = info.NativeSupported;
            Console.WriteLine("验证路径: " + (native ? "原生引擎 (native)" : "外部工具 (external)"));
            return 0;
        }

        // ----------------------------------------------------------------
        private static int CmdBench(string[] args)
        {
            string archive = GetOpt(args, new string[] { "-a", "--archive" });
            int threads = ParseInt(GetOpt(args, new string[] { "-t", "--threads" }), 0);
            int seconds = ParseInt(GetOpt(args, new string[] { "--seconds" }), 3);
            if (archive == null) { Console.Error.WriteLine("用法: dictcrack bench -a <archive> [-t 线程] [--seconds 秒]"); return 2; }
            if (!File.Exists(archive)) { Console.Error.WriteLine("文件不存在: " + archive); return 2; }
            ArchiveInfo info = ArchiveParser.Parse(archive);
            if (!info.NativeSupported)
            {
                Console.Error.WriteLine("该压缩包不支持原生验证（" + info.DetectNote + "），基准测速需要 RAR5 或加密 ZIP。");
                return 2;
            }
            Verifier v = VerifierFactory.Create(info, null, archive);
            Console.WriteLine(v.Describe());
            double single = Benchmark.Measure(v, 1, seconds);
            Console.WriteLine("单线程: " + Math.Round(single, 1) + " 个/秒");
            double all = Benchmark.Measure(v, threads > 0 ? threads : 0, seconds);
            Console.WriteLine((threads > 0 ? threads + " 线程" : "自动线程") + ": " + Math.Round(all, 1) + " 个/秒");
            return 0;
        }

        // ----------------------------------------------------------------
        private static CrackConfig ParseCrackArgs(string[] args)
        {
            CrackConfig cfg = new CrackConfig();
            List<string> dicts = new List<string>();
            bool[] used = new bool[args.Length];
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                string v;
                int start = i;
                bool opt = false;
                if (TryOpt(args, ref i, new string[] { "-a", "--archive" }, out v)) { cfg.ArchivePath = v; opt = true; }
                else if (TryOpt(args, ref i, new string[] { "-w", "--dict" }, out v)) { dicts.Add(v); opt = true; }
                else if (TryOpt(args, ref i, new string[] { "-w2" }, out v)) { cfg.DictFileB = v; opt = true; }
                else if (TryOpt(args, ref i, new string[] { "--rule", "--rules" }, out v))
                {
                    foreach (string r in v.Split(',')) { string t = r.Trim().ToLowerInvariant(); if (t.Length > 0 && Array.IndexOf(Rules.PresetNames, t) >= 0) cfg.Presets.Add(t); }
                    opt = true;
                }
                else if (TryOpt(args, ref i, new string[] { "--mask", "-m" }, out v)) { cfg.Mask = v; cfg.Mode = "mask"; opt = true; }
                else if (TryOpt(args, ref i, new string[] { "-1" }, out v)) { cfg.CustomSets[0] = v; opt = true; }
                else if (TryOpt(args, ref i, new string[] { "-2" }, out v)) { cfg.CustomSets[1] = v; opt = true; }
                else if (TryOpt(args, ref i, new string[] { "-3" }, out v)) { cfg.CustomSets[2] = v; opt = true; }
                else if (TryOpt(args, ref i, new string[] { "-4" }, out v)) { cfg.CustomSets[3] = v; opt = true; }
                else if (TryOpt(args, ref i, new string[] { "--min" }, out v)) { cfg.MaskMin = ParseInt(v, 1); opt = true; }
                else if (TryOpt(args, ref i, new string[] { "--max" }, out v)) { cfg.MaskMax = ParseInt(v, -1); opt = true; }
                else if (TryOpt(args, ref i, new string[] { "-t", "--threads" }, out v)) { cfg.Threads = ParseInt(v, 0); opt = true; }
                else if (TryOpt(args, ref i, new string[] { "--max-tries" }, out v)) { cfg.MaxTries = ParseLong(v, -1); opt = true; }
                else if (TryOpt(args, ref i, new string[] { "--tool" }, out v)) { cfg.UserTool = v; opt = true; }
                else if (TryOpt(args, ref i, new string[] { "--out" }, out v)) { cfg.OutFile = v; opt = true; }
                else if (TryOpt(args, ref i, new string[] { "--extract-to" }, out v)) { ExtractTo = v; opt = true; }
                else if (a == "--resume") { cfg.ResumeRequested = true; cfg.CheckpointEnabled = true; opt = true; }
                else if (a == "--no-checkpoint") { cfg.CheckpointEnabled = false; opt = true; }
                else if (a == "-q" || a == "--quiet") { cfg.Quiet = true; opt = true; }
                else if (a == "--dedupe") { cfg.Dedupe = true; opt = true; }
                if (opt) { used[start] = true; used[i] = true; }
            }
            // a typo like --masi would otherwise silently run the wrong attack
            for (int i = 0; i < args.Length; i++)
                if (!used[i] && args[i].Length > 1 && args[i][0] == '-')
                    Console.Error.WriteLine("警告: 无法识别的选项 " + args[i] + "（已忽略）");
            if (cfg.DictFiles.Count == 0) cfg.DictFiles = dicts;
            if (cfg.DictFileB != null && cfg.Mode != "mask") cfg.Mode = "comb";
            return cfg;
        }

        private static string ExtractTo;

        private static int CmdCrack(string[] args)
        {
            CrackConfig cfg = ParseCrackArgs(args);
            if (string.IsNullOrEmpty(cfg.ArchivePath))
            {
                PrintUsage();
                return 2;
            }
            if (cfg.Mode == "dict" && cfg.DictFiles.Count == 0)
            {
                Console.Error.WriteLine("错误: 字典模式需要 -w <字典文件>（或使用 --mask）。");
                return 2;
            }

            CancellationTokenSource cts = new CancellationTokenSource();
            int ctrlC = 0;
            Console.CancelKeyPress += delegate(object s, ConsoleCancelEventArgs e)
            {
                e.Cancel = true;
                if (System.Threading.Interlocked.Increment(ref ctrlC) >= 2)
                {
                    Console.Error.WriteLine("强制退出。");
                    Environment.Exit(3);
                }
                cts.Cancel();
                Console.Error.WriteLine("... 正在停止（再次 Ctrl+C 强制退出）");
            };

            Console.WriteLine("DictCrack 原生引擎 v1.0");
            CrackEngine engine = new CrackEngine(cfg);
            Thread progress = new Thread(delegate() { PrintProgressLine(engine, cfg); }) { IsBackground = true };
            progress.Start();
            CrackResult res = engine.Run(cts.Token);
            progress.Join();

            if (res.Error != null)
            {
                Console.Error.WriteLine("错误: " + res.Error);
                return 2;
            }
            if (res.Warning != null)
            {
                Console.Error.WriteLine("警告: " + res.Warning);
            }
            double rate = res.ElapsedSec > 0.2 ? res.Tried / res.ElapsedSec : 0;
            if (res.Found)
            {
                Console.WriteLine();
                Console.WriteLine("=== 找到密码: " + res.Password + " ===");
                Console.WriteLine("尝试 " + res.Tried + " 个, 用时 " + FormatTime(res.ElapsedSec) + ", 平均 " + Math.Round(rate, 1) + " 个/秒");
                if (res.ResultFile != null) Console.WriteLine("结果已保存: " + res.ResultFile);
                if (ExtractTo != null) return DoExtract(cfg.ArchivePath, res.Password, ExtractTo);
                return 0;
            }
            if (res.Cancelled) { Console.WriteLine("已取消（进度已保存, 下次加 --resume 继续）。"); return 3; }
            if (res.MaxedOut) { Console.WriteLine("达到 --max-tries 上限, 已停止（进度已保存, 加 --resume 继续）。"); return 3; }
            Console.WriteLine();
            Console.WriteLine("未找到密码。" + (engine.LogNote.Length > 0 ? "（编码方案: " + engine.LogNote + "）" : ""));
            Console.WriteLine("共尝试 " + res.Tried + " 个, 用时 " + FormatTime(res.ElapsedSec) + ", 平均 " + Math.Round(rate, 1) + " 个/秒");
            return 1;
        }

        private static int DoExtract(string archive, string password, string dir)
        {
            string tool = ToolLocator.FindExtractor();
            if (tool == null) { Console.Error.WriteLine("错误: 找不到 7z.exe, 无法解压。"); return 2; }
            Directory.CreateDirectory(dir);
            Console.WriteLine("正在解压到 " + dir + " ...");
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = tool;
            psi.Arguments = "x -y -p\"" + password.Replace("\"", "\"\"") + "\" -o\"" + dir + "\" \"" + archive + "\"";
            psi.UseShellExecute = false;
            using (Process p = Process.Start(psi))
            {
                p.WaitForExit();
                Console.WriteLine(p.ExitCode == 0 ? "解压完成。" : "解压失败（退出码 " + p.ExitCode + "）。");
                return p.ExitCode == 0 ? 0 : 2;
            }
        }

        // progress printer runs on a background timer; main thread joins the
        // engine, so console ownership is exclusive
        public static void PrintProgressLine(CrackEngine engine, CrackConfig cfg)
        {
            if (cfg.Quiet) return;
            long prevTried = 0; DateTime prevTime = DateTime.UtcNow;
            double rate = 0;
            while (!engine.Stats.Done)
            {
                Thread.Sleep(500);
                long tried = engine.Stats.Tried + engine.Stats.BaseTried;
                DateTime now = DateTime.UtcNow;
                double dt = (now - prevTime).TotalSeconds;
                if (dt > 0.4)
                {
                    double r = (tried - prevTried) / dt;
                    if (r > 0) rate = r;
                    prevTried = tried; prevTime = now;
                }
                long? total = engine.Stats.Total > 0 ? engine.Stats.Total : (long?)null;
                string eta = "";
                if (total.HasValue && rate > 0)
                {
                    long remain = total.Value - tried;
                    if (remain > 0) eta = " 剩余 " + FormatTime(remain / rate);
                }
                string cur = engine.Stats.Current;
                string tag = engine.Stats.CurrentTag;
                if (tag.Length > 0) cur = "[" + tag + "] " + cur;
                string line = string.Format("{0} | 已试 {1}{2} | {3} 个/秒{4} | 当前: {5}",
                    engine.Stats.Phase, tried, total.HasValue ? "/" + total.Value : "", Math.Round(rate, 1), eta, cur);
                if (line.Length > 110) line = line.Substring(0, 110);
                Console.Write("\r" + line.PadRight(118) + "\r");
            }
        }

        private static string FormatTime(double sec)
        {
            if (sec < 0 || double.IsNaN(sec) || double.IsInfinity(sec)) return "--:--";
            TimeSpan t = TimeSpan.FromSeconds(Math.Floor(sec));
            if (t.TotalHours >= 1) return string.Format("{0:00}:{1:00}:{2:00}", (int)t.TotalHours, t.Minutes, t.Seconds);
            return string.Format("{0:00}:{1:00}", t.Minutes, t.Seconds);
        }

        // ---- tiny arg helpers ------------------------------------------
        private static string GetOpt(string[] args, string[] names)
        {
            for (int i = 0; i < args.Length; i++)
            {
                string v;
                if (TryOpt(args, ref i, names, out v)) return v;
            }
            return null;
        }

        private static bool TryOpt(string[] args, ref int i, string[] names, out string value)
        {
            value = null;
            foreach (string n in names)
            {
                if (args[i] == n)
                {
                    if (i + 1 < args.Length) { value = args[i + 1]; i++; return true; }
                    return false;
                }
                if (args[i].StartsWith(n + "=", StringComparison.Ordinal))
                { value = args[i].Substring(n.Length + 1); return true; }
            }
            return false;
        }

        private static int ParseInt(string s, int def)
        {
            int v;
            return int.TryParse(s, out v) ? v : def;
        }

        private static long ParseLong(string s, long def)
        {
            long v;
            return long.TryParse(s, out v) ? v : def;
        }

        private static void PrintUsage()
        {
            Console.WriteLine("DictCrack - 压缩包密码字典/掩码破解工具（原生引擎）");
            Console.WriteLine();
            Console.WriteLine("用法:");
            Console.WriteLine("  dictcrack crack -a <压缩包> -w <字典> [--rule years,digits,leet,rev,cap,double]");
            Console.WriteLine("                             [-w 更多字典]... [-t 线程] [--resume] [--out 文件]");
            Console.WriteLine("  dictcrack crack -a <压缩包> --mask \"密码前缀?d?d?d?d\" [-1 自定义字符集] [--min N --max N]");
            Console.WriteLine("  dictcrack crack -a <压缩包> -w <字典A> -w2 <字典B>          (组合攻击)");
            Console.WriteLine("  dictcrack info <压缩包> [--hashcat]  查看格式 / 加密方式 / 验证路径（--hashcat 导出 hashcat 格式）");
            Console.WriteLine("  dictcrack bench -a <压缩包>      基准测速（需要 RAR5 或加密 ZIP）");
            Console.WriteLine();
            Console.WriteLine("选项:");
            Console.WriteLine("  -t, --threads N      并行线程（0=自动, 默认自动 = 核数-2）");
            Console.WriteLine("  --max-tries N        最多尝试 N 个候选后停止（测试/分次运行）");
            Console.WriteLine("  --resume             从上次中断处继续（配合自动保存的会话）");
            Console.WriteLine("  --no-checkpoint      不写会话文件");
            Console.WriteLine("  --out <文件>         结果文件路径（默认 <压缩包名>_password.txt）");
            Console.WriteLine("  --extract-to <目录>  找到密码后自动解压到该目录");
            Console.WriteLine("  --tool <exe>         后备验证工具路径（默认自动找 7z.exe/rar.exe，可用环境变量 DICTCRACK_TOOL 指定）");
            Console.WriteLine("  --dedupe             字典模式去掉重复候选（跨行去重，占用内存）");
            Console.WriteLine("  -q, --quiet          不输出进度行");
            Console.WriteLine();
            Console.WriteLine("掩码占位符: ?l 小写 ?u 大写 ?d 数字 ?s 特殊 ?a 全部 ?h/?H 十六进制 ?1..?4 自定义");
            Console.WriteLine("字典: 可指定多个 -w；-w - 从 stdin 读入字典。变异规则按选择顺序链式叠加。");
            Console.WriteLine("退出码: 0 找到密码 | 1 未找到 | 2 出错 | 3 已停止（可 --resume）");
        }
    }
}
