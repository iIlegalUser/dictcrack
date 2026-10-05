// RemoteEngine.cs -- process-mode driver that lets the GUI crack with the
// Rust engine (rust\...\dictcrack.exe): spawns the CLI with --progress,
// parses the JSONL protocol on stdout into EngineStats updates, and maps
// the terminal found/done events onto CrackResult. Cancel is stdin EOF
// (the WinForms host has no console for Ctrl+C). RustLocator probes for a
// usable Rust exe and falls back to the built-in C# engine when none
// answers. ASCII only source.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace DictCrack
{
    // ------------------------------------------------------------------
    // Locates a usable Rust dictcrack.exe. Candidates are probed with
    // --version and must answer like the Rust CLI ("dictcrack <ver>", exit
    // 0): the C# CLI usually sits right next to the GUI in dist\ and has no
    // --version, so it exits 2 and is rejected without an engine mix-up.
    internal static class RustLocator
    {
        private static readonly object _lock = new object();
        private static string _found;
        private static bool _probed;

        internal static string Find()
        {
            lock (_lock)
            {
                if (_probed) return _found;
                string exeDir = AppDomain.CurrentDomain.BaseDirectory;
                string rel = Path.Combine("rust", "target", "x86_64-pc-windows-gnu", "release", "dictcrack.exe");
                string[] cands = new string[]
                {
                    // canonical deployed name (no clash with the C# CLI)
                    Path.Combine(exeDir, "dictcrack-rs.exe"),
                    // a Rust dictcrack.exe dropped next to the GUI (only
                    // accepted after the --version probe passes)
                    Path.Combine(exeDir, "dictcrack.exe"),
                    // dev layouts: GUI in dist\ or in the repo root
                    Path.Combine(exeDir, rel),
                    Path.GetFullPath(Path.Combine(exeDir, "..", rel)),
                };
                foreach (string c in cands)
                {
                    if (!File.Exists(c)) continue;
                    if (Probe(c)) { _found = c; break; }
                }
                _probed = true;
                return _found;
            }
        }

        // --version handshake: Rust prints "dictcrack <ver>" and exits 0;
        // anything else (C# CLI, blocked by AV, stale build) is rejected
        internal static bool Probe(string exe)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = exe;
                psi.Arguments = "--version";
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                using (Process p = Process.Start(psi))
                {
                    string so = p.StandardOutput.ReadToEnd();
                    p.StandardError.ReadToEnd();
                    if (!p.WaitForExit(5000)) { try { p.Kill(); } catch { } return false; }
                    return p.ExitCode == 0 && so.TrimStart().StartsWith("dictcrack", StringComparison.Ordinal);
                }
            }
            catch { return false; }
        }
    }

    // ------------------------------------------------------------------
    // Flat-object JSON scanner for one --progress protocol line:
    // {"key":"value","n":123,...}. Returns null for anything it cannot
    // read - the caller ignores such lines, which is exactly the
    // forward-compatibility rule of the protocol.
    internal static class MiniJson
    {
        internal static Dictionary<string, string> Parse(string text)
        {
            try
            {
                if (text == null) return null;
                text = text.Trim();
                if (text.Length < 2 || text[0] != '{' || text[text.Length - 1] != '}') return null;
                Dictionary<string, string> kv = new Dictionary<string, string>();
                int i = 1;
                while (i < text.Length)
                {
                    while (i < text.Length && (text[i] == ' ' || text[i] == ',' || text[i] == '\n' || text[i] == '\r' || text[i] == '\t')) i++;
                    if (i < text.Length && text[i] == '}') break;
                    if (i >= text.Length || text[i] != '"') return null;
                    int keyStart = ++i;
                    while (i < text.Length && text[i] != '"') { if (text[i] == '\\') i++; i++; }
                    if (i >= text.Length) return null;
                    string key = JsonUnescape(text.Substring(keyStart, i - keyStart));
                    i++;
                    while (i < text.Length && (text[i] == ' ' || text[i] == ':')) i++;
                    if (i >= text.Length) return null;
                    string val;
                    if (text[i] == '"')
                    {
                        int valStart = ++i;
                        while (i < text.Length && text[i] != '"') { if (text[i] == '\\') i++; i++; }
                        if (i >= text.Length) return null;
                        val = JsonUnescape(text.Substring(valStart, i - valStart));
                        i++;
                    }
                    else
                    {
                        int valStart = i;
                        while (i < text.Length && text[i] != ',' && text[i] != '}') i++;
                        val = text.Substring(valStart, i - valStart).Trim();
                    }
                    kv[key] = val;
                }
                return kv;
            }
            catch { return null; }
        }

        // full JSON string unescape (\" \\ \/ \b \f \n \r \t \uXXXX) - not
        // SessionState.Unescape, whose lenient rules are tuned for the
        // session file and would turn \n into a bare 'n'
        private static string JsonUnescape(string s)
        {
            if (s.IndexOf('\\') < 0) return s;
            StringBuilder sb = new StringBuilder(s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                if (s[i] == '\\' && i + 1 < s.Length)
                {
                    char n = s[++i];
                    switch (n)
                    {
                        case 'n': sb.Append('\n'); continue;
                        case 'r': sb.Append('\r'); continue;
                        case 't': sb.Append('\t'); continue;
                        case 'b': sb.Append('\b'); continue;
                        case 'f': sb.Append('\f'); continue;
                        case 'u':
                            if (i + 4 < s.Length)
                            {
                                int code;
                                if (int.TryParse(s.Substring(i + 1, 4), System.Globalization.NumberStyles.HexNumber,
                                    System.Globalization.CultureInfo.InvariantCulture, out code))
                                { sb.Append((char)code); i += 4; continue; }
                            }
                            sb.Append('u');
                            continue;
                        default: sb.Append(n); continue;   // \" \\ \/ and anything lenient
                    }
                }
                sb.Append(s[i]);
            }
            return sb.ToString();
        }
    }

    // ------------------------------------------------------------------
    internal sealed class RemoteCrackEngine
    {
        private readonly CrackConfig _cfg;
        private readonly string _exe;

        public readonly EngineStats Stats = new EngineStats();
        public string LogNote = "";

        private string _foundPw;
        private string _foundFile;
        private string _doneStatus;
        private string _doneError;
        private string _doneNote;
        private long _endTried;
        private double _endElapsed;

        public RemoteCrackEngine(CrackConfig cfg, string exe) { _cfg = cfg; _exe = exe; }

        /// <summary>
        /// Spawns the Rust CLI and pumps its stdout protocol until the
        /// process exits. Never throws for a failed run - everything lands
        /// in res.Error like the built-in engine. Runs on the GUI's work
        /// thread, mirroring CrackEngine.Run.
        /// </summary>
        public CrackResult Run(CancellationToken external)
        {
            CrackResult res = new CrackResult();
            // named kernel event as the cancel signal: created before the
            // spawn, set on GUI cancel, opened by the child by name (no
            // console for Ctrl+C, and stdin EOF would falsely cancel any
            // non-interactive caller)
            string evName = "Local\\dictcrack-gui-" + Guid.NewGuid().ToString("N");
            using (EventWaitHandle cancelEvent = new EventWaitHandle(false, EventResetMode.ManualReset, evName))
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = _exe;
                psi.Arguments = BuildArgs(_cfg) + " --cancel-event " + QuoteArg(evName);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.StandardOutputEncoding = new UTF8Encoding(false);
                psi.StandardErrorEncoding = new UTF8Encoding(false);

                using (Process p = Process.Start(psi))
                {
                    System.Threading.Tasks.Task<string> errTask = p.StandardError.ReadToEndAsync();

                    // cancel watcher: GUI cancel => set the child's cancel
                    // event (the Rust side stops gracefully and still saves
                    // its session); kill only if it overstays the grace
                    // window. If the run ends normally the watcher exits
                    // without touching the process.
                    Thread watcher = new Thread(delegate()
                    {
                        while (!external.IsCancellationRequested)
                        {
                            try { if (p.HasExited) return; } catch { return; }
                            Thread.Sleep(100);
                        }
                        try { cancelEvent.Set(); } catch { }
                        try { if (!p.WaitForExit(15000)) p.Kill(); } catch { }
                    }) { IsBackground = true };
                    watcher.Start();

                    string line;
                    while ((line = p.StandardOutput.ReadLine()) != null)
                        HandleLine(line);
                    if (!p.HasExited) p.WaitForExit();
                    try { watcher.Join(500); } catch { }

                    string errText = "";
                    try { errText = errTask.Result ?? ""; } catch { }
                    Finish(res, p.ExitCode, errText);
                }
            }
            return res;
        }

        private void HandleLine(string line)
        {
            if (line == null) return;
            line = line.Trim();
            if (line.Length == 0 || line[0] != '{') return;
            Dictionary<string, string> kv = MiniJson.Parse(line);
            if (kv == null) return;   // unknown line: ignore (forward compat)
            string ev;
            kv.TryGetValue("ev", out ev);
            if (ev == "stats")
            {
                Stats.SetTried(GetL(kv, "tried"));
                long total = GetL(kv, "total");
                if (total >= 0) Stats.Total = total;
                string s;
                if (kv.TryGetValue("phase", out s)) Stats.Phase = s;
                if (kv.TryGetValue("current", out s)) Stats.Current = s;
                if (kv.TryGetValue("tag", out s)) Stats.CurrentTag = s;
            }
            else if (ev == "found")
            {
                _foundPw = Get(kv, "password") ?? "";
                _foundFile = Get(kv, "result_file");
                _endTried = GetL(kv, "tried");
                _endElapsed = GetD(kv, "elapsed");
                Stats.Done = true;
            }
            else if (ev == "done")
            {
                _doneStatus = Get(kv, "status");
                _doneError = Get(kv, "error");
                _doneNote = Get(kv, "note");
                _endTried = GetL(kv, "tried");
                _endElapsed = GetD(kv, "elapsed");
                Stats.Done = true;
            }
            // unknown ev: ignore
        }

        private void Finish(CrackResult res, int exitCode, string errText)
        {
            res.Tried = _endTried;
            res.ElapsedSec = _endElapsed;
            LogNote = _doneNote ?? "";
            if (_foundPw != null)
            {
                res.Found = true;
                res.Password = _foundPw;
                res.ResultFile = _foundFile;
                return;
            }
            if (_doneStatus == "cancelled") res.Cancelled = true;
            else if (_doneStatus == "maxed_out") res.MaxedOut = true;
            else if (_doneStatus != "not_found")
            {
                // no terminal event at all: the process died or the protocol
                // broke - surface the CLI's stderr (human-readable Chinese)
                // instead of a silent failure
                string tail = Tail(errText);
                res.Error = _doneError ?? (tail.Length > 0 ? tail : "Rust 引擎异常退出（退出码 " + exitCode + "）。");
                return;
            }
            // cancelled/maxed_out can also carry a producer/worker error
            if (_doneError != null && res.Error == null) res.Error = _doneError;
        }

        private static string Tail(string s)
        {
            if (s == null) return "";
            s = s.Trim();
            if (s.Length == 0) return "";
            string[] lines = s.Split('\n');
            return lines[lines.Length - 1].Trim();
        }

        private static string Get(Dictionary<string, string> kv, string key)
        {
            string v;
            return kv.TryGetValue(key, out v) ? v : null;
        }

        private static long GetL(Dictionary<string, string> kv, string key)
        {
            string v;
            long n;
            return kv.TryGetValue(key, out v) && long.TryParse(v, out n) ? n : 0;
        }

        private static double GetD(Dictionary<string, string> kv, string key)
        {
            string v;
            double d;
            return kv.TryGetValue(key, out v) && double.TryParse(v, System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out d) ? d : 0;
        }

        // ----------------------------------------------------------------
        // argv assembly. Path/mask strings must reach the Rust CLI byte-
        // identical to what ParamsHash saw on this side, or a session saved
        // by one engine would be rejected by the other.
        internal static string BuildArgs(CrackConfig cfg)
        {
            List<string> a = new List<string>();
            a.Add("crack");
            a.Add("-a"); a.Add(cfg.ArchivePath);
            if (cfg.Mode == "mask")
            {
                a.Add("--mask"); a.Add(cfg.Mask);
                if (!string.IsNullOrEmpty(cfg.CustomSets[0])) { a.Add("-1"); a.Add(cfg.CustomSets[0]); }
                if (!string.IsNullOrEmpty(cfg.CustomSets[1])) { a.Add("-2"); a.Add(cfg.CustomSets[1]); }
                a.Add("--min"); a.Add(cfg.MaskMin.ToString());
                a.Add("--max"); a.Add(cfg.MaskMax.ToString());
            }
            else if (cfg.Mode == "comb")
            {
                a.Add("-w"); a.Add(cfg.DictFiles[0]);
                a.Add("--w2"); a.Add(cfg.DictFileB);
            }
            else
            {
                foreach (string f in cfg.DictFiles) { a.Add("-w"); a.Add(f); }
                if (cfg.Presets.Count > 0)
                {
                    a.Add("--rule");
                    a.Add(string.Join(",", cfg.Presets.ToArray()));
                }
            }
            a.Add("-t"); a.Add(cfg.Threads.ToString());
            if (!cfg.CheckpointEnabled) a.Add("--no-checkpoint");
            if (cfg.ResumeRequested) a.Add("--resume");
            // pin every crack-time artifact to the GUI's own folder: the
            // session must stay interoperable with the built-in engine's
            // resume dialog, and the result file where the GUI expects it
            a.Add("--session-file"); a.Add(CrackEngine.SessionPath);
            a.Add("--out"); a.Add(DefaultResultPath(cfg.ArchivePath));
            a.Add("--progress");
            StringBuilder sb = new StringBuilder();
            foreach (string s in a)
            {
                if (sb.Length > 0) sb.Append(' ');
                sb.Append(QuoteArg(s));
            }
            return sb.ToString();
        }

        // the built-in engine's WriteResultFile default, so both engines
        // drop the result file in the same place
        internal static string DefaultResultPath(string archive)
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
                Path.GetFileNameWithoutExtension(archive) + "_password.txt");
        }

        // standard CRT argv quoting (the Rust CLI reads argv via
        // GetCommandLineW, which parses with these rules): quotes and
        // backslashes-before-quote escaped, trailing backslashes doubled
        internal static string QuoteArg(string s)
        {
            if (s.Length > 0 && s.IndexOfAny(new char[] { ' ', '\t', '\n', '"' }) < 0) return s;
            StringBuilder sb = new StringBuilder();
            sb.Append('"');
            int back = 0;
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '\\') { back++; continue; }
                if (back > 0)
                {
                    // a quote ends the run: 2n+1 backslashes then the quote;
                    // any other char releases the run unchanged (2n backslashes
                    // before a non-quote are literal)
                    if (c == '"') sb.Append('\\', back * 2 + 1);
                    else sb.Append('\\', back);
                    back = 0;
                }
                else if (c == '"') sb.Append('\\');
                sb.Append(c);
            }
            if (back > 0) sb.Append('\\', back * 2);
            sb.Append('"');
            return sb.ToString();
        }
    }

    // ------------------------------------------------------------------
    // GUI bench via the Rust CLI, so the measured throughput matches the
    // engine that will actually crack. Folds the CLI's two rate lines into
    // the same status text the built-in bench prints.
    internal static class RustBench
    {
        internal static string Run(string exe, string archive, int threads)
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = exe;
            psi.Arguments = "bench -a " + RemoteCrackEngine.QuoteArg(archive) + " -t " + threads;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.StandardOutputEncoding = new UTF8Encoding(false);
            psi.StandardErrorEncoding = new UTF8Encoding(false);
            using (Process p = Process.Start(psi))
            {
                string so = p.StandardOutput.ReadToEnd();
                string se = p.StandardError.ReadToEnd();
                p.WaitForExit();
                if (p.ExitCode != 0)
                {
                    string msg = se.Trim();
                    throw new ApplicationException(msg.Length > 0 ? msg : "退出码 " + p.ExitCode);
                }
                string single = null, all = null;
                foreach (string raw in so.Split('\n'))
                {
                    string l = raw.Trim();
                    int colon = l.IndexOf(':');
                    if (colon <= 0 || !l.EndsWith("个/秒", StringComparison.Ordinal)) continue;
                    if (l.StartsWith("单线程", StringComparison.Ordinal)) single = l.Substring(colon + 1).Trim();
                    else all = l.Substring(colon + 1).Trim();
                }
                if (single != null && all != null)
                    return "测速完成: 单线程 " + single + " · 多线程 " + all;
                return "测速完成: " + so.Trim();
            }
        }
    }
}
