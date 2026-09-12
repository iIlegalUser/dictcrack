// Engine.cs -- orchestration: candidate producer + N verifier threads,
// checkpoint/resume sessions, live stats, benchmark mode. ASCII only.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace DictCrack
{
    public sealed class CrackConfig
    {
        public string ArchivePath;
        public string Mode = "dict";                 // dict | mask | comb
        public List<string> DictFiles = new List<string>();
        public string DictFileB;
        public List<string> Presets = new List<string>();
        public string Mask;
        public string[] CustomSets = new string[4];
        public int MaskMin = 1;
        public int MaskMax = -1;                     // -1 = full mask length
        public int Threads;                          // 0 = auto
        public bool CheckpointEnabled = true;
        public bool ResumeRequested;
        public long MaxTries = -1;
        public string UserTool;
        public bool Quiet;
        public string OutFile;                       // result file path (--out), default next to the exe
        public bool Dedupe;                          // dictionary mode: drop candidates already tried earlier in the run

        public string ParamsHash()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("mode=").Append(Mode).Append(';');
            foreach (string f in DictFiles) sb.Append("w=").Append(f).Append(';');
            if (DictFileB != null) sb.Append("w2=").Append(DictFileB).Append(';');
            foreach (string p in Presets) sb.Append("r=").Append(p).Append(';');
            if (Mask != null) sb.Append("m=").Append(Mask).Append(';');
            sb.Append("min=").Append(MaskMin).Append(';').Append("max=").Append(MaskMax).Append(';');
            for (int i = 0; i < 4; i++) sb.Append("c").Append(i).Append('=').Append(CustomSets[i] ?? "").Append(';');
            using (SHA256 sha = SHA256.Create())
            {
                byte[] d = sha.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));
                StringBuilder hx = new StringBuilder(64);
                foreach (byte b in d) hx.Append(b.ToString("x2"));
                return hx.ToString();
            }
        }
    }

    public sealed class CrackResult
    {
        public bool Found;
        public string Password;
        public string Error;
        public string Warning;
        public bool Cancelled;
        public bool MaxedOut;
        public long Tried;
        public double ElapsedSec;
        public string ResultFile;
    }

    public sealed class EngineStats
    {
        private long _tried;
        private long _baseTried;                 // candidates already tried before a resume
        private long _total = -1;
        private volatile string _phase = "准备中";
        private volatile string _current = "";
        private volatile string _currentTag = "";
        private volatile string _position = "";
        private volatile bool _done;

        public long Tried { get { return Interlocked.Read(ref _tried); } }
        public void AddTried() { Interlocked.Increment(ref _tried); }
        public bool Reached(long n) { return Interlocked.Read(ref _tried) >= n; }
        public long BaseTried { get { return Interlocked.Read(ref _baseTried); } set { Interlocked.Exchange(ref _baseTried, value); } }
        public long Total { get { return Interlocked.Read(ref _total); } set { Interlocked.Exchange(ref _total, value); } }
        public string Phase { get { return _phase; } set { _phase = value; } }
        public string Current { get { return _current; } set { _current = value ?? ""; } }
        public string CurrentTag { get { return _currentTag; } set { _currentTag = value ?? ""; } }
        public string Position { get { return _position; } set { _position = value ?? ""; } }
        public bool Done { get { return _done; } set { _done = value; } }
    }

    // ------------------------------------------------------------------
    public sealed class CrackEngine
    {
        private readonly CrackConfig _cfg;
        public EngineStats Stats = new EngineStats();
        public string LogNote = "";

        public CrackEngine(CrackConfig cfg) { _cfg = cfg; }

        public static string SessionPath
        {
            get
            {
                // every crack-time artifact stays next to the executable -
                // the user explicitly does not want files on C:
                return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "session.json");
            }
        }

        public CrackResult Run(CancellationToken external)
        {
            CrackResult res = new CrackResult();
            Stopwatch sw = Stopwatch.StartNew();
            string archive = Path.GetFullPath(_cfg.ArchivePath);
            if (!File.Exists(archive)) { res.Error = "压缩包文件不存在: " + archive; return res; }

            ArchiveInfo info;
            try { info = ArchiveParser.Parse(archive); }
            catch (Exception ex) { res.Error = "解析压缩包失败: " + ex.Message; return res; }

            Verifier verifier;
            try { verifier = VerifierFactory.Create(info, _cfg.UserTool, archive); }
            catch (ApplicationException ex) { res.Error = ex.Message; return res; }

            // pre-flight: an unencrypted archive must error out, not "crack"
            if (info.Kind == ArchiveKind.Rar5 && info.Rar5 == null)
            { res.Error = "该压缩包没有密码保护，无需破解。"; return res; }
            if (info.Kind == ArchiveKind.Zip && info.Zip == null && info.DetectNote.IndexOf("no encrypted entry", StringComparison.Ordinal) >= 0)
            { res.Error = "该压缩包没有密码保护（或未检测到加密条目）。"; return res; }
            if (!verifier.Native && !ProbeEncrypted(archive, _cfg.UserTool))
            { res.Error = "该压缩包没有密码保护，无需破解。"; return res; }

            ZipVerifier.ResetCache(archive);
            SpawnVerifier.ArchivePath = archive;
            EngineParamsHash.Value = _cfg.ParamsHash();
            EngineParamsHash.DictFp = DictFingerprint(_cfg);
            ICandidateSource source;
            try { source = BuildSource(); }
            catch (Exception ex) { res.Error = "构造攻击计划失败: " + ex.Message; return res; }

            SourcePosition pos = new SourcePosition();
            SessionState sess = null;
            if (_cfg.CheckpointEnabled)
            {
                if (_cfg.ResumeRequested) sess = SessionState.Load(SessionPath);
                else DeleteSession();
                if (sess != null && (!sess.Matches(archive, _cfg.ParamsHash(), EngineParamsHash.DictFp)))
                {
                    sess = null;
                    LogNote = "已忽略不匹配的历史会话";
                }
                if (sess != null)
                {
                    pos.FileIdx = sess.FileIdx; pos.LineIdx = sess.LineIdx;
                    pos.Seg = sess.Seg; pos.Counter = sess.Counter;
                    pos.IdxA = sess.IdxA; pos.IdxB = sess.IdxB;
                    Stats.Phase = "续跑: " + sess.SaveTimeText;
                }
            }

            long? total = source.Total;
            if (total.HasValue) Stats.Total = total.Value;
            int threads = _cfg.Threads;
            if (threads <= 0)
            {
                int cores = Environment.ProcessorCount;
                threads = Math.Max(1, Math.Min(32, cores - 2));
            }
            long sessionTried = 0;
            if (sess != null)
            {
                // the producer runs ahead of the verifiers: candidates still
                // sitting in the queue or mid-Verify when the run stopped are
                // not covered by the saved position. Rewind a safety margin -
                // re-trying a handful of candidates is harmless, skipping
                // them would miss passwords.
                long margin = threads * 8 + threads + 16;
                pos.LineIdx = pos.LineIdx > margin ? pos.LineIdx - margin : 0;
                pos.Counter = pos.Counter > (ulong)margin ? pos.Counter - (ulong)margin : 0;
                pos.IdxB = pos.IdxB > margin ? pos.IdxB - margin : 0;
                pos.IdxA = pos.IdxA > margin ? pos.IdxA - margin : 0;
                if (pos.IdxA < sess.IdxA) pos.IdxB = 0;   // earlier A line: B restarts
                sessionTried = sess.TriedAll;
            }
            Stats.BaseTried = sessionTried;
            Stats.Phase = Stats.Phase.StartsWith("续跑", StringComparison.Ordinal)
                ? Stats.Phase : verifier.Describe();

            BlockingCollection<Candidate> queue = new BlockingCollection<Candidate>(threads * 8);
            CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(external);
            CancellationToken ct = cts.Token;

            SourcePosition livePos = pos; // producer mutates it; checkpoint thread snapshots

            Thread producer = new Thread(delegate()
            {
                try
                {
                    foreach (Candidate cand in source.Enumerate(pos, ct))
                    {
                        queue.Add(cand, ct);
                    }
                }
                catch (OperationCanceledException) { }
                catch (Exception ex) { ProducerError = ex.Message; }
                finally { queue.CompleteAdding(); }
            }) { IsBackground = true, Name = "dictcrack-producer" };

            string hitPassword = null;
            object hitLock = new object();
            long maxTries = _cfg.MaxTries;

            Thread[] workers = new Thread[threads];
            for (int w = 0; w < threads; w++)
            {
                workers[w] = new Thread(delegate()
                {
                    try
                    {
                        foreach (Candidate cand in queue.GetConsumingEnumerable(ct))
                        {
                            if (ct.IsCancellationRequested && hitPassword != null) return;
                            Stats.Current = cand.Pw;
                            Stats.CurrentTag = cand.Tag;
                            Stats.AddTried();
                            bool ok;
                            try { ok = verifier.Verify(cand.Pw); }
                            catch (Exception ex) { WorkerError = ex.Message; ok = false; }
                            if (ok)
                            {
                                lock (hitLock)
                                {
                                    if (hitPassword == null) hitPassword = cand.Pw;
                                }
                                cts.Cancel();
                                return;
                            }
                            if (maxTries > 0 && Stats.Reached(maxTries))
                            {
                                MaxedOut = true;
                                cts.Cancel();
                                return;
                            }
                        }
                    }
                    catch (OperationCanceledException) { }
                }) { IsBackground = true, Name = "dictcrack-worker" };
            }

            Timer checkpointTimer = null;
            if (_cfg.CheckpointEnabled)
            {
                checkpointTimer = new Timer(delegate(object state)
                {
                    if (!Stats.Done && hitPassword == null)
                        if (!SaveSession(archive, source, livePos, Stats.BaseTried + Stats.Tried))
                            _sessionSaveFailed = true;
                }, null, 3000, 3000);
            }

            producer.Start();
            for (int w = 0; w < threads; w++) workers[w].Start();
            try { foreach (Thread t in workers) t.Join(); producer.Join(); }
            catch { }
            if (checkpointTimer != null) { using (checkpointTimer) checkpointTimer.Change(Timeout.Infinite, Timeout.Infinite); }
            Stats.Done = true;
            sw.Stop();

            res.Tried = Stats.BaseTried + Stats.Tried;
            res.ElapsedSec = sw.Elapsed.TotalSeconds;
            res.Cancelled = external.IsCancellationRequested && hitPassword == null;
            res.MaxedOut = MaxedOut;

            if (hitPassword != null)
            {
                res.Found = true;
                res.Password = hitPassword;
                res.ResultFile = WriteResultFile(archive, hitPassword, _cfg.OutFile);
                DeleteSession();
            }
            else if (res.Cancelled || MaxedOut)
            {
                if (_cfg.CheckpointEnabled)
                    if (!SaveSession(archive, source, livePos, Stats.BaseTried + Stats.Tried))
                        _sessionSaveFailed = true;
                if (ProducerError != null) res.Error = "候选生成失败: " + ProducerError;
                else if (WorkerError != null) res.Error = "验证线程错误: " + WorkerError;
            }
            else
            {
                DeleteSession();
                if (ProducerError != null) res.Error = "候选生成失败: " + ProducerError;
                else if (WorkerError != null) res.Error = "验证线程错误: " + WorkerError;
            }
            if (_sessionSaveFailed && !res.Found)
                res.Warning = "会话/进度文件写入失败（exe 目录可能只读），断点续跑不可用。";
            if (source is DictionarySource) LogNote = ((DictionarySource)source).LastPlanNote;
            return res;
        }

        private bool _sessionSaveFailed;
        private volatile bool MaxedOut;        private volatile string ProducerError;
        private volatile string WorkerError;

        private ICandidateSource BuildSource()
        {
            if (_cfg.Mode == "mask")
            {
                if (string.IsNullOrEmpty(_cfg.Mask)) throw new ApplicationException("掩码为空。");
                int maxLen = _cfg.MaskMax > 0 ? _cfg.MaskMax : CountTokens(_cfg.Mask);
                return new MaskSource(_cfg.Mask, _cfg.CustomSets, _cfg.MaskMin, maxLen);
            }
            if (_cfg.Mode == "comb")
            {
                if (_cfg.DictFiles.Count < 1 || string.IsNullOrEmpty(_cfg.DictFileB))
                    throw new ApplicationException("组合模式需要两个字典文件。");
                return new CombinatorSource(_cfg.DictFiles[0], _cfg.DictFileB);
            }
            if (_cfg.DictFiles.Count == 0) throw new ApplicationException("没有指定字典文件。");
            foreach (string f in _cfg.DictFiles)
                if (f != "-" && !File.Exists(f)) throw new ApplicationException("字典文件不存在: " + f);
            return new DictionarySource(_cfg.DictFiles, _cfg.Presets, _cfg.Dedupe);
        }

        private static int CountTokens(string mask)
        {
            int n = 0; bool lit = false;
            for (int i = 0; i < mask.Length; i++)
            {
                if (mask[i] == '?' && i + 1 < mask.Length)
                {
                    char c = mask[i + 1];
                    if ("lud?sahH1234".IndexOf(c) >= 0) { n++; i++; lit = false; continue; }
                    if (c == '?') { i++; lit = true; continue; }
                }
                if (!lit) { n++; lit = true; }
            }
            return Math.Max(1, n);
        }

        private static bool ProbeEncrypted(string archive, string userTool)
        {
            string tool = userTool;
            if (string.IsNullOrEmpty(tool) || !File.Exists(tool)) tool = ToolLocator.FindExtractor();
            if (tool == null) throw new ApplicationException("未找到可用的解压工具（7z.exe / rar.exe）。");
            SpawnVerifier.ArchivePath = archive;
            SpawnVerifier probe = new SpawnVerifier(tool);
            return !probe.Verify("");   // empty password: 0 = no password prompt needed
        }

        private static string WriteResultFile(string archive, string password, string outFile)
        {
            string defaultPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
                Path.GetFileNameWithoutExtension(archive) + "_password.txt");
            if (!string.IsNullOrEmpty(outFile))
            {
                try { WriteResultText(outFile, password); return outFile; }
                catch { }   // unwritable -- fall through to the default location
            }
            try { WriteResultText(defaultPath, password); return defaultPath; }
            catch { return null; }
        }

        private static void WriteResultText(string path, string password)
        {
            // explicit GBK (936), never Encoding.Default: the system
            // ANSI codepage on a non-Chinese locale silently mangles
            // Chinese passwords into '?' (roundtrip check cannot catch
            // that loss - a '?' stays '?' through encode/decode)
            Encoding enc = Encoding.GetEncoding(936);
            byte[] text = enc.GetBytes(password);
            byte[] roundtrip = enc.GetBytes(enc.GetString(text));
            bool lossless = roundtrip.Length == text.Length;
            for (int i = 0; i < text.Length && lossless; i++) if (roundtrip[i] != text[i]) lossless = false;
            if (!lossless) enc = new UTF8Encoding(true);
            File.WriteAllText(path, password + "\r\n", enc);
        }

        // content fingerprint of every dictionary feeding the run: a resume
        // position (line/counter indices) into an edited dictionary is
        // meaningless, so a changed size/mtime invalidates the session
        public static string DictFingerprint(CrackConfig cfg)
        {
            if (cfg.Mode == "mask") return "";
            try
            {
                List<string> files = new List<string>();
                if (cfg.Mode == "comb")
                {
                    if (cfg.DictFiles.Count > 0) files.Add(cfg.DictFiles[0]);
                    if (cfg.DictFileB != null) files.Add(cfg.DictFileB);
                }
                else files.AddRange(cfg.DictFiles);
                StringBuilder sb = new StringBuilder();
                foreach (string f in files)
                {
                    if (f == "-") { sb.Append("stdin;"); continue; }
                    FileInfo fi = new FileInfo(f);
                    if (!fi.Exists) return null;
                    sb.Append(fi.Length).Append(':').Append(fi.LastWriteTimeUtc.Ticks).Append(';');
                }
                return sb.ToString();
            }
            catch { return null; }
        }

        private static bool SaveSession(string archive, ICandidateSource source, SourcePosition pos, long tried)
        {
            SessionState s = new SessionState();
            s.Archive = archive; s.Params = EngineParamsHash.Value; s.DictFp = EngineParamsHash.DictFp;
            s.TriedAll = tried;
            s.FileIdx = pos.FileIdx; s.LineIdx = pos.LineIdx;
            s.Seg = pos.Seg; s.Counter = pos.Counter;
            s.IdxA = pos.IdxA; s.IdxB = pos.IdxB;
            s.SaveTimeText = DateTime.Now.ToString("HH:mm:ss");
            return s.Save(SessionPath);
        }

        // set by Run before any checkpoint can fire
        internal static class EngineParamsHash
        {
            public static string Value;
            public static string DictFp;
        }

        private static void DeleteSession()
        {
            try { File.Delete(SessionPath); } catch { }
        }
    }

    // ------------------------------------------------------------------
    public sealed class SessionState
    {
        public string Archive;
        public string Params;
        public string DictFp;       // dictionary size/mtime fingerprint; edited dicts invalidate the session
        public long TriedAll;
        public int FileIdx;
        public long LineIdx;
        public int Seg;
        public ulong Counter;
        public long IdxA;
        public long IdxB;
        public string SaveTimeText;

        public bool Matches(string archive, string paramsHash, string dictFp)
        {
            if (!string.Equals(Archive, archive, StringComparison.OrdinalIgnoreCase) || Params != paramsHash) return false;
            if (dictFp == null) return true;        // fingerprint unavailable: keep the old lenient behavior
            return DictFp == dictFp;                // sessions saved before this field existed fail for dict runs (safe restart)
        }

        public bool Save(string path)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("{\n");
            AppendKv(sb, "archive", Archive); sb.Append(",\n");
            AppendKv(sb, "params", Params); sb.Append(",\n");
            AppendKv(sb, "dictfp", DictFp); sb.Append(",\n");
            sb.Append("  \"tried\": ").Append(TriedAll).Append(",\n");
            sb.Append("  \"fileIdx\": ").Append(FileIdx).Append(",\n");
            sb.Append("  \"lineIdx\": ").Append(LineIdx).Append(",\n");
            sb.Append("  \"seg\": ").Append(Seg).Append(",\n");
            sb.Append("  \"counter\": ").Append(Counter).Append(",\n");
            sb.Append("  \"idxA\": ").Append(IdxA).Append(",\n");
            sb.Append("  \"idxB\": ").Append(IdxB).Append(",\n");
            AppendKv(sb, "saveTime", SaveTimeText); sb.Append("\n");
            sb.Append("}\n");
            string tmp = path + ".tmp";
            try
            {
                File.WriteAllText(tmp, sb.ToString(), new UTF8Encoding(false));
                try { File.Replace(tmp, path, null); }
                catch { File.Copy(tmp, path, true); try { File.Delete(tmp); } catch { } }
                return true;
            }
            catch { return false; }
        }

        private static void AppendKv(StringBuilder sb, string key, string val)
        {
            sb.Append("  \"").Append(key).Append("\": \"");
            foreach (char c in val ?? "")
            {
                if (c == '\\' || c == '"') { sb.Append('\\').Append(c); }
                else if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                else sb.Append(c);
            }
            sb.Append("\"");
        }

        public static SessionState Load(string path)
        {
            try
            {
                Dictionary<string, string> kv = new Dictionary<string, string>();
                string text = File.ReadAllText(path, new UTF8Encoding(false));
                int i = 0;
                while ((i = text.IndexOf('"', i)) >= 0)
                {
                    int keyStart = ++i;
                    while (i < text.Length && text[i] != '"') { if (text[i] == '\\') i++; i++; }
                    if (i >= text.Length) break;
                    string key = Unescape(text.Substring(keyStart, i - keyStart));
                    i++;
                    int colon = text.IndexOf(':', i);
                    if (colon < 0) break;
                    i = colon + 1;
                    while (i < text.Length && (text[i] == ' ' || text[i] == '\t')) i++;
                    if (i >= text.Length) break;
                    string val;
                    if (text[i] == '"')
                    {
                        int valStart = ++i;
                        while (i < text.Length && text[i] != '"') { if (text[i] == '\\') i++; i++; }
                        if (i > text.Length) break;
                        val = Unescape(text.Substring(valStart, Math.Min(i, text.Length) - valStart));
                        i++;
                    }
                    else
                    {
                        int valStart = i;
                        while (i < text.Length && text[i] != ',' && text[i] != '\n' && text[i] != '}') i++;
                        val = text.Substring(valStart, i - valStart).Trim();
                    }
                    kv[key] = val;
                }
                SessionState s = new SessionState();
                string tmp;
                kv.TryGetValue("archive", out s.Archive);
                kv.TryGetValue("params", out s.Params);
                kv.TryGetValue("dictfp", out s.DictFp);
                kv.TryGetValue("saveTime", out s.SaveTimeText);
                s.TriedAll = kv.TryGetValue("tried", out tmp) ? ParseLong(tmp) : 0;
                s.FileIdx = kv.TryGetValue("fileIdx", out tmp) ? (int)ParseLong(tmp) : 0;
                s.LineIdx = kv.TryGetValue("lineIdx", out tmp) ? ParseLong(tmp) : 0;
                s.Seg = kv.TryGetValue("seg", out tmp) ? (int)ParseLong(tmp) : 0;
                s.Counter = kv.TryGetValue("counter", out tmp) ? ParseUlong(tmp) : 0;
                s.IdxA = kv.TryGetValue("idxA", out tmp) ? ParseLong(tmp) : 0;
                s.IdxB = kv.TryGetValue("idxB", out tmp) ? ParseLong(tmp) : 0;
                if (s.Archive == null) return null;
                return s;
            }
            catch { return null; }
        }

        private static long ParseLong(string s) { long v; return long.TryParse(s, out v) ? v : 0; }
        private static ulong ParseUlong(string s) { ulong v; return ulong.TryParse(s, out v) ? v : 0; }

        private static string Unescape(string s)
        {
            if (s.IndexOf('\\') < 0) return s;
            StringBuilder sb = new StringBuilder(s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                if (s[i] == '\\' && i + 1 < s.Length)
                {
                    char n = s[++i];
                    if (n == 'u' && i + 4 < s.Length)
                    {
                        int code;
                        if (int.TryParse(s.Substring(i + 1, 4), System.Globalization.NumberStyles.HexNumber, null, out code))
                        { sb.Append((char)code); i += 4; continue; }
                    }
                    sb.Append(n);
                }
                else sb.Append(s[i]);
            }
            return sb.ToString();
        }
    }

    // ------------------------------------------------------------------
    public static class Benchmark
    {
        public static double Measure(Verifier verifier, int threads, int seconds)
        {
            if (threads <= 0)
            {
                int cores = Environment.ProcessorCount;
                threads = Math.Max(1, Math.Min(32, cores - 2));
            }
            long total = 0;
            Stopwatch sw = Stopwatch.StartNew();
            Thread[] ts = new Thread[threads];
            for (int t = 0; t < threads; t++)
            {
                ts[t] = new Thread(delegate()
                {
                    long mine = 0;
                    int seed = t * 7919 + 13;
                    Random rnd = new Random(seed);
                    byte[] buf = new byte[8];
                    while (sw.Elapsed.TotalSeconds < seconds)
                    {
                        rnd.NextBytes(buf);
                        string pwd = Convert.ToBase64String(buf);
                        try { verifier.Verify(pwd); }
                        catch { }
                        mine++;
                    }
                    Interlocked.Add(ref total, mine);
                }) { IsBackground = true };
                ts[t].Start();
            }
            foreach (Thread t in ts) t.Join();
            sw.Stop();
            double rate = total / sw.Elapsed.TotalSeconds;
            return rate;
        }
    }
}
