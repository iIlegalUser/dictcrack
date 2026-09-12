// Attacks.cs -- candidate generation: dictionary (multi-encoding sweep +
// mutation presets), mask/brute force, combinator. Each source exposes a
// serializable position so the engine can checkpoint and resume.
// ASCII only.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DictCrack
{
    // ------------------------------------------------------------------
    public sealed class SourcePosition
    {
        public int FileIdx;
        public long LineIdx;
        public int Seg;          // mask: current expanded length
        public ulong Counter;    // mask: odometer
        public long IdxA;        // combinator
        public long IdxB;
    }

    // ------------------------------------------------------------------
    // a candidate plus a human-readable tag of where it came from (the
    // dictionary encoding of the sweep, empty for mask/combinator) so the
    // UI can explain "mojibake-looking" cross-encoding candidates
    public sealed class Candidate
    {
        public string Pw;
        public string Tag;
        public Candidate(string pw, string tag) { Pw = pw; Tag = tag ?? ""; }
    }

    public interface ICandidateSource
    {
        IEnumerable<Candidate> Enumerate(SourcePosition pos, System.Threading.CancellationToken ct);
        long? Total { get; }
        string Describe();
        string PositionText(SourcePosition pos);
    }

    // ------------------------------------------------------------------
    // raw byte line splitter shared by the dictionary and combinator
    // sources: 0x0A can never appear inside a UTF-8/GBK multibyte char, so
    // byte-level splitting is safe for the sweep encodings (UTF-16 uses
    // the framework reader instead). Segments are valid only until the
    // next MoveNext - the caller decodes before asking for more.
    public struct RawLine
    {
        public byte[] Buf;
        public int Offset;
        public int Count;
        public long Index;
    }

    public static class RawLines
    {
        public static IEnumerable<RawLine> Enumerate(Stream fs, long startOffset, System.Threading.CancellationToken ct)
        {
            if (startOffset > 0) fs.Seek(startOffset, SeekOrigin.Begin);
            byte[] buf = new byte[1 << 20];
            int fill = 0;
            long idx = 0;
            while (true)
            {
                if (ct.IsCancellationRequested) yield break;
                int n = fs.Read(buf, fill, buf.Length - fill);
                bool eof = n == 0;
                int end = fill + n;
                int start = 0;
                for (int i = 0; i < end; i++)
                {
                    if (buf[i] == 0x0A)
                    {
                        int len = i - start;
                        if (len > 0 && buf[start + len - 1] == 0x0D) len--;
                        yield return new RawLine { Buf = buf, Offset = start, Count = len, Index = idx++ };
                        start = i + 1;
                    }
                }
                int keep = end - start;
                if (!eof && keep == end && end == buf.Length)
                {
                    // single line longer than the buffer: grow
                    byte[] nb = new byte[buf.Length * 2];
                    Array.Copy(buf, nb, end);
                    buf = nb;
                    fill = end;
                    continue;
                }
                if (eof)
                {
                    int len = keep;
                    if (len > 0 && buf[start + len - 1] == 0x0D) len--;
                    if (len > 0) yield return new RawLine { Buf = buf, Offset = start, Count = len, Index = idx++ };
                    yield break;
                }
                // move the partial line to the front and refill
                Array.Copy(buf, start, buf, 0, keep);
                fill = keep;
            }
        }
    }

    // ------------------------------------------------------------------
    public static class DictEncoding
    {
        // path convenience wrapper (the stream position is irrelevant here)
        public static List<Encoding> Plan(string path, out string planNote)
        {
            long skip;
            using (FileStream fs = File.OpenRead(path))
            {
                return Plan(fs, out planNote, out skip);
            }
        }

        // Plans the encoding sweep for a stream (position is left where it
        // was). bomSkip tells the raw byte splitter how many bytes of a
        // UTF-8 BOM to skip so the first line does not carry a U+FEFF;
        // UTF-16 BOMs are consumed by StreamReader itself.
        public static List<Encoding> Plan(Stream fs, out string planNote, out long bomSkip)
        {
            bomSkip = 0;
            long pos0 = fs.Position;
            List<Encoding> encs = new List<Encoding>();
            int b0 = fs.ReadByte(), b1 = fs.ReadByte(), b2 = fs.ReadByte();
            if (b0 == 0xEF && b1 == 0xBB && b2 == 0xBF)
            {
                encs.Add(new UTF8Encoding(false, true));
                planNote = "UTF-8 (BOM)";
                bomSkip = 3;
                fs.Position = pos0;
                return encs;
            }
            if (b0 == 0xFF && b1 == 0xFE)
            {
                encs.Add(new UnicodeEncoding(false, true, true));
                planNote = "UTF-16LE (BOM)";
                fs.Position = pos0;
                return encs;
            }
            if (b0 == 0xFE && b1 == 0xFF)
            {
                encs.Add(new UnicodeEncoding(true, true, true));
                planNote = "UTF-16BE (BOM)";
                fs.Position = pos0;
                return encs;
            }
            fs.Position = pos0;
            // no BOM: strict-decode the first 256 KB as UTF-8; trim trailing
            // high bytes so a cut inside a multibyte sequence cannot fake an
            // illegal one. Valid UTF-8 keeps both passes, GBK text runs
            // ANSI(GBK) alone - a probe can only save time, never skip a hit.
            try
            {
                long len = fs.Length - pos0;
                int probeLen = (int)Math.Min(262144L, len);
                byte[] buf = new byte[probeLen];
                ArchiveParser.ReadFull(fs, buf);
                fs.Position = pos0;   // the caller keeps reading from the start
                if (probeLen < len)
                {
                    int valid = probeLen;
                    while (valid > 0 && buf[valid - 1] >= 0x80) valid--;
                    byte[] buf2 = new byte[valid];
                    Array.Copy(buf, buf2, valid);
                    buf = buf2;
                }
                Encoding strict = new UTF8Encoding(false, true);
                strict.GetString(buf);
                encs.Add(strict);
                encs.Add(GetAnsi());
                planNote = "UTF-8 + ANSI(GBK)";
                return encs;
            }
            catch { }
            encs.Add(GetAnsi());
            planNote = "ANSI(GBK)";
            return encs;
        }

        public static Encoding GetAnsi()
        {
            try { return Encoding.GetEncoding(936); }
            catch { return Encoding.Default; }
        }

        public static string EncLabel(Encoding e)
        {
            if (e is UTF8Encoding) return "UTF-8";
            if (e.CodePage == 1200) return "UTF-16LE";
            if (e.CodePage == 1201) return "UTF-16BE";
            if (e.CodePage == 936) return "ANSI(GBK)";
            return e.WebName;
        }

        // BOM-annotated encoding used when rewriting the dictionary
        public static Encoding SaveEncoding(Encoding e)
        {
            if (e is UTF8Encoding) return new UTF8Encoding(true);   // keep BOM
            if (e.CodePage == 1200) return new UnicodeEncoding(false, true);
            if (e.CodePage == 1201) return new UnicodeEncoding(true, true);
            return Encoding.GetEncoding(936);
        }
    }

    // ------------------------------------------------------------------
    // mutation presets - chained: with several presets selected each one
    // also mutates the outputs of the presets before it (word -> word+year
    // -> word+year+digits), which covers the common "word+year+number"
    // password shapes; per-line dedup and a fan-out cap keep it bounded
    public static class Rules
    {
        public static readonly string[] PresetNames = new string[] { "years", "digits", "leet", "rev", "cap", "double" };
        public static readonly string[] PresetDescZh = new string[] {
            "年份后缀 1980-今年+1", "数字后缀 0-9/00-99", "leet 变形(a@e3o0i1s5g9)",
            "倒序", "首字母大写", "双写(abcabc)" };

        public static IEnumerable<string> Apply(string preset, string w)
        {
            if (string.IsNullOrEmpty(w)) yield break;
            switch (preset)
            {
                case "years":
                    int yMax = DateTime.Now.Year + 1;
                    for (int y = 1980; y <= yMax; y++) yield return w + y.ToString();
                    break;
                case "digits":
                    for (int d = 0; d <= 9; d++) yield return w + (char)('0' + d);
                    for (int d = 0; d <= 99; d++) yield return w + d.ToString("00");
                    break;
                case "leet":
                    {
                        string t = w.Replace('a', '@').Replace('e', '3').Replace('o', '0')
                                    .Replace('i', '1').Replace('s', '5').Replace('g', '9').Replace('t', '7');
                        if (t != w) yield return t;
                        break;
                    }
                case "rev":
                    {
                        char[] a = w.ToCharArray(); Array.Reverse(a);
                        string t = new string(a);
                        if (t != w) yield return t;
                        break;
                    }
                case "cap":
                    {
                        string t = char.ToUpper(w[0]) + w.Substring(1);
                        if (t != w) yield return t;
                        break;
                    }
                case "double":
                    yield return w + w;
                    break;
            }
        }
    }

    // ------------------------------------------------------------------
    public sealed class DictionarySource : ICandidateSource
    {
        private readonly List<string> _files;
        private readonly List<string> _presets;
        private readonly HashSet<string> _global;   // cross-line dedupe (--dedupe); null otherwise
        private long _countedTotal = -1;
        public string LastPlanNote = "";

        // cap on chained mutation outputs per line: without it a long
        // preset stack could explode combinatorially
        private const int MutationCap = 100000;

        public DictionarySource(List<string> files, List<string> presets) : this(files, presets, false) { }

        public DictionarySource(List<string> files, List<string> presets, bool dedupe)
        {
            _files = files; _presets = presets;
            _global = dedupe ? new HashSet<string>(StringComparer.Ordinal) : null;
        }

        public long? Total
        {
            get
            {
                // with mutation presets each line fans out by a content-
                // dependent factor, so a line count would only mislead the
                // progress display - report unknown instead
                if (_presets.Count > 0) return null;
                if (_countedTotal < 0)
                {
                    long t = 0;
                    foreach (string f in _files)
                    {
                        if (f == "-") { _countedTotal = -1; return null; }  // stdin: unknown length
                        try { t += CountLines(f); } catch { }
                    }
                    _countedTotal = t;
                }
                return _countedTotal;
            }
        }

        public string Describe()
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < _files.Count; i++)
            {
                if (i > 0) sb.Append(", ");
                sb.Append(_files[i] == "-" ? "(stdin)" : Path.GetFileName(_files[i]));
            }
            if (_presets.Count > 0) sb.Append(" + ").Append(string.Join("/", _presets.ToArray()));
            return sb.ToString();
        }

        public string PositionText(SourcePosition pos)
        {
            string f = (pos.FileIdx >= 0 && pos.FileIdx < _files.Count) ? Path.GetFileName(_files[pos.FileIdx]) : "?";
            return string.Format("文件 {0}/{1} 行 {2}", pos.FileIdx + 1, _files.Count, pos.LineIdx);
        }

        private static long CountLines(string path)
        {
            long count = 0; bool inLine = false;
            using (FileStream fs = File.OpenRead(path))
            {
                byte[] buf = new byte[1 << 16];
                int n;
                while ((n = fs.Read(buf, 0, buf.Length)) > 0)
                {
                    for (int i = 0; i < n; i++)
                    {
                        if (buf[i] == 0x0A) { count++; inLine = false; }
                        else inLine = true;
                    }
                }
            }
            return count + (inLine ? 1 : 0);
        }

        private static Stream LoadStdin()
        {
            MemoryStream ms = new MemoryStream();
            using (Stream stdin = Console.OpenStandardInput())
            {
                byte[] buf = new byte[1 << 16];
                int n;
                while ((n = stdin.Read(buf, 0, buf.Length)) > 0) ms.Write(buf, 0, n);
            }
            ms.Position = 0;
            return ms;
        }

        public IEnumerable<Candidate> Enumerate(SourcePosition pos, System.Threading.CancellationToken ct)
        {
            // reused across lines (producer thread only) - allocating a
            // fresh dictionary per line showed up as GC pressure at the
            // million-candidates-per-second scale
            Dictionary<string, string> emitted = new Dictionary<string, string>(32);
            for (int fi = 0; fi < _files.Count; fi++)
            {
                if (fi < pos.FileIdx) continue;
                pos.FileIdx = fi;
                string path = _files[fi];
                Stream stream;
                List<Encoding> encs; string note; long bomSkip;
                if (path == "-")
                {
                    stream = LoadStdin();
                    encs = DictEncoding.Plan(stream, out note, out bomSkip);
                }
                else
                {
                    if (!File.Exists(path)) continue;
                    stream = File.OpenRead(path);
                    encs = DictEncoding.Plan(stream, out note, out bomSkip);
                }
                LastPlanNote = note;
                using (stream)
                {
                    bool utf16 = encs.Count == 1 && (encs[0].CodePage == 1200 || encs[0].CodePage == 1201);
                    if (utf16)
                    {
                        // UTF-16 bytes can contain 0x0A inside a character, so
                        // split with the framework reader and decode once
                        string tag = DictEncoding.EncLabel(encs[0]);
                        long lineIdx = 0;
                        using (StreamReader sr = new StreamReader(stream, encs[0]))
                        {
                            string line;
                            while ((line = sr.ReadLine()) != null)
                            {
                                if (ct.IsCancellationRequested) yield break;
                                if (lineIdx < pos.LineIdx) { lineIdx++; continue; }
                                pos.LineIdx = lineIdx;
                                lineIdx++;
                                string t = Sanitize(line);
                                if (t == null) continue;
                                if (_global != null && !_global.Add(t)) continue;
                                yield return new Candidate(t, tag);
                            }
                        }
                    }
                    else
                    {
                        foreach (RawLine rl in RawLines.Enumerate(stream, bomSkip, ct))
                        {
                            if (rl.Index < pos.LineIdx) continue;
                            pos.LineIdx = rl.Index;
                            emitted.Clear();
                            foreach (Candidate cand in DecodeAndMutate(rl.Buf, rl.Offset, rl.Count, encs, emitted))
                                yield return cand;
                        }
                    }
                }
                pos.LineIdx = 0;
            }
        }

        private IEnumerable<Candidate> DecodeAndMutate(byte[] buf, int offset, int count, List<Encoding> encs, Dictionary<string, string> emitted)
        {
            // decode the line under every planned encoding (the encoding
            // sweep), skipping duplicates within the line
            for (int i = 0; i < encs.Count; i++)
            {
                string s;
                try { s = encs[i].GetString(buf, offset, count); }
                catch { s = null; }
                if (s == null) continue;
                string t = Sanitize(s);
                if (t != null && !emitted.ContainsKey(t) && (_global == null || _global.Add(t)))
                {
                    string tag = DictEncoding.EncLabel(encs[i]);
                    emitted[t] = tag;
                    yield return new Candidate(t, tag);
                }
            }
            // chained mutations: each preset also mutates the outputs of
            // the presets before it (word -> word+year -> word+year+digits)
            if (_presets.Count > 0)
            {
                List<KeyValuePair<string, string>> frontier = new List<KeyValuePair<string, string>>(emitted);
                for (int pi = 0; pi < _presets.Count; pi++)
                {
                    if (emitted.Count >= MutationCap) yield break;
                    List<KeyValuePair<string, string>> next = new List<KeyValuePair<string, string>>();
                    foreach (KeyValuePair<string, string> kv in frontier)
                    {
                        foreach (string m in Rules.Apply(_presets[pi], kv.Key))
                        {
                            if (emitted.ContainsKey(m)) continue;
                            if (_global != null && !_global.Add(m)) continue;
                            if (emitted.Count >= MutationCap) yield break;
                            emitted[m] = kv.Value;   // mutations keep the tag of the base word
                            next.Add(new KeyValuePair<string, string>(m, kv.Value));
                            yield return new Candidate(m, kv.Value);
                        }
                    }
                    frontier = next;
                }
            }
        }

        private static string Sanitize(string s)
        {
            if (s == null || s.Length == 0) return null;
            if (s[0] == ';') return null;               // comment lines, as in the old GUI
            if (s == "\uFEFF") return null;
            return s;
        }
    }

    // ------------------------------------------------------------------
    public sealed class MaskSource : ICandidateSource
    {
        private class Token { public string Fixed; public char[] Set; }
        private readonly List<Token> _tokens = new List<Token>();
        private readonly int _minLen, _maxLen;
        private readonly ulong[] _spacePerLen = new ulong[0];
        public readonly ulong TotalSpace;

        public MaskSource(string mask, string[] customSets, int minLen, int maxLen)
        {
            ParseMask(mask, customSets);
            int full = _tokens.Count;
            if (minLen < 1) minLen = 1;
            if (maxLen < minLen) maxLen = minLen;
            if (maxLen > full) maxLen = full;
            _minLen = minLen; _maxLen = maxLen;
            _spacePerLen = new ulong[_maxLen + 1];
            for (int l = _minLen; l <= _maxLen; l++)
            {
                // only charset tokens consume counter values; fixed strings
                // render whole and count as one combination
                ulong space = 1; bool overflow = false;
                for (int t = 0; t < l; t++)
                {
                    if (_tokens[t].Set == null) continue;
                    ulong size = (ulong)_tokens[t].Set.Length;
                    if (size == 0) continue;
                    if (space > ulong.MaxValue / size) { overflow = true; break; }
                    space *= size;
                }
                _spacePerLen[l] = overflow ? ulong.MaxValue : space;
                if (overflow || TotalSpace > ulong.MaxValue - _spacePerLen[l]) TotalSpace = ulong.MaxValue;
                else TotalSpace += _spacePerLen[l];
            }
        }

        private void ParseMask(string mask, string[] customSets)
        {
            StringBuilder lit = new StringBuilder();
            for (int i = 0; i < mask.Length; i++)
            {
                char c = mask[i];
                if (c == '?' && i + 1 < mask.Length)
                {
                    char n = mask[i + 1];
                    char[] set = ResolveSet(n, customSets);
                    if (set != null)
                    {
                        if (lit.Length > 0) { _tokens.Add(new Token { Fixed = lit.ToString() }); lit.Length = 0; }
                        _tokens.Add(new Token { Set = set });
                        i++;
                        continue;
                    }
                    if (n == '?') { lit.Append('?'); i++; continue; }
                }
                lit.Append(c);
            }
            if (lit.Length > 0) _tokens.Add(new Token { Fixed = lit.ToString() });
        }

        private static char[] ResolveSet(char code, string[] customSets)
        {
            switch (code)
            {
                case 'l': return Chars("abcdefghijklmnopqrstuvwxyz");
                case 'u': return Chars("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
                case 'd': return Chars("0123456789");
                case 's': return Chars("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~");
                case 'a': return Chars("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ");
                case 'h': return Chars("0123456789abcdef");
                case 'H': return Chars("0123456789ABCDEF");
                case '1': case '2': case '3': case '4':
                    {
                        string s = customSets[code - '1'];
                        return string.IsNullOrEmpty(s) ? null : Chars(s);
                    }
                default: return null;
            }
        }

        private static char[] Chars(string s) { return s.ToCharArray(); }

        public long? Total { get { return TotalSpace >= ulong.MaxValue ? (long?)null : (long)TotalSpace; } }

        public string Describe()
        {
            return string.Format("掩码 {0} 长度 {1}-{2}", DescribeMask(), _minLen, _maxLen);
        }

        private string DescribeMask()
        {
            StringBuilder sb = new StringBuilder();
            foreach (Token t in _tokens)
            {
                if (t.Fixed != null) sb.Append(t.Fixed);
                else if (t.Set.Length == 10) sb.Append("?d");
                else if (t.Set.Length == 26) sb.Append(t.Set[0] == 'a' ? "?l" : "?u");
                else if (t.Set.Length == 16) sb.Append("?h");
                else if (t.Set.Length == 32) sb.Append("?s");
                else if (t.Set.Length == 95) sb.Append("?a");
                else sb.Append("?[" + new string(t.Set) + "]");
            }
            return sb.ToString();
        }

        public string PositionText(SourcePosition pos)
        {
            return string.Format("长度 {0} 进度 {1}", pos.Seg, pos.Counter);
        }

        public IEnumerable<Candidate> Enumerate(SourcePosition pos, System.Threading.CancellationToken ct)
        {
            // capture the saved position once: pos is mutated below and must
            // not leak into the start-offset decision of later segments
            int savedSeg = pos.Seg;
            ulong savedCounter = pos.Counter;
            for (int len = _minLen; len <= _maxLen; len++)
            {
                if (len < savedSeg) continue;
                pos.Seg = len;
                ulong space = _spacePerLen[len];
                ulong start = (len == savedSeg) ? savedCounter : 0;
                // collect charset slots within this token prefix; fixed
                // strings render whole and consume no counter digits
                List<int> slots = new List<int>();
                int charCount = 0;
                List<int> charPos = new List<int>();
                for (int t = 0; t < len; t++)
                {
                    Token tok = _tokens[t];
                    if (tok.Set != null) { slots.Add(t); charPos.Add(charCount); charCount++; }
                    else charCount += tok.Fixed.Length;
                }
                char[] buf = new char[charCount];
                int[] sizes = new int[slots.Count];
                for (int i = 0; i < slots.Count; i++) sizes[i] = _tokens[slots[i]].Set.Length;
                ulong counter = start;
                while (counter < space)
                {
                    if (ct.IsCancellationRequested) yield break;
                    ulong c = counter;
                    for (int i = slots.Count - 1; i >= 0; i--)
                    {
                        Token tok = _tokens[slots[i]];
                        buf[charPos[i]] = tok.Set[(int)(c % (ulong)sizes[i])];
                        c /= (ulong)sizes[i];
                    }
                    int at = 0;
                    for (int t = 0; t < len; t++)
                    {
                        Token tok = _tokens[t];
                        if (tok.Set == null)
                        {
                            for (int k = 0; k < tok.Fixed.Length; k++) buf[at++] = tok.Fixed[k];
                        }
                        else at++;
                    }
                    pos.Counter = counter;
                    yield return new Candidate(new string(buf), "");
                    counter++;
                }
                pos.Counter = 0;
            }
        }
    }

    // ------------------------------------------------------------------
    public sealed class CombinatorSource : ICandidateSource
    {
        private readonly string _fileA, _fileB;
        private List<string> _bLines;
        private long _countTotal = -1;

        public CombinatorSource(string fileA, string fileB) { _fileA = fileA; _fileB = fileB; }

        // B is fully loaded: every line under every planned encoding,
        // deduped globally (the same encoding sweep the dictionary source
        // uses - the old behavior read a UTF-8 B as GBK mojibake)
        private List<string> LoadB()
        {
            if (_bLines != null) return _bLines;
            List<string> lines = new List<string>(1 << 16);
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
            string note;
            List<Encoding> encs = DictEncoding.Plan(_fileB, out note);
            foreach (Encoding e in encs)
            {
                try
                {
                    foreach (string l in File.ReadLines(_fileB, e))
                    {
                        string t = Sanitize(l);
                        if (t != null && seen.Add(t)) lines.Add(t);
                    }
                }
                catch { }   // a strict encoding may reject foreign bytes; the next planned encoding still runs
            }
            _bLines = lines;
            return lines;
        }

        public long? Total
        {
            get
            {
                // approximate: A's encoding-sweep variants per raw line are
                // content-dependent, so a*x can only underestimate
                if (_countTotal < 0)
                {
                    long a = CountSafe(_fileA), b = LoadB().Count;
                    _countTotal = (a > 0 && b > 0 && a > long.MaxValue / b) ? long.MaxValue : a * b;
                }
                return _countTotal;
            }
        }

        private static long CountSafe(string path) { try { return new DictionarySource(new List<string> { path }, new List<string>()).Total ?? 0; } catch { return 0; } }

        public string Describe() { return Path.GetFileName(_fileA) + " × " + Path.GetFileName(_fileB); }

        public string PositionText(SourcePosition pos) { return string.Format("A行 {0} B行 {1}", pos.IdxA, pos.IdxB); }

        public IEnumerable<Candidate> Enumerate(SourcePosition pos, System.Threading.CancellationToken ct)
        {
            List<string> b = LoadB();
            string note; long bomSkip;
            List<Encoding> encs;
            using (Stream probe = File.OpenRead(_fileA))
            {
                encs = DictEncoding.Plan(probe, out note, out bomSkip);
            }
            long savedA = pos.IdxA, savedB = pos.IdxB;
            // savedB applies to the FIRST variant of the resume line only;
            // later variants restart from 0 (re-trying candidates is safe,
            // skipping them would miss passwords)
            bool bResumePending = true;
            Dictionary<string, string> variants = new Dictionary<string, string>(8);

            bool utf16A = encs.Count == 1 && (encs[0].CodePage == 1200 || encs[0].CodePage == 1201);
            if (utf16A)
            {
                using (StreamReader sr = new StreamReader(_fileA, encs[0]))
                {
                    string line; long idxA = 0;
                    while ((line = sr.ReadLine()) != null)
                    {
                        if (ct.IsCancellationRequested) yield break;
                        if (idxA < savedA) { idxA++; continue; }
                        pos.IdxA = idxA;
                        string ta = Sanitize(line);
                        idxA++;
                        if (ta == null) continue;
                        long startB = (bResumePending && pos.IdxA == savedA) ? savedB : 0;
                        if (pos.IdxA == savedA) bResumePending = false;
                        for (long ib = startB; ib < b.Count; ib++)
                        {
                            if (ct.IsCancellationRequested) yield break;
                            pos.IdxB = ib;
                            yield return new Candidate(ta + b[(int)ib], "");
                        }
                        pos.IdxB = 0;
                    }
                }
            }
            else
            {
                using (Stream fs = File.OpenRead(_fileA))
                {
                    foreach (RawLine rl in RawLines.Enumerate(fs, bomSkip, ct))
                    {
                        if (rl.Index < savedA) continue;
                        pos.IdxA = rl.Index;
                        // encoding sweep on A with per-line dedup
                        variants.Clear();
                        for (int e = 0; e < encs.Count; e++)
                        {
                            string s;
                            try { s = encs[e].GetString(rl.Buf, rl.Offset, rl.Count); }
                            catch { continue; }
                            string ta = Sanitize(s);
                            if (ta == null || variants.ContainsKey(ta)) continue;
                            variants[ta] = "";
                            long startB = (bResumePending && rl.Index == savedA) ? savedB : 0;
                            if (rl.Index == savedA) bResumePending = false;
                            for (long ib = startB; ib < b.Count; ib++)
                            {
                                if (ct.IsCancellationRequested) yield break;
                                pos.IdxB = ib;
                                yield return new Candidate(ta + b[(int)ib], "");
                            }
                            pos.IdxB = 0;
                        }
                    }
                }
            }
        }

        private static string Sanitize(string s)
        {
            if (string.IsNullOrEmpty(s) || s[0] == ';') return null;
            return s;
        }
    }
}
