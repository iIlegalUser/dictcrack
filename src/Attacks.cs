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
    public static class DictEncoding
    {
        public static List<Encoding> Plan(string path, out string planNote)
        {
            List<Encoding> encs = new List<Encoding>();
            using (FileStream fs = File.OpenRead(path))
            {
                int b0 = fs.ReadByte(), b1 = fs.ReadByte(), b2 = fs.ReadByte();
                if (b0 == 0xEF && b1 == 0xBB && b2 == 0xBF)
                {
                    encs.Add(new UTF8Encoding(false, true));
                    planNote = "UTF-8 (BOM)";
                    return encs;
                }
                if (b0 == 0xFF && b1 == 0xFE)
                {
                    encs.Add(new UnicodeEncoding(false, true, true));
                    planNote = "UTF-16LE (BOM)";
                    return encs;
                }
                if (b0 == 0xFE && b1 == 0xFF)
                {
                    encs.Add(new UnicodeEncoding(true, true, true));
                    planNote = "UTF-16BE (BOM)";
                    return encs;
                }
            }
            // no BOM: strict-decode the first 256 KB as UTF-8; trim trailing
            // high bytes so a cut inside a multibyte sequence cannot fake an
            // illegal one. Valid UTF-8 keeps both passes, GBK text runs
            // ANSI(GBK) alone - a probe can only save time, never skip a hit.
            List<Encoding> both = new List<Encoding>();
            both.Add(new UTF8Encoding(false, true));
            both.Add(GetAnsi());
            try
            {
                using (FileStream fs = File.OpenRead(path))
                {
                    long len = fs.Length;
                    int probeLen = (int)Math.Min(262144L, len);
                    byte[] buf = new byte[probeLen];
                    ArchiveParser.ReadFull(fs, buf);
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
                    encs.Add(both[0]); encs.Add(both[1]);
                    planNote = "UTF-8 + ANSI(GBK)";
                    return encs;
                }
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
    // mutation presets - each independently emits extra candidates after
    // the base word (no cross-products; documented in README)
    public static class Rules
    {
        public static readonly string[] PresetNames = new string[] { "years", "digits", "leet", "rev", "cap", "double" };
        public static readonly string[] PresetDescZh = new string[] {
            "年份后缀 1980-2026", "数字后缀 0-9/00-99", "leet 变形(a@e3o0i1s5g9)",
            "倒序", "首字母大写", "双写(abcabc)" };

        public static IEnumerable<string> Apply(string preset, string w)
        {
            if (string.IsNullOrEmpty(w)) yield break;
            switch (preset)
            {
                case "years":
                    for (int y = 1980; y <= 2026; y++) yield return w + y.ToString();
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
        private long _countedTotal = -1;
        public string LastPlanNote = "";

        public DictionarySource(List<string> files, List<string> presets)
        {
            _files = files; _presets = presets;
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
                sb.Append(Path.GetFileName(_files[i]));
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

        public IEnumerable<Candidate> Enumerate(SourcePosition pos, System.Threading.CancellationToken ct)
        {
            for (int fi = 0; fi < _files.Count; fi++)
            {
                if (fi < pos.FileIdx) continue;
                pos.FileIdx = fi;
                string path = _files[fi];
                if (!File.Exists(path)) continue;
                string note;
                List<Encoding> encs = DictEncoding.Plan(path, out note);
                LastPlanNote = note;
                bool utf16 = encs.Count == 1 && (encs[0].CodePage == 1200 || encs[0].CodePage == 1201);

                if (utf16)
                {
                    // UTF-16 bytes can contain 0x0A inside a character, so
                    // split with the framework reader and decode once
                    string tag = DictEncoding.EncLabel(encs[0]);
                    long lineIdx = 0;
                    using (StreamReader sr = new StreamReader(path, encs[0]))
                    {
                        string line;
                        while ((line = sr.ReadLine()) != null)
                        {
                            if (ct.IsCancellationRequested) yield break;
                            if (lineIdx++ < pos.LineIdx) continue;
                            pos.LineIdx = lineIdx - 1;
                            Dictionary<string, string> emitted = new Dictionary<string, string>();
                            string t = Sanitize(line);
                            if (t != null && !emitted.ContainsKey(t))
                            {
                                emitted[t] = tag;
                                yield return new Candidate(t, tag);
                            }
                        }
                    }
                }
                else
                {
                    // raw byte line splitting is safe for UTF-8/GBK: the
                    // byte 0x0A can never appear inside a multibyte char.
                    // Decode each line under every planned encoding (the
                    // encoding sweep), skipping duplicates within the line.
                    long lineIdx = 0;
                    using (FileStream fs = File.OpenRead(path))
                    {
                        byte[] buf = new byte[1 << 20];
                        List<ArraySegment<byte>> parts = new List<ArraySegment<byte>>(4096);
                        int fill = 0;
                        while (true)
                        {
                            if (ct.IsCancellationRequested) yield break;
                            int n = fs.Read(buf, fill, buf.Length - fill);
                            bool eof = n == 0;
                            int end = fill + n;
                            parts.Clear();
                            int start = 0;
                            for (int i = 0; i < end; i++)
                            {
                                if (buf[i] == 0x0A)
                                {
                                    int len = i - start;
                                    if (len > 0 && buf[start + len - 1] == 0x0D) len--;
                                    parts.Add(new ArraySegment<byte>(buf, start, len));
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
                            // emit complete lines
                            foreach (ArraySegment<byte> seg in parts)
                            {
                                if (lineIdx++ < pos.LineIdx) continue;
                                pos.LineIdx = lineIdx - 1;
                                Dictionary<string, string> emitted = new Dictionary<string, string>();
                                foreach (Candidate cand in DecodeAndMutate(buf, seg, encs, emitted))
                                    yield return cand;
                            }
                            if (eof)
                            {
                                int len = keep;
                                if (len > 0 && buf[start + len - 1] == 0x0D) len--;
                                if (len > 0)
                                {
                                    if (lineIdx++ < pos.LineIdx) { }
                                    else
                                    {
                                        pos.LineIdx = lineIdx - 1;
                                        Dictionary<string, string> emitted = new Dictionary<string, string>();
                                        ArraySegment<byte> seg = new ArraySegment<byte>(buf, start, len);
                                        foreach (Candidate cand in DecodeAndMutate(buf, seg, encs, emitted))
                                            yield return cand;
                                    }
                                }
                                yield break;
                            }
                            // move the partial line to the front and refill
                            Array.Copy(buf, start, buf, 0, keep);
                            fill = keep;
                        }
                    }
                }
                pos.LineIdx = 0;
            }
        }

        private IEnumerable<Candidate> DecodeAndMutate(byte[] buf, ArraySegment<byte> seg, List<Encoding> encs, Dictionary<string, string> emitted)
        {
            for (int i = 0; i < encs.Count; i++)
            {
                string s;
                try { s = encs[i].GetString(buf, seg.Offset, seg.Count); }
                catch { s = null; }
                if (s == null) continue;
                string t = Sanitize(s);
                if (t != null && !emitted.ContainsKey(t))
                {
                    string tag = DictEncoding.EncLabel(encs[i]);
                    emitted[t] = tag;
                    yield return new Candidate(t, tag);
                }
            }
            // mutations keep the tag of the base word they mutate
            List<KeyValuePair<string, string>> bases = new List<KeyValuePair<string, string>>(emitted);
            foreach (KeyValuePair<string, string> kv in bases)
                foreach (string preset in _presets)
                    foreach (string m in Rules.Apply(preset, kv.Key))
                        if (!emitted.ContainsKey(m))
                        {
                            emitted[m] = kv.Value;
                            yield return new Candidate(m, kv.Value);
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

        private List<string> LoadB()
        {
            if (_bLines != null) return _bLines;
            string note;
            List<Encoding> encs = DictEncoding.Plan(_fileB, out note);
            Encoding e = encs[encs.Count - 1]; // encoding sweep on B: use ANSI fallback for combinator
            List<string> lines = new List<string>(1 << 16);
            foreach (string l in File.ReadLines(_fileB, e))
            {
                string t = Sanitize(l);
                if (t != null) lines.Add(t);
            }
            _bLines = lines;
            return lines;
        }

        public long? Total
        {
            get
            {
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
            string note;
            List<Encoding> encs = DictEncoding.Plan(_fileA, out note);
            Encoding e = encs[encs.Count - 1];
            long idxA = 0, idxB = 0;
            if (pos.IdxA > 0) { idxA = pos.IdxA; }
            if (pos.IdxA == idxA) idxB = pos.IdxB;
            foreach (string la in File.ReadLines(_fileA, e))
            {
                if (ct.IsCancellationRequested) yield break;
                string ta = Sanitize(la);
                if (ta == null) continue;
                if (idxA < pos.IdxA) { idxA++; continue; }
                pos.IdxA = idxA;
                for (; idxB < b.Count; idxB++)
                {
                    if (ct.IsCancellationRequested) yield break;
                    pos.IdxB = idxB;
                    yield return new Candidate(ta + b[(int)idxB], "");
                }
                idxB = 0;
                pos.IdxB = 0;
                idxA++;
            }
        }

        private static string Sanitize(string s)
        {
            if (string.IsNullOrEmpty(s) || s[0] == ';') return null;
            return s;
        }
    }
}
