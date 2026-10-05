// unittests.cs -- pure unit tests for DictCrack's logic, compiled into
// the same assembly as the engine sources so internal members are
// reachable (run-tests.ps1 covers the end-to-end paths with real
// archives; this file covers the parsers/generators without fixtures).
// ASCII only. Exit code = number of failed checks.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace DictCrack
{
    internal static class UnitTests
    {
        private static int _fail;

        private static void Check(string name, bool ok)
        {
            if (ok) Console.WriteLine("  PASS " + name);
            else { Console.WriteLine("  FAIL " + name); _fail++; }
        }

        private static string Hex(byte[] b)
        {
            StringBuilder sb = new StringBuilder(b.Length * 2);
            foreach (byte x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }

        private static byte[] Bytes(string s) { return Encoding.ASCII.GetBytes(s); }

        private static string TempDir()
        {
            string d = Path.Combine(Path.GetTempPath(), "dictcrack-ut-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(d);
            return d;
        }

        private static List<string> Collect(ICandidateSource src)
        {
            List<string> got = new List<string>();
            SourcePosition pos = new SourcePosition();
            foreach (Candidate c in src.Enumerate(pos, CancellationToken.None)) got.Add(c.Pw);
            return got;
        }

        private static int Main(string[] args)
        {
            TestPbkdf2();
            TestSessionRoundTrip();
            TestSessionFingerprint();
            TestRules();
            TestDictionarySource();
            TestUtf16Rules();
            TestMaskSource();
            TestRawLines();
            TestEncodingPlan();
            TestZip64();
            TestZip64ManyEntries();
            TestHashcatFormat();
            TestResultEncoding();
            TestWinArgQuote();
            TestRar5Truncation();
            TestMiniJson();
            TestRemoteQuoteArg();
            TestRemoteBuildArgs();
            Console.WriteLine(_fail == 0 ? "ALL PASS" : ("FAILURES: " + _fail));
            return _fail;
        }

        // ----------------------------------------------------------------
        private static void TestPbkdf2()
        {
            Console.WriteLine("unit: PBKDF2 known vectors (CNG path vs RFC vectors)");
            // RFC-documented PBKDF2-HMAC-SHA256/SHA1 vectors
            Check("pbkdf2-sha256 c=1",
                Hex(NativeCrypto.Pbkdf2Sha256(Bytes("password"), Bytes("salt"), 1, 32))
                == "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
            Check("pbkdf2-sha256 c=4096",
                Hex(NativeCrypto.Pbkdf2Sha256(Bytes("password"), Bytes("salt"), 4096, 32))
                == "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
            Check("pbkdf2-sha1 c=1",
                Hex(NativeCrypto.Pbkdf2Sha1(Bytes("password"), Bytes("salt"), 1, 20))
                == "0c60c80f961f0e71f3a9b524af6012062fe037a6");
            Check("pbkdf2-sha1 c=4096",
                Hex(NativeCrypto.Pbkdf2Sha1(Bytes("password"), Bytes("salt"), 4096, 20))
                == "4b007901b765489abead49d926f721d065a429c1");
        }

        private static void TestSessionRoundTrip()
        {
            Console.WriteLine("unit: session save/load round trip");
            string dir = TempDir();
            try
            {
                string path = Path.Combine(dir, "session.json");
                SessionState s = new SessionState();
                s.Archive = "D:\\test\\\u6863\u6848.rar";    // backslash + CJK
                s.Params = "ab\"cd";                          // quote escape
                s.DictFp = "123:456;";
                s.TriedAll = 12345678901L;
                s.FileIdx = 2; s.LineIdx = 34567; s.Seg = 4;
                s.Counter = 18446744073709551615UL;
                s.IdxA = 9; s.IdxB = 10;
                s.SaveTimeText = "12:00:00\nx";               // control char escape
                Check("save ok", s.Save(path));
                SessionState r = SessionState.Load(path);
                Check("load non-null", r != null);
                if (r != null)
                {
                    Check("archive", r.Archive == s.Archive);
                    Check("params", r.Params == s.Params);
                    Check("dictfp", r.DictFp == s.DictFp);
                    Check("tried", r.TriedAll == s.TriedAll);
                    Check("fields", r.FileIdx == 2 && r.LineIdx == 34567 && r.Seg == 4
                        && r.Counter == 18446744073709551615UL && r.IdxA == 9 && r.IdxB == 10);
                    Check("savetime", r.SaveTimeText == "12:00:00\nx");
                }
                File.WriteAllText(path, "this is not json {{{");
                Check("garbage -> null", SessionState.Load(path) == null);
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }

        private static void TestSessionFingerprint()
        {
            Console.WriteLine("unit: session fingerprint matching");
            string dir = TempDir();
            try
            {
                string f = Path.Combine(dir, "d.txt");
                File.WriteAllText(f, "one\n");
                CrackConfig cfg = new CrackConfig();
                cfg.Mode = "dict"; cfg.DictFiles.Add(f);
                string fp1 = CrackEngine.DictFingerprint(cfg);
                Check("fp deterministic", fp1 == CrackEngine.DictFingerprint(cfg));
                File.WriteAllText(f, "one\ntwo\nthree\n");
                Check("fp changes with content", fp1 != CrackEngine.DictFingerprint(cfg));

                SessionState old = new SessionState();
                old.Archive = "a.rar"; old.Params = "p";
                Check("old session (no fp) rejected for dict", !old.Matches("a.rar", "p", fp1));
                Check("null fp keeps lenient", old.Matches("a.rar", "p", null));
                old.DictFp = fp1;
                Check("matching fp accepted", old.Matches("a.rar", "p", fp1));

                cfg.Mode = "mask";
                Check("mask fp empty", CrackEngine.DictFingerprint(cfg) == "");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }

        private static void TestRules()
        {
            Console.WriteLine("unit: mutation rules");
            int years = 0; bool hasCurrent = false;
            int yMax = DateTime.Now.Year + 1;
            foreach (string m in Rules.Apply("years", "w"))
            {
                years++;
                if (m == "w" + yMax) hasCurrent = true;
            }
            Check("years dynamic count", years == yMax - 1980 + 1);
            Check("years includes current+1", hasCurrent);
            int digits = 0;
            foreach (string m in Rules.Apply("digits", "w")) digits++;
            Check("digits count 110", digits == 110);
            Check("empty word no output", !Rules.Apply("years", "").GetEnumerator().MoveNext());
        }

        private static void TestDictionarySource()
        {
            Console.WriteLine("unit: dictionary source");
            string dir = TempDir();
            try
            {
                // UTF-8 BOM: the first line must not carry a U+FEFF
                string bom = Path.Combine(dir, "bom.txt");
                File.WriteAllBytes(bom, new byte[] { 0xEF, 0xBB, 0xBF }
                    .Concat(Encoding.UTF8.GetBytes("alpha\r\nbeta\n")).ToArray());
                List<string> got = Collect(new DictionarySource(new List<string> { bom }, new List<string>()));
                Check("bom file line count", got.Count == 2);
                Check("bom stripped from first line", got.Count > 0 && got[0] == "alpha");

                // GBK Chinese without BOM
                string gbk = Path.Combine(dir, "gbk.txt");
                File.WriteAllBytes(gbk, Encoding.GetEncoding(936).GetBytes("\u5bc6\u7801test\n"));
                got = Collect(new DictionarySource(new List<string> { gbk }, new List<string>()));
                Check("gbk decode", got.Count == 1 && got[0] == "\u5bc6\u7801test");

                // chained mutations: years then digits -> word+year+digit
                string plain = Path.Combine(dir, "p.txt");
                File.WriteAllText(plain, "foo\n");
                List<string> presets = new List<string> { "years", "digits" };
                got = Collect(new DictionarySource(new List<string> { plain }, presets));
                Check("base word present", got.Contains("foo"));
                Check("year suffix", got.Contains("foo1999"));
                Check("chained year+digit", got.Contains("foo19990"));
                Check("no cross dup", got.IndexOf("foo") == 0);

                // --dedupe: the same file twice must not re-emit candidates
                DictionarySource single = new DictionarySource(new List<string> { plain }, new List<string>(), false);
                DictionarySource dupe = new DictionarySource(new List<string> { plain, plain }, new List<string>(), true);
                Check("dedupe collapses repeated file", Collect(dupe).Count == Collect(single).Count);

                // combinator with encoding sweep: UTF-8 A and GBK B both survive
                string utf8a = Path.Combine(dir, "a.txt");
                File.WriteAllBytes(utf8a, new byte[] { 0xEF, 0xBB, 0xBF }.Concat(Encoding.UTF8.GetBytes("x\n")).ToArray());
                string utf8b = Path.Combine(dir, "b.txt");
                File.WriteAllBytes(utf8b, new byte[] { 0xEF, 0xBB, 0xBF }.Concat(Encoding.UTF8.GetBytes("y\n")).ToArray());
                CombinatorSource comb = new CombinatorSource(utf8a, utf8b);
                got = Collect(comb);
                Check("combinator pair", got.Contains("xy"));
                Check("combinator total", comb.Total == 1);
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }

        private static void TestMaskSource()
        {
            Console.WriteLine("unit: mask source");
            // note: maxLen is the literal length bound here; the engine
            // converts -1 (= full mask) via CountTokens before constructing
            MaskSource m = new MaskSource("?d?d", new string[4], 2, 2);
            Check("mask total 100", m.Total == 100);
            SourcePosition pos = new SourcePosition();
            IEnumerator<Candidate> it = m.Enumerate(pos, CancellationToken.None).GetEnumerator();
            Check("mask first 00", it.MoveNext() && it.Current.Pw == "00");
            Check("mask second 01", it.MoveNext() && it.Current.Pw == "01");
            MaskSource m2 = new MaskSource("?d?d?d", new string[4], 1, 2);
            Check("mask min/max total 110", m2.Total == 110);
            MaskSource m3 = new MaskSource("ab?1", new string[] { "xy" }, 2, 2);
            Check("custom set total 2", m3.Total == 2);
            Check("mask total overflow -> null", new MaskSource("?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a", new string[4], 1, 16).Total == null);
        }

        private static void TestRawLines()
        {
            Console.WriteLine("unit: raw line splitter");
            string dir = TempDir();
            try
            {
                string f = Path.Combine(dir, "lines.txt");
                File.WriteAllBytes(f, Bytes("ab\r\ncd\nef"));
                // segments are only valid until the next MoveNext (the buffer
                // shifts in place), so decode immediately like the engine does
                List<string> got = new List<string>();
                List<long> idxs = new List<long>();
                foreach (RawLine rl in RawLines.Enumerate(File.OpenRead(f), 0, CancellationToken.None))
                {
                    got.Add(Encoding.ASCII.GetString(rl.Buf, rl.Offset, rl.Count));
                    idxs.Add(rl.Index);
                }
                Check("crlf/lf/no-trailing", got.Count == 3
                    && got[0] == "ab" && got[1] == "cd" && got[2] == "ef"
                    && idxs[0] == 0 && idxs[2] == 2);

                string big = Path.Combine(dir, "big.txt");
                byte[] payload = new byte[3 << 20];
                for (int i = 0; i < payload.Length; i++) payload[i] = (byte)'x';
                File.WriteAllBytes(big, payload);
                got = new List<string>();
                foreach (RawLine rl in RawLines.Enumerate(File.OpenRead(big), 0, CancellationToken.None))
                    got.Add(Encoding.ASCII.GetString(rl.Buf, rl.Offset, rl.Count));
                Check("line longer than 1MB buffer", got.Count == 1 && got[0].Length == payload.Length);
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }

        private static string Decode(RawLine l) { return Encoding.ASCII.GetString(l.Buf, l.Offset, l.Count); }

        private static void TestEncodingPlan()
        {
            Console.WriteLine("unit: encoding plan");
            string dir = TempDir();
            try
            {
                string note; long skip;
                string p = Path.Combine(dir, "u8.txt");
                File.WriteAllBytes(p, new byte[] { 0xEF, 0xBB, 0xBF, 0x61 });
                using (Stream s = File.OpenRead(p)) DictEncoding.Plan(s, out note, out skip);
                Check("utf8 bom skip", note == "UTF-8 (BOM)" && skip == 3);

                p = Path.Combine(dir, "u16.txt");
                File.WriteAllBytes(p, new byte[] { 0xFF, 0xFE, 0x61, 0x00 });
                using (Stream s = File.OpenRead(p)) DictEncoding.Plan(s, out note, out skip);
                Check("utf16le bom", note == "UTF-16LE (BOM)" && skip == 0);

                p = Path.Combine(dir, "gbk.txt");
                File.WriteAllBytes(p, Encoding.GetEncoding(936).GetBytes("\u5bc6\u7801"));
                using (Stream s = File.OpenRead(p)) DictEncoding.Plan(s, out note, out skip);
                Check("gbk ansi only", note == "ANSI(GBK)");

                p = Path.Combine(dir, "asc.txt");
                File.WriteAllBytes(p, Bytes("abc"));
                using (Stream s = File.OpenRead(p)) DictEncoding.Plan(s, out note, out skip);
                Check("ascii dual sweep", note == "UTF-8 + ANSI(GBK)");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }

        private static void TestZip64()
        {
            Console.WriteLine("unit: ZIP64 central directory");
            string dir = TempDir();
            try
            {
                string p = Path.Combine(dir, "z64.zip");
                File.WriteAllBytes(p, BuildZip64Fixture());
                ArchiveInfo info = ArchiveParser.Parse(p);
                Check("detected as zip", info.Kind == ArchiveKind.Zip);
                Check("zip64 entry parsed", info.Zip != null);
                if (info.Zip != null)
                {
                    Check("zip64 name", info.Zip.Name == "a");
                    Check("zip64 not aes", !info.Zip.Aes);
                    Check("zip64 comp size", info.Zip.CompDataSize == 88);
                    Check("zip64 data start", info.Zip.DataStart == 63);   // 30+1+20 local header + 12 enc header
                    Check("zip64 check byte", info.Zip.CheckByte == 0x12);
                }
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }

        // minimal encrypted-ZipCrypto ZIP with all classic fields at
        // 0xFFFFFFFF and the real values in ZIP64 records/extra fields
        private static byte[] BuildZip64Fixture()
        {
            MemoryStream ms = new MemoryStream();
            BinaryWriter w = new BinaryWriter(ms);
            w.Write((uint)0x04034b50);            // local header
            w.Write((ushort)20);
            w.Write((ushort)0x0001);              // encrypted
            w.Write((ushort)8);                   // deflate
            w.Write((ushort)0); w.Write((ushort)0x5A00);
            w.Write((uint)0x12345678);            // crc
            w.Write((uint)0xFFFFFFFF);            // comp size (zip64)
            w.Write((uint)0xFFFFFFFF);            // uncomp size (zip64)
            w.Write((ushort)1);                   // name len
            w.Write((ushort)20);                  // extra len (zip64: 4+16)
            w.Write((byte)'a');
            w.Write((ushort)0x0001); w.Write((ushort)16);
            w.Write(262144L); w.Write(100L);
            byte[] data = new byte[100];
            new Random(7).NextBytes(data);
            w.Write(data);
            long cdOffset = ms.Length;
            w.Write((uint)0x02014b50);            // central directory
            w.Write((ushort)20); w.Write((ushort)20);
            w.Write((ushort)0x0001); w.Write((ushort)8);
            w.Write((ushort)0); w.Write((ushort)0x5A00);
            w.Write((uint)0x12345678);
            w.Write((uint)0xFFFFFFFF); w.Write((uint)0xFFFFFFFF);
            w.Write((ushort)1); w.Write((ushort)28); w.Write((ushort)0);
            w.Write((ushort)0); w.Write((ushort)0); w.Write((uint)0);
            w.Write((uint)0xFFFFFFFF);            // local offset (zip64)
            w.Write((byte)'a');
            w.Write((ushort)0x0001); w.Write((ushort)24);
            w.Write(262144L); w.Write(100L); w.Write(0L);
            long cdSize = ms.Length - cdOffset;
            long z64Pos = ms.Length;
            w.Write((uint)0x06064b50);            // ZIP64 EOCD
            w.Write((ulong)44);
            w.Write((ushort)45); w.Write((ushort)45);
            w.Write((uint)0); w.Write((uint)0);
            w.Write((ulong)1); w.Write((ulong)1);
            w.Write((ulong)cdSize); w.Write((ulong)cdOffset);
            w.Write((uint)0x07064b50);            // ZIP64 locator
            w.Write((uint)0);
            w.Write((ulong)z64Pos);
            w.Write((uint)1);
            w.Write((uint)0x06054b50);            // EOCD with sentinels
            w.Write((ushort)0xFFFF); w.Write((ushort)0xFFFF);
            w.Write((ushort)0xFFFF); w.Write((ushort)0xFFFF);
            w.Write((uint)0xFFFFFFFF); w.Write((uint)0xFFFFFFFF);
            w.Write((ushort)0);
            return ms.ToArray();
        }

    private static void TestHashcatFormat()
    {
        Console.WriteLine("unit: hashcat -m 13000 format");
        Rar5CryptInfo ci = new Rar5CryptInfo();
        ci.Salt = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
        ci.PswCheck = new byte[] { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7 };
        ci.Lg2Count = 15;
        Check("hashcat rar5",
            ArchiveParser.HashcatRar5(ci)
            == "$rar5$16$000102030405060708090a0b0c0d0e0f$15$a0a1a2a3a4a5a6a7$8");
    }

    // ----------------------------------------------------------------
    // ZIP64 with more than 65535 entries: the classic EOCD count field
    // holds 0xFFFF and the real count lives in the ZIP64 EOCD record.
    // Regression: the count used to be truncated to ushort, so a 65536-
    // entry archive parsed as 0 entries and the encrypted entry was lost.
    private static void TestZip64ManyEntries()
    {
        Console.WriteLine("unit: ZIP64 archive with 65536 entries");
        string dir = TempDir();
        try
        {
            string p = Path.Combine(dir, "many.zip");
            File.WriteAllBytes(p, BuildZip64ManyEntries(65536));
            ArchiveInfo info = ArchiveParser.Parse(p);
            Check("many-entry zip64 detected", info.Kind == ArchiveKind.Zip);
            Check("encrypted entry found despite 65536 entries", info.Zip != null);
            if (info.Zip != null)
            {
                Check("many-entry target name", info.Zip.Name == "e");
                Check("many-entry comp size", info.Zip.CompDataSize == 88);
            }
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    // minimal ZIP64 chain whose central directory holds n records; only
    // the LAST record is encrypted (flags bit0) and has a real local
    // header, the rest are 47-byte stubs the parser merely walks past
    private static byte[] BuildZip64ManyEntries(int n)
    {
        MemoryStream ms = new MemoryStream();
        BinaryWriter w = new BinaryWriter(ms);
        w.Write((uint)0x04034b50);            // local header of the target
        w.Write((ushort)20);
        w.Write((ushort)0x0001);              // encrypted
        w.Write((ushort)8);                   // deflate
        w.Write((ushort)0); w.Write((ushort)0x5A00);
        w.Write((uint)0x12345678);            // crc
        w.Write((uint)100); w.Write((uint)100);
        w.Write((ushort)1); w.Write((ushort)0);
        w.Write((byte)'e');
        w.Write(new byte[12 + 100]);          // 12-byte enc header + payload (contents not verified)
        long cdOffset = ms.Length;
        for (int i = 0; i < n; i++)
        {
            bool last = i == n - 1;
            w.Write((uint)0x02014b50);        // central directory record
            w.Write((ushort)20); w.Write((ushort)20);
            w.Write((ushort)(last ? 0x0001 : 0));
            w.Write((ushort)8);
            w.Write((ushort)0); w.Write((ushort)0x5A00);
            w.Write((uint)0x12345678);
            w.Write((uint)100); w.Write((uint)100);
            w.Write((ushort)1); w.Write((ushort)0); w.Write((ushort)0);
            w.Write((ushort)0); w.Write((ushort)0); w.Write((uint)0);
            w.Write(0u);                      // local offset (only 'last' is opened)
            w.Write((byte)(last ? (byte)'e' : (byte)'x'));
        }
        long cdSize = ms.Length - cdOffset;
        long z64Pos = ms.Length;
        w.Write((uint)0x06064b50);            // ZIP64 EOCD: real entry count
        w.Write((ulong)44);
        w.Write((ushort)45); w.Write((ushort)45);
        w.Write((uint)0); w.Write((uint)0);
        w.Write((ulong)n); w.Write((ulong)n);
        w.Write((ulong)cdSize); w.Write((ulong)cdOffset);
        w.Write((uint)0x07064b50);            // ZIP64 locator
        w.Write((uint)0);
        w.Write((ulong)z64Pos);
        w.Write((uint)1);
        w.Write((uint)0x06054b50);            // EOCD with 0xFFFF sentinels
        w.Write((ushort)0xFFFF); w.Write((ushort)0xFFFF); w.Write((ushort)0xFFFF);
        w.Write((ushort)0xFFFF);
        w.Write((uint)0xFFFFFFFF); w.Write((uint)0xFFFFFFFF);
        w.Write((ushort)0);
        return ms.ToArray();
    }

    // ----------------------------------------------------------------
    // UTF-16LE dictionaries are split with StreamReader (0x0A can occur
    // inside a UTF-16 unit pair); regression: that path skipped the
    // mutation presets entirely, so rules silently never applied.
    private static void TestUtf16Rules()
    {
        Console.WriteLine("unit: UTF-16 dictionary runs mutation presets");
        string dir = TempDir();
        try
        {
            string p = Path.Combine(dir, "u16.txt");
            File.WriteAllBytes(p, new byte[] { 0xFF, 0xFE }.Concat(Encoding.Unicode.GetBytes("foo\r\n")).ToArray());
            DictionarySource src = new DictionarySource(new List<string> { p }, new List<string> { "digits" });
            List<string> got = new List<string>();
            foreach (Candidate c in src.Enumerate(new SourcePosition(), CancellationToken.None)) got.Add(c.Pw);
            Check("utf16 base word first", got.Count > 0 && got[0] == "foo");
            Check("utf16 single-digit suffix", got.Contains("foo0"));
            Check("utf16 double-digit suffix", got.Contains("foo99"));
            Check("utf16 fan-out 111", got.Count == 111);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    // ----------------------------------------------------------------
    // result file encoding: GBK when lossless, UTF-8 BOM otherwise.
    // Regression: the old byte-level roundtrip check could not catch
    // chars GBK best-fits to '?' (emoji, rare CJK) - such passwords were
    // silently corrupted in the result file.
    private static void TestResultEncoding()
    {
        Console.WriteLine("unit: result file encoding policy");
        string dir = TempDir();
        try
        {
            // char outside GBK must fall back to UTF-8 with BOM
            string p = Path.Combine(dir, "res-emoji.txt");
            string pw = "pw\U0001F600x";
            CrackEngine.WriteResultText(p, pw);
            Check("non-GBK password roundtrips", File.ReadAllText(p, Encoding.UTF8).Trim() == pw);
            byte[] head = new byte[3];
            using (FileStream fs = File.OpenRead(p)) { fs.Read(head, 0, 3); }
            Check("non-GBK written as UTF-8 BOM", head[0] == 0xEF && head[1] == 0xBB && head[2] == 0xBF);

            // GBK-representable password stays GBK (no BOM prepended)
            string p2 = Path.Combine(dir, "res-gbk.txt");
            CrackEngine.WriteResultText(p2, "\u5bc6\u7801123");
            using (FileStream fs = File.OpenRead(p2)) { fs.Read(head, 0, 3); }
            bool bom = head[0] == 0xEF && head[1] == 0xBB && head[2] == 0xBF;
            Check("GBK password stays GBK", !bom
                && File.ReadAllText(p2, Encoding.GetEncoding(936)).Trim() == "\u5bc6\u7801123");

            // trailing backslash is GBK-representable and must survive
            string p3 = Path.Combine(dir, "res-bs.txt");
            CrackEngine.WriteResultText(p3, "abc\\");
            Check("trailing backslash roundtrips", File.ReadAllText(p3, Encoding.GetEncoding(936)).Trim() == "abc\\");
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    // ----------------------------------------------------------------
    // argument quoting for the 7z/rar spawn path. The two tool families
    // parse command lines differently (both verified by round-tripping
    // real passwords through the real executables):
    //   - 7z.exe self-parses the raw command line: backslashes are always
    //     literal, "" collapses to one quote -> the simple doubling form
    //     round-trips every password, and the CRT-escaped form BREAKS
    //     trailing backslashes (7z received abc" for "abc\\").
    //   - rar.exe/unrar.exe are standard CRT argv programs: a trailing
    //     backslash must be doubled or the closing quote is escaped
    //     (child received abc" for the password abc\).
    private static void TestWinArgQuote()
    {
        Console.WriteLine("unit: WinArg quoting for spawned tools");
        // 7z family: simple doubling form
        Check("7z plain", WinArg.QuoteForTool("C:\\t\\7z.exe", "plain") == "\"plain\"");
        Check("7z space", WinArg.QuoteForTool("C:\\t\\7z.exe", "with space") == "\"with space\"");
        Check("7z embedded quote", WinArg.QuoteForTool("C:\\t\\7z.exe", "a\"b") == "\"a\"\"b\"");
        Check("7z interior backslash", WinArg.QuoteForTool("C:\\t\\7z.exe", "a\\b") == "\"a\\b\"");
        Check("7z trailing backslash literal", WinArg.QuoteForTool("C:\\t\\7z.exe", "abc\\") == "\"abc\\\"");
        // CRT argv family: escaping form
        Check("rar plain", WinArg.QuoteForTool("C:\\t\\rar.exe", "plain") == "\"plain\"");
        Check("rar embedded quote", WinArg.QuoteForTool("C:\\t\\rar.exe", "a\"b") == "\"a\\\"b\"");
        Check("rar interior backslash literal", WinArg.QuoteForTool("C:\\t\\rar.exe", "a\\b") == "\"a\\b\"");
        Check("rar trailing backslash doubled", WinArg.QuoteForTool("C:\\t\\rar.exe", "abc\\") == "\"abc\\\\\"");
        Check("rar backslash+quote escaped", WinArg.QuoteForTool("C:\\t\\rar.exe", "a\\\"") == "\"a\\\\\\\"\"");
        // unknown tool -> CRT argv escaping (the conservative default)
        Check("unknown tool uses argv escaping", WinArg.QuoteForTool("C:\\t\\other.exe", "abc\\") == "\"abc\\\\\"");
        // raw Quote() keeps the CRT rules for direct callers
        Check("argv plain", WinArg.Quote("plain") == "\"plain\"");
        Check("argv space", WinArg.Quote("with space") == "\"with space\"");
    }

    // ----------------------------------------------------------------
    // a RAR5 file whose header chain is truncated mid-vint must parse
    // gracefully (no crypt record) instead of throwing EndOfStream
    private static void TestRar5Truncation()
    {
        Console.WriteLine("unit: RAR5 truncated header tolerated");
        string dir = TempDir();
        try
        {
            string p = Path.Combine(dir, "trunc.rar");
            byte[] sig = new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00 };
            byte[] trunc = new byte[] { 0, 0, 0, 0, 0x80, 0x80, 0x80, 0x80, 0x80 };  // CRC + unterminated vint
            File.WriteAllBytes(p, sig.Concat(trunc).ToArray());
            ArchiveInfo info = ArchiveParser.Parse(p);
            Check("detected as rar5", info != null && info.Kind == ArchiveKind.Rar5);
            Check("no crypt record, no throw", info != null && info.Rar5 == null);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    // ----------------------------------------------------------------
    // --progress protocol parsing (RemoteEngine.MiniJson): the shape the
    // Rust CLI emits must parse, hostile payloads must round-trip,
    // structural surprises must yield null (the forward-compat rule)
    private static void TestMiniJson()
    {
        Console.WriteLine("unit: MiniJson flat-object scanner");
        // hand-written line pinning the exact wire shape
        Dictionary<string, string> kv = MiniJson.Parse(
            "{\"ev\":\"found\",\"password\":\"x\\\"y\\\\z\",\"tried\":123,\"elapsed\":4.6}");
        Check("parses", kv != null);
        Check("ev", kv != null && kv["ev"] == "found");
        Check("quote+backslash round-trip", kv != null && kv["password"] == "x\"y\\z");
        Check("number kept as text", kv != null && kv["tried"] == "123");
        Check("float kept as text", kv != null && kv["elapsed"] == "4.6");

        // hostile password (quote, backslash, LF, CJK, control char) built
        // with a local emitter using the same escape rules as the Rust side
        string hostile = "pw\"q\\\n中\u0007";
        Dictionary<string, string> kv2 = MiniJson.Parse(
            "{\"ev\":\"found\",\"password\":" + JsonQuote(hostile) + "}");
        Check("hostile round-trip", kv2 != null && kv2["password"] == hostile);

        Check("non-object rejected", MiniJson.Parse("hello") == null);
        Check("unterminated string rejected", MiniJson.Parse("{\"a\":\"b}") == null);
        Check("missing key quote rejected", MiniJson.Parse("{a\"\":1}") == null);
        Check("empty object ok", MiniJson.Parse("{}") != null && MiniJson.Parse("{}").Count == 0);
        Check("spaces tolerated", MiniJson.Parse("{ \"a\" : \"b\" , \"c\":5 }") != null);
        Check("unknown value type token kept raw",
            MiniJson.Parse("{\"n\":true}") != null && MiniJson.Parse("{\"n\":true}")["n"] == "true");
    }

    // same escaping rules as the Rust json_escape (protocol wire format)
    private static string JsonQuote(string s)
    {
        StringBuilder sb = new StringBuilder();
        sb.Append('"');
        foreach (char c in s)
        {
            if (c == '"') sb.Append("\\\"");
            else if (c == '\\') sb.Append("\\\\");
            else if (c == '\n') sb.Append("\\n");
            else if (c == '\r') sb.Append("\\r");
            else if (c == '\t') sb.Append("\\t");
            else if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
            else sb.Append(c);
        }
        sb.Append('"');
        return sb.ToString();
    }

    // ----------------------------------------------------------------
    private static void TestRemoteQuoteArg()
    {
        Console.WriteLine("unit: RemoteCrackEngine.QuoteArg (CRT argv rules)");
        // anchors: hand-verified encodings
        Check("plain stays bare", RemoteCrackEngine.QuoteArg("plain") == "plain");
        Check("space quoted", RemoteCrackEngine.QuoteArg("with space") == "\"with space\"");
        // no space/tab/quote: stays bare, and an unquoted trailing backslash
        // is literal under CRT rules - no quoting needed
        Check("trailing backslash stays bare", RemoteCrackEngine.QuoteArg("abc\\") == "abc\\");
        Check("path backslashes stay bare", RemoteCrackEngine.QuoteArg("C:\\mydir\\a.rar") == "C:\\mydir\\a.rar");
        // quoted form: trailing backslashes must double before the close quote
        Check("quoted trailing backslash doubled", RemoteCrackEngine.QuoteArg("a b\\") == "\"a b\\\\\"");
        Check("inner quote escaped", RemoteCrackEngine.QuoteArg("a\"b") == "\"a\\\"b\"");
        Check("empty becomes quoted", RemoteCrackEngine.QuoteArg("") == "\"\"");
        // property: every hostile value survives its own encoding when the
        // consumer decodes with CRT/GetCommandLineW rules (what the Rust
        // CLI's std::env::args does)
        string[] hostile = new string[]
        {
            "pw\"q\\", "endbs\\", "a\\b\\c", "pw\\\"q", "C:\\my dir\\a.rar",
            "with\ttab", "中密\\码", "\"lead", "trailing\\\\", "x\\", "a \"b\" c"
        };
        foreach (string s in hostile)
            Check("round-trip: " + s, DecodeFirstArg(RemoteCrackEngine.QuoteArg(s)) == s);
    }

    // CRT argv decoder for ONE argument as emitted by QuoteArg (inverse
    // of the encoding rules; see Raymond Chen "Everyone quotes command
    // line arguments the wrong way")
    private static string DecodeFirstArg(string s)
    {
        if (s.Length == 0 || s[0] != '"') return s;
        StringBuilder sb = new StringBuilder();
        int back = 0;
        for (int i = 1; i < s.Length; i++)
        {
            char c = s[i];
            if (c == '\\') { back++; continue; }
            if (c == '"')
            {
                if (back % 2 == 0)
                {
                    sb.Append('\\', back / 2);
                    return sb.ToString();                   // 2n backslashes + quote: arg ends
                }
                sb.Append('\\', back / 2).Append('"');      // 2n+1: n backslashes + literal quote
                back = 0;
            }
            else
            {
                sb.Append('\\', back);
                back = 0;
                sb.Append(c);
            }
        }
        sb.Append('\\', back);
        return sb.ToString();
    }

    // ----------------------------------------------------------------
    private static void TestRemoteBuildArgs()
    {
        Console.WriteLine("unit: RemoteCrackEngine.BuildArgs (GUI -> Rust argv)");
        CrackConfig cfg = new CrackConfig();
        cfg.ArchivePath = "a.rar";
        cfg.Mode = "dict";
        cfg.DictFiles.Add("d1.txt");
        cfg.Presets.Add("years");
        cfg.Threads = 4;
        string args = RemoteCrackEngine.BuildArgs(cfg);
        Check("crack subcommand", args.StartsWith("crack ", StringComparison.Ordinal));
        Check("archive", args.Contains(" -a a.rar "));
        Check("dict", args.Contains(" -w d1.txt "));
        Check("rule", args.Contains(" --rule years "));
        Check("threads", args.Contains(" -t 4 "));
        Check("progress flag", args.EndsWith(" --progress", StringComparison.Ordinal));
        Check("session file pinned", args.Contains("--session-file ") && args.Contains("session.json"));
        Check("result file pinned", args.Contains("--out ") && args.Contains("_password.txt"));

        cfg.Mode = "mask";
        cfg.Mask = "ab?d?d?d";
        cfg.MaskMin = 1; cfg.MaskMax = 6;
        cfg.CustomSets[0] = "x1"; cfg.CustomSets[1] = null;
        args = RemoteCrackEngine.BuildArgs(cfg);
        Check("mask", args.Contains("--mask ab?d?d?d"));
        Check("custom set 1", args.Contains(" -1 x1 "));
        Check("no custom set 2", !args.Contains(" -2 "));
        Check("min/max", args.Contains("--min 1") && args.Contains("--max 6"));

        cfg = new CrackConfig();
        cfg.ArchivePath = "a.rar";
        cfg.Mode = "comb";
        cfg.DictFiles.Add("A.txt");
        cfg.DictFileB = "B.txt";
        cfg.CheckpointEnabled = false;
        cfg.ResumeRequested = true;
        args = RemoteCrackEngine.BuildArgs(cfg);
        Check("comb w", args.Contains(" -w A.txt "));
        Check("comb w2", args.Contains(" --w2 B.txt "));
        Check("no-checkpoint", args.Contains("--no-checkpoint"));
        Check("resume", args.Contains("--resume"));

        // paths with spaces survive as one quoted argv element
        cfg = new CrackConfig();
        cfg.ArchivePath = @"C:\my dir\a.rar";
        cfg.Mode = "dict";
        cfg.DictFiles.Add(@"C:\my dir\d.txt");
        args = RemoteCrackEngine.BuildArgs(cfg);
        Check("space path one token", args.Contains(@" -a ""C:\my dir\a.rar"" "));
    }
}
}
