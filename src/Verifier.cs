// Verifier.cs -- password verification for RAR5 (native PBKDF2 header
// check), ZIP (native ZipCrypto / WinZip-AES) and a 7z.exe fallback for
// everything else (RAR4, 7z, -hp without check data, ...). ASCII only.
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace DictCrack
{
    public abstract class Verifier
    {
        public abstract bool Verify(string password);
        public virtual bool Native { get { return false; } }
        public virtual string Describe() { return "external tool"; }
    }

    // ------------------------------------------------------------------
    // RAR5: PswCheck = fold8(PBKDF2-HMAC-SHA256(UTF8(pwd), salt, 2^lg+32))
    // (the +32 matches unrar's chain continuation for the check value)
    public sealed class Rar5Verifier : Verifier
    {
        private readonly byte[] _salt;
        private readonly byte[] _check;
        private readonly long _iters;

        public Rar5Verifier(Rar5CryptInfo ci)
        {
            _salt = ci.Salt;
            _check = ci.PswCheck;
            _iters = (1L << ci.Lg2Count) + 32;
        }

        public override bool Native { get { return true; } }

        public override string Describe()
        {
            return string.Format("RAR5 native header check (PBKDF2-SHA256, {0} iterations)", _iters);
        }

        public override bool Verify(string password)
        {
            byte[] pwd = Encoding.UTF8.GetBytes(password);
            byte[] key = NativeCrypto.Pbkdf2Sha256(pwd, _salt, _iters, 32);
            byte[] check = new byte[8];
            for (int i = 0; i < 32; i++) check[i % 8] ^= key[i];
            for (int i = 0; i < 8; i++) if (check[i] != _check[i]) return false;
            return true;
        }
    }

    // ------------------------------------------------------------------
    public sealed class ZipVerifier : Verifier
    {
        private readonly ZipTargetInfo _t;

        public ZipVerifier(ZipTargetInfo t) { _t = t; }

        public override bool Native { get { return true; } }

        public override string Describe()
        {
            if (_t.Aes) return string.Format("ZIP native WinZip-AES{0} check (PBKDF2-SHA1, target \"{1}\")",
                _t.AesStrength * 64 + 64, _t.Name);
            return string.Format("ZIP native ZipCrypto check + full CRC confirm (target \"{0}\")", _t.Name);
        }

        public override bool Verify(string password)
        {
            if (_t.Aes) return VerifyAes(password);
            return VerifyZipCrypto(password);
        }

        // WinZip AES: PBKDF2-HMAC-SHA1 1000 iterations over salt, deriving
        // 2*keyLen+2 bytes; the last 2 bytes are the password verification
        // value. A PV match is confirmed with the 10-byte HMAC-SHA1 over
        // the WHOLE encrypted data (a prefix HMAC would not match the
        // stored MAC - this bit large archives with a small-file test
        // suite once).
        private bool VerifyAes(string password)
        {
            int keyLen = _t.AesStrength == 1 ? 16 : (_t.AesStrength == 2 ? 24 : 32);
            byte[] pwd = Encoding.UTF8.GetBytes(password);
            byte[] salt = new byte[_t.EncHeader.Length - 2];
            Array.Copy(_t.EncHeader, salt, salt.Length);
            byte[] storedPv = new byte[] { _t.EncHeader[_t.EncHeader.Length - 2], _t.EncHeader[_t.EncHeader.Length - 1] };
            byte[] derived = NativeCrypto.Pbkdf2Sha1(pwd, salt, 1000, 2 * keyLen + 2);
            if (derived[2 * keyLen] != storedPv[0] || derived[2 * keyLen + 1] != storedPv[1]) return false;
            byte[] macKey = new byte[keyLen];
            Array.Copy(derived, keyLen, macKey, 0, keyLen);
            try
            {
                using (HMACSHA1 hmac = new HMACSHA1(macKey))
                using (FileStream fs = new FileStream(ArchivePath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16))
                {
                    fs.Seek(_t.DataStart, SeekOrigin.Begin);
                    byte[] buf = new byte[1 << 16];
                    long left = _t.CompDataSize;
                    while (left > 0)
                    {
                        int n = fs.Read(buf, 0, (int)Math.Min((long)buf.Length, left));
                        if (n <= 0) return false;
                        hmac.TransformBlock(buf, 0, n, null, 0);
                        left -= n;
                    }
                    hmac.TransformFinalBlock(new byte[0], 0, 0);
                    byte[] mac = hmac.Hash;
                    for (int i = 0; i < 10; i++) if (mac[i] != _t.Mac[i]) return false;
                }
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
            return true;
        }

        // legacy ZipCrypto: 1-byte check (1/256 false positives) followed by
        // a full decrypt+inflate+CRC confirm, so reported hits are real
        private bool VerifyZipCrypto(string password)
        {
            ZcState st = new ZcState(password);
            byte[] eh = _t.EncHeader;
            byte last = 0;
            for (int i = 0; i < 12; i++) last = st.DecryptByte(eh[i]);
            if (last != _t.CheckByte) return false;
            return ConfirmFull(st);
        }

        private bool ConfirmFull(ZcState st)
        {
            try
            {
                using (FileStream fs = new FileStream(ArchivePath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16))
                {
                    fs.Seek(_t.DataStart, SeekOrigin.Begin);
                    using (ZcStream zs = new ZcStream(fs, st, _t.CompDataSize))
                    {
                        uint crc;
                        if (_t.Method == 8)
                        {
                            using (DeflateStream ds = new DeflateStream(zs, CompressionMode.Decompress))
                            {
                                crc = PumpCrc(ds);
                            }
                        }
                        else
                        {
                            crc = PumpCrc(zs);
                        }
                        return crc == _t.Crc32;
                    }
                }
            }
            catch (InvalidDataException) { return false; }   // garbage deflate
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
        }

        private static uint PumpCrc(Stream s)
        {
            byte[] buf = new byte[1 << 16];
            uint crc = 0;
            int n;
            while ((n = s.Read(buf, 0, buf.Length)) > 0) crc = Crc32.Update(crc, buf, 0, n);
            return crc;
        }

        // set by the factory so the confirm can reopen the archive
        public static string ArchivePath;
    }

    // ------------------------------------------------------------------
    internal sealed class ZcState
    {
        private uint _k0, _k1, _k2;

        public ZcState(string password)
        {
            _k0 = 0x12345678; _k1 = 0x23456789; _k2 = 0x34567890;
            byte[] pwd = Encoding.UTF8.GetBytes(password);
            for (int i = 0; i < pwd.Length; i++) Update(pwd[i]);
        }

        public ZcState(ZcState other)
        {
            _k0 = other._k0; _k1 = other._k1; _k2 = other._k2;
        }

        private void Update(byte c)
        {
            _k0 = Crc32.RawStep(_k0, c);
            _k1 = _k1 + (_k0 & 0xFF);
            _k1 = _k1 * 134775813 + 1;
            _k2 = Crc32.RawStep(_k2, (byte)(_k1 >> 24));
        }

        public byte DecryptByte(byte c)
        {
            byte p = (byte)(c ^ DecByte());
            Update(p);
            return p;
        }

        private byte DecByte()
        {
            uint temp = (_k2 | 2) & 0xFFFF;
            return (byte)(((temp * (temp ^ 1)) >> 8) & 0xFF);
        }
    }

    // decrypting stream for the ZipCrypto full-CRC confirm
    internal sealed class ZcStream : Stream
    {
        private readonly Stream _base;
        private readonly ZcState _st;
        private long _left;

        public ZcStream(Stream baseStream, ZcState state, long length)
        {
            _base = baseStream; _st = state; _left = length;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_left <= 0) return 0;
            if (count > _left) count = (int)_left;
            int n = _base.Read(buffer, offset, count);
            for (int i = 0; i < n; i++) buffer[offset + i] = _st.DecryptByte(buffer[offset + i]);
            _left -= n;
            return n;
        }

        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
        public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
    }

    // ------------------------------------------------------------------
    // everything the native paths cannot handle goes through 7z t -p<pwd>
    public sealed class SpawnVerifier : Verifier
    {
        private readonly string _tool;

        public SpawnVerifier(string toolPath) { _tool = toolPath; }

        public override string Describe() { return "external tool test (" + Path.GetFileName(_tool) + ")"; }

        public override bool Verify(string password)
        {
            if (password.IndexOf('\r') >= 0 || password.IndexOf('\n') >= 0) return false;
            string quoted = "\"" + password.Replace("\"", "\"\"") + "\"";
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = _tool;
            psi.Arguments = "t -y -p" + quoted + " \"" + SpawnVerifier.ArchivePath + "\"";
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.RedirectStandardInput = true;
            using (Process p = Process.Start(psi))
            {
                try { p.StandardInput.Close(); } catch { }
                // drain both pipes concurrently - a sequential ReadToEnd
                // deadlocks when the child fills one pipe while we block on
                // the other (happens on the large output of a successful t)
                System.Threading.Tasks.Task<string> so = p.StandardOutput.ReadToEndAsync();
                string err = p.StandardError.ReadToEnd();
                p.WaitForExit();
                try { so.Wait(1000); } catch { }
                return p.ExitCode == 0;
            }
        }

        public static string ArchivePath;
    }

    // ------------------------------------------------------------------
    public static class VerifierFactory
    {
        public static Verifier Create(ArchiveInfo info, string userTool, string archivePath)
        {
            if (!string.IsNullOrEmpty(archivePath))
            {
                string full = Path.GetFullPath(archivePath);
                ZipVerifier.ArchivePath = full;
                SpawnVerifier.ArchivePath = full;
            }
            if (info.Kind == ArchiveKind.Rar5 && info.NativeSupported)
                return new Rar5Verifier(info.Rar5);
            if (info.Kind == ArchiveKind.Zip && info.NativeSupported)
                return new ZipVerifier(info.Zip);
            string tool = userTool;
            if (string.IsNullOrEmpty(tool) || !File.Exists(tool)) tool = ToolLocator.FindExtractor();
            if (tool == null)
                throw new ApplicationException("未找到可用的解压工具（7z.exe / rar.exe），无法测试该压缩包。");
            return new SpawnVerifier(tool);
        }
    }

    public static class ToolLocator
    {
        // returns a 7z.exe/rar.exe for the spawn fallback; the native paths
        // never need it
        public static string FindExtractor()
        {
            string[] candidates = new string[]
            {
                "D:\\Software\\Scoop\\shims\\7z.exe",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "7-Zip\\7z.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WinRAR\\rar.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "7-Zip\\7z.exe"),
                "D:\\Software\\WinRAR\\rar.exe"
            };
            foreach (string c in candidates)
                if (File.Exists(c)) return c;
            foreach (string name in new string[] { "7z.exe", "rar.exe", "unrar.exe" })
            {
                string path = Probe(name);
                if (path != null) return path;
            }
            return null;
        }

        private static string Probe(string exe)
        {
            string pathVar = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (string dir in pathVar.Split(';'))
            {
                if (dir.Length == 0) continue;
                try
                {
                    string p = Path.Combine(dir.Trim(), exe);
                    if (File.Exists(p)) return p;
                }
                catch { }
            }
            return null;
        }
    }
}
