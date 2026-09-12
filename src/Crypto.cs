// Crypto.cs -- native CNG PBKDF2 (bcrypt.dll), CRC32, SHA-256 helpers.
// Pure ASCII source; compiles with the in-box .NET Framework csc (C# 5).
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace DictCrack
{
    internal static class NativeCrypto
    {
        // BCryptDeriveKeyPBKDF2 is several times faster than the managed
        // Rfc2898DeriveBytes and available on every supported Windows build.
        [DllImport("bcrypt.dll")]
        private static extern int BCryptOpenAlgorithmProvider(out IntPtr hAlg, [MarshalAs(UnmanagedType.LPWStr)] string algId,
            [MarshalAs(UnmanagedType.LPWStr)] string implementation, uint flags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlg, uint flags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDeriveKeyPBKDF2(IntPtr hAlg, byte[] password, uint cbPassword,
            byte[] salt, uint cbSalt, ulong iterations, byte[] derivedKey, uint cbDerived, uint flags);

        private const uint BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008;
        private const int STATUS_SUCCESS = 0;

        private static bool _initFailed;

        // CNG serializes PBKDF2 calls that share one algorithm handle
        // (measured: throughput plateaus at ~4 threads). One handle per
        // thread restores linear scaling, so handles are cached per thread.
        [ThreadStatic]
        private static IntPtr _tlsSha256;
        [ThreadStatic]
        private static IntPtr _tlsSha1;

        private static IntPtr GetThreadAlg(bool sha256)
        {
            IntPtr h = sha256 ? _tlsSha256 : _tlsSha1;
            if (h != IntPtr.Zero) return h;
            int st = BCryptOpenAlgorithmProvider(out h, sha256 ? "SHA256" : "SHA1", null, BCRYPT_ALG_HANDLE_HMAC_FLAG);
            if (st != STATUS_SUCCESS) { _initFailed = true; return IntPtr.Zero; }
            if (sha256) _tlsSha256 = h; else _tlsSha1 = h;
            return h;
        }

        private static byte[] Pbkdf2Cng(bool sha256, byte[] pwd, byte[] salt, long iterations, int bytes)
        {
            IntPtr h = GetThreadAlg(sha256);
            if (h == IntPtr.Zero) return null;
            byte[] outBuf = new byte[bytes];
            int st = BCryptDeriveKeyPBKDF2(h, pwd, (uint)pwd.Length, salt, (uint)salt.Length,
                (ulong)iterations, outBuf, (uint)bytes, 0);
            return st == STATUS_SUCCESS ? outBuf : null;
        }

        // PBKDF2 with the requested hash. Only a failed HANDLE OPEN makes
        // the managed fallback permanent; a failed derive call is transient
        // (previously any single failure downgraded the whole run to the
        // several-times-slower managed implementation).
        public static byte[] Pbkdf2Sha256(byte[] pwd, byte[] salt, long iterations, int bytes)
        {
            if (!_initFailed)
            {
                byte[] r = Pbkdf2Cng(true, pwd, salt, iterations, bytes);
                if (r != null) return r;
            }
            using (var d = new Rfc2898DeriveBytes(pwd, salt, (int)Math.Min(iterations, int.MaxValue - 1), HashAlgorithmName.SHA256))
                return d.GetBytes(bytes);
        }

        public static byte[] Pbkdf2Sha1(byte[] pwd, byte[] salt, long iterations, int bytes)
        {
            if (!_initFailed)
            {
                byte[] r = Pbkdf2Cng(false, pwd, salt, iterations, bytes);
                if (r != null) return r;
            }
            using (var d = new Rfc2898DeriveBytes(pwd, salt, (int)Math.Min(iterations, int.MaxValue - 1), HashAlgorithmName.SHA1))
                return d.GetBytes(bytes);
        }

        public static byte[] Sha256(byte[] data) { using (var h = SHA256.Create()) return h.ComputeHash(data); }
    }

    internal static class Crc32
    {
        private static readonly uint[] Table = BuildTable();

        private static uint[] BuildTable()
        {
            uint[] t = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint c = i;
                for (int k = 0; k < 8; k++) c = ((c & 1) != 0) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
                t[i] = c;
            }
            return t;
        }

        public static uint Update(uint crc, byte[] buf, int offset, int count)
        {
            uint c = crc ^ 0xFFFFFFFFu;
            for (int i = offset; i < offset + count; i++) c = Table[(c ^ buf[i]) & 0xFF] ^ (c >> 8);
            return c ^ 0xFFFFFFFFu;
        }

        public static uint Compute(byte[] buf, int offset, int count) { return Update(0, buf, offset, count); }

        // raw table step without the pre/post inversion - used by the
        // ZipCrypto key schedule which keeps non-inverted running keys
        public static uint RawStep(uint c, byte b) { return Table[(c ^ b) & 0xFF] ^ (c >> 8); }
    }
}
