// ArchiveInfo.cs -- archive format detection and parsing of the pieces
// needed for native password verification (RAR5 crypt records, ZIP
// encrypted entry descriptors). ASCII only.
using System;
using System.Collections.Generic;
using System.IO;

namespace DictCrack
{
    public enum ArchiveKind { Rar5, RarLegacy, Zip, SevenZip, Unknown }

    public sealed class Rar5CryptInfo
    {
        public byte[] Salt;        // 16 bytes
        public byte Lg2Count;      // log2 of PBKDF2 iterations
        public byte[] PswCheck;    // 8 bytes, may be null (no check data stored)
        public bool HeaderEncrypted; // true when taken from HEAD_CRYPT (-hp)
        public string EntryName;   // file name for file-level crypt (null for -hp)
    }

    public sealed class ZipTargetInfo
    {
        public bool Aes;               // true = WinZip AES, false = legacy ZipCrypto
        public int AesStrength;        // 1/2/3 -> 128/192/256
        public byte[] EncHeader;       // ZipCrypto: 12 enc-header bytes; AES: salt+PV
        public byte CheckByte;         // ZipCrypto 1-byte check
        public byte[] Mac;             // AES: stored 10-byte HMAC-SHA1
        public long DataStart;         // offset of encrypted data (after salt/PV for AES)
        public long CompDataSize;      // encrypted data length (excl. salt/PV/MAC for AES)
        public int Method;             // 0 stored, 8 deflate (ZipCrypto confirm)
        public uint Crc32;             // stored CRC of uncompressed data
        public string Name;
    }

    public sealed class ArchiveInfo
    {
        public ArchiveKind Kind;
        public Rar5CryptInfo Rar5;
        public ZipTargetInfo Zip;
        public string DetectNote = "";

        public bool NativeSupported
        {
            get
            {
                if (Kind == ArchiveKind.Rar5) return Rar5 != null && Rar5.PswCheck != null && Rar5.Lg2Count <= 24;
                if (Kind == ArchiveKind.Zip) return Zip != null;
                return false;
            }
        }
    }

    internal static class ArchiveParser
    {
        public static ArchiveInfo Parse(string path)
        {
            ArchiveInfo info = new ArchiveInfo();
            byte[] head = ReadHead(path, 8);
            if (head.Length >= 8 && head[0] == 0x52 && head[1] == 0x61 && head[2] == 0x72 && head[3] == 0x21
                && head[4] == 0x1A && head[5] == 0x07 && head[6] == 0x01 && head[7] == 0x00)
            {
                info.Kind = ArchiveKind.Rar5;
                info.Rar5 = ParseRar5(path);
                if (info.Rar5 == null) info.DetectNote = "RAR5: no password check data found in headers";
                return info;
            }
            if (head.Length >= 7 && head[0] == 0x52 && head[1] == 0x61 && head[2] == 0x72 && head[3] == 0x21
                && head[4] == 0x1A && head[5] == 0x07 && head[6] == 0x00)
            {
                info.Kind = ArchiveKind.RarLegacy;
                info.DetectNote = "RAR 1.5-4.x format (native header check not supported)";
                return info;
            }
            if (head.Length >= 6 && head[0] == 0x37 && head[1] == 0x7A && head[2] == 0xBC && head[3] == 0xAF
                && head[4] == 0x27 && head[5] == 0x1C)
            {
                info.Kind = ArchiveKind.SevenZip;
                info.DetectNote = "7z format (native check requires LZMA; using external tool)";
                return info;
            }
            if (head.Length >= 4 && head[0] == 0x50 && head[1] == 0x4B)
            {
                info.Kind = ArchiveKind.Zip;
                info.Zip = ParseZip(path);
                if (info.Zip == null) info.DetectNote = "ZIP: no encrypted entry found (or archive is empty/unreadable)";
                return info;
            }
            info.Kind = ArchiveKind.Unknown;
            info.DetectNote = "unrecognized signature; will try external tool anyway";
            return info;
        }

        private static byte[] ReadHead(string path, int count)
        {
            using (FileStream fs = File.OpenRead(path))
            {
                byte[] buf = new byte[count];
                int read = fs.Read(buf, 0, count);
                if (read == count) return buf;
                byte[] trimmed = new byte[read];
                Array.Copy(buf, trimmed, read);
                return trimmed;
            }
        }

        // ---- RAR5 --------------------------------------------------------
        // Header chain layout: CRC32(4) HeaderSize(vint) then HeaderSize
        // bytes. The extra area is the LAST ExtraAreaSize bytes of the
        // body, so type-specific fields never need parsing except for
        // HEAD_CRYPT where the crypt data IS the type-specific part.
        private static Rar5CryptInfo ParseRar5(string path)
        {
            using (FileStream fs = File.OpenRead(path))
            using (BinaryReader br = new BinaryReader(fs))
            {
                fs.Seek(8, SeekOrigin.Begin);
                Rar5CryptInfo fromFileHeader = null;
                while (true)
                {
                    long headerStart = fs.Position;
                    if (headerStart + 7 > fs.Length) return fromFileHeader;
                    br.ReadBytes(4); // header CRC32
                    ulong headerSize = ReadVint(br);
                    if (headerSize == 0 || headerSize > 0x10000000L) return fromFileHeader;
                    long bodyStart = fs.Position;
                    long bodyEnd = bodyStart + (long)headerSize;
                    if (bodyEnd > fs.Length) return fromFileHeader;
                    byte[] body = br.ReadBytes((int)headerSize);
                    int pos = 0;
                    ulong type = ReadVint(body, ref pos);
                    ulong flags = ReadVint(body, ref pos);
                    ulong extraSize = (flags & 0x0001UL) != 0 ? ReadVint(body, ref pos) : 0;
                    ulong dataSize = (flags & 0x0002UL) != 0 ? ReadVint(body, ref pos) : 0;

                    if (type == 5) return fromFileHeader; // end of archive

                    if (type == 4)
                    {
                        // archive encryption header (-hp): version, flags,
                        // lg2, salt, [check+csum]; no IV here and the whole
                        // rest of the archive is encrypted
                        Rar5CryptInfo ci = ParseRar5CryptBody(body, pos, false, true, null);
                        return ci; // nothing else readable when headers are encrypted
                    }

                    if ((type == 2 || type == 3) && extraSize > 0 && fromFileHeader == null)
                    {
                        // FILE / SERVICE header: scan extra records for CRYPT
                        long extraStart = body.Length - (long)extraSize;
                        if (extraStart >= pos)
                        {
                            int epos = (int)extraStart;
                            int eend = body.Length;
                            while (epos + 2 <= eend)
                            {
                                int recStart = epos;
                                ulong recSize = ReadVint(body, ref epos);
                                if (recSize == 0 || recStart + (long)recSize > eend) break;
                                int recEnd = recStart + (int)recSize;
                                ulong recType = ReadVint(body, ref epos);
                                if (recType == 1)
                                {
                                    string name = TryReadFileName(body, pos, extraStart);
                                    Rar5CryptInfo ci = ParseRar5CryptBody(body, epos, true, false, name);
                                    if (ci != null) { fromFileHeader = ci; break; }
                                }
                                epos = recEnd;
                            }
                        }
                    }
                    // jump to next header; data area (file payload) is skipped
                    fs.Seek(bodyEnd + (long)dataSize, SeekOrigin.Begin);
                }
            }
        }

        private static string TryReadFileName(byte[] body, int pos, long extraStart)
        {
            // FILE header type-specific per arcread.cpp: fileFlags(vint)
            // unpSize(vint) attr(vint) [mtime(4) if fileFlags&0x0002]
            // [crc32(4) if fileFlags&0x0004] compInfo(vint) hostOS(vint)
            // nameLen(vint) name. Cosmetic: sanity-check the result.
            try
            {
                int p = pos;
                ulong fileFlags = ReadVint(body, ref p);
                ReadVint(body, ref p);  // unpacked size
                ReadVint(body, ref p);  // attributes
                if ((fileFlags & 0x0002UL) != 0) p += 4;   // mtime
                if ((fileFlags & 0x0004UL) != 0) p += 4;   // data CRC32
                ReadVint(body, ref p);  // compression info
                ReadVint(body, ref p);  // host OS
                ulong nameLen = ReadVint(body, ref p);
                if (nameLen > 0 && nameLen < 1024 && p + (int)nameLen <= extraStart && p + (int)nameLen <= body.Length)
                {
                    string name = System.Text.Encoding.UTF8.GetString(body, p, (int)nameLen);
                    bool printable = name.Length > 0;
                    foreach (char c in name) if (c < 0x20 || c == 0x7F) { printable = false; break; }
                    if (printable) return name;
                }
            }
            catch { }
            return null;
        }

        // FHEXTRA_CRYPT body: version(vint) flags(vint) lg2(1) salt(16)
        // iv(16) [check(8) csum(4) when flags bit0]. The HEAD_CRYPT variant
        // has the same fields minus the IV.
        private static Rar5CryptInfo ParseRar5CryptBody(byte[] body, int pos, bool hasIv, bool headerEnc, string entryName)
        {
            try
            {
                int p = pos;
                ulong version = ReadVint(body, ref p);
                if (version != 0) return null;
                ulong flags = ReadVint(body, ref p);
                byte lg2 = body[p]; p += 1;
                if (lg2 > 24) return null;
                if (p + 16 > body.Length) return null;
                byte[] salt = new byte[16];
                Array.Copy(body, p, salt, 0, 16); p += 16;
                if (hasIv) p += 16;
                byte[] check = null;
                if ((flags & 0x0001UL) != 0)
                {
                    if (p + 12 > body.Length) return null;
                    check = new byte[8];
                    Array.Copy(body, p, check, 0, 8);
                    byte[] csum = new byte[4];
                    Array.Copy(body, p + 8, csum, 0, 4);
                    // integrity of the stored check: sha256(check)[0..3]
                    byte[] dig = NativeCrypto.Sha256(check);
                    for (int i = 0; i < 4; i++) if (dig[i] != csum[i]) return null;
                }
                Rar5CryptInfo ci = new Rar5CryptInfo();
                ci.Salt = salt; ci.Lg2Count = lg2; ci.PswCheck = check; ci.HeaderEncrypted = headerEnc;
                ci.EntryName = entryName;
                return ci;
            }
            catch { return null; }
        }

        private static ulong ReadVint(BinaryReader br)
        {
            ulong value = 0; int shift = 0;
            while (true)
            {
                int b = br.ReadByte();
                value |= ((ulong)(b & 0x7F)) << shift;
                if ((b & 0x80) == 0) return value;
                shift += 7;
                if (shift > 63) throw new InvalidDataException("bad vint");
            }
        }

        private static ulong ReadVint(byte[] buf, ref int pos)
        {
            ulong value = 0; int shift = 0;
            while (true)
            {
                if (pos >= buf.Length) throw new InvalidDataException("bad vint");
                int b = buf[pos++];
                value |= ((ulong)(b & 0x7F)) << shift;
                if ((b & 0x80) == 0) return value;
                shift += 7;
                if (shift > 63) throw new InvalidDataException("bad vint");
            }
        }

        // ---- ZIP ----------------------------------------------------------
        private static ZipTargetInfo ParseZip(string path)
        {
            using (FileStream fs = File.OpenRead(path))
            {
                if (fs.Length < 22) return null;
                byte[] tail = new byte[66000];
                long tailStart = Math.Max(0, fs.Length - tail.Length);
                fs.Seek(tailStart, SeekOrigin.Begin);
                int tailLen = fs.Read(tail, 0, tail.Length);
                int eocd = -1;
                for (int i = tailLen - 22; i >= 0; i--)
                {
                    if (tail[i] == 0x50 && tail[i + 1] == 0x4B && tail[i + 2] == 0x05 && tail[i + 3] == 0x06)
                    { eocd = i; break; }
                }
                if (eocd < 0) return null;
                ushort entryCount = BitConverter.ToUInt16(tail, eocd + 10);
                uint cdSize = BitConverter.ToUInt32(tail, eocd + 12);
                // the EOCD stores absolute offsets; subtract what lies before
                // them so archives with a prepended stub (SFX) still parse
                long eocdFilePos = tailStart + eocd;
                long cdOffset = BitConverter.ToUInt32(tail, eocd + 16);
                long baseOffset = eocdFilePos - (long)(cdSize + cdOffset);
                if (baseOffset < 0) baseOffset = 0;
                cdOffset += baseOffset;

                ZipTargetInfo best = null;
                long pos = cdOffset;
                for (int n = 0; n < entryCount; n++)
                {
                    if (pos + 46 > fs.Length) break;
                    fs.Seek(pos, SeekOrigin.Begin);
                    byte[] cde = new byte[46];
                    if (ReadFull(fs, cde) != 46) break;
                    if (cde[0] != 0x50 || cde[1] != 0x4B || cde[2] != 0x01 || cde[3] != 0x02) break;
                    ushort flags = BitConverter.ToUInt16(cde, 8);
                    ushort method = BitConverter.ToUInt16(cde, 10);
                    ushort dostime = BitConverter.ToUInt16(cde, 12);
                    uint crc = BitConverter.ToUInt32(cde, 16);
                    uint compSize = BitConverter.ToUInt32(cde, 20);
                    ushort nameLen = BitConverter.ToUInt16(cde, 28);
                    ushort extraLen = BitConverter.ToUInt16(cde, 30);
                    ushort commentLen = BitConverter.ToUInt16(cde, 32);
                    uint localOffset = BitConverter.ToUInt32(cde, 42);
                    byte[] nameBuf = new byte[nameLen];
                    if (ReadFull(fs, nameBuf) != nameLen) break;
                    byte[] extraBuf = new byte[extraLen];
                    if (extraLen > 0 && ReadFull(fs, extraBuf) != extraLen) break;
                    string name = System.Text.Encoding.UTF8.GetString(nameBuf);

                    if ((flags & 0x0001) != 0 && compSize > 0)
                    {
                        ZipTargetInfo cand = BuildZipTarget(path, baseOffset + localOffset, nameLen, extraLen, flags, method,
                            dostime, crc, compSize, name, extraBuf);
                        if (cand != null && IsBetter(cand, best)) best = cand;
                    }
                    pos += 46 + nameLen + extraLen + commentLen;
                    if (cdSize > 0 && pos > cdOffset + cdSize) break;
                }
                return best;
            }
        }

        private static bool IsBetter(ZipTargetInfo cand, ZipTargetInfo best)
        {
            // AES beats ZipCrypto (conclusive 16-bit check + MAC); inside a
            // class prefer the smallest entry so a hit confirms cheaply.
            if (best == null) return true;
            if (cand.Aes != best.Aes) return cand.Aes;
            return cand.CompDataSize < best.CompDataSize;
        }

        private static ZipTargetInfo BuildZipTarget(string path, long localOffset, int centralNameLen,
            int centralExtraLen, ushort flags, ushort method, ushort dostime, uint crc, uint compSize,
            string name, byte[] centralExtra)
        {
            try
            {
                // resolve the local header: local name/extra lengths may
                // differ from the central copy, and the data offset depends
                // on the LOCAL values
                byte[] lh = new byte[30];
                using (FileStream fs = File.OpenRead(path))
                {
                    fs.Seek(localOffset, SeekOrigin.Begin);
                    if (ReadFull(fs, lh) != 30) return null;
                    if (lh[0] != 0x50 || lh[1] != 0x4B || lh[2] != 0x03 || lh[3] != 0x04) return null;
                    ushort localNameLen = BitConverter.ToUInt16(lh, 26);
                    ushort localExtraLen = BitConverter.ToUInt16(lh, 28);
                    long dataStart = localOffset + 30 + localNameLen + localExtraLen;

                    // AES extra field: look in the central extra first
                    bool aes = false; int strength = 0;
                    byte[] extra = centralExtra;
                    int i = 0;
                    while (i + 4 <= extra.Length)
                    {
                        ushort id = BitConverter.ToUInt16(extra, i);
                        ushort sz = BitConverter.ToUInt16(extra, i + 2);
                        if (id == 0x9901 && sz >= 7)
                        {
                            int st = extra[i + 8];
                            if (st >= 1 && st <= 3) { aes = true; strength = st; }
                            break;
                        }
                        i += 4 + sz;
                    }

                    ZipTargetInfo t = new ZipTargetInfo();
                    t.Name = name; t.Method = method; t.Crc32 = crc;
                    if (aes)
                    {
                        int saltLen = strength == 1 ? 8 : (strength == 2 ? 12 : 16);
                        if (compSize < saltLen + 12) return null;
                        byte[] head = new byte[saltLen + 2];
                        fs.Seek(dataStart, SeekOrigin.Begin);
                        if (ReadFull(fs, head) != head.Length) return null;
                        t.Aes = true; t.AesStrength = strength;
                        t.EncHeader = head;                       // salt(8/12/16)+PV(2)
                        t.DataStart = dataStart + saltLen + 2;
                        t.CompDataSize = compSize - saltLen - 12;
                        byte[] mac = new byte[10];
                        fs.Seek(t.DataStart + t.CompDataSize, SeekOrigin.Begin);
                        if (ReadFull(fs, mac) != 10) return null;
                        t.Mac = mac;
                        return t;
                    }
                    else
                    {
                        if (method != 0 && method != 8) return null;
                        byte[] eh = new byte[12];
                        fs.Seek(dataStart, SeekOrigin.Begin);
                        if (ReadFull(fs, eh) != 12) return null;
                        t.Aes = false;
                        t.EncHeader = eh;
                        // when bit3 (data descriptor) is set the CRC in the
                        // header is zero and the check byte uses the DOS time
                        t.CheckByte = (byte)(((flags & 0x0008) != 0 ? (uint)(dostime >> 8) : (crc >> 24)) & 0xFF);
                        t.DataStart = dataStart + 12;
                        t.CompDataSize = compSize - 12;
                        return t;
                    }
                }
            }
            catch { return null; }
        }

        internal static int ReadFull(Stream s, byte[] buf)
        {
            int total = 0;
            while (total < buf.Length)
            {
                int n = s.Read(buf, total, buf.Length - total);
                if (n <= 0) break;
                total += n;
            }
            return total;
        }
    }
}
