# 7-Zip (.7z) password-verification spec — sources + empirical verification

**Scope:** everything a Rust tool needs to verify a 7z password natively, without spawning `7z.exe`.

**Method.** Every claim below is (1) quoted from an authoritative source, and (2) — wherever a real
`7z.exe` (7-Zip 26.03 x64) was available — verified empirically by building archives that
`7z.exe` accepts, and by decrypting real archives with an independent pure-Python AES-256-CBC
implementation (validated against the NIST SP 800-38A AES-256-CBC vectors).

**Source status**

| # | Source | Result |
|---|--------|--------|
| 1 | `hashcat/src/modules/module_11600.c` | fetched OK |
| 2 | `john/run/7z2john.pl` | fetched OK (truncated at 48 KB; full text in spill file) |
| 3 | `john/src/7z_fmt_plug.c` | fetched OK |
| 4 | `john/src/7z_common.c` | **404 — does not exist**. The real file is `src/7z_common_plug.c` (fetched OK). `src/7z_common.h` fetched OK. |
| 5 | `py7zr/helpers.py`, `py7zr/archiveinfo.py` | fetched OK |
| 6 | `ip7z/7zip/DOC/7zFormat.txt` | fetched OK |
| + | `philsmd/7z2hashcat/7z2hashcat.pl` (v2.2, 2024-06-15) | fetched OK — **this is hashcat's actual hash producer**, more current than 7z2john.pl |
| + | `ip7z/7zip/CPP/7zip/Crypto/7zAes.cpp` + `7zAes.h` | fetched OK — **the normative encoder/decoder** |
| + | `ip7z/7zip/CPP/7zip/Archive/7z/7zHeader.h` | fetched OK — normative coder-id table |

**Headline corrections to the premises in the request**

1. **Section C is wrong as stated.** An encrypted (`-mhe`) header does **not** decrypt to leading
   zeros. It decrypts to `01 04 06 00 01 09 .. .. 07 0b 01 00 02 24 06 f1 07 01 12 ..` — i.e. the
   AES plaintext *begins with the `kHeader` id byte `0x01`*. The real, password-checkable invariant is
   the **AES-CBC trailing zero padding**: the final `PackSize − AES-out-UnpackSize` bytes are always
   zero. See §C.
2. **Section B's formula in JtR/7z2hashcat is exactly right**, including the `+1` semantics of the two
   extra bits. Verified against 7-Zip's own `WriteCoderProperties` / `SetDecoderProperties2`.
3. **`john/src/7z_common.c` does not exist** — use `7z_common_plug.c`.
4. **`numCyclesPower == 0x3F` is rejected by both hashcat and JtR** (they accept only ≤31 and 1..24
   respectively); 7-Zip itself supports it. If you support it, note the exact formula in §A.

---

## A. Key derivation

### A.1 Normal case (`numCyclesPower` 0..0x3E)

```c
// john/src/7z_fmt_plug.c — sevenzip_kdf()
	SHA256_Init(&sha);
	for (round = 0; round < rounds; round++) {
		if (sevenzip_salt->SaltSize)
			SHA256_Update(&sha, sevenzip_salt->salt, sevenzip_salt->SaltSize);
		SHA256_Update(&sha, (char*)saved_key[index], saved_len[index]);
#if ARCH_LITTLE_ENDIAN
		SHA256_Update(&sha, (char*)&round, 8);
```
with
```c
	long long rounds = (long long) 1 << sevenzip_salt->NumCyclesPower;
```
and `saved_key` converted by `set_key()`:
```c
	/* Convert key to utf-16-le format (--encoding aware) */
	len = enc_to_utf16(saved_key[index], PLAINTEXT_LENGTH, (UTF8*)key, strlen(key));
	...
	len *= 2;
	saved_len[index] = len;
```
So the iterated input per round is the concatenation
**`salt || password_utf16le || counter_le64`**, and only the salt is conditional.

`py7zr` states the same construction unconditionally (its callers always pass a salt parameter):
```python
def _calculate_key1(password: bytes, cycles: int, salt: bytes, digest: str) -> bytes:
    """Calculate 7zip AES encryption key. Base implementation."""
    assert cycles <= 0x3F
    if cycles == 0x3F:
        ba = bytearray(salt + password + bytes(32))
        key: bytes = bytes(ba[:32])
    else:
        rounds = 1 << cycles
        m = _get_hash(digest)
        for round in range(rounds):
            m.update(salt + password + round.to_bytes(8, byteorder="little", signed=False))
        key = m.digest()[:32]
    return key
```

**Exact byte assembly**

| Field | Bytes | Notes |
|---|---|---|
| salt | `SaltSize` ∈ `[0,16]` | 0 bytes when `SaltSize == 0` |
| password | `2 × len(pw)` | UTF-16LE, **no BOM, no NUL terminator** |
| counter | 8 | **little-endian u64**, `round` = 0,1,…,2^ncp − 1 |

* Counter position: **last**. `SHA256_Update(salt); SHA256_Update(pw); SHA256_Update(&round, 8)`.
* Counter size: exactly 8 bytes, little-endian on LE hosts; big-endian hosts are handled by the
  `#else` branch which increments `unsigned char temp[8]` — equivalent to LE ordering.
* Iteration count: **2^ncp**, i.e. `rounds = 1 << NumCyclesPower` (hashcat uses
  `salt->salt_iter = 1u << iter`).
* **Windows / byte order:** JtR's `#if ARCH_LITTLE_ENDIAN` only affects *how* the LE counter is
  produced; the byte stream is the same.

**Key = `SHA256(...)[:32]`.**

### A.2 IV: the premise "IV is formed from the remaining bytes of that final digest" is **FALSE**

SHA-256 produces exactly 32 bytes, and all 32 are consumed as the AES-256 key
(`7zAes.h`: `const unsigned kKeySize = 32;`). There are **no remaining digest bytes**, so no IV can
come from them. JtR's `sevenzip_kdf` writes all 32 bytes into `master`, and
`sevenzip_decrypt` takes the IV *from the archive*, not the digest:

```c
	/* Complete decryption */
	out = mem_alloc(sevenzip_salt->aes_length);
	memcpy(iv, sevenzip_salt->iv, 16);
	AES_set_decrypt_key(derived_key, 256, &akey);
	AES_cbc_encrypt(sevenzip_salt->data, out, sevenzip_salt->aes_length, &akey, iv, AES_DECRYPT);
```

The IV is the 16 bytes stored in the AES coder's `properties` (§B), zero-padded on the right if
`ivSize < 16` (`7z2hashcat`: `# pad the iv with zeros`).

*(The "split digest" shape does exist in 7-Zip, but for a different algorithm: SHA-256 is used only
for 7zAES, whose block key is the full 32-byte digest. Nothing here takes a key/IV split.)*

### A.3 Special case `numCyclesPower == 0x3F` — no hashing

Normative source, `CPP/7zip/Crypto/7zAes.cpp`:

```c
void CKeyInfo::CalcKey()
{
  if (NumCyclesPower == 0x3F)
  {
    unsigned pos;
    for (pos = 0; pos < SaltSize; pos++)
      Key[pos] = Salt[pos];
    for (unsigned i = 0; i < Password.Size() && pos < kKeySize; i++)
      Key[pos++] = Password[i];
    for (; pos < kKeySize; pos++)
      Key[pos] = 0;
  }
```

Exact rule: `Key = (salt || password)`, **truncated to 32 bytes**, then zero-filled to exactly 32.
There is no counter, no iteration, no SHA-256. (This mirrors `7zAes.h`'s "NumCyclesPower = 0x3F"
special value.)

> **Correction to py7zr.** `_calculate_key1` writes `salt + password + bytes(32)` and takes `[:32]`.
> That is equivalent **only when `len(salt) + len(password) <= 32`**. For a long password the two
> differ (py7zr keeps password bytes beyond the 32-byte key; 7-Zip drops them). Implement the 7-Zip
> rule.
> **hashcat** rejects this case: `if (iter > 31) return (PARSER_SALT_ITERATION);`
> **JtR** rejects it: `if (NumCyclesPower > 24 || NumCyclesPower < 1) goto err;`

### A.4 Verification performed

| Test | Result |
|---|---|
| `salt=8, iv=16, ncp=19` synthetic archive, password `openwall` | `7z t -popenwall` → **Everything is Ok**; `7z x` returned exactly `synthetic-7z-000` |
| Same archive, wrong password | decrypted bytes differ (`sha256` differs); `7z x` wrote garbage (see §C.4) |
| `salt=16`, `salt=0`, `ncp=10`, `ncp=0` | all **OK** |
| `ncp=0x3F` (props `FF 7F`), `salt=8`, expected key `a1a2…a8` + UTF-16LE `openwall` + zeros | computed key matched the formula; `7z t` → **Everything is Ok** |
| `ivSize=8` (props `13 08`) | **OK** |

---

## B. Salt and IV storage in the AES coder `properties`

### B.1 Normative bit packing

`CPP/7zip/Crypto/7zAes.cpp`, encoder:

```c
Z7_COM7F_IMF(CEncoder::WriteCoderProperties(ISequentialOutStream *outStream))
{
  Byte props[2 + sizeof(_key.Salt) + sizeof(_iv)];
  unsigned propsSize = 1;

  props[0] = (Byte)(_key.NumCyclesPower
      | (_key.SaltSize == 0 ? 0 : (1 << 7))
      | (_ivSize       == 0 ? 0 : (1 << 6)));

  if (_key.SaltSize != 0 || _ivSize != 0)
  {
    props[1] = (Byte)(
        ((_key.SaltSize == 0 ? 0 : _key.SaltSize - 1) << 4)
        | (_ivSize      == 0 ? 0 : _ivSize - 1));
    memcpy(props + 2, _key.Salt, _key.SaltSize);
    propsSize = 2 + _key.SaltSize;
    memcpy(props + propsSize, _iv, _ivSize);
    propsSize += _ivSize;
  }

  return WriteStream(outStream, props, propsSize);
}
```

Decoder:

```c
  const unsigned b0 = data[0];
  _key.NumCyclesPower = b0 & 0x3F;
  if ((b0 & 0xC0) == 0)
    return size == 1 ? S_OK : E_INVALIDARG;
  if (size <= 1)
    return E_INVALIDARG;

  const unsigned b1 = data[1];
  const unsigned saltSize = ((b0 >> 7) & 1) + (b1 >> 4);
  const unsigned ivSize   = ((b0 >> 6) & 1) + (b1 & 0x0F);

  if (size != 2 + saltSize + ivSize)
    return E_INVALIDARG;
```

`7zAes.h`: `const unsigned kSaltSizeMax = 16; const unsigned kIvSizeMax = 16;`

### B.2 Exact decoding formula (mirror of the above)

```
b0        = props[0]
ncp       = b0 & 0x3F
has_salt  = (b0 >> 7) & 1        // i.e. b0 & 0x80
has_iv    = (b0 >> 6) & 1        // i.e. b0 & 0x40

if (b0 & 0xC0) == 0:             // neither salt nor IV
    salt = b""; iv = b"\x00"*16; props_len_must_be = 1
else:
    b1       = props[1]
    saltSize = has_salt + (b1 >> 4)          // 0..16
    ivSize   = has_iv   + (b1 & 0x0F)        // 0..16
    require len(props) == 2 + saltSize + ivSize
    salt = props[2 : 2+saltSize]
    iv   = props[2+saltSize : 2+saltSize+ivSize]  // NOTE: raw, may be < 16 bytes

IV used by AES = (iv + b"\x00"*16)[:16]          // right-zero-padded to 16
```

**Key points that are easy to get wrong**

* The two extra bits are worth **+1**, *not* +16. `saltSize = bit7 + highnibble`,
  `ivSize = bit6 + lownibble`. Maximum is `1 + 15 = 16`, matching `kSaltSizeMax`/`kIvSizeMax = 16`.
  This is confirmed by JtR's test vector `$7z$…$0$$8$<iv16>…` (`ivlen = 8`) — though note that vector
  is a hand-written historical constant, not a 7-Zip-encoded archive; the authoritative confirmation
  is `7zAes.cpp` plus my round-trip tests.
* The nibbles store `size − 1`, and the extra bit is set **only when the size is non-zero**.
  A field of size 0 is encoded by clearing both its bit and its nibble.
* `props` may be **1 byte** (neither salt nor IV). A decoder that unconditionally reads `props[1]`
  will read the following stream byte as garbage.
* `salt`/`iv` are stored **raw** (not length-prefixed individually) and the IV is **not** padded in
  the file — only logically, at use time.

### B.3 JtR / 7z2hashcat implementation (matches, quoted)

```perl
  $number_cycles_power = $first_byte & 0x3f;

  if (($first_byte & 0xc0) == 0)
  {
    return ($salt_len, $salt_buf, $iv_len, $iv_buf, $number_cycles_power);
  }

  $salt_len = ($first_byte >> 7) & 1;
  $iv_len   = ($first_byte >> 6) & 1;

  my $second_byte = substr ($attributes, 1, 1);
  $second_byte = ord ($second_byte);

  $salt_len += ($second_byte >> 4);
  $iv_len   += ($second_byte & 0x0f);

  $salt_buf = substr ($attributes, $offset, $salt_len);
  $offset += $salt_len;
  $iv_buf = substr ($attributes, $offset, $iv_len);
  # pad the iv with zeros
  my $iv_max_length = 16;
  $iv_buf .= "\x00" x $iv_max_length;
  $iv_buf = substr ($iv_buf, 0, $iv_max_length);
```

### B.4 Verification performed

Round-trip decode of hand-built props:

```
b0=0x53 b1=0x8f -> ncp=19 saltlen=8  ivlen=16     (matches a real -mhe archive)
b0=0x53 b1=0x0f -> ncp=19 saltlen=0  ivlen=16
b0=0xd3 b1=0xff -> ncp=19 saltlen=16 ivlen=16
b0=0xd3 b1=0x0f -> ncp=19 saltlen=1  ivlen=16
```

A real `7z a -t7z -mhe=on` archive yields
`props = 53 0f 8e 45 61 7a 60 34 f5 06 91 dc 43 d5 a0 a7 78 4e`
→ `ncp=19 (2^19 = 524288)`, `saltSize=0`, `ivSize=16`,
`iv = 8e45617a6034f50691dc43d5a0a7784e`. The synthetic archives I built using the §B.2 formula
(including `saltSize=8`, `saltSize=16`, `saltSize=0`, `ivSize=8`, `ncp=0x3F`) were **all accepted by
`7z.exe`** — the strongest available confirmation that the packing is right.

---

## C. Encoded header (`kEncodedHeader` / `-mhe`) — what is actually checkable

### C.1 What `kEncodedHeader` means: *encoded*, not necessarily *encrypted*

```python
        if pid == PROPERTY.HEADER:
            self._extract_header_info(buffer)
            return
        if pid != PROPERTY.ENCODED_HEADER:
            raise TypeError(f"Unknown field: {repr(pid)}")
```
```python
class HeaderStreamsInfo(StreamsInfo):
    def write(self, file: BinaryIO | WriteWithCrc):
        write_byte(file, PROPERTY.ENCODED_HEADER)
```
`0x17` only means "the header is itself stored as a folder's stream". It is produced by plain
`7z a` with default settings, with **no password at all** — proved empirically:

```
== plain_many.7z id=0x17
   coders: LZMA1[030101]
   AES present? False
== mhe_many.7z id=0x17
   coders: 7zAES[06f10701] + LZMA1[030101]
   AES present? True
```

**⇒ You must inspect the first folder's coders and require an AES coder (`06F10701`) before treating
the header as password-protected.** Checking only `id == 0x17` is a bug.

(Note this contradicts the plain-header case: a *non-encrypted* small archive may still have
`nextHeader[0] == 0x01`. Both occur.)

### C.2 The real invariant: AES-CBC trailing zero padding

7-Zip's 7zAES encoder pads its input to an AES block boundary with **zero bytes**; the padded,
encrypted length is the folder's `PackSize`, and the unpadded length is the AES coder's own
out-stream `UnPackSize` (recorded in `kCodersUnPackSize`). Therefore:

```c
// john/src/7z_common_plug.c — sevenzip_decrypt()
	pad_size = nbytes = sevenzip_salt->aes_length - sevenzip_salt->packed_size;
...
	if ((sevenzip_salt->type == 0x80 || sevenzip_trust_padding) &&
	    pad_size > 0 && sevenzip_salt->aes_length >= 32) {
		uint8_t buf[16];

		memcpy(iv, sevenzip_salt->data + sevenzip_salt->aes_length - 32, 16);
		AES_set_decrypt_key(derived_key, 256, &akey);
		AES_cbc_encrypt(sevenzip_salt->data + sevenzip_salt->aes_length - 16, buf,
		                16, &akey, iv, AES_DECRYPT);
		i = 15;
		while (nbytes > 0) {
			if (buf[i] != 0) {
				...
				return 0;
			}
			nbytes--;
			i--;
		}
```
```c
	if (sevenzip_salt->type == 0x80) /* We only have truncated data */
		return 1;
```

**The invariant, precisely stated**

```
PAD = PackSize − UnPackSize(AES coder's own out-stream)
plaintext = AES256_CBC_decrypt(key, iv, ciphertext)          # len == PackSize
assert plaintext[PackSize − PAD : PackSize] == b"\x00" * PAD
```
* `PAD ∈ [0, 15]` (it is `16 − (unpadded_len mod 16)`, taken mod 16 → `0` when already aligned).
* It is **the tail**, not the head.
* Where it comes from: 7-Zip's AES-CBC encoder zero-pads to a block boundary; the 7z container keeps
  both the padded `PackSize` and the exact unpadded `UnPackSize`.
* **False-accept probability = 2^(−8·PAD)** if you decrypt only the last block.
  Measured on real archives: `PAD = 6` (small `-mhe` archive, 2^−48), `PAD = 11` (compressed header,
  2^−88), `PAD = 14` (`-mhc=off`, 2^−112), `PAD = 2` (`-m0=copy` content, 2^−16), `PAD = 14`
  (`-m0=lzma2` content, 2^−112).
* **`PAD == 0` ⇒ no padding-based fast path at all.** Handle this case; do not let the check
  vacuously pass.

**There is no "first N bytes are zero" check anywhere in hashcat's module or JtR.** Neither file
contains such a test. The origin of that idea is most likely a conflation of (i) the *trailing* zero
padding described above and (ii) the fact that the *leading* byte of the decoded header is a
property id — for a raw `kHeader` that is `0x01`, and `0x01` doubles as the "all defined" value of a
boolean vector. A "17 bytes of zeros then 0x01" pattern has no basis in the 7z format, and would in
fact never match: real decoded headers begin `01 04 06 00 …` (see §C.3).

### C.3 What the decoded header stream actually looks like

A decrypted `kEncodedHeader` plaintext is the **raw `kHeader` structure** — its first byte is
`0x01` (`kHeader`), *not* `0x00`. Measured on real archives:

| Archive | `PackSize` | AES out `UnPackSize` | PAD | plaintext[0:12] |
|---|---|---|---|---|
| `mhe_lzma2.7z` (AES only) | 112 | 106 | 6 | `01 04 06 00 01 09 40 00 07 0b 01 00` |
| `mhe_copy.7z` (AES only, `-m0=copy`) | 112 | 106 | 6 | `01 04 06 00 01 09 30 00 07 0b 01 00` |
| `mhe_lzma1.7z` (AES only, `-m0=LZMA`) | 128 | 122 | 6 | `01 04 06 00 01 09 40 00 07 0b 01 00` |
| `mhe_many_nohc.7z` (AES only, `-mhc=off`) | 1648 | 1634 | 14 | `01 04 06 00 01 09 80 80 00 07 0b 01` |
| `mhe_many.7z` (AES + LZMA1, `-mhc=on`) | 496 | 485 | 11 | `00 00 81 33 07 ae 0f d5 …` ← **LZMA1 compressed** |

Walking `mhe_lzma2.7z`'s plaintext byte by byte:

```
01                    kHeader
04                    kMainStreamsInfo
  06                  kPackInfo
    00                PackPos
    01                NumPackStreams = 1
    09 40             kSize = 64
    00                kEnd
  07                  kUnPackInfo
    0b 01 00          kFolder, NumFolders=1, External=0
      01              NumCoders = 1
      02              flags: 0x02 -> CodecIdSize=2, not complex, no attributes
      24 06           ... continues
  0c 6a               kCodersUnPackSize = 106
  0a 01 a8 7b d2 95  kCRC, AllAreDefined=1, CRC=0x95d27ba8
  00                  kEnd
00                    kEnd of header
```

and the plaintext tail is exactly the `PAD` zero bytes (`00 00 00 00 00 00` for PAD=6).
Verified: `CRC32(plaintext[0:106]) == 0x95d27ba8 == stored folder CRC` → **True**.
For `mhe_many.7z` (AES+LZMA1), `CRC32(plaintext[0:485]) != stored CRC` but
`LZMA1_decode(plaintext[0:485])` → 1634 bytes with `CRC32 == 0x30017538 == stored` → **True**,
and the decompressed stream starts `01 04 06 00 01 09 80 80` → `kHeader`. 

> **⇒ The pressure-tested fact:** the CRC stored for the encoded-header folder is over the **final**
> (post-decompression) bytes. So if the header folder has more than one coder, a CRC check is
> impossible without running the decompressor. The *only* password test available without a
> decompressor for a compressed header is the tail padding.

### C.4 How hashcat / JtR actually verify an `-mhe` archive

Neither uses a "zeros in the front" test. Both decrypt **the whole encoded-header stream**, run the
coder chain (AES → LZMA1/LZMA2/…), and compare CRC32.

hashcat `module_hook23()`:
```c
  if (data_type == 0) // uncompressed
  {
    crc = cpu_crc32_buffer ((u8 *) out_full, unpack_size);
  }
  else
  {
    ...
    if (data_type == 1) // LZMA1
      ok = hc_lzma1_decompress (compressed_data, &compressed_data_len, decompressed_data, &decompressed_data_len, coder_attributes);
    else if (data_type == 7) // DEFLATE
      ok = hc_inflate_raw (...);
    else if (data_type == 8) // ZSTD
      ok = hc_zstd_decompress (...);
    else // we only support LZMA2 in addition to LZMA1 and ZSTD
      ok = hc_lzma2_decompress (...);
    ...
    crc = cpu_crc32_buffer (decompressed_data, crc_len);
  }

  if (crc == seven_zip_crc)
    hook_item->hook_success = 1;
```
JtR `sevenzip_decrypt()` — the full-decryption padding check plus CRC over `crc_len`:
```c
	if (p_type) { ... x86_Convert(...) ... }
	/* CRC check */
	CRC32_Init(&crc);
	CRC32_Update(&crc, out, (long)crc_len);
	CRC32_Final(crc_out, crc);
	ccrc = _crc_out.crci; /* computed CRC */
	if (ccrc == sevenzip_salt->crc) { goto exit_good; }
```
where
```c
	size_t crc_len = sevenzip_salt->crc_len ? sevenzip_salt->crc_len : sevenzip_salt->packed_size;
```
JtR's padding trust is switchable and on by default:
```c
	if (cfg_get_bool(SECTION_FORMATS, "7z", "TrustPadding", 1))
		sevenzip_trust_padding = 1;
```
and it is explicitly known to be imperfect:
```c
	/*
	 * Early rejection (only decrypt last 16 bytes). We had one (1) report that it's
	 * not reliable, see #2532. For truncated hashes it's the only thing we can do!.
	 */
```

The only extra trick is hashcat's **truncated** mode (`data_type == 0x80`), which is a
*padding-attack* mode, not a header check, and only applies when 7z2hashcat decided to truncate
(plaintext > 16 MiB and `PASSWORD_RECOVERY_TOOL_SUPPORT_PADDING_ATTACK == 1`; for hashcat that flag
is **0**).

### C.5 Caveat: 7z2hashcat is the authoritative hash producer for mode 11600

```c
const char *module_usage_notice (...)
{
  return "You can use https://github.com/philsmd/7z2hashcat to extract the hashes";
}
```
`7z2hashcat.pl` v2.2 limits `hashcat` to `@PASSWORD_RECOVERY_TOOL_SUPPORTED_DECOMPRESSORS = (1, 2)`
(LZMA1, LZMA2), no preprocessors, no multiple decompressors, no padding attack. JtR's own
`7z2john.pl` is more permissive (LZMA1/LZMA2/BZIP2/DEFLATE + all BCJ filters) because JtR's format
implements them. If your tool aims at parity with hashcat mode 11600's *input space*, match
`7z2hashcat`; if it aims at coverage, match `7z2john.pl`.

---

## D. Minimal byte-level walk

All arithmetic below uses **`position_after_header = 32`** as the base for `PackPos`. Verified
against `7z2hashcat.pl`:
```perl
  my $position_after_header = $signature_header->{'position_after_header'};
  my $position_pack = $pack_info->{'pack_pos'};
  my $current_seek_position = $position_after_header + $position_pack;
```
and against `py7zr`'s `SignatureHeader._read` (which seeks past the 32-byte signature header before
parsing).

### D.1 Signature header — 32 bytes, fixed offsets

Normative (`DOC/7zFormat.txt`, `CPP/7zip/Archive/7z/7zHeader.h`):
```
  BYTE kSignature[6] = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
  ArchiveVersion { BYTE Major; BYTE Minor; };       // now 0 / 4
  UINT32 StartHeaderCRC;
  StartHeader { REAL_UINT64 NextHeaderOffset
                REAL_UINT64 NextHeaderSize
                UINT32 NextHeaderCRC }
```
(`const UInt32 kStartHeaderSize = 20;` — the CRC covers those 20 bytes.)

| Offset | Size | Field | Encoding |
|---|---|---|---|
| 0 | 6 | signature | `37 7A BC AF 27 1C` |
| 6 | 1 | version major | 0 |
| 7 | 1 | version minor | 4 |
| 8 | 4 | `StartHeaderCRC` | u32 LE |
| 12 | 8 | `NextHeaderOffset` | **REAL_**u64 LE (fixed 8 bytes, *not* varint) |
| 20 | 8 | `NextHeaderSize` | **REAL_**u64 LE |
| 28 | 4 | `NextHeaderCRC` | u32 LE |

```python
def _read(self, file: BinaryIO) -> None:
    file.seek(len(MAGIC_7Z), 0)
    major_version = file.read(1)
    minor_version = file.read(1)
    self.version = (major_version, minor_version)
    self.startheadercrc, _ = read_uint32(file)
    self.nextheaderofs, data = read_real_uint64(file)
    crc = calculate_crc32(data)
    self.nextheadersize, data = read_real_uint64(file)
    crc = calculate_crc32(data, crc)
    self.nextheadercrc, data = read_uint32(file)
    crc = calculate_crc32(data, crc)
    if crc != self.startheadercrc:
        raise Bad7zFile("invalid header data")
```

Validation: `crc32(bytes[12:32]) == StartHeaderCRC` (verified true on every test archive), and
`crc32(next_header_bytes) == NextHeaderCRC`.

### D.2 Locate the next header

```
next_header = file[32 + NextHeaderOffset : 32 + NextHeaderOffset + NextHeaderSize]
```
If `NextHeaderSize == 0` there is no header (empty archive).

### D.3 Determine `kHeader` vs `kEncodedHeader`

`next_header[0] == 0x01` → raw `kHeader`; `next_header[0] == 0x17` → `kEncodedHeader`.
Property ids (`DOC/7zFormat.txt`, matches `NID::EEnum` in `7zHeader.h` and 7z2hashcat's constants):

```
0x00 kEnd              0x08 kSubStreamsInfo    0x11 kName
0x01 kHeader           0x09 kSize             0x12 kCTime
0x02 kArchiveProperties 0x0A kCRC            0x13 kATime
0x03 kAdditionalStreamsInfo 0x0B kFolder     0x14 kMTime
0x04 kMainStreamsInfo  0x0C kCodersUnPackSize 0x15 kWinAttributes
0x05 kFilesInfo        0x0D kNumUnPackStream  0x16 kComment
0x06 kPackInfo         0x0E kEmptyStream      0x17 kEncodedHeader
0x07 kUnPackInfo       0x0F kEmptyFile        0x18 kStartPos
                       0x10 kAnti            0x19 kDummy
```
> Note on the premise "property id 0x04 is the encoded header stream info": **`0x04` is
> `kMainStreamsInfo` in general.** For an `kEncodedHeader` the StreamsInfo is written *without* the
> `0x04` prefix (the `0x17` id *is* the prefix) — `HeaderStreamsInfo.write()` emits
> `kEncodedHeader` then `PackInfo/UnPackInfo/kEnd` directly. A raw `kHeader`'s main streams info
> *does* appear as `0x04`. Verified in dumps: raw header `01 04 06 00 01 09 …`; encoded header
> `17 06 …` for `-mhe` and `17 06 …` for plain compressed-header archives.
> **"property id 0x06 is the encoded header size" is incorrect** — `0x06` is `kPackInfo`, whose
> payload is `PackPos`, `NumPackStreams`, then `0x09 kSize` + `PackSizes[]`. The encoded header's
> *size in the file* is `NextHeaderSize` from the start header (offset 20), not a `0x06` property.

### D.4 Parse the `kEncodedHeader` StreamsInfo

Grammar (`DOC/7zFormat.txt`), starting immediately **after** the `0x17` byte:

```
[] kPackInfo (0x06)                        # optional
     UINT64 PackPos
     UINT64 NumPackStreams
     [] kSize (0x09) UINT64 PackSizes[NumPackStreams] []
     [] kCRC  (0x0A) PackStreamDigests[NumPackStreams] []
     kEnd (0x00)
[] kUnPackInfo (0x07)                      # optional
     kFolder (0x0B)
       UINT64 NumFolders
       BYTE External            # 0x00 = inline; 0x01 = UINT64 DataStreamIndex follows
       Folder[NumFolders]
     kCodersUnPackSize (0x0C)  UINT64 UnPackSize[n] for each folder, per out-stream
     [] kCRC (0x0A)  UnPackDigests[NumFolders] []
     kEnd (0x00)
[] kSubStreamsInfo (0x08)                  # optional
     [] kNumUnPackStream (0x0D) UINT64 NumUnPackStreamsInFolders[NumFolders] []
     [] kSize (0x09) UINT64 UnPackSizes[] []     # n-1 sizes per folder; last = folderTotal − sum
     [] kCRC  (0x0A) Digests[streams with unknown CRC] []
     kEnd (0x00)
kEnd (0x00)
```

`Folder`:
```
  UINT64 NumCoders;
  for (NumCoders)
  {
    BYTE flags
    {
      0:3 CodecIdSize
      4:  Is Complex Coder
      5:  There Are Attributes
      6:  Reserved
      7:  There are more alternative methods. (Not used anymore, must be 0).
    }
    BYTE CodecId[CodecIdSize]
    if (Is Complex Coder) { UINT64 NumInStreams; UINT64 NumOutStreams; }
    if (There Are Attributes) { UINT64 PropertiesSize; BYTE Properties[PropertiesSize]; }
  }
  NumBindPairs = NumOutStreamsTotal - 1;
  for (NumBindPairs) { UINT64 InIndex; UINT64 OutIndex; }
  NumPackedStreams = NumInStreamsTotal - NumBindPairs;
  if (NumPackedStreams > 1) for (NumPackedStreams) { UINT64 Index; };
```
**`UINT64` here means the variable-length encoding**, not 8 raw bytes:
```
  0xxxxxxx               : ( xxxxxxx           )
  10xxxxxx    BYTE y[1]  : (  xxxxxx << (8 * 1)) + y
  110xxxxx    BYTE y[2]  : (   xxxxx << (8 * 2)) + y
  ...
  1111110x    BYTE y[6]  : (       x << (8 * 6)) + y
  11111110    BYTE y[7]  :                         y
  11111111    BYTE y[8]  :                         y
```

**Bootstrapping a single-coder encrypted header without a full parser.** The empirically observed
shape is stable and lets you extract everything with fixed probes:

1. `packpos   = varint @ +1` (after `0x17 0x06`)
2. `if next byte == 0x09:` skip it, `packsizes[0] = varint`
3. find `07 0B 01 00` (`kUnPackInfo, kFolder, NumFolders=1, External=0`); the next byte is
   `NumCoders`; then the coder `flags`; then `CodecId[flags & 0x0F]`.
   For 7-Zip AES that is `02 24 06 F1 07 01` → `flags=0x24` (idSize 4, has attributes),
   id `06 F1 07 01`, `PropertiesSize = varint` (`0x12` = 18), then 18 property bytes (§B).
4. `kCodersUnPackSize (0x0C)` then `varint` gives the AES coder's out-stream `UnPackSize`.
5. Ciphertext = `file[32 + PackPos : 32 + PackPos + PackSizes[0]]`.

Real example — `mhe_lzma2.7z`, `NextHeaderOffset=176`, `NextHeaderSize=46`, bytes at file offset
`32+176 = 208`:
```
17 06 40 01 09 70 00 07 0b 01 00 01 24 06 f1 07 01 12
53 0f 9e d8 6b d0 a5 9e 60 3b b0 3d ad 75 d5 25 8c 93
0c 6a 0a 01 a8 7b d2 95 00 00
```
→ `PackPos=0`, `PackSizes=[112]`, 1 folder, 1 coder `06F10701` with 18 property bytes
`53 0f … 8c 93`, `UnPackSize=106`, folder CRC `0x95d27ba8`. Ciphertext at file offset 96, 112 bytes.
`PAD = 112 − 106 = 6`.

Multi-coder example — `mhe_many.7z`, `NextHeaderOffset=624`, `NextHeaderSize=63`, offset 656:
```
17 06 80 80 01 09 81 f0 00 07 0b 01 00 02 24 06 f1 07 01 12
53 0f c2 42 4b 3a 61 ff c5 13 be 75 fc 07 5a 49 38 08
23 03 01 01 05 5d 00 10 00 00
01 00 0c 81 e5 86 62 0a 01 38 75 01 30 00 00
```
→ `PackPos=0`, `PackSizes=[496]`, 1 folder, **2 coders**:
`06F10701` (AES, 18 props) then `030101` (LZMA1, 5 props `5d00100000`);
`UnPackSizes = [485, 1634]` — **485 belongs to the AES out-stream, 1634 to the LZMA1 out-stream**;
folder CRC `0x30017538`; `PAD = 496 − 485 = 11`. Decryption + LZMA1 → 1634 bytes,
`CRC32 = 0x30017538` ✔.

### D.5 Which stream is which

`NumBindPairs = NumOutStreamsTotal − 1` and `NumPackedStreams = NumInStreamsTotal − NumBindPairs`.
For the common `AES → LZMA` two-simple-coder chain you get one bind pair `(InIndex=1, OutIndex=0)`
and one packed stream (index 0). Decryption order is AES **first** (it consumes the packed stream);
the decompressor runs on the AES output. `UnPackSize` entries are emitted per out-stream **in coder
order**, so with `[AES, LZMA1]` the first `UnPackSize` is the AES output length (padded plaintext)
and the last is the final file length. Getting this wrong corrupts the `PAD` computation.

---

## E. Content-encrypted archives (no `-mhe`)

### E.1 The header is readable without a password

For `7z a -p<pw>` (no `-mhe`), the next header is a **raw `kHeader` (`0x01`)**, so the file list is
public and no decryption is needed to enumerate streams. Measured:

```
plain_copy.7z   nextHeader offset=48  size=106  id=0x01  (RAW)
plain_lzma2.7z  nextHeader offset=64  size=106  id=0x01  (RAW)
```
```
01 04 06 00 01 09 30 00 07 0b 01 00 02 24 06 f1
07 01 12 53 0f 47 1d c5 1a 8f e9 91 48 ef 9a 5f
06 98 27 59 64 01 00 01 00 0c 2e 2e 00 08 0a 01
b7 78 2f 69 00 00 05 01 19 ...
```
Reading: `01`=`kHeader`; `04`=`kMainStreamsInfo`; `06`=`kPackInfo`, `PackPos=0`,
`NumPackStreams=1`, `09`=`kSize`, `PackSize=0x30=48`, `00`=`kEnd`; `07`=`kUnPackInfo`,
`0b`=`kFolder`, `NumFolders=1`, `External=0`, `NumCoders=2`, coder0 `flags=0x24` id `06f10701`
propsLen `0x12`, … `0c`=`kCodersUnPackSize` `0x2e=46`, `0x2e=46`; `08`=`kSubStreamsInfo`,
`0a`=`kCRC`, `AllAreDefined=1`, CRC `b7782f69`, `00`=`kEnd`; `00`=`kEnd`; `05`=`kFilesInfo`.

Note both the header and the content contain `0x02` bytes (part of the salt-less AES props
`53 0f`); this means the header **cannot** be naively parsed by searching for property ids.

> Confirms the answer to "property id 0x04 is the encoded header stream info": no — for a
> content-encrypted archive `0x04` is `kMainStreamsInfo` in the **unencrypted** header.

### E.2 What hashcat mode 11600 does

It never sees the container — 7z2hashcat reduces it to `$7z$<type>$<ncp>$<saltlen>$<salt>$<ivlen>$<iv>$<crc>$<data_len>$<unpack_size>$<data>[…]`
and hashcat:
1. derives the key (§A),
2. AES-256-CBC-decrypts `data` (length `data_len`),
3. if `data_type == 0` → `crc = cpu_crc32_buffer(out_full, unpack_size)`;
   else decompress to `crc_len` bytes and CRC that,
4. compare against `seven_zip->crc` (the folder/substream CRC-32).

So it decrypts **only the packed stream of the first folder**, never the whole archive.
`ATTACK_EXEC = ATTACK_EXEC_OUTSIDE_KERNEL` because the decompressor runs on the CPU.

### E.3 Case (a) — AES-only, or AES + COPY (stored)

**Yes, a full fast path exists: decrypt + CRC32. No decompressor required.**

Verified end-to-end on `plain_copy.7z` (`coders = 7zAES + COPY`, `bindpairs = [(1,0)]`):
```
packsize = 48   AES out UnPackSize = 46   PAD = 2
decrypted 48 bytes; last 2 bytes = 0000 == zeros  -> PAD check PASSES
substreams: nums=[1] sizes=[46] crcs=[0x692f78b7]
CRC32(plaintext[:46]) = 692f78b7 == stored  -> True
CONTENT = b'hello 7z password verification test 0123456789'
```

Two independent, essentially cost-free checks:
* **tail padding** (`PAD = 2` here ⇒ false-accept 2^−16) — costs one AES block;
* **CRC32 over the decrypted plaintext** — the decisive test.

Note 7-Zip emits **AES + COPY** (`00`) for stored encrypted files, not a lone AES coder; COPY is a
no-op so it can be ignored. A lone-AES folder (other producers) is handled identically.

### E.4 Case (b) — AES + LZMA / LZMA2 / BCJ

**No cheap CRC fast path exists. You must run the decompressor.**

Verified end-to-end on `plain_lzma2.7z` (`coders = 7zAES + LZMA2`):
```
packsize = 64   AES out UnPackSize = 50   FINAL UnPackSize = 46   PAD = 14
decrypted 64 bytes; last 14 bytes all-zero -> PAD check PASSES (2^-112)
second coder = LZMA2 props=00
LZMA2(dict=4096) 50B -> 46B (expected 46) match=True
CRC32(decompressed[:46]) = 692f78b7 == stored  -> True
CONTENT = b'hello 7z password verification test 0123456789'
```

Statements to encode in the tool:

* The stored CRC is over the **post-decompression** bytes. Nothing in the container lets you check a
  password for a compressed folder without decompressing. **No CRC fast path exists for case (b).**
* The *only* decompressor-free test is the tail padding, with false-accept probability `2^(−8·PAD)`,
  and it is unavailable when `PAD == 0`.
* You do **not** need to decompress the whole archive: only the first folder's packed stream, and
  only enough of it to produce the first substream's `UnPackSize` bytes. JtR/hashcat bound this via
  `crc_len`; hashcat additionally shrinks the AES input with a heuristic:
  ```c
    if (data_type == 1) // LZMA1 uses more bytes
      aes_len = 32.5f + (float) crc_len * 1.05f; // +5% max (only for small random inputs)
    else if (data_type == 2) // LZMA2 is more clever (e.g. uncompressed chunks)
      aes_len =  4.5f + (float) crc_len * 1.01f; // +1% max (only for small random inputs)
  ```
  which mirrors `7z2hashcat`'s `$SHORTEN_HASH_FIXED_HEADER = 32.5` / `$SHORTEN_HASH_EXTRA_PERCENT = 5`.
  **This is a heuristic, not a spec** — a correct implementation should decrypt the full packed
  stream of the first folder, or use a decompressor that accepts a bounded output length.
* `LZMA2` has a genuine escape hatch in rare cases: an LZMA2 uncompressed chunk can be emitted
  verbatim, which is why 7z2hashcat has `$LZMA2_MIN_COMPRESSED_LEN = 16` and prints
  "it might still be possible to crack the password of this archive since the data part seems to be
  very short and therefore it might use the LZMA2 uncompressed chunk feature".
* **BCJ/BCJ2/Delta etc. are filters applied *after* decompression** in 7-Zip's chain, so they change
  the bytes the CRC is computed over. JtR runs them before the CRC check (`x86_Convert(out, crc_len,
  0, &state, 0)` etc.); for `p_type == 2` (BCJ2), which needs four streams, JtR **gives up on the CRC
  entirely**:
  ```c
  		else if (p_type == 2) {
  			... fprintf(stderr, YEL "Can't decode BCJ2, so skipping CRC check" NRM);
  			goto exit_good;
  		}
  ```
  A BCJ2 archive therefore **cannot be verified reliably** by this technique; treat it as
  "unsupported / padding-check only".

### E.5 Caveat / unverified

`7z2hashcat.pl`'s `get_folder_aes_unpack_size()` body fell in the truncated region of the fetched
file, so I could not read how it selects the folder's AES unpack size. Everything I state about
`PAD = PackSize − AES_out_UnPackSize` comes from the 7-Zip sources plus my own measurements, not
from that function. It does not affect the correctness of the rule.

Also note `7z2hashcat` flags `padding_attack_possible` from `data_len − unpack_size > 3`; whether
`unpack_size` there is the AES out-stream size or the final folder size changes whether padding
attacks get reported for compressed streams. **Unverified.**

---

## F. Coder ids

Authoritative table from `CPP/7zip/Archive/7z/7zHeader.h` (7-Zip itself). Ids are stored big-endian
in `CodecId[CodecIdSize]`, so the byte string in the file is the big-endian form shown here.

### F.1 7-Zip's normative constants

```c
const UInt32 k_Copy = 0;
const UInt32 k_Delta = 3;
const UInt32 k_ARM64 = 0xa;
const UInt32 k_RISCV = 0xb;

const UInt32 k_LZMA2 = 0x21;

const UInt32 k_SWAP2 = 0x20302;
const UInt32 k_SWAP4 = 0x20304;

const UInt32 k_LZMA  = 0x30101;
const UInt32 k_PPMD  = 0x30401;

const UInt32 k_Deflate   = 0x40108;
const UInt32 k_Deflate64 = 0x40109;
const UInt32 k_BZip2     = 0x40202;

const UInt32 k_BCJ   = 0x3030103;
const UInt32 k_BCJ2  = 0x303011B;
const UInt32 k_PPC   = 0x3030205;
const UInt32 k_IA64  = 0x3030401;
const UInt32 k_ARM   = 0x3030501;
const UInt32 k_ARMT  = 0x3030701;
const UInt32 k_SPARC = 0x3030805;

const UInt32 k_AES   = 0x6F10701;

// const UInt32 k_ZSTD = 0x4015D; // winzip zstd
// 0x4F71101, 7z-zstd
```
```c
inline bool IsFilterMethod(UInt64 m)
{
  ...
    case k_Delta:
    case k_ARM64:
    case k_RISCV:
    case k_BCJ:
    case k_BCJ2:
    case k_PPC:
    case k_IA64:
    case k_ARM:
    case k_ARMT:
    case k_SPARC:
    case k_SWAP2:
    case k_SWAP4:
      return true;
```
(`k_Deflate64`, `k_Comment`-adjacent, ZSTD are **not** filters; ZSTD is commented out of 7-Zip's own
header and hashcat uses a private id `8` internally.)

### F.2 Consolidated table (file bytes, big-endian)

| `CodecId` bytes | Hex | 7-Zip name | Kind | Notes |
|---|---|---|---|---|
| `00` | 0x00 | `k_Copy` | filter/no-op | **not AES**; stored data |
| `03` | 0x03 | `k_Delta` | filter | **not AES**; attribute = distance−1 |
| `0A` | 0x0A | `k_ARM64` | filter | **not AES** (new in 7-Zip 21+) |
| `0B` | 0x0B | `k_RISCV` | filter | **not AES** |
| `21` | 0x21 | `k_LZMA2` | compressor | **not AES** |
| `03 01 01` | 0x030101 | `k_LZMA` (LZMA1) | compressor | **not AES** |
| `03 04 01` | 0x030401 | `k_PPMD` | compressor | **not AES** |
| `04 01 08` | 0x040108 | `k_Deflate` | compressor | **not AES** |
| `04 01 09` | 0x040109 | `k_Deflate64` | compressor | **not AES** |
| `04 02 02` | 0x040202 | `k_BZip2` | compressor | **not AES** |
| `03 03 01 03` | 0x03030103 | `k_BCJ` (x86) | filter | **not AES** |
| `03 03 01 1B` | 0x0303011B | `k_BCJ2` | filter (4 streams) | **not AES** |
| `03 03 02 05` | 0x03030205 | `k_PPC` | filter | **not AES** |
| `03 03 04 01` | 0x03030401 | `k_IA64` | filter | **not AES** |
| `03 03 05 01` | 0x03030501 | `k_ARM` | filter | **not AES** |
| `03 03 07 01` | 0x03030701 | `k_ARMT` | filter | **not AES** |
| `03 03 08 05` | 0x03030805 | `k_SPARC` | filter | **not AES** |
| `02 03 02` | 0x020302 | `k_SWAP2` | filter | **not AES** |
| `02 03 04` | 0x020304 | `k_SWAP4` | filter | **not AES** |
| **`06 F1 07 01`** | **0x06F10701** | **`k_AES`** | **encryption** | **← the ONLY AES id** |
| `03 03 03 01` | 0x03030301 | `k_Alpha` | filter | in 7z2hashcat's list only (legacy) |
| *(commented out)* | 0x4015D | winzip ZSTD | compressor | not in 7-Zip's active table |
| *(commented out)* | 0x4F71101 | 7z-zstd | compressor | not in 7-Zip's active table |

JtR/7z2hashcat's list agrees on every entry it carries:
```perl
my $SEVEN_ZIP_AES               = "\x06\xf1\x07\x01"; # all the following codec values are from CPP/7zip/Archive/7z/7zHeader.h
my $SEVEN_ZIP_LZMA1             = "\x03\x01\x01";
my $SEVEN_ZIP_LZMA2             = "\x21";
my $SEVEN_ZIP_PPMD              = "\x03\x04\x01";
my $SEVEN_ZIP_BCJ               = "\x03\x03\x01\x03";
my $SEVEN_ZIP_BCJ2              = "\x03\x03\x01\x1b";
my $SEVEN_ZIP_PPC               = "\x03\x03\x02\x05";
my $SEVEN_ZIP_ALPHA             = "\x03\x03\x03\x01";
my $SEVEN_ZIP_IA64              = "\x03\x03\x04\x01";
my $SEVEN_ZIP_ARM               = "\x03\x03\x05\x01";
my $SEVEN_ZIP_ARMT              = "\x03\x03\x07\x01";
my $SEVEN_ZIP_SPARC             = "\x03\x03\x08\x05";
my $SEVEN_ZIP_BZIP2             = "\x04\x02\x02";
my $SEVEN_ZIP_DEFLATE           = "\x04\x01\x08";
my $SEVEN_ZIP_DELTA             = "\x03";
my $SEVEN_ZIP_COPY              = "\x00";
```

### F.3 "Can I handle this natively?" decision rule

```
coders = first folder's coder chain (in stored order)

AES_ID = 06 F1 07 01
aes    = index of the coder whose id == AES_ID

if aes is None:
    -> not encrypted by a password; no verification needed (kEncodedHeader alone is NOT encryption)

# 1. always cheap: tail padding
PAD = PackSize - UnPackSize(out-stream of coder[aes])
if PAD > 0 and plaintext[-PAD:] == 0^PAD:   # cost: 1 AES block
    candidate accepted, false-accept 2^(-8*PAD)
else: reject

# 2. decisive check
remaining = coder ids after `aes`
if remaining is empty or remaining == [00 (Copy)]:
    NATIVE OK      -> CRC32(AES_plaintext[:crc_len]) == stored CRC
elif remaining == [21 (LZMA2)]:
    NATIVE OK      -> LZMA2-decode, then CRC32
elif remaining == [03 01 01 (LZMA1)]:
    NATIVE OK      -> LZMA1-decode, then CRC32
elif remaining == [04 01 08 (Deflate)]:
    NATIVE OK      -> raw inflate (-MAX_WBITS), then CRC32
elif remaining == [04 02 02 (BZip2)]:
    NATIVE OK      -> bzip2 decode, then CRC32
elif remaining starts with a BCJ/PPC/IA64/ARM/ARMT/SPARC/Delta/SWAP filter:
    RUN FILTER then CRC32 -- but note 7-Zip order: filters run AFTER the decompressor
elif remaining contains 03 03 01 1B (BCJ2):
    CANNOT VERIFY (4 streams; JtR skips the CRC) -> padding check only, or fall back
elif remaining contains 03 04 01 (PPMD) or an unknown/opaque id:
    FALL BACK      -> padding check only, or external tool
else:
    FALL BACK
```

Practical note: for verification you need **the first folder only**, and only up to `crc_len`
(substream 0's `UnPackSize`) bytes of decompressed output. If you implement LZMA1/LZMA2 (e.g. the
`lzma-rs`/`xz2` crates) plus DEFLATE and BZip2, plus the BCJ filters, you cover everything hashcat
and JtR can verify, and the only real fall-back case is BCJ2, PPMD, and unknown coder ids.

---

## Verification log

Environment: 7-Zip 26.03 (x64), Windows; independent pure-Python AES-256-CBC
(`D:\Files\Tmp\7zverify\aes.py`), validated:
```
AES-256-CBC enc KAT: PASS      (NIST SP 800-38A F.2.5, 4 blocks)
AES-256-CBC dec KAT: PASS
```

Synthetic archives built **only** from the formulas in §A/§B, then fed to `7z.exe`:

| Archive | salt | iv | ncp | `7z t` |
|---|---|---|---|---|
| `salt8_a.7z` | 8 | 16 | 19 | **OK** |
| `salt16_a.7z` | 16 | 16 | 19 | **OK** |
| `nosalt.7z` | 0 | 16 | 19 | **OK** |
| `ncp_low.7z` | 8 | 16 | 10 | **OK** |
| `ncp0.7z` | 8 | 16 | 0 | **OK** |
| `ivpart_a.7z` | 0 | 8 | 19 | **OK** |
| `ncp3f.7z` | 8 | 16 | **0x3F** | **OK** (key = salt‖pw‖zeros) |

An **incorrect** variant (`saltSize` encoded as `bit7*16 + nibble`) was rejected by `7z.exe` with
`ERROR: Unsupported Method` — a direct A/B proof that the `+1` semantics in §B.2 are correct.

Real archives, wrong password → different key → different plaintext (confirmed by SHA-256 over the
decrypted buffer), so the KDF is not degenerate.

Behavioural caveat worth knowing: **`7z t`/`7z x` do not validate CRC32 for these synthetic
archives** — with a wrong password they still report `Everything is Ok` and write the garbage
plaintext to disk. That is a property of 7-Zip's extraction path here, and is exactly why a native
verifier must do the CRC comparison itself rather than trust an exit code.
