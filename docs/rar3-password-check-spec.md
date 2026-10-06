# RAR 1.5–4.x ("RAR3"/"RAR4") password-check: byte-level specification

**Scope:** exactly how hashcat and John the Ripper decide whether a candidate password is correct
for a RAR 1.5–4.x archive. All claims are backed by quoted source. Every uncertainty is flagged
inline with **[UNCERTAIN]** / **[UNVERIFIED]**.

---

## 0. CORRECTION TO THE PREMISE — read this first

The task statement's mode mapping is **wrong**. Verified against the fetched sources:

| Mode | `HASH_NAME` / `FORMAT_NAME` | What it actually is | Evidence |
|---|---|---|---|
| **12500** | `"RAR3-hp"` | RAR3, **encrypted headers** (`-hp`) | `module_12500.c`: `static const char *HASH_NAME = "RAR3-hp";` |
| **13000** | `"RAR5"` | **RAR5**, PBKDF2-HMAC-SHA256 — *not RAR3-p* | `module_13000.c`: `static const char *HASH_NAME = "RAR5";`, `SIGNATURE_RAR5 = "$rar5$"` |
| **23700** | `"RAR3-p (Uncompressed)"` | RAR3 `-p`, **STORED only** (`method == 30`) | `module_23700.c`: `HASH_NAME = "RAR3-p (Uncompressed)"`, `if (method != 30) return (PARSER_SALT_VALUE);` |
| **23800** | `"RAR3-p (Compressed)"` | RAR3 `-p`, **compressed** (LZ + PPMd) | `module_23800.c`: `HASH_NAME = "RAR3-p (Compressed)"`, `if (method < 31) ... if (method > 35) ...` |

Consequences:

* **`src/modules/module_13000.c` is irrelevant to this task.** It is RAR5: 16-byte salt, 16-byte IV,
  `$rar5$…` signature, PBKDF2. It contains **no** `crc32` check and **no** AES-128-CBC-of-file-data
  check. Everything the question asks about "mode 13000 = RAR3-p stored" is answered below by
  **mode 23700** instead.
* The question "what does hashcat mode 23700 verify?" is answered by 23700 itself (stored), and the
  question "what does mode 23700 verify for a compressed file?" is a category error — 23700
  **rejects** compressed files at parse time. The compressed case is **23800**, which is covered.

Other fetches that failed (must be stated explicitly, per instructions):

| Requested URL | Result |
|---|---|
| `.../openwall/john/bleeding-jumbo/run/rar2john.py` | **HTTP 404** — file does not exist at that path |
| `.../openwall/john/bleeding-jumbo/src/rar_fmt.c` | **HTTP 404** — file renamed |
| `.../openwall/john/bleeding-jumbo/src/rar_common.c` | **HTTP 404** — file does not exist |
| `.../openwall/john/bleeding-jumbo/src/rar_common.h` | HTTP 200 — **this is the real CPU format file** (contains `fmt_rar`, `check_rar`, `struct fmt_main fmt_rar`) |
| `.../hashcat/master/docs/hashcat-example-hashes.txt` | HTTP 404 |

Substitutions used, all successfully fetched and quoted:

* John RAR3 parser (the real `rar2john`): **`src/rar2john.c`**
  `https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/src/rar2john.c`
* John RAR3 CPU format + verify function: **`src/rar_common.h`** (misleading name)
* John RAR3 format registration/KDF: **`src/rar_fmt_plug.c`**
* Reference implementation of the RAR3 KDF: **unrar `crypt3.cpp`**
  `https://raw.githubusercontent.com/aawc/unrar/master/crypt3.cpp`
* Reference implementation of RAR3 header parsing + header CRC: **unrar `rawread.cpp`, `arcread.cpp`**

---

## A. `-hp` (header-encrypted) archive layout

### A.1 Where the 8-byte salt and the 16 check bytes live

For `-hp` archives the *file* headers are encrypted too, so there is no usable file header to read a
salt from. Both John and hashcat use the **end-of-archive block**, which is always encrypted with the
same key/IV and has a **known plaintext**: its first byte is the ENDARC header type.

John's parser seeks to `filesize - 24` and consumes 24 bytes = **8 salt + 16 ciphertext**
(`src/rar2john.c`, in `process_file()`, `if (type == 0)` branch):

```c
	/* process -hp mode files
	   use Marc's end-of-archive block decrypt trick */
	if (type == 0) {
		unsigned char buf[24];
		...
		printf("%s:$RAR3$*%d*", base_aname, type);
		jtr_fseek64(fp, -24, SEEK_END);
		if (fread(buf, 24, 1, fp) != 1) {
		...
		for (i = 0; i < 8; i++) { /* salt */
			printf("%c%c", itoa16[ARCH_INDEX(buf[i] >> 4)],
			    itoa16[ARCH_INDEX(buf[i] & 0x0f)]);
		}
		printf("*");
		/* encrypted block with known plaintext */
		for (i = 8; i < 24; i++) {
			printf("%c%c", itoa16[ARCH_INDEX(buf[i] >> 4)],
			       itoa16[ARCH_INDEX(buf[i] & 0x0f)]);
		}
```

So, with `L` = total archive file size:

| Bytes (file offsets) | Meaning |
|---|---|
| `[L-24 .. L-17]` | 8-byte **salt** |
| `[L-16 .. L-1]` | 16 bytes of **AES-128-CBC ciphertext** (first ciphertext block of the ENDARC block) |

The ENDARC block itself starts at `L-24`; the 8-byte salt is written *unencrypted* immediately before
the encrypted block data. The encrypted data being read is the **first 16 bytes of the encrypted
stream**, i.e. the very first CBC block, which decrypts with the IV directly (no chaining needed).

**[UNCERTAIN]** Why the salt can be 8 bytes before the ENDARC block: hashcat's parser hardcodes no
file position at all (the salt+16 bytes come from the hash line), and John hardcodes *exactly*
`-24 / +8 / +16`. The RAR3 spec permits 8 bytes of extra "SubData" for `HEAD_SERVICE` and I could not
positively confirm the ENDARC block contains any — the most likely reading is a small gap/boundary
(possibly with the archive's terminating padding), and John simply relies on the invariant "the last
24 bytes of a `-hp` archive are salt ‖ first ciphertext block". A byte-level dump of a real `-hp`
archive would settle this; treat the "gap" explanation as unverified.

`-hp` detection: the **MAIN header's** `Flags & 0x0080` (`MHD_PASSWORD`) set ⇒ `-hp`; a file header's
`Flags & 0x0004` (`LHD_PASSWORD`) set ⇒ `-p`. (`src/rar2john.c`):

```c
	archive_hdr_head_flags =
	    archive_hdr_block[4] << 8 | archive_hdr_block[3];
	if (archive_hdr_head_flags & 0x0080) {	/* file header block is encrypted */
		type = 0;	/* RAR file was created using -hp flag */
	} else
		type = 1;
```

### A.2 The exact check

**John (`src/rar_common.h`, `check_rar()`, `cur_file->type == 0` branch) — this is the normative
statement:**

```c
	if (cur_file->type == 0) {	/* rar-hp mode */
		AES_set_decrypt_key(key, 128, &aes_ctx);
		AES_cbc_encrypt(cur_file->data, plain, 16, &aes_ctx, iv, AES_DECRYPT);

		cracked[index] = !memcmp(plain, "\xc4\x3d\x7b\x00\x40\x07\x00", 7);
		return;
	}
```

**hashcat (`src/modules/module_12500.c`, `module_hash_decode`) — the same constant, as a comment plus
a hardcoded digest:**

```c
  // there's no hash for rar3. the data which is in crypted_pos is some encrypted data and
  // if it matches the value \xc4\x3d\x7b\x00\x40\x07\x00 after decrypt we know that we successfully cracked it.

  digest[0] = 0xc43d7b00;
  digest[1] = 0x40070000;
  digest[2] = 0;
  digest[3] = 0;
```

and the compare kernel (`OpenCL/m12500-pure.cl`, `m12500_comp`):

```c
  AES128_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

  u32 iv[2];

  iv[0] = tmps[gid].iv[0];
  iv[1] = tmps[gid].iv[1];

  out[0] ^= hc_swap32_S (iv[0]);
  out[1] ^= hc_swap32_S (iv[1]);

  const u32 r0 = out[0];
  const u32 r1 = out[1];
```

### A.3 Exact comparison expression, in bytes

Let `P` = the 16-byte AES-128-CBC **decryption** of the 16 ciphertext bytes, using the derived key and
`IV[0..15]` (IV derivation in section D). Then:

```
C (John)     : memcmp(P, "\xc4\x3d\x7b\x00\x40\x07\x00", 7) == 0
C (hashcat)  : (P[0..3] as a big-endian word) == 0xc43d7b00
            && (P[4..7] as a big-endian word) == 0x40070000
```

i.e. byte-for-byte:

```
P[0] == 0xC4
P[1] == 0x3D
P[2] == 0x7B
P[3] == 0x00
P[4] == 0x40
P[5] == 0x07
P[6] == 0x00
P[7] == 0x00      <-- pinned by hashcat (digest[1] low half); NOT compared by John's 7-byte memcmp
```

* **Bytes hashed/compared:** the **first 7** plaintext bytes (`P[0..6]`) by John; the **first 8**
  (`P[0..7]`) by hashcat. **No CRC32 is involved at all.**
* **Bytes NOT used:** `P[8..15]` are never inspected by either tool.
* **No expected-value field anywhere in the archive** is read for `-hp`. The expected value is a
  compile-time constant. There is no CRC32 comparison and no "2-byte little-endian field".
* The 8th byte being `0x00` is the ENDARC block's `HeadType` byte; John's 7-byte compare leaves it
  unpinned, hashcat's word compare pins it to zero. Both are correct in practice.

**Timing note:** this is the entire check — one AES block decrypt. It is also visible in the KDF
structure: `module_kernel_loops_min/max = ROUNDS_RAR3 / 16` and no `esalt` is used
(`module_esalt_size = MODULE_DEFAULT`), i.e. the check needs no per-salt bulk data.

---

## B. `-p` (plain headers, encrypted file data) — STORED / uncompressed (`method == 0x30`)

### B.1 Where the 8-byte salt is

The salt is stored **inside the file header block, immediately after the file-name field**, 8 bytes,
and only when file-header `Flags & 0x400` (`LHD_SALT`) is set.

John (`src/rar2john.c`):

```c
		/* salt processing */
		if (file_hdr_head_flags & 0x400) {
			ext_time_size -= 8;
			if (fread(salt, 8, 1, fp) != 1) {
```

The file name is read just before it, and its length comes from `NameSize` at block offset 26:

```c
		/* file name processing */
		file_name_size =
		    file_hdr_block[27] << 8 | file_hdr_block[26];
		...
		if (fread(file_name, file_name_size, 1, fp) != 1) {
```

Reference unrar (`arcread.cpp`, `ReadHeader15`, `HEAD_FILE` case) confirms the same order and the
8-byte size:

```c
        size_t ReadNameSize=Min(NameSize,MAXPATHSIZE);
        std::string FileName(ReadNameSize,0);
        Raw.GetB((byte *)&FileName[0],ReadNameSize);
        ...
        if ((hd->Flags & LHD_SALT)!=0)
          Raw.GetB(hd->Salt,SIZE_SALT30);
```

with `SIZE_SALT30 == 8`. Note unrar inserts optional *sub-data* between the name and the salt, but
that path exists only for `HEAD_SERVICE` blocks; for a normal `HEAD_FILE` the salt follows the name
directly:

```c
          // Calculate the size of optional data.
          int DataSize=int(hd->HeadSize-NameSize-SIZEOF_FILEHEAD3);
          if ((hd->Flags & LHD_SALT)!=0)
            DataSize-=SIZE_SALT30;
```

**Layout of the salt region:**

```
[block+ 0 ..  1] HeadCRC        (2)
[block+ 2      ] HeadType       (1) = 0x74
[block+ 3 ..  4] Flags          (2)   bit 0x0400 = LHD_SALT
[block+ 5 ..  6] HeadSize       (2)
[block+ 7 .. 10] PackSize       (4)
[block+11 .. 14] UnpSize        (4)
[block+15      ] HostOS         (1)
[block+16 .. 19] FileCRC        (4)   <-- the comparison target for STORED files
[block+20 .. 23] FileTime       (4)
[block+24      ] UnpVer         (1)   must be >= 29 for RAR3 crypto
[block+25      ] Method         (1)   0x30 = stored
[block+26 .. 27] NameSize       (2)
[block+28 .. 31] FileAttr       (4)
[block+32 .. 32+NameSize-1]  FileName
[ ...         ] (HEAD_SERVICE only: SubData)
[ +0  .. +7   ] Salt (8 bytes, iff Flags & 0x400)
[ ...         ] EXT_TIME (iff Flags & 0x1000)
```

After the header, the file data (encrypted, CBC) begins at `block + HeadSize`, length `PackSize`.

### B.2 hashcat mode 23700 — the verify (compare) function, quoted

There is no separate "verify" function in hashcat modules; the verification *is* the compare kernel.
`OpenCL/m23700-pure.cl`, `m23700_comp`:

```c
  const u32 pack_size   = esalt_bufs[DIGESTS_OFFSET_HOST].pack_size;
  const u32 unpack_size = esalt_bufs[DIGESTS_OFFSET_HOST].unpack_size;

  if (pack_size > unpack_size) // could be aligned
  {
    if (pack_size >= 32) // otherwise IV...
    {
      const u32 pack_size_elements = pack_size / 4;

      u32 last_block_encrypted[4];

      last_block_encrypted[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data[pack_size_elements - 4 + 0];
      last_block_encrypted[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data[pack_size_elements - 4 + 1];
      last_block_encrypted[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data[pack_size_elements - 4 + 2];
      last_block_encrypted[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data[pack_size_elements - 4 + 3];

      u32 last_block_decrypted[4];

      AES128_decrypt (ks, last_block_encrypted, last_block_decrypted, s_td0, s_td1, s_td2, s_td3, s_td4);

      u32 last_block_iv[4];

      last_block_iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data[pack_size_elements - 8 + 0];
      ...
      last_block_decrypted[0] ^= last_block_iv[0];
      last_block_decrypted[1] ^= last_block_iv[1];
      last_block_decrypted[2] ^= last_block_iv[2];
      last_block_decrypted[3] ^= last_block_iv[3];

      if ((last_block_decrypted[3] & 0xff) != 0) return;
    }
  }
  ...
  u32 data_left = unpack_size;

  u32 crc32 = ~0;

  for (u32 i = 0, j = 0; i < pack_size / 16; i += 1, j += 4)
  {
    u32 data[4];

    data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data[j + 0];
    ...
    u32 out[4];

    AES128_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    out[0] ^= iv[0];
    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    crc32 = round_crc32_16_S (crc32, out, data_left, l_crc32tab);

    iv[0] = data[0];
    iv[1] = data[1];
    iv[2] = data[2];
    iv[3] = data[3];

    data_left -= 16;
  }
```

and the digest it is compared against, set in `module_hash_decode` (`module_23700.c`):

```c
  // CRC32

  const u8 *crc32_pos = token.buf[3];

  u32 crc32_sum = hex_to_u32 (crc32_pos);
  ...
  // digest

  digest[0] = crc32_sum ^ 0xffffffff;
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;
```

### B.3 Does it decrypt everything and CRC32 it?

**It decrypts the whole `PackSize` and CRC32s the first `UnpSize` bytes.**

* The loop runs `i < pack_size / 16` — an AES-128-CBC decrypt of **all** `pack_size` bytes (starting
  with `iv` = the KDF IV, chaining `iv = ciphertext block`).
* `round_crc32_16_S (crc32, out, data_left, table)` folds in only `MIN(data_left, 16)` bytes
  (`OpenCL/inc_checksum_crc.cl`):

  ```c
  DECLSPEC u32 round_crc32_16_S (const u32 crc32, PRIVATE_AS const u32 *buf, const u32 len, LOCAL_AS u32 *crc32table)
  {
    #define MIN(a,b) (((a) < (b)) ? (a) : (b))

    const int crc_len = MIN (len, 16);

    #undef MIN

    u32 c = crc32;

    for (int i = 0; i < crc_len; i++)
    {
      const u32 idx = i / 4;
      const u32 mod = i % 4;
      const u32 sht = (3 - mod) * 8;

      const u32 b = buf[idx] >> sht; // b & 0xff (but already done in round_crc32 ())

      c = round_crc32_l_S (c, b, crc32table);
    }

    return c;
  }
  ```
* CRC initialised to `~0` = `0xffffffff`, and the *raw* register (no final inversion) is compared
  against `crc32_sum ^ 0xffffffff`. Net effect: the compared value **is the standard CRC32 of the
  first `UnpSize` plaintext bytes**.
* Because `module_hash_decode` requires `pack_size % 16 == 0` and `unpack_size <= pack_size`, and RAR
  pads stored data to a 16-byte boundary, `pack_size == round_up_16(unp_size)` in the normal case.

**[UNCERTAIN — implementation caveat, worth knowing before you copy it]** `data_left` is a `u32` and
is decremented unconditionally by 16 at the end of every iteration. If `pack_size` were strictly
larger than `round_up_16(unp_size)`, `data_left` would underflow and `MIN(len,16)` would then return
16, folding extra ciphertext blocks into the CRC. The kernel appears to rely on
`pack_size == round_up_16(unp_size)`. Do **not** replicate the underflow; implement the semantic
"CRC32 over exactly `UnpSize` plaintext bytes".

### B.4 The cheap prefix / padding check

**Yes — but it does not use a prefix; it uses the tail.** The primary early-rejection for STORED files
is a **padding check on the final plaintext block**, which needs **one** AES decrypt (plus one
ciphertext word read) rather than the whole stream. hashcat (quoted above): `if (pack_size >= 32)`,
take the last 16 ciphertext bytes as `last_block_encrypted`, the 16 bytes before them as
`last_block_iv`, AES-decrypt once, XOR, and require the **last** plaintext byte to be `0x00`
(`(last_block_decrypted[3] & 0xff) != 0` ⇒ reject). This is exactly the final padding byte of a
zero-padded stored file.

John does the equivalent with a different formulation (`src/rar_common.h`, `check_rar()`,
`method == 0x30` branch):

```c
		if (cur_file->method == 0x30) {	/* stored, not deflated */
			CRC32_t crc;
			unsigned char crc_out[4];
			uint64_t size = cur_file->unp_size;
			unsigned char *cipher = cur_file->data;

			/* Check padding for early rejection, when possible */
			if (cur_file->unp_size % 16) {
				const char zeros[16] = { 0 };
				const int pad_start = cur_file->unp_size % 16;
				const int pad_size = 16 - pad_start;
				unsigned char last_iv[16];

				AES_set_decrypt_key(key, 128, &aes_ctx);

				if (cur_file->pack_size < 32) {
					memcpy(last_iv, iv, 16);
					AES_cbc_encrypt(cur_file->data, plain, 16, &aes_ctx, last_iv, AES_DECRYPT);
				} else {
					memcpy(last_iv, cur_file->data + cur_file->pack_size - 32, 16);
					AES_cbc_encrypt(cur_file->data + cur_file->pack_size - 16, plain,
					                16, &aes_ctx, last_iv, AES_DECRYPT);
				}
				if (!(cracked[index] = !memcmp(&plain[pad_start], zeros, pad_size)))
					return;
			}

			/* Use full decryption with CRC check.
			   Compute CRC of the decompressed plaintext */
			CRC32_Init(&crc);
			AES_set_decrypt_key(key, 128, &aes_ctx);

			while (size) {
				unsigned int inlen = (size > 16) ? 16 : size;

				AES_cbc_encrypt(cipher, plain, 16, &aes_ctx, iv, AES_DECRYPT);
				CRC32_Update(&crc, plain, inlen);

				size -= inlen;
				cipher += inlen;
			}
			CRC32_Final(crc_out, crc);

			/* Compare computed CRC with stored CRC */
			cracked[index] = !memcmp(crc_out, &cur_file->crc.c, 4);
			return;
		}
```

Key points:

* John's "cipher" is the **first** ciphertext block when `pack_size < 32` (IV = KDF IV), matched by
  hashcat's explicit `if (pack_size >= 32) // otherwise IV...` guard.
* **This padding check is only valid when `UnpSize % 16 != 0`.** Both implementations gate on it
  (hashcat implicitly via `pack_size > unpack_size`). If it *is* a multiple of 16 there is no padding
  to test and you must do the full CRC.
* **Important distinction:** the check covers the **tail** (`plain[pad_start .. 15]` of the final
  block), *not* a prefix. There is no "decrypt first N bytes and compare" check for STORED files.

### B.5 Minor: the CRC byte-order detail in `$RAR3$*1*…`

For `method != 0x30` (i.e. compressed, mode 23800 territory) John **inverts** the CRC word at load
time (`src/rar_common.h`, `get_binary`):

```c
		if (file->method != 0x30)
#if ARCH_LITTLE_ENDIAN
			file->crc.w = ~file->crc.w;
#else
			file->crc.w = JOHNSWAP(~file->crc.w);
#endif
```

so that the same `memcmp(&unp_crc, &cur_file->crc.c, 4)` works for both the stored path (which uses
`CRC32_Final`, already inverted) and the `rar_unpack29()` path (whose `unp_crc` is the raw
non-inverted register). For a Rust implementation the clean rule is simply: **`FileCRC` (a plain
little-endian `u32` at block offset 16) equals the standard CRC32 of the plaintext** — for a stored
file the CRC32 of the first `UnpSize` decrypted bytes; for a compressed file the CRC32 of the fully
decompressed data.

---

## C. `-p` compressed file

### C.1 What hashcat verifies — mode **23800** (not 23700)

`module_23700.c` **refuses** compressed files outright:

```c
  // method

  const u8 *method_pos = token.buf[8];

  const u32 method = hc_strtoul ((const char *) method_pos, NULL, 10);

  if (method != 30) return (PARSER_SALT_VALUE);
```

Mode 23800 accepts `31..35` and does a **full LZ / PPMd unpack** in a host-side hook
(`module_hook23 → rar3_decode()`), then compares a CRC32 in the kernel:

`src/modules/module_23800.c`, `module_hash_decode`:

```c
  // method

  const u8 *method_pos = token.buf[8];

  const u32 method = hc_strtoul ((const char *) method_pos, NULL, 10);

  if (method < 31) return (PARSER_SALT_VALUE);
  if (method > 35) return (PARSER_SALT_VALUE);

  rar3_hook_salt->method = method;

  // digest

  digest[0] = crc32_sum;
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;
```

`OpenCL/m23800-pure.cl`, `m23800_comp` — **the entire compare**:

```c
  if (hooks[gid].unpack_status != 0) return;

  u32 crc32 = hooks[gid].crc32;

  const u32 r0 = crc32;
  const u32 r1 = 0;
  const u32 r2 = 0;
  const u32 r3 = 0;
```

`unpack_status` must be `HC_RAR3_UNPACK_OK == 0` (`src/modules/rar3/rar3_status.h`):

```c
typedef enum hc_rar3_unpack_status
{
  HC_RAR3_UNPACK_OK           = 0, // unpacked to the expected length
  HC_RAR3_UNPACK_SHORT_OUTPUT = 1, // the unpack stopped before the expected length
  HC_RAR3_UNPACK_REJECTED_PPM = 2, // the PPM block header cannot be valid, so no unpack was tried
  HC_RAR3_UNPACK_REJECTED_LZ  = 3, // the LZ block header cannot be valid, so no unpack was tried
  HC_RAR3_UNPACK_UNSUPPORTED  = 4, // the stream uses a construct the decoder does not implement

} hc_rar3_unpack_status_t;
```

**Exact expression:**
`crc32_of_full_LZ_or_PPM_decompression == FileCRC` **AND** `produced_length == UnpSize`, with
`FileCRC` taken verbatim (no `^ 0xffffffff` on either side — both sides are the standard CRC32).
This is confirmed by `rar3_decode()`:

```c
  ctx.crc = 0xffffffff;
  ...
  if (ctx.status == HC_RAR3_UNPACK_OK)
  {
    // A filter left half collected means the stream stopped inside one, so the length is short anyway.

    ctx.status = (ctx.produced == unpack_size) ? HC_RAR3_UNPACK_OK : HC_RAR3_UNPACK_SHORT_OUTPUT;

    if (ctx.collecting == 1) ctx.status = HC_RAR3_UNPACK_SHORT_OUTPUT;
  }
  ...
  return ctx.crc ^ 0xffffffff;
```

John is semantically identical (`src/rar_common.h`, `check_rar()`, `#if HAVE_UNRAR` branch):

```c
			if (rar_unpack29(cur_file->data, solid, unpack_t)) {
				cracked[index] = !memcmp(&unpack_t->unp_crc, &cur_file->crc.c, 4);
```

### C.2 Is there a cheap prefix check without decompressing?

**Yes — cheap, but only a *probabilistic filter*, not a check.** It decrypts the first 16 bytes and
validates the LZ block header (or the PPMd header). It cannot confirm a password; it can only reject.

hashcat (`src/modules/module_23800.c`, `module_hook23`):

```c
  const u8 *first_block_decrypted = (const u8 *) hook_item->first_block_decrypted;

  // Nothing clears the hook buffer between candidates, so every path out of here writes a status.

  if (first_block_decrypted[0] & 0x80)
  {
    if (rar3_ppm_header_ok (first_block_decrypted) == 0)
    {
      hook_item->unpack_status = HC_RAR3_UNPACK_REJECTED_PPM;

      return;
    }
  }
  else
  {
    // LZ checks here.
    if ((first_block_decrypted[0] & 0x40)             // KeepOldTable can't be set
     || (check_huffman (first_block_decrypted)) == 0) // Huffman table check
    {
      hook_item->unpack_status = HC_RAR3_UNPACK_REJECTED_LZ;

      return;
    }
  }
```

John (`src/rar_common.h`, `check_rar()`, uncompressed-fallback = compressed branch):

```c
			/* Decrypt just one block for early rejection */
			AES_set_decrypt_key(key, 128, &aes_ctx);
			AES_cbc_encrypt(cur_file->data, plain, 16, &aes_ctx, pre_iv, AES_DECRYPT);

			/* Early rejection */
			if (plain[0] & 0x80) {
				// PPM checks here.
				if (!(plain[0] & 0x20) ||    // Reset bit must be set
				    (plain[1] & 0x80)) {     // MaxMB must be < 128
					cracked[index] = 0;
					return;
				}
			} else {
				// LZ checks here.
				if ((plain[0] & 0x40) ||     // KeepOldTable can't be set
				    !check_huffman(plain)) { // Huffman table check
					cracked[index] = 0;
					return;
				}
			}
```

The PPMd header rule, verbatim from hashcat's own decoder (`src/rar3_decode.c`):

```c
// The 2 rules a PPM block header has to satisfy. module_23800.c applies them to the first decrypted
// block before it decrypts the rest, which is the cheapest rejection a wrong password gets.

static int rar3_ppm_header_ok (const u8 *in)
{
  if ((in[0] & 0x20) == 0) return 0;   // the model has to be reset
  if ((in[1] & 0x80) != 0) return 0;   // the memory field cannot name more than RAR3_PPM_MAX_MB

  return 1;
}
```

The LZ `check_huffman()` (identical in John `src/rar_common.h` and hashcat
`src/modules/module_23800.c`; hashcat credits John):

```c
/*
 * This function is loosely based on JimF's check_inflate_CODE2() from
 * pkzip_fmt. Together with the other bit-checks, we are rejecting over 96%
 * of the candidates without resorting to a slow full check (which in turn
 * may reject semi-early, especially if it's a PPM block)
 *
 * Input is first 16 bytes of RAR buffer decrypted, as-is. It also contain the
 * first 2 bits, which have already been decoded, and have told us we had an
 * LZ block (RAR always use dynamic Huffman table) and keepOldTable was not set.
 *
 * RAR use 20 x (4 bits length, optionally 4 bits zerocount), and reversed
 * byte order.
 */
```

(John's comment states the filter rejects **>96 %** of wrong candidates — quoted verbatim.)

**Bottom line for your Rust tool:** for a compressed `-p` file there is **no** exact prefix check.
The only exact verification is a full `rar_unpack29`-equivalent LZ (and PPMd) decompression followed
by the CRC32/length comparison. The 16-byte prefix only yields a ~96 %-effective rejection filter.

### C.3 Adjudication of your claim

> **CLAIM:** "decrypt the first 16 bytes of file data; plaintext bytes at index 13..15 must equal the
> low 3 bytes of the file header's CRC32 field"

### VERDICT: **FALSE.** It is not a garbled version of anything — it is simply wrong.

Reasoning, checked against every source above:

1. **No implementation anywhere compares decrypted plaintext bytes to the CRC32 field.** The only
   places any decrypted plaintext byte is compared to anything are:
   * `-hp`: `memcmp(plain, "\xc4\x3d\x7b\x00\x40\x07\x00", 7)` — a constant, not a header field.
   * stored `-p`: `memcmp(&plain[pad_start], zeros, pad_size)` — against **zero**, at the **tail** of
     the **last** block, not bytes 13..15 of the **first** block.
   * compressed `-p`: bit-wise LZ/PPMd header validation — no CRC32 involvement at all.
   The CRC32 field is only ever compared against a **computed CRC32** (hashcat `digest[0] = crc32_sum`
   / `round_crc32_16_S(...)`, John `memcmp(crc_out, &cur_file->crc.c, 4)`).
2. **There is no "low 3 bytes" truncation of the CRC32 anywhere.** Every CRC32 comparison is a full
   4-byte compare (`memcmp(..., 4)` in John; full 32-bit equality against `digest[0]` in hashcat).
3. **Plaintext bytes 13..15 of the first block are not special.** In the stored-padding check the
   compared range is `plain[pad_start .. 15]` where `pad_start = UnpSize % 16` — which happens to be
   13 only when `UnpSize % 16 == 13`, and only for the **last** block, and only against zero.
4. Where the claim *may* come from: conflating (a) `-hp`'s "decrypt 16 bytes and compare a constant",
   (b) the stored-padding "last byte(s) must be zero" check, and (c) the CRC32 field's existence. The
   plausible 3-byte flavour is the `\x40\x07\x00` tail of the `-hp` constant appearing at plaintext
   indices **4,5,6** (not 13..15), compared against a constant (not the CRC32).

**Correct expressions, for reference:**

| Case | Exact check |
|---|---|
| `-hp` | `AES128-CBC_decrypt(ct[0..15])[0..6] == C4 3D 7B 00 40 07 00` (hashcat additionally pins byte 7 == `00`) |
| `-p`, stored, `UnpSize % 16 != 0` | `AES128-CBC_decrypt(last_ct_block)[UnpSize%16 .. 15] == 0` ×(16 − UnpSize%16) — *filter only* |
| `-p`, stored | `crc32(plaintext[0 .. UnpSize-1]) == le32(FileCRC @ block+16)` |
| `-p`, compressed | `crc32(full_decompress(data)) == le32(FileCRC @ block+16)` **and** decompressed length == `UnpSize`; prefix filter = LZ Huffman / PPMd header check on the first decrypted 16 bytes |

---

## D. KDF — confirmed, with one correction to your wording

The reference implementation is unrar `crypt3.cpp`, `CryptData::SetKey30`. **This single source
answers every part of question D** and is quoted in full below:

```c
void CryptData::SetKey30(bool Encrypt,SecPassword *Password,const wchar *PwdW,const byte *Salt)
{
  ...
  if (!Cached)
  {
    byte RawPsw[2*MAXPASSWORD+SIZE_SALT30];
    size_t PswLength=wcslen(PwdW);
    size_t RawLength=2*PswLength;
    WideToRaw(PwdW,PswLength,RawPsw,RawLength);
    if (Salt!=NULL)
    {
      memcpy(RawPsw+RawLength,Salt,SIZE_SALT30);
      RawLength+=SIZE_SALT30;
    }
    sha1_context c;
    sha1_init(&c);

    const uint HashRounds=0x40000;
    for (uint I=0;I<HashRounds;I++)
    {
      sha1_process_rar29( &c, RawPsw, RawLength );
      byte PswNum[3];
      PswNum[0]=(byte)I;
      PswNum[1]=(byte)(I>>8);
      PswNum[2]=(byte)(I>>16);
      sha1_process(&c, PswNum, 3);
      if (I%(HashRounds/16)==0)
      {
        sha1_context tempc=c;
        uint32 digest[5];
        sha1_done( &tempc, digest );
        AESInit[I/(HashRounds/16)]=(byte)digest[4];
      }
    }
    uint32 digest[5];
    sha1_done( &c, digest );
    for (uint I=0;I<4;I++)
      for (uint J=0;J<4;J++)
        AESKey[I*4+J]=(byte)(digest[I]>>(J*8));
    ...
  }
  rin.Init(Encrypt, AESKey, 128, AESInit);
```

Verdict per sub-claim:

| Your claim | Verdict |
|---|---|
| SHA-1 over UTF-16LE password ‖ salt ‖ 3 bytes LE round counter `I` | **TRUE** — `WideToRaw` (UTF-16LE), `memcpy(RawPsw+RawLength,Salt,SIZE_SALT30)` with `SIZE_SALT30 == 8`, `PswNum[0..2] = I, I>>8, I>>16` |
| iterated `0x40000` times (= 262144) | **TRUE** — `const uint HashRounds=0x40000;`, `for (uint I=0;I<HashRounds;I++)` |
| "the `rar29` write-back quirk" | **TRUE** — `sha1_process_rar29()` (not plain `sha1_process`) is used for the password‖salt part. hashcat implements it as `sha1_update_rar29()` / `sha1_transform_rar29()` which returns the expanded `w[]` and **writes the expanded schedule back into the caller's buffer** (`w[n_idx …] = t[…];` in `m12500-pure.cl`). This matters only for `RawLength > 64` (long passwords); for `PswLength <= 28` bytes it degenerates to ordinary SHA-1. |
| IV bytes from digest byte index 19 at every round where `I % (0x40000/16) == 0` | **TRUE for the index/round rule** — `if (I%(HashRounds/16)==0) { ... AESInit[I/(HashRounds/16)]=(byte)digest[4]; }`. `HashRounds/16 == 0x4000 == 16384`, so there are exactly 16 samples, at `I = 0, 16384, …, 245760`. |
| "i.e. digest[4] low byte" | **TRUE on a little-endian host** — `(byte)digest[4]` is the low byte of word 4. |
| "last byte of the big-endian digest" | **TRUE, and equivalent** — SHA-1's digest is 20 bytes; `digest[4]` is the last 4 bytes, and `(byte)digest[4]` is the *most significant byte* of word 4, which is the **last byte (index 19)** of the big-endian digest. Your phrasing is right, but be aware the two descriptions coincide *only* because `(byte)` truncation picks the MSB on a little-endian machine. hashcat's kernel uses `(ctx_iv.h[4] & 0xff)`, i.e. explicitly the low byte of `h[4]` = the same value. |

  hashcat, `OpenCL/m12500-pure.cl`, `m12500_loop`:

  ```c
  // update IV:

  const u32 init_pos = LOOP_POS / (ROUNDS / 16);
  ...
  // final () for the IV byte:

  sha1_final (&ctx_iv);

  const u32 iv_idx = init_pos / 4;
  const u32 iv_off = init_pos % 4;

  tmps[gid].iv[iv_idx] |= (ctx_iv.h[4] & 0xff) << (iv_off * 8);
  ```

  John, `src/rar_fmt_plug.c`, `crypt_all()` (non-SIMD path):

  ```c
  		SHA1_Init(&ctx);
  		for (i = 0; i < ROUNDS; i++) {
  			PswNum[0] = (unsigned char) i;
  			if ( ((unsigned char) i) == 0) {
  				PswNum[1] = (unsigned char) (i >> 8);
  				PswNum[2] = (unsigned char) (i >> 16);
  			}
  			SHA1_Update(&ctx, RawPsw, RawLength);
  			if (i % (ROUNDS / 16) == 0) {
  				tempctx = ctx;
  				SHA1_Final(tempout, &tempctx);
  				aes_iv[i16 + i / (ROUNDS / 16)] = tempout[19];
  			}
  		}
  ```

  **`tempout[19]`** is the explicit confirmation of digest byte index 19 — identical to unrar's
  `(byte)digest[4]`.

| AES-128 key = little-endian serialization of the final digest's first 4 words | **TRUE** — `AESKey[I*4+J]=(byte)(digest[I]>>(J*8));` for `I=0..3`, `J=0..3`. That is exactly `digest[0]` LE, `digest[1]` LE, `digest[2]` LE, `digest[3]` LE, concatenated. John does the same by byte-swapping on a little-endian host: `for (i = 0; i < 4; i++) digest[i] = JOHNSWAP(digest[i]); memcpy(&aes_key[i16], (unsigned char*)digest, 16);` |

**One correction to your wording:** "with the `rar29` write-back quirk" applies to the
password‖salt update (`sha1_process_rar29`), **not** to the 3-byte counter append
(`sha1_process`, the ordinary one). unrar calls the two differently in the same loop body; do not
apply the quirk to `PswNum`.

**Final `sha1_final` is ordinary SHA-1** (`sha1_done(&c, digest)`), with `ctx.len == 0x40000 * (pw_len + 8 + 3)`:

hashcat `m12500_comp`:
```c
  w3[3] = (ROUNDS * p3) * 8;      // p3 = pw_len + 8 + 3
  sha1_transform (w0, w1, w2, w3, h);
```
John `src/rar_fmt_plug.c` (SIMD path) uses the equivalent `*tail = cur_len*8;` after `cur_len`
reached `ROUNDS * RawLength` with `RawLength = pw_len + 8 + 3`.

**Salt length is 8 in all RAR3 modes** — `-hp` and `-p` alike:
`module_12500.c` / `module_23700.c` / `module_23800.c`: `salt->salt_len = 8;`, and John:
`#define SALT_SIZE 8`, `get_salt()` reads `for (i = 0; i < 8; i++)`.
(The 16-byte figure belongs to RAR5 / mode 13000 and is **not** applicable here.)

Also note unrar's password truncation, which your Rust tool must match to be bit-compatible:

```c
  if (wcslen(PwdW)>=MAXPASSWORD_RAR)
    uiMsg(UIERROR_TRUNCPSW,MAXPASSWORD_RAR-1);

  PwdW[Min(MAXPASSWORD_RAR,MAXPASSWORD)-1]=0; // For compatibility with existing archives.
```

hashcat caps at `pw_max = 128` bytes unoptimized / `20` bytes with the optimized kernel
(`module_pw_max` in all three modules); John uses `PLAINTEXT_LENGTH 28` in the classic build and
`26` in the SIMD build.

---

## E. Exact field layout of RAR4 MAIN / FILE header blocks

All multi-byte integers are **little-endian**. Offsets are relative to the **start of the block**
(the first byte being `HeadCRC`'s low byte). Confirmed independently by unrar `arcread.cpp`
(`ReadHeader15`), whose `Raw.Get2/Get1/Get4` are sequential little-endian reads
(`rawread.cpp`: `Get2 → Data[ReadPos]+(Data[ReadPos+1]<<8)`, `Get4 → RawGet4(...)`), and by John's
`src/rar2john.c`, which indexes `file_hdr_block[]` directly.

### E.1 Common short block header (`SIZEOF_SHORTBLOCKHEAD` = 7 bytes)

| Offset | Size | Field | Notes |
|---|---|---|---|
| +0 | 2 | `HeadCRC` | header CRC; see E.4 |
| +2 | 1 | `HeadType` | `0x72` MARK, `0x73` MAIN, `0x74` FILE, `0x75` ENDARC, `0x77` CMT, `0x7a` SUB/CMT, `0x7b` PROTECT, `0x78`/`0x79` old service |
| +3 | 2 | `Flags` | MAIN vs FILE meanings |
| +5 | 2 | `HeadSize` | total block size incl. these 7 bytes; data starts at `block + HeadSize` |

hashcat `module_12500.c` comment (independent confirmation of the `-hp` flag bit):
`if (archive_hdr_block[2] != 0x73)` in John; the flag bits used above are from
`archive_hdr_head_flags & 0x0080` (MAIN `MHD_PASSWORD`) and `file_hdr_head_flags & 0x0004`
(FILE `LHD_PASSWORD`).

### E.2 MAIN header (`0x73`)

| Offset | Size | Field |
|---|---|---|
| +0 | 2 | `HeadCRC` |
| +2 | 1 | `HeadType` = 0x73 |
| +3 | 2 | `Flags` |
| +5 | 2 | `HeadSize` |
| **+7** | **2** | **`HighPosAV`** |
| **+9** | **4** | **`PosAV`** |

unrar `arcread.cpp`:
```c
    case HEAD_MAIN:
      MainHead.Reset();
      MainHead.SetBaseBlock(ShortBlock);
      MainHead.HighPosAV=Raw.Get2();
      MainHead.PosAV=Raw.Get4();
```
John (`src/rar2john.c`) only reads the first 13 bytes of the MAIN block and then skips to
`HeadSize`, which is consistent:
```c
	/* archive header block */
	if (fread(archive_hdr_block, 13, 1, fp) != 1) { ... }
	if (archive_hdr_block[2] != 0x73) { ... }
```
`HeadSize` is read at `archive_hdr_block[6]<<8 | archive_hdr_block[5]` — **confirming +5..+6**.

### E.3 FILE header (`0x74`) — you asked specifically about `FileCRC`

| Offset | Size | Field | unrar accessor | John index |
|---|---|---|---|---|
| +0 | 2 | `HeadCRC` | `Raw.Get2()` | `[0..1]` |
| +2 | 1 | `HeadType` (`0x74`) | `Raw.Get1()` | `[2]` |
| +3 | 2 | `Flags` | `Raw.Get2()` | `[3..4]` |
| +5 | 2 | `HeadSize` | `Raw.Get2()` | `[5..6]` |
| +7 | 4 | `PackSize` (low 32) | `hd->DataSize=Raw.Get4()` | `[7..10]` |
| +11 | 4 | `UnpSize` (low 32) | `LowUnpSize=Raw.Get4()` | `[11..14]` |
| +15 | 1 | `HostOS` | `hd->HostOS=Raw.Get1()` | `[15]` |
| **+16** | **4** | **`FileCRC`** | `hd->FileHash.CRC32=Raw.Get4()` | **`[16..19]`** |
| +20 | 4 | `FileTime` (DOS) | `FileTime=Raw.Get4()` | `[20..23]` |
| +24 | 1 | `UnpVer` | `hd->UnpVer=Raw.Get1()` | `[24]` |
| +25 | 1 | `Method` | `hd->Method=Raw.Get1()-0x30` | `[25]` |
| +26 | 2 | `NameSize` | `NameSize=Raw.Get2()` | `[26..27]` |
| +28 | 4 | `FileAttr` | `hd->FileAttr=Raw.Get4()` | — |
| +32 | `NameSize` | `FileName` | `Raw.GetB(...)` | read separately |
| … | … | optional `SubData` (HEAD_SERVICE only) | | |
| … | 8 | `Salt` (`SIZE_SALT30`) iff `Flags & 0x400` | `Raw.GetB(hd->Salt,SIZE_SALT30)` | read separately |
| … | … | `EXT_TIME` iff `Flags & 0x1000` | | |
| … | 4+4 | `HighPackSize`, `HighUnpSize` iff `Flags & 0x100` (`LHD_LARGE`) | `Raw.Get4(); Raw.Get4();` | `rejbuf` |

**`FileCRC` is at byte offset `+16` from the start of the block** (`[16],[17],[18],[19]`,
little-endian, `crc = b16 | b17<<8 | b18<<16 | b19<<24`). This is confirmed *three* ways:

1. unrar's sequential reads (above) — 7+4+4+1 = 16.
2. John's raw parser computes `file_hdr_pack_size` from `file_hdr_block[10..7]` and
   `file_hdr_unp_size` from `file_hdr_block[14..11]`, i.e. PackSize at +7 and UnpSize at +11, then:
   ```c
		memcpy(file_crc, file_hdr_block + 16, 4);
		for (i = 0; i < 4; i++) { /* encode file_crc */
			best_len += sprintf(&best[best_len], "%c%c", itoa16[ARCH_INDEX(file_crc[i] >> 4)], itoa16[ARCH_INDEX(file_crc[i] & 0x0f)]);
		}
   ```
3. John's `file_hdr_block[24] < 29` version gate (UnpVer at +24) and `method = file_hdr_block[25]`
   (`rand`-check comment "0x30 - storing"), plus `file_name_size = file_hdr_block[27] << 8 | file_hdr_block[26]`.

The standard RAR4 "part 1" of the file header is therefore exactly **32 bytes** — matching John's
`count = fread(file_hdr_block, 32, 1, fp);` and unrar's `SIZEOF_FILEHEAD3`.

Note: `LHD_LARGE` (`Flags & 0x100`) adds `HighPackSize`/`HighUnpSize` **after** the 32-byte part
(John: after the name, reading two extra `rejbuf` 4-byte words; unrar: after `FileAttr`). The
low-32 values remain at +7/+11.

### E.4 The RAR4 header CRC rule

**Yes — it is the low 16 bits of CRC32 over the block bytes starting at the `HeadType` byte and
running to the end of the header.** unrar `rawread.cpp`:

```c
uint RawRead::GetCRC15(bool ProcessedOnly) // RAR 1.5 block CRC.
{
  if (DataSize<=2)
    return 0;
  uint HeaderCRC=CRC32(0xffffffff,&Data[2],(ProcessedOnly ? ReadPos:DataSize)-2);
  return ~HeaderCRC & 0xffff;
}
```

Interpretation, precisely:

* `&Data[2]` — start at the **`HeadType`** byte (offset +2).
* length = `DataSize - 2` — i.e. through the end of the header (the whole `HeadSize` bytes that were
  read), so the range is `[block+2, block+HeadSize)`.
* Standard reflected CRC-32 (`CRC32` in unrar is the reflected `0xEDB88320` polynomial), initialised
  to `0xffffffff`, **final XOR `0xffffffff`**, then **truncated to the low 16 bits**.
  Equivalently: `HeadCRC == (crc32(block[2 .. HeadSize-1]) & 0xFFFF)`.
* `ProcessedOnly` selects `ReadPos` instead of `DataSize`, used only for the
  `hd->CommentInHeader` (`LHD_COMMENT`) case where an old-style comment is embedded:

```c
        bool CRCProcessedOnly=hd->CommentInHeader;
        uint HeaderCRC=Raw.GetCRC15(CRCProcessedOnly);
        if (hd->HeadCRC!=HeaderCRC)
        {
          BrokenHeader=true;
          ErrHandler.SetErrorCode(RARX_WARNING);
          ...
```

  i.e. for a FILE header with `LHD_COMMENT` set, the CRC covers only up to the name (the point where
  parsing stopped) rather than the whole block.

### E.5 Do hashcat / John rely on that rule?

**No — neither tool validates any RAR4 header CRC.** Searched all fetched hashcat RAR3 modules and
John's `rar2john.c`, `rar_common.h`, `rar_fmt_plug.c`: the only CRC32 computed is the **plaintext
data CRC32**, never a header CRC. (`module_23700.c`/`module_23800.c` name a token `crc32_sum`, but
its value comes from the hash line's `hex(crc)` field, which `rar2john` filled from `FileCRC` at
block +16 — it is the *file data* CRC.)

Practical implications for you:

* You may use the header CRC to **validate your own header parse** (a strong sanity check), and you
  should verify it against real archives before trusting your offset table.
* If your parser sees a header whose CRC does not match, that is a strong signal you have the wrong
  offsets, an unhandled `LHD_COMMENT`/`LHD_LARGE` case, or a **`-hp` archive** — in which case the
  header bytes are AES-encrypted and the CRC is meaningless until decrypted.

---

## F. What an attacker-supplied hash line contains (modes 12500 / 23700 / 23800)

### F.1 Mode 12500 — `RAR3-hp` (`module_12500.c`)

Format string (`module_hash_encode`):

```c
  return snprintf (line_buf, line_size, "%s*0*%08x%08x*%08x%08x%08x%08x",
      SIGNATURE_RAR3,
      byte_swap_32 (salt->salt_buf[0]),
      byte_swap_32 (salt->salt_buf[1]),
      salt->salt_buf[2],
      salt->salt_buf[3],
      salt->salt_buf[4],
      salt->salt_buf[5]);
```

Sample `ST_HASH`:
`$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317`

Token spec (`token_cnt = 4`):

| # | Field | Length | Notes |
|---|---|---|---|
| 0 | `$RAR3$` | 6 | fixed signature |
| 1 | type | 1 | must be `'0'` (`if (type_pos[0] != '0') return (PARSER_SIGNATURE_UNMATCHED);`) |
| 2 | salt (hex) | 16 | exactly 8 bytes |
| 3 | ciphertext (hex) | 32 | exactly 16 bytes |

**Archive fields that matter:** only the last 24 bytes of the file (8-byte salt, 16-byte encrypted
block). No `PackSize`, `UnpSize`, `FileCRC`, `Method`, `NameSize`, or file name is needed. The
expected plaintext is a hardcoded constant (section A).

### F.2 Modes 23700 / 23800 — `RAR3-p`

Format string (`module_23700.c` / `module_23800.c` `module_hash_encode`):

```c
      "%s*1*%08x%08x*%08x*%u*%u*1*%s*%i"          // 23800: trailing %i = method (31..35)
      "%s*1*%08x%08x*%08x*%u*%u*1*%s*30"          // 23700: literal 30
```

`token_cnt = 9` in both:

| # | Sample value (23800 `ST_HASH`) | Meaning | Constraints |
|---|---|---|---|
| 0 | `$RAR3$` | signature | fixed len 6 |
| 1 | `1` | **type**: `1` = `-p` | must be `'1'` |
| 2 | `ad56eb40219c9da2` | **8-byte salt** (hex, 16 chars) | fixed len 16, hex |
| 3 | `834064ce` | **FileCRC** (hex, 8 chars) — the value from FILE header offset **+16** | fixed len 8, hex |
| 4 | `32` | **PackSize** (decimal) | 23700: `1..327680` **and `% 16 == 0`**; 23800: `1..327680` |
| 5 | `13` | **UnpSize** (decimal) | 23700: `1..655360` **and `<= PackSize`**; 23800: `1..655360` |
| 6 | `1` | **is-data-inline** flag; `1` = the ciphertext is hex-encoded in field 7, `0` = fields 7/8 are `archive_name` and byte offset | must be `'1'` for hashcat |
| 7 | `eb47b1abe17a1a75bce9…` | **encrypted file data**, hex | `data_len == pack_size * 2` (23700); `2..655056` chars (23800) |
| 8 | `33` | **Method** (`0x33` = normal) | 23700: must equal `30`; 23800: `31..35` |

Sample 23700 `ST_HASH` (stored):
`$RAR3$*1*e54a73729887cb53*49b0a846*16*14*1*34620bcca8176642a210b1051901921e*30`

**Which archive fields matter, mapping to the file header:**

| Hash-line field | FILE header source |
|---|---|
| salt (field 2) | `Flags & 0x400` ⇒ the 8 bytes after the name |
| FileCRC (field 3) | block offset **+16**, read as a little-endian `u32` (`Raw.Get4()`), reproduced by `rar2john` as `memcpy(file_crc, file_hdr_block + 16, 4)` |
| PackSize (field 4) | block offset **+7**, `Raw.Get4()` (+ `HighPackSize` if `Flags & 0x100`) |
| UnpSize (field 5) | block offset **+11**, `Raw.Get4()` (+ `HighUnpSize` if `Flags & 0x100`) |
| data (field 7) | the encrypted bytes at `block + HeadSize`, length `PackSize` (John inlines them; it can also emit `0*archive_name*offset` instead) |
| Method (field 8) | block offset **+25** (`Raw.Get1()`, stored as `0x30..0x35`) |

John's emitted `-p` line (from `src/rar2john.c`) is the same shape with the ciphertext inlined:

```c
		best_len += sprintf(&best[best_len], "*%"PRIu64"*%"PRIu64"*",
		        (uint64_t)file_hdr_pack_size,
		        (uint64_t)file_hdr_unp_size);

		/* We always store it inline */

		best_len += sprintf(&best[best_len], "1*");
		...
		best_len += sprintf(p, "*%02x:%d::", method, type);
```

The trailing `:1::` is JtR's type/GECOS separator, not part of hashcat's format.
**Do not feed John output to hashcat unmodified** (the `%02x` method is written in hex by John but
parsed as decimal by hashcat's `hc_strtoul(..., 10)`).

Which file to pick: `rar2john` explicitly prefers a **stored** file (`method == 0x30`) and the
smallest `PackSize`, and warns when the candidate is too small to avoid false positives:

```c
		if (bestsize.unp < (bestsize.method > 0x30 ? 5 : 1))
			fprintf(stderr, "! WARNING best candidate found is too small, you may see false positives.\n");
```

Because a 32-bit CRC32 is only a 2^-32 filter, a tiny stored file with `UnpSize` of 1 or 2 bytes will
produce false positives — the same caveat applies to your Rust tool.

---

## Appendix: consolidated byte-level recipe for a Rust implementation

```
KDF(pw_bytes_utf16le, salt8) -> (key16, iv16):
    buf = pw_utf16le || salt8                       // length L = 2*len(pw) + 8
    h = SHA1_INIT
    for I in 0 .. 0x40000:
        sha1_update_rar29(h, buf, L)                // quirk: may rewrite buf's expanded words when L > 64
        sha1_update(h, [I & 0xFF, (I>>8) & 0xFF, (I>>16) & 0xFF])
        if I % 0x4000 == 0:
            d = sha1_final_copy(h)
            iv[I / 0x4000] = d[19]                  // == (d_word[4] & 0xFF) on LE
    d = sha1_final_copy(h)
    key = le32(d[0]) || le32(d[1]) || le32(d[2]) || le32(d[3])
    return (key, iv)
```

```
check_hp(archive_bytes) -> bool:
    L = len(archive_bytes)
    salt = archive_bytes[L-24 : L-16]
    ct   = archive_bytes[L-16 : L  ]
    (key, iv) = KDF(pw, salt)
    P = AES128_CBC_decrypt(key, iv, ct)             // single block, IV = iv
    return P[0..6] == C4 3D 7B 00 40 07 00          // hashcat additionally requires P[7] == 0x00
```

```
check_p_stored(file_hdr_block, data_offset, file_bytes) -> bool:
    flags    = le16(file_hdr_block[3..4])
    headsize = le16(file_hdr_block[5..6])
    packsize = le32(file_hdr_block[7..10])
    unpsize  = le32(file_hdr_block[11..14])
    filecrc  = le32(file_hdr_block[16..19])
    namesize = le16(file_hdr_block[26..27])
    method   = file_hdr_block[25]
    assert method == 0x30 and flags & 0x0004 and flags & 0x400
    assert file_hdr_block[24] >= 29
    salt_off = 32 + namesize                        // (plus SubData for HEAD_SERVICE)
    salt = file_hdr_block[salt_off : salt_off+8]
    (key, iv) = KDF(pw, salt)
    ct = file_bytes[data_offset : data_offset + packsize]
    plain = AES128_CBC_decrypt(key, iv, ct)         // whole stream; chaining iv = ct block
    // optional cheap filter (only valid when unpsize % 16 != 0):
    //   plain[unpsize .. round_up_16(unpsize)-1] all zero
    return crc32_standard(plain[0:unpsize]) == filecrc
```

```
check_p_compressed(...) -> bool:
    // identical parse; method in 0x31..0x35
    (key, iv) = KDF(pw, salt)
    plain = AES128_CBC_decrypt(key, iv, ct)
    // optional filter on plain[0:16]:
    //   if plain[0] & 0x80: PPM  -> (plain[0] & 0x20) != 0 && (plain[1] & 0x80) == 0
    //   else:               LZ   -> (plain[0] & 0x40) == 0 && check_huffman(plain)
    out = rar_unpack29_equivalent(plain, unpsize)   // full LZ (and PPMd) decompression
    return out.len == unpsize && crc32_standard(out) == filecrc
```

```
header_crc_ok(block) -> bool:                        // NOT used by hashcat or John
    headsize = le16(block[5..6])
    return le16(block[0..1]) == (crc32_standard(block[2:headsize]) & 0xFFFF)
```

---

## Source index

| Source | URL |
|---|---|
| hashcat 12500 (RAR3-hp) | https://raw.githubusercontent.com/hashcat/hashcat/master/src/modules/module_12500.c |
| hashcat 13000 (**RAR5**, not RAR3-p) | https://raw.githubusercontent.com/hashcat/hashcat/master/src/modules/module_13000.c |
| hashcat 23700 (RAR3-p **Uncompressed**) | https://raw.githubusercontent.com/hashcat/hashcat/master/src/modules/module_23700.c |
| hashcat 23800 (RAR3-p **Compressed**) | https://raw.githubusercontent.com/hashcat/hashcat/master/src/modules/module_23800.c |
| hashcat RAR3 decoder | https://raw.githubusercontent.com/hashcat/hashcat/master/src/modules/rar3_decode.c |
| hashcat RAR3 unpack status | https://raw.githubusercontent.com/hashcat/hashcat/master/src/modules/rar3/rar3_status.h |
| hashcat m12500 kernel | https://raw.githubusercontent.com/hashcat/hashcat/master/OpenCL/m12500-pure.cl |
| hashcat m23700 kernel | https://raw.githubusercontent.com/hashcat/hashcat/master/OpenCL/m23700-pure.cl |
| hashcat m23800 kernel | https://raw.githubusercontent.com/hashcat/hashcat/master/OpenCL/m23800-pure.cl |
| hashcat CRC helpers | https://raw.githubusercontent.com/hashcat/hashcat/master/OpenCL/inc_checksum_crc.cl |
| John `rar2john` (real location) | https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/src/rar2john.c |
| John RAR3 CPU format + verify | https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/src/rar_common.h |
| John RAR3 format registration + KDF | https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/src/rar_fmt_plug.c |
| unrar RAR3 KDF (normative) | https://raw.githubusercontent.com/aawc/unrar/master/crypt3.cpp |
| unrar RAR3 header CRC | https://raw.githubusercontent.com/aawc/unrar/master/rawread.cpp |
| unrar RAR3 header parsing | https://raw.githubusercontent.com/aawc/unrar/master/arcread.cpp |
