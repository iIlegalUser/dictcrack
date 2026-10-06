# ============================================================
#  run-tests.ps1 -- end-to-end tests for the native DictCrack
#
#  ASCII only on purpose (safe under any system code page).
#
#  Usage:
#    powershell -ExecutionPolicy Bypass -File tests\run-tests.ps1
#    powershell -ExecutionPolicy Bypass -File tests\run-tests.ps1 -ExePath <cli.exe>
#
#  -ExePath points the suite at a different dictcrack CLI binary (e.g. the
#  Rust rewrite); GUI tests and the C# build step are skipped in that mode.
# ============================================================

param([string]$ExePath = '')

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist'
$cli  = Join-Path $dist 'dictcrack.exe'
$gui  = Join-Path $dist 'dictcrack-gui.exe'
$cfg  = Join-Path $dist 'dictcrack-gui.cfg'

# ---- build -----------------------------------------------------------
if ($ExePath -ne '') {
    Write-Output ("== external CLI under test: " + $ExePath + " ==")
    if (-not (Test-Path $ExePath)) { throw ("ExePath not found: " + $ExePath) }
    $cli = (Resolve-Path $ExePath).Path
    # session.json / result files are written next to the tested exe; make
    # sure no stale session from an earlier run leaks into the resume tests
    $extDir = Split-Path -Parent $cli
    $stale = Join-Path $extDir 'session.json'
    if (Test-Path $stale) { Remove-Item -LiteralPath $stale -Force }
} else {
    Write-Output '== building =='
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'build\build.ps1') | ForEach-Object { Write-Output "  $_" }
    if (-not (Test-Path $cli)) { throw 'dictcrack.exe was not produced' }
    if (-not (Test-Path $gui)) { throw 'dictcrack-gui.exe was not produced' }
}

# ---- tools -----------------------------------------------------------
$rar = $null
foreach ($cand in @('D:\Software\WinRAR\rar.exe',
    (Join-Path $env:ProgramFiles 'WinRAR\rar.exe'))) {
    if ($cand -and (Test-Path $cand)) { $rar = $cand; break }
}
if (-not $rar) { $c = Get-Command rar.exe -ErrorAction SilentlyContinue; if ($c) { $rar = $c.Source } }
$sz = $null
foreach ($cand in @('D:\Software\Scoop\shims\7z.exe',
    (Join-Path $env:ProgramFiles '7-Zip\7z.exe'))) {
    if (Test-Path $cand) { $sz = $cand; break }
}
if (-not $sz) { $c = Get-Command 7z.exe -ErrorAction SilentlyContinue; if ($c) { $sz = $c.Source } }
if (-not $sz) { Write-Output 'SKIP: 7z.exe not found - cannot build fixtures'; exit 0 }
Write-Output ("7z: " + $sz)
if ($rar) { Write-Output ("rar: " + $rar) } else { Write-Output 'rar.exe not found: RAR5 fixtures will be skipped' }

# Pin the fallback tool for the whole suite: ToolLocator prefers the
# DICTCRACK_TOOL environment variable, so a user-set variable pointing at
# rar.exe would silently move the 7z-fixture spawn tests (19-21) onto the
# CRT-argv quoting path and test something else than the comments claim.
$oldTool = $env:DICTCRACK_TOOL
$env:DICTCRACK_TOOL = $sz

# ---- protect the user's GUI cfg ---------------------------------------
$cfgBak = $null
if (Test-Path $cfg) {
    $cfgBak = Join-Path $dist 'dictcrack-gui.cfg.testbak'
    Move-Item -LiteralPath $cfg -Destination $cfgBak -Force
}
# snapshot pre-existing result files so the finally only removes the ones
# the tests created (a real crack result may live next to the exe)
$preResults = @(Get-ChildItem (Join-Path $dist '*_password.txt') -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })

$fail = 0
$tmp = $null
$session = Join-Path (Split-Path -Parent $cli) 'session.json'

function Fail([string]$name, [string]$why) {
    Write-Output ("  FAIL {0} ({1})" -f $name, $why)
    $script:fail++
}
function Pass([string]$name) { Write-Output ("  PASS " + $name) }

function Run-Cli {
    # returns exit code; stdout/stderr available via $script:lastOut.
    # EAP must be Continue here: with Stop, redirecting the child's
    # stderr (2>&1) raises NativeCommandError on error-path tests.
    #
    # Runs under a watchdog on purpose: a CLI that never returns (the
    # pre-flight done-flag hang once wedged the whole suite with no output)
    # must fail the test, not block CI forever. 120s is far above the
    # slowest legitimate case here (test 15/26 resume runs are seconds).
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $job = Start-Job -ScriptBlock {
        param($exe, $cliArgs)
        $ErrorActionPreference = 'Continue'
        $o = & $exe @cliArgs 2>&1
        [pscustomobject]@{ Out = (($o | ForEach-Object { "$_" }) -join "`n"); Code = $LASTEXITCODE }
    } -ArgumentList $script:cli, $args
    if (-not (Wait-Job $job -Timeout 120)) {
        Stop-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        $ErrorActionPreference = $old
        $script:lastOut = 'TIMEOUT: CLI did not exit within 120s'
        return -999
    }
    $r = Receive-Job $job
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    $ErrorActionPreference = $old
    $script:lastOut = $r.Out
    return $r.Code
}

try {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('dictcrack-test-' + [System.Guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    # 256 KB of pseudo-random bytes: incompressible, so encrypted entries
    # stay large and the AES-HMAC / ZipCrypto full-CRC confirms run over
    # real multi-KB data (a 34-byte payload once hid an HMAC prefix bug)
    $pb = New-Object byte[] 262144
    (New-Object Random 42).NextBytes($pb)
    [System.IO.File]::WriteAllBytes((Join-Path $tmp 'payload.txt'), $pb)

    # ---- fixtures ----------------------------------------------------
    # rar.exe is a standard CRT argv program, so PowerShell's own argument
    # quoting produces the command line it expects; only 7z.exe parses the
    # raw line itself and needs the ProcessStartInfo route (New-7zRaw below)
    function New-Rar([string]$name, [string]$pw, [bool]$hp) {
        $a = Join-Path $script:tmp $name
        if ($hp) { & $script:rar a -ep -ma5 "-hp$pw" $a (Join-Path $script:tmp 'payload.txt') | Out-Null }
        else { & $script:rar a -ep -ma5 "-p$pw" $a (Join-Path $script:tmp 'payload.txt') | Out-Null }
        if (-not (Test-Path $a)) { throw "failed to create $a" }
        return $a
    }
    function New-Zip([string]$name, [string]$pw, [string]$mem) {
        $a = Join-Path $script:tmp $name
        & $script:sz a -tzip "-mem=$mem" "-p$pw" $a (Join-Path $script:tmp 'payload.txt') | Out-Null
        if (-not (Test-Path $a)) { throw "failed to create $a" }
        return $a
    }
    function New-7z([string]$name, [string]$pw) {
        $a = Join-Path $script:tmp $name
        & $script:sz a "-p$pw" $a (Join-Path $script:tmp 'payload.txt') | Out-Null
        if (-not (Test-Path $a)) { throw "failed to create $a" }
        return $a
    }
    # RAR 1.5-4.x fixtures. WinRAR 7.12 cannot create RAR4 ("-ma4" is
    # rejected: unknown option), so the two gold archives are frozen here as
    # hex literals. Both were verified against external reference
    # decryptors before being frozen:
    #   rar4hp.rar  -hp, pw HpGold55   -> UnRAR.exe t exit 0 (wrong pw 3)
    #   rar4p.rar   -p stored, pw Rar4Gold9 -> 7z.exe t exit 0 (wrong pw 2)
    function New-Rar4([string]$name, [string]$hex) {
        $a = Join-Path $script:tmp $name
        $bytes = New-Object byte[] ($hex.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
        }
        [System.IO.File]::WriteAllBytes($a, $bytes)
        return $a
    }
    # 7z fixtures used by the native-7z tests. The coder layout of an archive
    # decides whether a password can be checked natively, so these cover one
    # archive per branch:
    #   s7z_mhe   header-encrypted (-mhe), AES-only header folder -> native CRC
    #   s7z_copy  content-encrypted, stored entry (AES + COPY)   -> native CRC
    #   s7z_lzma2 content-encrypted, LZMA2 entry                 -> external tool
    # (a "-mhe" archive whose header needs a decompressor also falls back;
    #  that branch is covered by the Rust unit tests' frozen samples)
    function New-7zMhe([string]$name, [string]$pw) {
        $a = Join-Path $script:tmp $name
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $script:sz
        $psi.Arguments = 'a -y -mhe=on "-p' + $pw + '" "' + $a + '" "' + (Join-Path $script:tmp 'payload.txt') + '"'
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        $p.WaitForExit()
        if ($p.ExitCode -ne 0) { throw ("7z exited " + $p.ExitCode + " while creating " + $a) }
        if (-not (Test-Path $a)) { throw "failed to create $a" }
        return $a
    }
    function New-7zCopy([string]$name, [string]$pw) {
        # -m0=Copy keeps the entry stored, so the only coder above AES is COPY
        $a = Join-Path $script:tmp $name
        & $script:sz a -y -m0=Copy "-p$pw" $a (Join-Path $script:tmp 'payload.txt') | Out-Null
        if (-not (Test-Path $a)) { throw "failed to create $a" }
        return $a
    }
    function New-7zCopyTiny([string]$name, [string]$pw, [int]$bytes) {
        # a payload small enough to fit ONE AES block (pack == 16) with
        # padding. Regression guard: the AES+COPY padding pre-filter used to
        # look at the previous ciphertext block for the CBC IV, so a
        # single-block stream had no IV to chain from and every candidate was
        # rejected -- a silent false negative on a real password.
        $a = Join-Path $script:tmp $name
        $src = Join-Path $script:tmp ("tiny" + $bytes + ".bin")
        $buf = New-Object byte[] $bytes
        for ($i = 0; $i -lt $bytes; $i++) { $buf[$i] = 0x41 + ($i % 26) }
        [System.IO.File]::WriteAllBytes($src, $buf)
        & $script:sz a -y -m0=Copy "-p$pw" $a $src | Out-Null
        if (-not (Test-Path $a)) { throw "failed to create $a" }
        return $a
    }
    function New-7zLzma2([string]$name, [string]$pw) {
        $a = Join-Path $script:tmp $name
        & $script:sz a -y -m0=LZMA2 "-p$pw" $a (Join-Path $script:tmp 'payload.txt') | Out-Null
        if (-not (Test-Path $a)) { throw "failed to create $a" }
        return $a
    }
    function New-7zRaw([string]$name, [string]$pw) {        # a password containing quotes cannot go through PowerShell's native
        # argument encoding (PS rewrites " to \"), but 7z.exe parses the raw
        # command line itself ("" collapses to one quote), so build that line
        # directly - same rules WinArg.SimpleQuote applies on the crack side
        $a = Join-Path $script:tmp $name
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $script:sz
        $psi.Arguments = 'a -y -p' + ($pw -replace '"', '""') + ' "' + $a + '" "' + (Join-Path $script:tmp 'payload.txt') + '"'
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        $p.WaitForExit()
        if ($p.ExitCode -ne 0) { throw ("7z exited " + $p.ExitCode + " while creating " + $a) }
        if (-not (Test-Path $a)) { throw "failed to create $a" }
        return $a
    }

    $rar5 = $null; $rar5hp = $null; $rar5cn = $null
    if ($rar) {
        $rar5 = New-Rar 'rar5.rar' 'Secret42' $false
        $rar5hp = New-Rar 'rar5hp.rar' 'head999' $true
    }
    $zc = New-Zip 'zc.zip' 'zippw0' 'ZipCrypto'
    $za = New-Zip 'za.zip' 'aespw1' 'AES256'
    $s7 = New-7z 's7.7z' '7zpw2'
    # native-7z fixtures, one per coder-layout branch (see New-7zMhe etc.)
    $s7mhe = New-7zMhe 's7mhe.7z' 'mhepw77'
    $s7copy = New-7zCopy 's7copy.7z' 'copypw88'
    $s7lzma2 = New-7zLzma2 's7lzma2.7z' 'lzmapw99'
    # RAR4 gold samples (see New-Rar4): hp = header-encrypted, p = stored -p
    $rar4hp = New-Rar4 'rar4hp.rar' ('526172211a0700ce997380000d000000000000002b91d04c6e88f71551ec4427d1525719' +
        '3c8498c3f5d9a217d44725a3c16fe7b6b845e34bef23412d6fce3bbc05248fad73506e52' +
        'badf2f2769f960be8d8c16903627623886af1a90c348e1358c92c40c88f5282b428f492c' +
        '77e2b0a41d9c5f38626d22a5386ea6908ae7e906a91e543a')
    $rar4p = New-Rar4 'rar4p.rar' ('526172211a0700cf907300000d000000000000005ae17404843000200000001d00000003' +
        '17dabb7e000000501d30080020000000676f6c642e74787411c3a54f8e2b90d1211b0f19' +
        '0c49038d823063bf4407acdd11a4a4548ae77eb1e43543531f4e3861c43d7b00400700')
    $plain = Join-Path $tmp 'plain.zip'
    & $sz a $plain (Join-Path $tmp 'payload.txt') | Out-Null

    # ---- helper: dict + result file ----------------------------------
    function Write-Dict([string]$name, [string[]]$lines) {
        $d = Join-Path $script:tmp $name
        Set-Content -Path $d -Value $lines
        return $d
    }
    function Result-Path([string]$arch) {
        # result files land next to the tested exe (dist\ for the C# build,
        # the exe's own dir for -ExePath), not a fixed directory
        $exeDir = Split-Path -Parent $script:cli
        return Join-Path $exeDir (([System.IO.Path]::GetFileNameWithoutExtension($arch)) + '_password.txt')
    }
    function Remove-Result([string]$arch) {
        Remove-Item (Result-Path $arch) -Force -ErrorAction SilentlyContinue
    }
    function Read-Result([string]$arch) {
        $p = Result-Path $arch
        if (-not (Test-Path $p)) { return $null }
        # the tool writes results as explicit GBK(936)/UTF-8-BOM, never the
        # machine's system ANSI page (CI runners are en-US)
        return ([System.IO.File]::ReadAllText($p, [System.Text.Encoding]::GetEncoding(936))).Trim()
    }
    function Expect-Hit([string]$name, [string]$arch, [string]$dict, [string]$pw) {
        Remove-Result $arch
        $code = Run-Cli crack -a $arch -w $dict -q
        $got = Read-Result $arch
        if ($code -eq 0 -and $got -eq $pw) { Pass $name }
        else { Fail $name ("exit=" + $code + " got='" + $got + "'") }
    }

    # ---- test 1-3: info + native hits --------------------------------
    if ($rar) {
        Write-Output 'test 1: info reports RAR5 native path'
        $code = Run-Cli info $rar5
        if ($code -eq 0 -and $script:lastOut -match 'RAR 5' -and $script:lastOut -match 'native') { Pass 'test 1' }
        else { Fail 'test 1' ($script:lastOut -replace "`n", ' | ') }

        Write-Output 'test 2: RAR5 -p dictionary hit (native PBKDF2 check)'
        $d = Write-Dict 'd2.txt' @('apple', 'wrong', 'Secret42', 'banana')
        Expect-Hit 'test 2' $rar5 $d 'Secret42'

        Write-Output 'test 3: RAR5 -hp (header encryption) dictionary hit'
        $d = Write-Dict 'd3.txt' @('apple', 'head999', 'banana')
        Expect-Hit 'test 3' $rar5hp $d 'head999'
    } else {
        Write-Output 'test 1-3: SKIP (no rar.exe)'
    }

    # ---- test 3a-3d: RAR4 native path (frozen gold samples) ----------
    # These do NOT need rar.exe: the archives are byte literals already
    # validated against UnRAR/7z.exe, and RAR4 was previously spawn-only.
    #
    # Only the Rust engine has native RAR4; the C# engine deliberately keeps
    # the 7z.exe fallback. So the *routing* assertion is engine-aware while
    # the hit/miss assertions run on both (the fallback reaches the same
    # answers, just through a subprocess).
    $rustEngine = $ExePath -ne ''
    Write-Output 'test 3a: info routes RAR4 -hp to the engine that supports it'
    $code = Run-Cli info $rar4hp
    $wantRoute = if ($rustEngine) { 'native' } else { 'external' }
    if ($code -eq 0 -and $script:lastOut -match 'RAR 1.5-4.x' -and $script:lastOut -match $wantRoute) { Pass 'test 3a' }
    else { Fail 'test 3a' ("want=" + $wantRoute + " " + ($script:lastOut -replace "`n", ' | ')) }

    Write-Output 'test 3b: RAR4 -hp dictionary hit (SHA-1 KDF + ENDARC block)'
    $d = Write-Dict 'd3b.txt' @('apple', 'HpGold55', 'banana')
    Expect-Hit 'test 3b' $rar4hp $d 'HpGold55'

    Write-Output 'test 3c: RAR4 -p stored dictionary hit (KDF + AES-CBC + CRC32)'
    $code = Run-Cli info $rar4p
    # the target entry name only appears once the Rust parser reads the RAR4
    # file header; the C# engine has no RAR4 header support
    $nameOk = (-not $rustEngine) -or ($script:lastOut -match 'gold.txt')
    if ($code -ne 0 -or -not $nameOk) { Fail 'test 3c' ('info: ' + ($script:lastOut -replace "`n", ' | ')) }
    else {
        $d = Write-Dict 'd3c.txt' @('apple', 'banana', 'Rar4Gold9')
        Expect-Hit 'test 3c' $rar4p $d 'Rar4Gold9'
    }

    Write-Output 'test 3d: RAR4 wrong dictionary exhausts (exit 1, no result)'
    $d = Write-Dict 'd3d.txt' @('apple', 'Rar4Gold', 'HpGold5', 'banana')
    Remove-Result $rar4hp
    $code = Run-Cli crack -a $rar4hp -w $d -q
    if ($code -eq 1 -and -not (Test-Path (Result-Path $rar4hp))) { Pass 'test 3d' }
    else { Fail 'test 3d' ("exit=" + $code) }

    Write-Output 'test 4: ZIP ZipCrypto hit incl. full-CRC confirm'
    $d = Write-Dict 'd4.txt' @('apple', 'zippw0')
    Expect-Hit 'test 4' $zc $d 'zippw0'

    Write-Output 'test 5: ZIP AES-256 hit (PBKDF2 + HMAC verify)'
    $d = Write-Dict 'd5.txt' @('apple', 'aespw1')
    Expect-Hit 'test 5' $za $d 'aespw1'

    Write-Output 'test 6: 7z archive via external tool fallback'
    $d = Write-Dict 'd6.txt' @('apple', '7zpw2')
    Expect-Hit 'test 6' $s7 $d '7zpw2'

    # ---- test 6a-6d: native 7z paths ---------------------------------
    # Which 7z archives can be checked natively depends on the coder chain,
    # not on the file extension: an AES-only header (or AES + COPY) has a
    # CRC to compare, while AES + LZMA/LZMA2 needs a decompressor and must
    # stay on the external tool.
    #
    # Native 7z exists only in the Rust engine, so 6a (routing) and 6d (the
    # no-external-tool proof) require -ExePath. The hit/miss assertions 6b/6c
    # run on both engines, since the C# fallback reaches the same answers
    # through 7z.exe.
    if ($rustEngine) {
        Write-Output 'test 6a: info routes 7z branches (native vs external)'
        $iMhe = (Run-Cli info $s7mhe) | Out-Null; $oMhe = $script:lastOut
        $iCopy = (Run-Cli info $s7copy) | Out-Null; $oCopy = $script:lastOut
        $iLz = (Run-Cli info $s7lzma2) | Out-Null; $oLz = $script:lastOut
        $mheNative = ($oMhe -match 'native') -and ($oMhe -notmatch 'external')
        $copyNative = ($oCopy -match 'native') -and ($oCopy -notmatch 'external')
        $lzExternal = $oLz -match 'external'
        if ($mheNative -and $copyNative -and $lzExternal) { Pass 'test 6a' }
        else {
            Fail 'test 6a' ("mhe=[" + ($oMhe -replace "`n", ' ') + "] copy=[" + ($oCopy -replace "`n", ' ') +
                "] lzma2=[" + ($oLz -replace "`n", ' ') + "]")
        }
    } else {
        Write-Output 'test 6a: SKIP (routing assertions need the Rust engine)'
    }

    Write-Output 'test 6b: 7z -mhe dictionary hit (AES-only header CRC)'
    $d = Write-Dict 'd6b.txt' @('apple', 'mhepw77', 'banana')
    Expect-Hit 'test 6b' $s7mhe $d 'mhepw77'

    Write-Output 'test 6c: 7z AES+COPY content hit (CRC over plaintext)'
    $d = Write-Dict 'd6c.txt' @('apple', 'copypw88')
    Expect-Hit 'test 6c' $s7copy $d 'copypw88'

    # The decisive check that 6b/6c are really native: with the fallback tool
    # pointing at a nonexistent path, a spawn-based verifier cannot work at
    # all, so a hit here can only come from the native 7z path. (On the C#
    # engine there is no native path, so this would fail by design.)
    if ($rustEngine) {
        Write-Output 'test 6d: no false positive without any external tool'
        $savedTool = $env:DICTCRACK_TOOL
        $env:DICTCRACK_TOOL = Join-Path $tmp 'no-such-tool.exe'
        try {
            Remove-Result $s7mhe
            $cGood = Run-Cli crack -a $s7mhe -w (Write-Dict 'd6d1.txt' @('apple', 'mhepw77')) -t 2 -q
            $gotGood = Read-Result $s7mhe
            Remove-Result $s7mhe
            $cBad = Run-Cli crack -a $s7mhe -w (Write-Dict 'd6d2.txt' @('apple', 'banana')) -t 2 -q
            $leaked = Test-Path (Result-Path $s7mhe)
            if ($cGood -eq 0 -and $gotGood -eq 'mhepw77' -and $cBad -eq 1 -and -not $leaked) { Pass 'test 6d' }
            else {
                Fail 'test 6d' ("good exit=" + $cGood + " got='" + $gotGood + "' bad exit=" + $cBad + " leaked=" + $leaked)
            }
        } finally {
            if ($null -ne $savedTool) { $env:DICTCRACK_TOOL = $savedTool } else { Remove-Item Env:\DICTCRACK_TOOL -ErrorAction SilentlyContinue }
        }
    } else {
        Write-Output 'test 6d: SKIP (needs the Rust engine native 7z path)'
    }

    # ---- test 6e: 7z needing a decompressor keeps working via the tool --
    Write-Output 'test 6e: AES+LZMA2 7z falls back to the external tool and still hits'
    $d = Write-Dict 'd6e.txt' @('apple', 'lzmapw99')
    Expect-Hit 'test 6e' $s7lzma2 $d 'lzmapw99'

    # ---- test 6f: single-cipher-block AES+COPY (false-negative guard) ---
    # A payload under 16 bytes yields a one-block AES-CBC stream, where the
    # padding filter has no preceding ciphertext block to use as the IV. It
    # must fall back to the coder's own IV, not reject every candidate: a
    # false negative here reports "not found" for a password that is correct.
    Write-Output 'test 6f: single-block AES+COPY still finds the right password'
    $s7tiny = New-7zCopyTiny 's7tiny.7z' 'tinypw11' 14
    $s7one = New-7zCopyTiny 's7one.7z' 'tinypw11' 1
    $d = Write-Dict 'd6f.txt' @('apple', 'tinypw11')
    $okT = $false; $okO = $false
    Remove-Result $s7tiny
    $cT = Run-Cli crack -a $s7tiny -w $d -t 2 -q
    if ($cT -eq 0 -and (Read-Result $s7tiny) -eq 'tinypw11') { $okT = $true }
    Remove-Result $s7one
    $cO = Run-Cli crack -a $s7one -w $d -t 2 -q
    if ($cO -eq 0 -and (Read-Result $s7one) -eq 'tinypw11') { $okO = $true }
    # and the wrong password must still be rejected on both
    $dB = Write-Dict 'd6f2.txt' @('apple', 'banana')
    Remove-Result $s7tiny
    $cB = Run-Cli crack -a $s7tiny -w $dB -t 2 -q
    $leak = Test-Path (Result-Path $s7tiny)
    if ($okT -and $okO -and $cB -eq 1 -and -not $leak) { Pass 'test 6f' }
    else {
        Fail 'test 6f' ("14B exit=" + $cT + " ok=" + $okT + " 1B exit=" + $cO + " ok=" + $okO +
            " wrong exit=" + $cB + " leaked=" + $leak)
    }

    Write-Output 'test 7: unencrypted archive errors out (exit 2)'
    Remove-Result $plain
    $code = Run-Cli crack -a $plain -w (Write-Dict 'd7.txt' @('x')) -q
    if ($code -eq 2) { Pass 'test 7' } else { Fail 'test 7' ("exit=" + $code) }

    Write-Output 'test 8: wrong dictionary exhausts (exit 1, no result file)'
    $d = Write-Dict 'd8.txt' @('apple', 'banana')
    Remove-Result $zc
    $code = Run-Cli crack -a $zc -w $d -q
    if ($code -eq 1 -and -not (Test-Path (Result-Path $zc))) { Pass 'test 8' }
    else { Fail 'test 8' ("exit=" + $code) }

    # ---- test 9: mask attack ------------------------------------------
    Write-Output 'test 9: mask attack on ZipCrypto (ab?d?d?d -> ab007)'
    $maskZip = New-Zip 'mask.zip' 'ab007' 'ZipCrypto'
    Remove-Result $maskZip
    $code = Run-Cli crack -a $maskZip --mask 'ab?d?d?d' -t 4 -q
    $got = Read-Result $maskZip
    if ($code -eq 0 -and $got -eq 'ab007') { Pass 'test 9' }
    else { Fail 'test 9' ("exit=" + $code + " got='" + $got + "'") }

    # ---- test 10: combinator ------------------------------------------
    Write-Output 'test 10: combinator attack (foo x bar99 -> foobar99)'
    $combZip = New-Zip 'comb.zip' 'foobar99' 'ZipCrypto'
    $da = Write-Dict 'ca.txt' @('aaa', 'foo', 'bbb')
    $db = Write-Dict 'cb.txt' @('zzz', 'bar99')
    Remove-Result $combZip
    $code = Run-Cli crack -a $combZip -w $da -w2 $db -t 4 -q
    $got = Read-Result $combZip
    if ($code -eq 0 -and $got -eq 'foobar99') { Pass 'test 10' }
    else { Fail 'test 10' ("exit=" + $code + " got='" + $got + "'") }

    # ---- test 11: rules preset ----------------------------------------
    Write-Output 'test 11: rules preset years (password -> password1999)'
    $ruleZip = New-Zip 'rule.zip' 'password1999' 'ZipCrypto'
    $d = Write-Dict 'd11.txt' @('hello', 'password', 'world')
    Remove-Result $ruleZip
    $code = Run-Cli crack -a $ruleZip -w $d --rule years -t 4 -q
    $got = Read-Result $ruleZip
    if ($code -eq 0 -and $got -eq 'password1999') { Pass 'test 11' }
    else { Fail 'test 11' ("exit=" + $code + " got='" + $got + "'") }

    # ---- tests 12-14: encoding matrix with Chinese passwords ----------
    # U+5BC6 U+7801 U+6D4B U+8BD5 + one/two/three; dictionaries are
    # written in each encoding; WinRAR handles the Unicode -p argument.
    function Test-Encoding([string]$tag, [System.Text.Encoding]$enc, [string]$pw) {
        if (-not $script:rar) { Write-Output ("  SKIP " + $tag); return }
        $a = New-Rar ($tag + '.rar') $pw $false
        $d = Join-Path $script:tmp ($tag + '-dict.txt')
        [System.IO.File]::WriteAllLines($d, @('wrong-one', $pw, 'wrong-two'), $enc)
        Expect-Hit $tag $a $d $pw
    }
    Write-Output 'test 12: UTF-8 BOM dictionary, Chinese password'
    Test-Encoding 'enc12' (New-Object System.Text.UTF8Encoding($true)) (-join ([char[]]@(0x5BC6, 0x7801, 0x6D4B, 0x8BD5) + [char]0x4E00))
    Write-Output 'test 13: UTF-16LE BOM dictionary, Chinese password'
    Test-Encoding 'enc13' ([System.Text.Encoding]::Unicode) (-join ([char[]]@(0x5BC6, 0x7801, 0x6D4B, 0x8BD5) + [char]0x4E8C))
    Write-Output 'test 14: GBK (ANSI, no BOM) dictionary, Chinese password'
    Test-Encoding 'enc14' ([System.Text.Encoding]::GetEncoding(936)) (-join ([char[]]@(0x5BC6, 0x7801, 0x6D4B, 0x8BD5) + [char]0x4E09))

    # ---- test 15: checkpoint resume ------------------------------------
    if ($rar) {
        Write-Output 'test 15: checkpoint + resume (--max-tries then --resume)'
        Remove-Item $session -Force -ErrorAction SilentlyContinue
        $big = Join-Path $tmp 'big.txt'
        $lines = New-Object System.Collections.Generic.List[string]
        for ($i = 1; $i -le 2000; $i++) { [void]$lines.Add('filler' + $i.ToString('00000')) }
        $lines[1499] = 'resumepw1337'
        [System.IO.File]::WriteAllLines($big, $lines)
        $resZip = New-Rar 'res.rar' 'resumepw1337' $false
        Remove-Result $resZip
        # fresh run without --resume must NOT pick up any session
        $code = Run-Cli crack -a $resZip -w $big -t 1 --max-tries 1000 -q
        if ($code -ne 3) { Fail 'test 15a' ("expected stop exit 3, got " + $code) }
        elseif (-not (Test-Path $session)) { Fail 'test 15a' 'no session file after maxed-out run' }
        else {
            $code = Run-Cli crack -a $resZip -w $big -t 1 --resume -q
            $got = Read-Result $resZip
            if ($code -eq 0 -and $got -eq 'resumepw1337') { Pass 'test 15' }
            else { Fail 'test 15b' ("exit=" + $code + " got='" + $got + "'") }
        }
        Remove-Item $session -Force -ErrorAction SilentlyContinue
    } else {
        Write-Output 'test 15: SKIP (no rar.exe)'
    }

    # ---- test 15b: RAR4 checkpoint + resume ----------------------------
    # The RAR4 KDF is ~10 ms/candidate, so a resume test is cheap here.
    # Verifies the session path works on the native RAR4 verifier too: a
    # maxed-out run records the position and --resume continues past it.
    Write-Output 'test 15b: RAR4 checkpoint + resume (--max-tries then --resume)'
    $big4 = Join-Path $tmp 'big4.txt'
    $lines4 = New-Object System.Collections.Generic.List[string]
    for ($i = 1; $i -le 40; $i++) { [void]$lines4.Add('filler' + $i.ToString('0000')) }
    $lines4[29] = 'Rar4Gold9'
    [System.IO.File]::WriteAllLines($big4, $lines4)
    Remove-Result $rar4p
    $code = Run-Cli crack -a $rar4p -w $big4 -t 2 --max-tries 10 -q
    if ($code -ne 3) { Fail 'test 15b-a' ("expected stop exit 3, got " + $code) }
    elseif (-not (Test-Path $session)) { Fail 'test 15b-a' 'no session file after maxed-out run' }
    else {
        $code = Run-Cli crack -a $rar4p -w $big4 -t 2 --resume -q
        $got = Read-Result $rar4p
        if ($code -eq 0 -and $got -eq 'Rar4Gold9') { Pass 'test 15b' }
        else { Fail 'test 15b-b' ("exit=" + $code + " got='" + $got + "'") }
    }
    Remove-Item $session -Force -ErrorAction SilentlyContinue
    Remove-Result $rar4p

    # ---- test 16: benchmark smoke --------------------------------------
    Write-Output 'test 16: benchmark smoke (native zip)'
    $code = Run-Cli bench -a $za -t 4 --seconds 1
    if ($code -eq 0 -and $script:lastOut -match '\d') { Pass 'test 16' }
    else { Fail 'test 16' ("exit=" + $code + " out='" + $script:lastOut + "'") }

    # ---- test 17: GUI auto-start e2e ------------------------------------
    Write-Output 'test 17: GUI auto-start finds password and writes result file'
    if ($ExePath -ne '') {
        Write-Output '  SKIP (external CLI has no GUI)'
    } elseif ($rar) {
        $gArch = New-Rar 'guitest.rar' 'guipw777' $false
        $d = Write-Dict 'd17.txt' @('aaa', 'guipw777', 'bbb')
        Remove-Result $gArch
        $p = Start-Process -FilePath $gui -ArgumentList @('-a', $gArch, '-w', $d, '-t', '4') -PassThru
        $rf = Result-Path $gArch
        $deadline = (Get-Date).AddSeconds(60)
        $ok = $false
        while ((Get-Date) -lt $deadline) {
            if (Test-Path $rf) { $ok = $true; break }
            if ($p.HasExited -and -not (Test-Path $rf)) { break }
            Start-Sleep -Milliseconds 300
        }
        $got = ''
        if ($ok) { $got = ([System.IO.File]::ReadAllText($rf, [System.Text.Encoding]::GetEncoding(936))).Trim() }
        if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Milliseconds 500
        if ($ok -and $got -eq 'guipw777') { Pass 'test 17' }
        else { Fail 'test 17' ("resultFile=" + $ok + " got='" + $got + "'") }
    } else {
        Write-Output 'test 17: SKIP (no rar.exe)'
    }

    # ---- test 18: GUI combinator auto-start (-w + -w2) ------------------
    Write-Output 'test 18: GUI combinator auto-start fills A+B and finds password'
    $gComb = Join-Path $tmp 'comb.zip'
    $gA = Join-Path $tmp 'ca.txt'
    $gB = Join-Path $tmp 'cb.txt'
    if ($ExePath -ne '') {
        Write-Output '  SKIP (external CLI has no GUI)'
    } elseif ((Test-Path $gComb) -and (Test-Path $gA) -and (Test-Path $gB)) {
        Remove-Result $gComb
        $p = Start-Process -FilePath $gui -ArgumentList @('-a', $gComb, '-w', $gA, '-w2', $gB, '-t', '4') -PassThru
        $rf = Result-Path $gComb
        $deadline = (Get-Date).AddSeconds(60)
        $ok = $false
        while ((Get-Date) -lt $deadline) {
            if (Test-Path $rf) { $ok = $true; break }
            if ($p.HasExited -and -not (Test-Path $rf)) { break }
            Start-Sleep -Milliseconds 300
        }
        $got = ''
        if ($ok) { $got = ([System.IO.File]::ReadAllText($rf, [System.Text.Encoding]::GetEncoding(936))).Trim() }
        if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Milliseconds 500
        if ($ok -and $got -eq 'foobar99') { Pass 'test 18' }
        else { Fail 'test 18' ("resultFile=" + $ok + " got='" + $got + "'") }
    } else {
        Write-Output '  SKIP (comb fixture missing)'
    }

    # ---- test 19: spawn path survives trailing-backslash passwords -----
    # Regression test for external-tool argument quoting: 7z.exe parses the
    # RAW command line itself (backslashes literal, "" -> one quote) while
    # rar.exe uses standard CRT argv rules (a trailing backslash escapes the
    # closing quote unless doubled). Wrong escaping of either kind turns
    # the password endbs\ into endbs" or endbs\\ and silently misses hits.
    # See Verifier.WinArg and the WinArg unit tests.
    Write-Output 'test 19: external-tool path with trailing-backslash password'
    $bsZip = New-7z 'bs.7z' 'endbs\'
    $d = Write-Dict 'd19.txt' @('wrong', 'endbs\')
    Remove-Result $bsZip
    $code = Run-Cli crack -a $bsZip -w $d -q
    $got = Read-Result $bsZip
    if ($code -eq 0 -and $got -eq 'endbs\') { Pass 'test 19' }
    else { Fail 'test 19' ("exit=" + $code + " got='" + $got + "'") }

    # ---- test 20: spawn path survives quote+backslash passwords --------
    # 7z doubling form: "" arrives as one quote, a trailing backslash stays
    # literal. CRT-style or wrongly-doubled escaping turns pw"q\ into
    # pw""q\ / pw"q\\ and silently misses the hit. Covers the verify spawn
    # path with the same hostile alphabet as test 19 plus a real quote.
    Write-Output 'test 20: external-tool path with quote+backslash password'
    $qZip = New-7zRaw 'q.7z' 'pw"q\'
    $d = Write-Dict 'd20.txt' @('wrong', 'pw"q\')
    Remove-Result $qZip
    $code = Run-Cli crack -a $qZip -w $d -q
    $got = Read-Result $qZip
    if ($code -eq 0 -and $got -eq 'pw"q\') { Pass 'test 20' }
    else { Fail 'test 20' ("exit=" + $code + " got='" + $got + "'") }

    # ---- test 21: --extract-to with the same hostile password ----------
    # covers the hit-time extract path's per-tool quoting of -p<password>,
    # -o<dir> (a directory name containing a space) and the archive path;
    # a regression here corrupts the unpacked output silently
    Write-Output 'test 21: --extract-to unpacks with quote+backslash password'
    $exDir = Join-Path $tmp 'ex dir'
    Remove-Item -LiteralPath $exDir -Recurse -Force -ErrorAction SilentlyContinue
    $code = Run-Cli crack -a $qZip -w (Write-Dict 'd21.txt' @('pw"q\')) -q --extract-to $exDir
    $extracted = Join-Path $exDir 'payload.txt'
    $okEx = (Test-Path $extracted) -and ((Get-Item $extracted).Length -eq 262144)
    if ($code -eq 0 -and $okEx) { Pass 'test 21' }
    else { Fail 'test 21' ("exit=" + $code + " extracted=" + $okEx) }

    # ---- test 22: open_error parity -- missing path / directory -------
    # C# File.Exists semantics: a directory takes the "not found" branch,
    # and every entry point exits 2 instead of crashing or reporting an
    # unknown format with exit 0 (the pre-open_error Rust behavior)
    Write-Output 'test 22: missing/directory archive exits 2 on info/bench/crack'
    $noDir = Join-Path $tmp 'no-such-dir'
    $d22 = Write-Dict 'd22.txt' @('x')
    $cInfo = Run-Cli info $noDir
    $cCrack = Run-Cli crack -a $noDir -w $d22 -q
    $cBench = Run-Cli bench -a $noDir
    if ($cInfo -eq 2 -and $cCrack -eq 2 -and $cBench -eq 2) { Pass 'test 22' }
    else { Fail 'test 22' ("info=" + $cInfo + " crack=" + $cCrack + " bench=" + $cBench) }

    # ---- test 22b: pre-flight rejections must not hang ----------------
    # Regression for a real hang: engine.run's early returns did not publish
    # the done flag, and main.rs prints with `while !done` then joins that
    # thread unconditionally -- so every pre-flight rejection looped forever
    # spamming the "preparing" progress line. The display thread only exists
    # when NOT -q, so each case here is deliberately run WITHOUT -q (with -q
    # there is no thread and the bug is invisible -- which is how it survived
    # the first e2e sweep). Run-Cli's 120s watchdog turns a regression into a
    # failure instead of a wedged suite.
    Write-Output 'test 22b: pre-flight rejections exit 2 without hanging (no -q)'
    $unenc = Join-Path $tmp 'unenc.7z'
    & $sz a $unenc (Join-Path $tmp 'payload.txt') | Out-Null
    $d22b = Write-Dict 'd22b.txt' @('x')
    $cMissing = Run-Cli crack -a (Join-Path $tmp 'nope.7z') -w $d22b -t 1
    $cDir = Run-Cli crack -a $noDir -w $d22b -t 1
    $cUnenc = Run-Cli crack -a $unenc -w $d22b -t 1
    $cProg = Run-Cli crack -a $unenc -w $d22b -t 1 --progress
    if ($cMissing -eq 2 -and $cDir -eq 2 -and $cUnenc -eq 2 -and $cProg -eq 2) { Pass 'test 22b' }
    else {
        Fail 'test 22b' ("missing=" + $cMissing + " dir=" + $cDir + " unenc=" + $cUnenc +
            " progress=" + $cProg + " (-999 = watchdog timeout)")
    }

    # ---- test 23: open_error parity -- locked (unreadable) file -------
    # a file held open with FileShare.None must hit the readable-error
    # branch and exit 2 on info AND bench (bench died on an unhandled Parse
    # exception before the fix) and on crack, never a silent exit 0
    Write-Output 'test 23: locked archive exits 2 on info/bench/crack'
    $locked = Join-Path $tmp 'locked.zip'
    Copy-Item $za $locked
    $fs = [System.IO.File]::Open($locked, 'Open', 'Read', 'None')
    try {
        $cInfo = Run-Cli info $locked
        $cBench = Run-Cli bench -a $locked
        $cCrack = Run-Cli crack -a $locked -w (Write-Dict 'd23.txt' @('x')) -q
    } finally {
        if ($fs) { $fs.Close() }
    }
    if ($cInfo -eq 2 -and $cBench -eq 2 -and $cCrack -eq 2) { Pass 'test 23' }
    else { Fail 'test 23' ("info=" + $cInfo + " bench=" + $cBench + " crack=" + $cCrack) }

    # ---- test 24: --progress JSONL protocol (GUI process mode) --------
    # on a hit stdout must be pure protocol: first line a JSON object, a
    # "found" event carrying the password, no human banner mixed in
    if ($ExePath -ne '') {
        Write-Output 'test 24-26: --progress/--session-file (Rust-only options)'

        Write-Output 'test 24: --progress emits JSON protocol lines on a hit'
        $d = Write-Dict 'd24.txt' @('apple', 'zippw0')
        Remove-Result $zc
        $code = Run-Cli crack -a $zc -w $d --progress
        $first = ($script:lastOut -split "`n")[0]
        if ($code -eq 0 -and $first.StartsWith('{') -and $script:lastOut -match '\"ev\":\"found\"' -and $script:lastOut -match '\"password\":\"zippw0\"') { Pass 'test 24' }
        else { Fail 'test 24' ("exit=" + $code + " first='" + $first + "'") }

        Write-Output 'test 25: --progress done event on exhaustion (exit 1)'
        $d = Write-Dict 'd25.txt' @('apple', 'banana')
        Remove-Result $zc
        $code = Run-Cli crack -a $zc -w $d --progress
        if ($code -eq 1 -and $script:lastOut -match '\"ev\":\"done\"' -and $script:lastOut -match '\"status\":\"not_found\"') { Pass 'test 25' }
        else { Fail 'test 25' ("exit=" + $code + " out='" + $script:lastOut + "'") }

        # ---- test 26: --session-file pins the session (GUI sharing) ----
        # the GUI passes its own session.json path; a maxed-out run must
        # write THERE (and nowhere else), and --resume continues through it
        Write-Output 'test 26: --session-file custom location + resume through it'
        $sess2 = Join-Path $tmp 'custom-session.json'
        Remove-Item -LiteralPath $sess2 -Force -ErrorAction SilentlyContinue
        Remove-Item $session -Force -ErrorAction SilentlyContinue
        $big26 = Join-Path $tmp 'big26.txt'
        $lines26 = New-Object System.Collections.Generic.List[string]
        for ($i = 1; $i -le 2000; $i++) { [void]$lines26.Add('filler' + $i.ToString('00000')) }
        $lines26[1499] = 'sesspw1337'
        [System.IO.File]::WriteAllLines($big26, $lines26)
        $sessZip = New-Zip 'sess.zip' 'sesspw1337' 'ZipCrypto'
        Remove-Result $sessZip
        $code = Run-Cli crack -a $sessZip -w $big26 -t 1 --max-tries 5 --progress --session-file $sess2
        if ($code -ne 3) { Fail 'test 26a' ("expected maxed-out exit 3, got " + $code) }
        elseif (-not (Test-Path $sess2)) { Fail 'test 26a' 'no session at the custom --session-file path' }
        elseif (Test-Path $session) { Fail 'test 26a' 'session leaked to the default exe-side path' }
        else {
            $code = Run-Cli crack -a $sessZip -w $big26 -t 1 --resume --progress --session-file $sess2
            $got = Read-Result $sessZip
            if ($code -eq 0 -and $got -eq 'sesspw1337') { Pass 'test 26' }
            else { Fail 'test 26b' ("exit=" + $code + " got='" + $got + "'") }
        }
        Remove-Item -LiteralPath $sess2 -Force -ErrorAction SilentlyContinue
        Remove-Result $sessZip
    } else {
        Write-Output 'test 24-26: SKIP (Rust-only options, C# CLI has no --progress)'
    }

} finally {
    if ($null -ne $oldTool) { $env:DICTCRACK_TOOL = $oldTool }
    else { Remove-Item Env:\DICTCRACK_TOOL -ErrorAction SilentlyContinue }
    # kill any surviving GUI processes started by the tests
    Get-CimInstance Win32_Process -Filter "Name = 'dictcrack-gui.exe'" -ErrorAction SilentlyContinue |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 500
    if ($tmp -and (Test-Path $tmp)) {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($cfgBak -and (Test-Path $cfgBak)) {
        Move-Item -LiteralPath $cfgBak -Destination $cfg -Force
    }
    Remove-Item $session -Force -ErrorAction SilentlyContinue
    Get-ChildItem (Join-Path $dist '*_password.txt') -ErrorAction SilentlyContinue |
        ForEach-Object { if ($preResults -notcontains $_.Name) { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue } }
}

Write-Output ("done: " + $fail + " failure(s)")
exit $fail
