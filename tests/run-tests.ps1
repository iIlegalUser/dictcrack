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
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = & $script:cli @args 2>&1
    $ErrorActionPreference = $old
    $script:lastOut = ($out | ForEach-Object { "$_" }) -join "`n"
    return $LASTEXITCODE
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
    function New-7zRaw([string]$name, [string]$pw) {
        # a password containing quotes cannot go through PowerShell's native
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

    Write-Output 'test 4: ZIP ZipCrypto hit incl. full-CRC confirm'
    $d = Write-Dict 'd4.txt' @('apple', 'zippw0')
    Expect-Hit 'test 4' $zc $d 'zippw0'

    Write-Output 'test 5: ZIP AES-256 hit (PBKDF2 + HMAC verify)'
    $d = Write-Dict 'd5.txt' @('apple', 'aespw1')
    Expect-Hit 'test 5' $za $d 'aespw1'

    Write-Output 'test 6: 7z archive via external tool fallback'
    $d = Write-Dict 'd6.txt' @('apple', '7zpw2')
    Expect-Hit 'test 6' $s7 $d '7zpw2'

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
