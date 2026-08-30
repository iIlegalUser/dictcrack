# ============================================================
#  run-tests.ps1 -- end-to-end tests for the native DictCrack
#
#  ASCII only on purpose (safe under any system code page).
#
#  Usage:
#    powershell -ExecutionPolicy Bypass -File tests\run-tests.ps1
#
#  What it does:
#    - rebuilds dist\ via build\build.ps1
#    - builds encrypted fixtures with WinRAR rar.exe (RAR5 -p / -hp)
#      and 7z (ZipCrypto / AES-256 zip, 7z). RAR4 cannot be created
#      by RAR 7; the 7z spawn path is covered by the .7z fixture.
#    - CLI tests: info, dict hits per format, unencrypted error,
#      mask attack, combinator, rules preset, encoding matrix
#      (UTF-8 BOM / UTF-16LE / GBK with Chinese passwords),
#      checkpoint resume (--max-tries + --resume), benchmark smoke
#    - GUI test: auto-start via command line, result file appears
#
#  Exit code: number of failed tests (0 = all pass).
# ============================================================

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist'
$cli  = Join-Path $dist 'dictcrack.exe'
$gui  = Join-Path $dist 'dictcrack-gui.exe'
$cfg  = Join-Path $dist 'dictcrack-gui.cfg'

# ---- build -----------------------------------------------------------
Write-Output '== building =='
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'build\build.ps1') | ForEach-Object { Write-Output "  $_" }
if (-not (Test-Path $cli)) { throw 'dictcrack.exe was not produced' }
if (-not (Test-Path $gui)) { throw 'dictcrack-gui.exe was not produced' }

# ---- tools -----------------------------------------------------------
$rar = 'D:\Software\WinRAR\rar.exe'
if (-not (Test-Path $rar)) { $rar = $null }
$sz = $null
foreach ($cand in @('D:\Software\Scoop\shims\7z.exe',
    (Join-Path $env:ProgramFiles '7-Zip\7z.exe'))) {
    if (Test-Path $cand) { $sz = $cand; break }
}
if (-not $sz) { $c = Get-Command 7z.exe -ErrorAction SilentlyContinue; if ($c) { $sz = $c.Source } }
if (-not $sz) { Write-Output 'SKIP: 7z.exe not found - cannot build fixtures'; exit 0 }
Write-Output ("7z: " + $sz)
if ($rar) { Write-Output ("rar: " + $rar) } else { Write-Output 'rar.exe not found: RAR5 fixtures will be skipped' }

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
$session = Join-Path $dist 'session.json'

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
        return Join-Path $dist (([System.IO.Path]::GetFileNameWithoutExtension($arch)) + '_password.txt')
    }
    function Remove-Result([string]$arch) {
        Remove-Item (Result-Path $arch) -Force -ErrorAction SilentlyContinue
    }
    function Read-Result([string]$arch) {
        $p = Result-Path $arch
        if (-not (Test-Path $p)) { return $null }
        return ([System.IO.File]::ReadAllText($p, [System.Text.Encoding]::Default)).Trim()
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
    if ($rar) {
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
        if ($ok) { $got = ([System.IO.File]::ReadAllText($rf, [System.Text.Encoding]::Default)).Trim() }
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
    if ((Test-Path $gComb) -and (Test-Path $gA) -and (Test-Path $gB)) {
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
        if ($ok) { $got = ([System.IO.File]::ReadAllText($rf, [System.Text.Encoding]::Default)).Trim() }
        if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Milliseconds 500
        if ($ok -and $got -eq 'foobar99') { Pass 'test 18' }
        else { Fail 'test 18' ("resultFile=" + $ok + " got='" + $got + "'") }
    } else {
        Write-Output '  SKIP (comb fixture missing)'
    }

} finally {
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
