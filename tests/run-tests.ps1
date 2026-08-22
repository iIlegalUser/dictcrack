# ============================================================
#  run-tests.ps1 -- end-to-end tests for the dictcrack GUI
#
#  ASCII only on purpose (safe under any system code page).
#
#  Usage:
#    powershell -STA -ExecutionPolicy Bypass -File tests\run-tests.ps1
#
#  What it does:
#    - locates 7z.exe (needed to build encrypted test archives)
#    - backs up the user's dictcrack-gui.cfg (tests overwrite it)
#      and restores it afterwards
#    - test 1: crack an archive whose password IS in the sample
#      dictionary (must find it and write the result file)
#    - test 2: crack an archive whose password is NOT in the
#      dictionary (both encoding passes must finish, no result file)
#    - test 3: same as test 1 but with an explicit -Threads 4
#      (thread selection flag must be accepted)
#    - tests 4-6: dictionary encoding matrix (UTF-8 BOM / UTF-16LE /
#      ANSI-GBK) with Chinese passwords - each encoding must crack;
#      test 6 also covers the strict UTF-8 probe skip
#    - test 7: Move-PasswordToTop extracted from the GUI file via AST
#      (moves to line 1, de-duplicates, keeps the BOM)
#
#  IMPORTANT: every GUI launch passes an explicit -Tool so a tool
#  remembered in dictcrack-gui.cfg can never intercept the .7z test
#  archives (rar.exe + .7z is correctly rejected by the GUI, which
#  would look like a hang to these tests).
#
#  Exit code: number of failed tests (0 = all pass).
# ============================================================

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$gui  = Join-Path $root 'dictcrack-gui.ps1'
$dict = Join-Path $root 'passwords_sample.txt'
$cfg  = Join-Path $root 'dictcrack-gui.cfg'

if (-not (Test-Path $gui))  { throw "GUI script not found: $gui" }
if (-not (Test-Path $dict)) { throw "sample dictionary not found: $dict" }

# ---- locate 7z.exe ---------------------------------------------------
$sz = $null
foreach ($cand in @(
    (Join-Path $env:ProgramFiles '7-Zip\7z.exe'),
    (Join-Path ${env:ProgramFiles(x86)} '7-Zip\7z.exe'),
    'D:\Software\Scoop\shims\7z.exe'
)) {
    if ($cand -and (Test-Path $cand)) { $sz = $cand; break }
}
if (-not $sz) {
    $cmd = Get-Command 7z.exe -ErrorAction SilentlyContinue
    if ($cmd) { $sz = $cmd.Source }
}
if (-not $sz) {
    Write-Output 'SKIP: 7z.exe not found, cannot build test archives'
    exit 0
}
Write-Output "using 7z: $sz"

# ---- protect the user's cfg ------------------------------------------
$cfgBak = $null
if (Test-Path $cfg) {
    $cfgBak = [System.IO.Path]::ChangeExtension($cfg, '.cfg.testbak')
    Move-Item -LiteralPath $cfg -Destination $cfgBak -Force
}

$fail = 0
$tmp  = $null
try {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('dictcrack-test-' + [System.Guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    $payload = Join-Path $tmp 'payload.txt'
    Set-Content -Path $payload -Value 'test payload'

    function New-TestArchive([string]$name, [string]$pw) {
        $a = Join-Path $script:tmp $name
        & $script:sz a "-p$pw" $a $script:payload | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $a)) { throw "failed to create $a" }
        return $a
    }

    function Start-Gui([string]$arch, [int]$threads, [string]$dictPath) {
        if (-not $dictPath) { $dictPath = $script:dict }
        $args = @('-STA', '-ExecutionPolicy', 'Bypass', '-File', $script:gui,
                  '-Arch', $arch, '-Dict', $dictPath, '-Tool', $script:sz)
        if ($threads -gt 0) { $args += @('-Threads', [string]$threads) }
        return (Start-Process powershell -ArgumentList $args -PassThru)
    }

    function Wait-ResultFile([string]$arch, [int]$timeoutSec) {
        $rf = Join-Path $root (([System.IO.Path]::GetFileNameWithoutExtension($arch)) + '_password.txt')
        $deadline = (Get-Date).AddSeconds($timeoutSec)
        while ((Get-Date) -lt $deadline) {
            if (Test-Path $rf) { return $rf }
            Start-Sleep -Milliseconds 300
        }
        return $null
    }

    # wait until 7z processes appear (cracking started), then until
    # they are gone again (all encoding passes finished)
    function Wait-CrackingFinished([int]$startTimeoutSec, [int]$finishTimeoutSec) {
        $sawStart = $false
        $deadline = (Get-Date).AddSeconds($startTimeoutSec)
        while ((Get-Date) -lt $deadline) {
            if (@(Get-Process 7z -ErrorAction SilentlyContinue).Count -gt 0) { $sawStart = $true; break }
            Start-Sleep -Milliseconds 200
        }
        if (-not $sawStart) { return $false }
        $deadline = (Get-Date).AddSeconds($finishTimeoutSec)
        while ((Get-Date) -lt $deadline) {
            if (@(Get-Process 7z -ErrorAction SilentlyContinue).Count -eq 0) { return $true }
            Start-Sleep -Milliseconds 300
        }
        return $false
    }

    function Stop-Gui($p) {
        if ($p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Milliseconds 500
    }

    # ---- test 1: password present in dictionary ----------------------
    Write-Output 'test 1: password in dictionary (expect hit)'
    $hit = New-TestArchive 'hit.7z' 'football'    # line 27 of passwords_sample.txt
    $p = Start-Gui $hit 0
    $rf = Wait-ResultFile $hit 40
    $pw = ''
    if ($rf) { $pw = (Get-Content $rf -Raw).Trim() }
    Stop-Gui $p
    if ($pw -eq 'football') {
        Write-Output '  PASS'
    } else {
        Write-Output "  FAIL (expected 'football', got '$pw')"
        $fail++
    }

    # ---- test 2: password absent from dictionary ---------------------
    Write-Output 'test 2: password NOT in dictionary (expect no result, clean finish)'
    $nf = New-TestArchive 'nf.7z' 'zz_not_in_dict'
    $p = Start-Gui $nf 0
    $finished = Wait-CrackingFinished 20 40
    Start-Sleep -Seconds 3   # let the UI settle after the last pass
    $rf = Join-Path $root 'nf_password.txt'
    Stop-Gui $p
    if ($finished -and -not (Test-Path $rf)) {
        Write-Output '  PASS'
    } else {
        Write-Output ("  FAIL (finished=" + $finished + ", resultFile=" + (Test-Path $rf) + ")")
        $fail++
    }

    # ---- test 3: explicit thread count -------------------------------
    Write-Output 'test 3: explicit -Threads 4 (expect hit)'
    $t3 = New-TestArchive 't3.7z' 'dragon'        # line 10 of passwords_sample.txt
    $p = Start-Gui $t3 4
    $rf = Wait-ResultFile $t3 40
    $pw = ''
    if ($rf) { $pw = (Get-Content $rf -Raw).Trim() }
    Stop-Gui $p
    if ($pw -eq 'dragon') {
        Write-Output '  PASS'
    } else {
        Write-Output ("  FAIL (expected 'dragon', got '" + $pw + "')")
        $fail++
    }

    # ---- tests 4-6: dictionary encoding matrix, Chinese passwords ----
    # The passwords are built from code points so this file stays ASCII.
    # The 7z command line is Unicode, so only the DICTIONARY decoding
    # path differs per test. Test 6 (ANSI/GBK, no BOM) also proves the
    # strict UTF-8 probe skip cannot skip a hit.
    function Test-Encoding([string]$tag, [System.Text.Encoding]$enc, [string]$pw) {
        Write-Output ("test " + $tag + ": " + $enc.WebName + " dictionary, Chinese password (expect hit)")
        $d = Join-Path $tmp ($tag + '-dict.txt')
        [System.IO.File]::WriteAllLines($d, @('wrong-one', $pw, 'wrong-two'), $enc)
        $a = New-TestArchive ($tag + '.7z') $pw
        $p = Start-Gui $a 0 $d
        $rf = Wait-ResultFile $a 40
        $got = ''
        if ($rf) { $got = ([System.IO.File]::ReadAllText($rf, [System.Text.Encoding]::Default)).Trim() }
        Stop-Gui $p
        if ($got -eq $pw) { Write-Output '  PASS' }
        else { Write-Output ("  FAIL (result file content mismatch, length=" + $got.Length + ")"); $fail++ }
    }
    # U+5BC6 U+7801 U+6D4B U+8BD5 = Chinese for "password test"; the
    # fifth char differs per test (one/two/three)
    Test-Encoding 'enc4' (New-Object System.Text.UTF8Encoding($true))  (-join ([char[]]@(0x5BC6, 0x7801, 0x6D4B, 0x8BD5) + [char]0x4E00))
    Test-Encoding 'enc5' ([System.Text.Encoding]::Unicode)              (-join ([char[]]@(0x5BC6, 0x7801, 0x6D4B, 0x8BD5) + [char]0x4E8C))
    Test-Encoding 'enc6' ([System.Text.Encoding]::Default)              (-join ([char[]]@(0x5BC6, 0x7801, 0x6D4B, 0x8BD5) + [char]0x4E09))

    # ---- test 7: Move-PasswordToTop (extracted from the GUI file) ----
    # The function lives inside the GUI script, which cannot be dot-
    # sourced (it would open the window). Parse the file and evaluate
    # just this function definition instead.
    Write-Output 'test 7: move found password to dictionary line 1'
    $guiAst = [System.Management.Automation.Language.Parser]::ParseFile($gui, [ref]$null, [ref]$null)
    $fnDef = $guiAst.Find({ param($a)
        $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $a.Name -eq 'Move-PasswordToTop' }, $true)
    if (-not $fnDef) {
        Write-Output '  FAIL (Move-PasswordToTop not found in GUI script)'
        $fail++
    } else {
        Invoke-Expression $fnDef.Extent.Text
        $d7 = Join-Path $tmp 'mv-dict.txt'
        [System.IO.File]::WriteAllLines($d7, @('aaa', 'bbb', 'middle-secret', 'ccc'), (New-Object System.Text.UTF8Encoding($true)))
        Move-PasswordToTop $d7 'middle-secret' 'utf8bom'
        $bytes = [System.IO.File]::ReadAllBytes($d7)
        $bomKept = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
        $lines = [System.IO.File]::ReadAllLines($d7, [System.Text.Encoding]::UTF8)
        $cnt = @($lines | Where-Object { $_ -eq 'middle-secret' }).Count
        if ($bomKept -and $lines.Count -eq 4 -and $lines[0] -eq 'middle-secret' -and $cnt -eq 1) {
            Write-Output '  PASS'
        } else {
            Write-Output ("  FAIL (bom=" + $bomKept + ", lines=" + $lines.Count + ", first='" + $lines[0] + "', occurrences=" + $cnt + ")")
            $fail++
        }
    }
} finally {
    # kill any surviving GUI processes BEFORE restoring the cfg, so a
    # late write cannot land after the restore
    Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" |
        Where-Object { $_.CommandLine -like ('*' + $gui + '*') } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 800
    # remove result files the tests dropped next to the GUI script
    # (real user results in that folder are untouched - only the three
    # test archive names are cleaned up)
    foreach ($n in @('hit', 'nf', 't3', 'enc4', 'enc5', 'enc6')) {
        Remove-Item (Join-Path $root ($n + '_password.txt')) -Force -ErrorAction SilentlyContinue
    }
    if ($tmp -and (Test-Path $tmp)) {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($cfgBak -and (Test-Path $cfgBak)) {
        Move-Item -LiteralPath $cfgBak -Destination $cfg -Force
    }
}

Write-Output ("done: " + $fail + " failure(s)")
exit $fail
