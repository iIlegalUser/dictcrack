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

    function Start-Gui([string]$arch, [int]$threads) {
        $args = @('-STA', '-ExecutionPolicy', 'Bypass', '-File', $script:gui,
                  '-Arch', $arch, '-Dict', $script:dict, '-Tool', $script:sz)
        if ($threads -gt 0) { $args += @('-Threads', [string]$threads) }
        return (Start-Process powershell -ArgumentList $args -PassThru)
    }

    function Wait-ResultFile([string]$arch, [int]$timeoutSec) {
        $rf = Join-Path (Split-Path -Parent $arch) (([System.IO.Path]::GetFileNameWithoutExtension($arch)) + '_password.txt')
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
    $rf = Join-Path $tmp 'nf_password.txt'
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
} finally {
    # kill any surviving GUI processes BEFORE restoring the cfg, so a
    # late write cannot land after the restore
    Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" |
        Where-Object { $_.CommandLine -like ('*' + $gui + '*') } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 800
    if ($tmp -and (Test-Path $tmp)) {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($cfgBak -and (Test-Path $cfgBak)) {
        Move-Item -LiteralPath $cfgBak -Destination $cfg -Force
    }
}

Write-Output ("done: " + $fail + " failure(s)")
exit $fail
