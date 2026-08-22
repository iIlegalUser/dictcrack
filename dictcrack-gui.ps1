# ============================================================
#  dictcrack-gui.ps1 -- GUI front-end for dictionary archive
#  password testing (RAR / ZIP / 7Z via WinRAR or 7-Zip)
#
#  Usage  : launch via dictcrack-gui.vbs / dictcrack-gui.bat, or
#           powershell -STA -ExecutionPolicy Bypass -File dictcrack-gui.ps1
#           optional: -Arch <archive> -Dict <dict.txt>  (auto start)
#
#  NOTE   : this file must stay UTF-8 WITH BOM (Chinese UI text),
#           otherwise PowerShell 5.1 misreads it as ANSI/GBK.
# ============================================================

param(
    [string]$Arch,
    [string]$Dict,
    [string]$Tool,
    # 0 = auto (half the logical cores, max 12); manual values are capped
    # at 32 - each thread is a full PowerShell runspace instance
    [ValidateRange(0, 32)]
    [int]$Threads = 0
)

$ErrorActionPreference = 'Stop'

# config file that remembers the last used archive / dictionary
$cfgFile = Join-Path $PSScriptRoot 'dictcrack-gui.cfg'

# result files are written next to this script, never into the folder
# that happens to hold the archive
$scriptDir = $PSScriptRoot

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -MemberDefinition '[DllImport("user32.dll")] public static extern bool SetProcessDPIAware();' -Name U32 -Namespace W
[void][W.U32]::SetProcessDPIAware()

# hide the PowerShell console window (no matter how the script was started)
Add-Type -MemberDefinition '[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow); [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();' -Name W32 -Namespace Native
[void][Native.W32]::ShowWindow([Native.W32]::GetConsoleWindow(), 0)

# ---- shared state between GUI thread and worker --------------------
$sync = @{
    running  = $false
    cancel   = $false
    done     = $true
    tried    = 0          # current pass progress (summed across workers)
    triedAll = 0          # finished passes + current pass
    total    = 0
    passN    = 0
    passTot  = 1
    passName = ''
    nWorkers = 0
    current  = ''
    found    = $null
    foundEnc = ''
    error    = $null
    outfile  = ''
    tool     = ''
    userTool = ''
    arch     = ''
    dict     = ''
    phase    = 'idle'     # informational: prep (reading dict) / pass (cracking)
}

# ---- parallelism: scale worker count to the machine ------------------
# each password attempt spawns a 7z/rar process whose KDF check is
# CPU-bound, so half the logical cores is a good default with headroom
# for the UI thread; capped at 12
$cores = [Environment]::ProcessorCount
function Get-AutoWorkerCount { [Math]::Min(12, [Math]::Max(1, [int][Math]::Round($cores / 2.0))) }
$script:workerCount = Get-AutoWorkerCount

# ---- helpers injected into the background runspaces via string --------
# $fnProc: child-process plumbing - needed by every password test
# $fnFind: tool detection - needed by the orchestrator; the UI thread
#          dot-sources the SAME block for its dropdown, so the probe
#          order exists only once (no duplicate to keep in sync)
$fnProc = @'
    function Invoke-ToolTest([string]$exe, [string]$argsLine) {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $exe
        $psi.Arguments = $argsLine
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.RedirectStandardInput = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        $p.StandardInput.Close()
        # both pipes are drained concurrently: sequential ReadToEnd can
        # deadlock when the child fills one pipe while we still block on
        # the other (possible on the large output of a SUCCESSFUL t run -
        # the one moment this must never hang)
        $so = $p.StandardOutput.ReadToEndAsync()
        $se = $p.StandardError.ReadToEndAsync()
        [void]$so.Result
        [void]$se.Result
        $p.WaitForExit()
        return $p.ExitCode
    }
    $q = [char]34
    function Test-Password([string]$exe, [string]$archive, [string]$pass) {
        # embedded double quotes are doubled -> survive command line parsing
        # (literal strings keep the string overload; $q+$q would bind to Replace(char,char) and throw)
        $p2 = $pass.Replace('"', '""')
        return Invoke-ToolTest $exe ("t -y -p$q$p2$q $q$archive$q")
    }
    function Test-NoPassword([string]$exe, [string]$archive) {
        # stdin is closed -> a password prompt fails immediately instead of hanging
        return Invoke-ToolTest $exe ("t -y $q$archive$q")
    }
'@
$fnFind = @'
    function Find-Tool([string]$dir, [string]$exe) {
        $list = @()
        foreach ($base in @($env:ProgramFiles, $env:ProgramW6432, ${env:ProgramFiles(x86)})) {
            if ($base) { $list += (Join-Path $base (Join-Path $dir $exe)) }
        }
        foreach ($p in $list) { if (Test-Path $p) { return $p } }
        $cmd = Get-Command $exe -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
        return $null
    }
'@
. ([scriptblock]::Create($fnFind))

# ---- orchestrator: tool detect + encoding passes + parallel slices ---
# runs in ONE background runspace (started from the Click handler). It
# slices the dictionary across N parallel pass workers, polls them and
# publishes progress into $sync under a lock; the UI timer only READS
# $sync (also under the lock).
$orchestrator = [scriptblock]::Create(@'
    param($sync, $passWorkerBlock, $workerCount, $scriptDir)
    # all writes to the shared $sync table go through these helpers: the
    # UI timer reads the table under the same lock - the standard way to
    # share one hashtable between the GUI thread and this worker thread
    function Get-Sync([string]$key) {
        [System.Threading.Monitor]::Enter($sync.SyncRoot)
        try { return $sync[$key] } finally { [System.Threading.Monitor]::Exit($sync.SyncRoot) }
    }
    function Set-Sync([hashtable]$updates) {
        [System.Threading.Monitor]::Enter($sync.SyncRoot)
        try {
            foreach ($k in $updates.Keys) { $sync[$k] = $updates[$k] }
        } finally { [System.Threading.Monitor]::Exit($sync.SyncRoot) }
    }
'@ + $fnProc + $fnFind + @'
    try {
        if (-not (Get-Sync 'cancel')) {
            $arch = $sync.arch
            $dict = $sync.dict
            $ext = [System.IO.Path]::GetExtension($arch).ToLower()

            $tool = $null
            if ($sync.userTool) {
                $tool = $sync.userTool
                $exeName = [System.IO.Path]::GetFileName($tool).ToLower()
                if (($exeName -eq 'rar.exe' -or $exeName -eq 'unrar.exe') -and $ext -ne '.rar') {
                    throw '所选工具只支持 RAR 压缩包，请改选 7-Zip（7z.exe）或使用自动检测。'
                }
            } else {
                $rar   = Find-Tool 'WinRAR' 'rar.exe'
                $unrar = Find-Tool 'WinRAR' 'unrar.exe'
                $sz    = Find-Tool '7-Zip'  '7z.exe'
                if ($ext -eq '.rar') {
                    $tool = $rar; if (-not $tool) { $tool = $unrar }; if (-not $tool) { $tool = $sz }
                } elseif ($ext -eq '.zip' -or $ext -eq '.7z') {
                    $tool = $sz
                } else {
                    $tool = $sz; if (-not $tool) { $tool = $rar }
                }
                if (-not $tool) { throw '未找到 WinRAR 或 7-Zip（rar.exe / unrar.exe / 7z.exe），可在界面手动指定工具路径。' }
            }
            Set-Sync @{ tool = $tool }

            if ((Test-NoPassword $tool $arch) -eq 0) {
                throw '该压缩包没有密码保护，无需破解。'
            }

            # ---- dictionary encoding: BOM detect, UTF-8 has priority -----
            $fs = [System.IO.File]::OpenRead($dict)
            $b0 = $fs.ReadByte(); $b1 = $fs.ReadByte(); $b2 = $fs.ReadByte(); $b3 = $fs.ReadByte()
            $fs.Close()
            if ($b0 -eq 0xEF -and $b1 -eq 0xBB -and $b2 -eq 0xBF) {
                $encodings = @(@{ n = 'UTF-8'; k = 'utf8bom'; e = [Text.Encoding]::UTF8 })
            } elseif ($b0 -eq 0xFF -and $b1 -eq 0xFE) {
                $encodings = @(@{ n = 'UTF-16LE'; k = 'utf16le'; e = [Text.Encoding]::Unicode })
            } elseif ($b0 -eq 0xFE -and $b1 -eq 0xFF) {
                throw '字典是 UTF-16BE 编码，请另存为 UTF-8 或 ANSI 后重试。'
            } else {
                # no BOM: strict-decode the first 256 KB as UTF-8. Real
                # UTF-8 (incl. pure ASCII) passes; GBK text almost always
                # hits an illegal sequence, so the futile UTF-8 pass over
                # a GBK dictionary is skipped entirely and ANSI runs alone.
                # A GBK file that happens to be valid UTF-8 keeps both
                # passes - the probe can only save time, never skip a hit.
                $encodings = @(
                    @{ n = 'UTF-8'; k = 'utf8'; e = [Text.Encoding]::UTF8 },
                    @{ n = 'ANSI(系统默认)'; k = 'ansi'; e = [Text.Encoding]::Default }
                )
                $fs = [System.IO.File]::OpenRead($dict)
                $fileLen = $fs.Length
                $probeLen = [int][Math]::Min(262144, $fileLen)
                $buf = New-Object byte[] $probeLen
                [void]$fs.Read($buf, 0, $probeLen)
                $fs.Close()
                if ($probeLen -lt $fileLen) {
                    # the probe may end mid multi-byte sequence: trim the
                    # trailing non-ASCII bytes so the cut itself cannot
                    # fake an illegal sequence
                    $valid = $probeLen
                    while ($valid -gt 0 -and $buf[$valid - 1] -ge 0x80) { $valid-- }
                    if ($valid -ne $probeLen) {
                        $buf2 = New-Object byte[] $valid
                        [Array]::Copy($buf, $buf2, $valid)
                        $buf = $buf2
                    }
                }
                $strict = New-Object System.Text.UTF8Encoding($false, $true)
                try { [void]$strict.GetString($buf) }
                catch { $encodings = @(@{ n = 'ANSI(系统默认)'; k = 'ansi'; e = [Text.Encoding]::Default }) }
            }

            Set-Sync @{ passTot = $encodings.Count }
            for ($i = 0; $i -lt $encodings.Count; $i++) {
                if (Get-Sync 'cancel') { break }
                $enc = $encodings[$i]
                Set-Sync @{ passN = $i + 1; passName = $enc.n; phase = 'pass' }

                # ReadAllLines loads everything and CLOSES the file at once -
                # a half-consumed ReadLines stream would keep the dict open
                # and break the "move password to top" write later
                $allLines = [System.IO.File]::ReadAllLines($dict, $enc.e)
                $pw = New-Object System.Collections.Generic.List[string]
                foreach ($line in $allLines) {
                    if ($line -and -not $line.StartsWith(';')) { $pw.Add($line) }
                }
                $pw = $pw.ToArray()
                Set-Sync @{ total = $pw.Count; tried = 0 }

                # ---- slice the dictionary across N parallel workers ----
                $n = [Math]::Min($workerCount, $pw.Count)
                if ($n -lt 1) { $n = 1 }
                $per = [int][Math]::Ceiling($pw.Count / [double]$n)
                $workers = @()
                for ($w = 0; $w -lt $n; $w++) {
                    $start = $w * $per
                    if ($start -ge $pw.Count) { break }
                    $end = [Math]::Min($start + $per, $pw.Count)
                    $slice = @($pw[$start..($end - 1)])
                    # one state table per worker: no two threads share a table
                    $state = @{ tried = 0; current = ''; found = $null; error = $null; done = $false; cancel = $false }
                    $ps = [powershell]::Create().AddScript($passWorkerBlock.ToString()).
                          AddArgument($state).AddArgument($tool).AddArgument($arch).AddArgument($slice)
                    $workers += , @{ ps = $ps; handle = $ps.BeginInvoke(); state = $state }
                }
                Set-Sync @{ nWorkers = @($workers).Count }

                # ---- poll workers until all done ----
                $found = $null
                while ($true) {
                    if (Get-Sync 'cancel') {
                        foreach ($wk in $workers) { $wk.state.cancel = $true }
                    }
                    $tried = 0
                    $allDone = $true
                    $found = $null
                    $cur = ''
                    $firstErr = $null
                    foreach ($wk in $workers) {
                        $tried += $wk.state.tried
                        if ($wk.state.found -and -not $found) { $found = $wk.state.found }
                        if (-not $wk.state.done) { $allDone = $false; if (-not $cur) { $cur = $wk.state.current } }
                        if (-not $firstErr -and $wk.state.error) { $firstErr = $wk.state.error }
                    }
                    if ($found) {
                        foreach ($wk in $workers) {
                            if (-not $wk.state.found) { $wk.state.cancel = $true }
                        }
                    }
                    Set-Sync @{ tried = $tried; current = $cur }
                    if ($allDone) { break }
                    Start-Sleep -Milliseconds 100
                }
                foreach ($wk in $workers) {
                    try { [void]$wk.ps.EndInvoke($wk.handle); $wk.ps.Dispose() } catch { }
                }
                Set-Sync @{ triedAll = ($sync.triedAll + $tried); current = '' }

                if ($found) {
                    # record the hit even when the user cancelled inside
                    # the poll gap - a confirmed password is always real
                    Set-Sync @{ found = $found; foundEnc = $enc.k }
                    break
                }
                if ($firstErr -and -not $found) { throw $firstErr }
                Set-Sync @{ phase = 'prep' }
            }
        }

        if (Get-Sync 'found') {
            $out = Join-Path $scriptDir (([System.IO.Path]::GetFileNameWithoutExtension($arch)) + '_password.txt')
            [System.IO.File]::WriteAllText($out, $sync.found + "`r`n", [Text.Encoding]::Default)
            Set-Sync @{ outfile = $out }
        }
    } catch {
        Set-Sync @{ error = $_.Exception.Message }
    } finally {
        Set-Sync @{ done = $true }
    }
'@)

# ---- pass worker: tests one slice of the dictionary -------------------
# each worker gets its OWN state hashtable - the UI aggregates them, so
# no two threads ever write the same table
$passWorker = [scriptblock]::Create(@'
    param($state, $tool, $arch, $passwords)
'@ + $fnProc + @'
    try {
        foreach ($p in $passwords) {
            if ($state.cancel) { break }
            $state.current = $p
            $state.tried++
            if ((Test-Password $tool $arch $p) -eq 0) {
                $state.found = $p
                break
            }
        }
    } catch {
        $state.error = $_.Exception.Message
    }
    $state.done = $true
'@)

# move the found password to line 1 of the dictionary file,
# preserving the encoding (incl. BOM) that the password matched under
function Move-PasswordToTop([string]$dictPath, [string]$pwdLine, [string]$encKey) {
    switch ($encKey) {
        'utf8bom' { $enc = New-Object System.Text.UTF8Encoding($true) }
        'utf16le' { $enc = [System.Text.Encoding]::Unicode }
        'ansi'    { $enc = [System.Text.Encoding]::Default }
        default   { $enc = New-Object System.Text.UTF8Encoding($false) }
    }
    $lines = [System.IO.File]::ReadAllLines($dictPath, $enc)
    $rest = @($lines | Where-Object { $_ -ne $pwdLine })
    $newLines = , $pwdLine + $rest
    $tmp = $dictPath + '.tmp'
    [System.IO.File]::WriteAllLines($tmp, $newLines, $enc)
    # three write-back methods, each fails on different setups:
    # Replace is atomic and keeps attributes but fails on some synced
    # folders (e.g. Nutstore), Copy overwrite works nearly everywhere,
    # Move is the last resort
    $done = $false
    $errs = @()
    try {
        [System.IO.File]::Replace($tmp, $dictPath, $null)
        $done = $true
    } catch { $errs += "Replace: $($_.Exception.Message)" }
    if (-not $done) {
        try {
            [System.IO.File]::Copy($tmp, $dictPath, $true)
            $done = $true
        } catch { $errs += "Copy: $($_.Exception.Message)" }
    }
    if (-not $done) {
        try {
            Move-Item -LiteralPath $tmp -Destination $dictPath -Force -ErrorAction Stop
            $done = $true
        } catch { $errs += "Move: $($_.Exception.Message)" }
    }
    try { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } } catch { }
    if (-not $done) { throw "无法写入字典文件（可能被其他程序占用）：$($errs -join '；')" }
}

# ------------------------- palette ------------------------------------
$cBg      = [System.Drawing.Color]::FromArgb(247, 248, 250)  # window background
$cHeader  = [System.Drawing.Color]::FromArgb(23, 32, 48)     # dark slate header
$cHeader2 = [System.Drawing.Color]::FromArgb(148, 163, 184)  # header subtitle
$cCard    = [System.Drawing.Color]::White
$cPrimary = [System.Drawing.Color]::FromArgb(37, 99, 235)    # blue
$cPrimHov = [System.Drawing.Color]::FromArgb(29, 78, 216)
$cText    = [System.Drawing.Color]::FromArgb(31, 41, 55)
$cSub     = [System.Drawing.Color]::FromArgb(107, 114, 128)  # gray text
$cBorder  = [System.Drawing.Color]::FromArgb(203, 213, 225)  # button border
$cBtnHov  = [System.Drawing.Color]::FromArgb(243, 244, 246)
$cTrack   = [System.Drawing.Color]::FromArgb(226, 232, 240)  # progress track
$cGreen   = [System.Drawing.Color]::FromArgb(22, 163, 74)
$cGreenDk = [System.Drawing.Color]::FromArgb(6, 95, 70)
$cGreenBg = [System.Drawing.Color]::FromArgb(236, 253, 245)
$cRed     = [System.Drawing.Color]::FromArgb(220, 38, 38)
$cOrange  = [System.Drawing.Color]::FromArgb(217, 119, 6)

# ------------------------- DPI-aware layout ---------------------------
# SetProcessDPIAware() above means we render at real pixels: fonts (pt)
# scale with DPI, but hardcoded pixel sizes do not. Measure the real DPI
# and scale every layout value so text never gets clipped.
$bmpTmp = New-Object System.Drawing.Bitmap(1, 1)
$gTmp = [System.Drawing.Graphics]::FromImage($bmpTmp)
$script:scale = $gTmp.DpiX / 96.0
$gTmp.Dispose(); $bmpTmp.Dispose()
if ($script:scale -lt 1.0) { $script:scale = 1.0 }
function S([double]$v) { [int][Math]::Round($v * $script:scale) }

# ------------------------- form --------------------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = 'DictCrack - 压缩包密码字典破解'
$form.ClientSize = [System.Drawing.Size]::new((S 672), (S 612))
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', 9)
$form.BackColor = $cBg
$form.FormBorderStyle = 'Sizable'
$form.MaximizeBox = $false
$form.AutoScaleMode = 'None'   # layout is scaled by S() instead
# width AND height are user-resizable within a generous ceiling.
# NOTE: a 0 dimension here is NOT "unlimited" in this WinForms build -
# it clamps the window to zero height right at the property assignment
$form.MaximumSize = [System.Drawing.Size]::new((S 1400), (S 1000))

# ---- header band (docked top) ----------------------------------------
$header = New-Object System.Windows.Forms.Panel
$header.Dock = 'Top'
$header.Height = S 68
$header.BackColor = $cHeader
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = 'DictCrack'
$lblTitle.ForeColor = [System.Drawing.Color]::White
$lblTitle.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', 14, [System.Drawing.FontStyle]::Bold)
$lblTitle.Location = [System.Drawing.Point]::new((S 22), (S 13))
$lblTitle.Size = [System.Drawing.Size]::new((S 320), (S 30))
$lblSub = New-Object System.Windows.Forms.Label
$lblSub.Text = '压缩包密码字典测试 · RAR / ZIP / 7Z'
$lblSub.ForeColor = $cHeader2
$lblSub.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', 8.5)
$lblSub.Location = [System.Drawing.Point]::new((S 24), (S 45))
$lblSub.Size = [System.Drawing.Size]::new((S 420), (S 18))
$header.Controls.AddRange(@($lblTitle, $lblSub))

# ---- content area (fills the rest) ------------------------------------
$content = New-Object System.Windows.Forms.Panel
$content.Dock = 'Fill'
$content.Padding = [System.Windows.Forms.Padding]::new((S 20), (S 14), (S 20), (S 10))
$content.BackColor = $cBg

$mkLabel = {
    param($text, $x, $y, $w, $h)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $text
    $l.Location = [System.Drawing.Point]::new((S $x), (S $y))
    $l.Size = [System.Drawing.Size]::new((S $w), (S $h))
    $l.TextAlign = 'MiddleLeft'
    $l.ForeColor = $cSub
    $l.BackColor = [System.Drawing.Color]::Transparent
    return $l
}

# secondary button: white with a light border (browse / stop / copy ...)
function New-Btn2([string]$text, $x, $y, $w, $h, $fg) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $text
    $b.Location = [System.Drawing.Point]::new((S $x), (S $y))
    $b.Size = [System.Drawing.Size]::new((S $w), (S $h))
    $b.FlatStyle = 'Flat'
    $b.FlatAppearance.BorderSize = 1
    $b.FlatAppearance.BorderColor = $cBorder
    $b.FlatAppearance.MouseOverBackColor = $cBtnHov
    $b.BackColor = [System.Drawing.Color]::White
    $b.ForeColor = $fg
    $b.Cursor = 'Hand'
    $b.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', 9)
    return $b
}

$lblArch = & $mkLabel '压缩包' 0 18 72 24
$txtArch = New-Object System.Windows.Forms.TextBox
$txtArch.Location = [System.Drawing.Point]::new((S 76), (S 16))
$txtArch.Size = [System.Drawing.Size]::new((S 446), (S 25))
$txtArch.ForeColor = $cText
$btnArch = New-Btn2 '浏览...' 532 13 100 30 $cText

$lblDict = & $mkLabel '字典文件' 0 64 72 24
$txtDict = New-Object System.Windows.Forms.TextBox
$txtDict.Location = [System.Drawing.Point]::new((S 76), (S 62))
$txtDict.Size = [System.Drawing.Size]::new((S 446), (S 25))
$txtDict.ForeColor = $cText
$btnDict = New-Btn2 '浏览...' 532 59 100 30 $cText

$lblToolSel = & $mkLabel '解压工具' 0 110 72 24
$cmbTool = New-Object System.Windows.Forms.ComboBox
$cmbTool.DropDownStyle = 'DropDownList'
$cmbTool.Location = [System.Drawing.Point]::new((S 76), (S 108))
$cmbTool.Size = [System.Drawing.Size]::new((S 446), (S 25))
$btnTool = New-Btn2 '浏览...' 532 105 100 30 $cText

$lblThreads = & $mkLabel '并行线程' 0 156 72 24
$cmbThreads = New-Object System.Windows.Forms.ComboBox
$cmbThreads.DropDownStyle = 'DropDownList'
$cmbThreads.Location = [System.Drawing.Point]::new((S 76), (S 154))
$cmbThreads.Size = [System.Drawing.Size]::new((S 446), (S 25))
$threadValues = New-Object System.Collections.ArrayList
[void]$cmbThreads.Items.Add(('自动（' + $cores + ' 核 → ' + (Get-AutoWorkerCount) + ' 线程）'))
[void]$threadValues.Add(0)
foreach ($t in @(1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 32)) {
    if ($t -le $cores) {
        [void]$cmbThreads.Items.Add(('' + $t + ' 线程'))
        [void]$threadValues.Add($t)
    }
}
$cmbThreads.SelectedIndex = 0

$toolPaths = New-Object System.Collections.ArrayList
[void]$cmbTool.Items.Add('自动检测（按压缩包类型选择）')
[void]$toolPaths.Add('')
$detRar   = Find-Tool 'WinRAR' 'rar.exe'
$detUnrar = Find-Tool 'WinRAR' 'unrar.exe'
$detSz    = Find-Tool '7-Zip'  '7z.exe'
if ($detRar)   { [void]$cmbTool.Items.Add("WinRAR  rar.exe ($detRar)");     [void]$toolPaths.Add($detRar) }
if ($detUnrar) { [void]$cmbTool.Items.Add("WinRAR  unrar.exe ($detUnrar)"); [void]$toolPaths.Add($detUnrar) }
if ($detSz)    { [void]$cmbTool.Items.Add("7-Zip  7z.exe ($detSz)");        [void]$toolPaths.Add($detSz) }
$cmbTool.SelectedIndex = 0

function Select-ToolPath([string]$path) {
    $i = $toolPaths.IndexOf($path)
    if ($i -ge 0) { $cmbTool.SelectedIndex = $i }
    else {
        [void]$cmbTool.Items.Add("手动: $path")
        [void]$toolPaths.Add($path)
        $cmbTool.SelectedIndex = $cmbTool.Items.Count - 1
    }
}

# ---- slim custom progress bar (track panel + fill panel) -------------
$pbTrack = New-Object System.Windows.Forms.Panel
$pbTrack.Location = [System.Drawing.Point]::new((S 76), (S 200))
$pbTrack.Size = [System.Drawing.Size]::new((S 556), (S 8))
$pbTrack.BackColor = $cTrack
$pbFill = New-Object System.Windows.Forms.Panel
$pbFill.Location = [System.Drawing.Point]::new(0, 0)
$pbFill.Size = [System.Drawing.Size]::new(0, (S 8))
$pbFill.BackColor = $cPrimary
$pbTrack.Controls.Add($pbFill)

$btnStart = New-Object System.Windows.Forms.Button
$btnStart.Text = '开始破解'
$btnStart.Location = [System.Drawing.Point]::new((S 76), (S 222))
$btnStart.Size = [System.Drawing.Size]::new((S 152), (S 40))
$btnStart.FlatStyle = 'Flat'
$btnStart.FlatAppearance.BorderSize = 0
$btnStart.FlatAppearance.MouseOverBackColor = $cPrimHov
$btnStart.BackColor = $cPrimary
$btnStart.ForeColor = [System.Drawing.Color]::White
$btnStart.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', 9.5, [System.Drawing.FontStyle]::Bold)
$btnStart.Cursor = 'Hand'
$btnStop = New-Btn2 '停止' 238 222 100 40 $cRed

$lblStatus = & $mkLabel '待机 - 选择压缩包与字典后点击开始' 76 278 556 22
$lblStatus.ForeColor = $cSub
$lblCurrent = & $mkLabel '' 76 302 556 20
$lblStats = & $mkLabel '' 76 326 556 20

$grp = New-Object System.Windows.Forms.GroupBox
$grp.Text = '破解结果'
$grp.Location = [System.Drawing.Point]::new((S 76), (S 358))
$grp.Size = [System.Drawing.Size]::new((S 556), (S 142))
$grp.ForeColor = $cSub
$grp.BackColor = $cCard
$txtPwd = New-Object System.Windows.Forms.TextBox
$txtPwd.ReadOnly = $true
$txtPwd.Location = [System.Drawing.Point]::new((S 16), (S 30))
$txtPwd.Size = [System.Drawing.Size]::new((S 412), (S 34))
$txtPwd.BorderStyle = 'FixedSingle'
$txtPwd.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', 13, [System.Drawing.FontStyle]::Bold)
$txtPwd.ForeColor = $cText
$btnCopy = New-Btn2 '复制密码' 436 29 106 34 $cText
# read-only box should not look editable: no I-beam cursor, no caret.
# TextBox shows a blinking caret even when ReadOnly, so kick focus to
# the copy button the moment the box receives it
$txtPwd.Cursor = 'Default'
$txtPwd.TabStop = $false
$txtPwd.Add_GotFocus({ [void]$btnCopy.Focus() })
$lblSave = New-Object System.Windows.Forms.Label
$lblSave.Text = ''
$lblSave.Location = [System.Drawing.Point]::new((S 16), (S 82))
$lblSave.Size = [System.Drawing.Size]::new((S 316), (S 44))
$lblSave.ForeColor = $cSub
$lblSave.BackColor = [System.Drawing.Color]::Transparent
$lblSave.AutoEllipsis = $true
$btnMove = New-Btn2 '密码提前到字典首行' 342 78 200 32 $cText
$grp.Controls.AddRange(@($txtPwd, $btnCopy, $lblSave, $btnMove))

$lblHint = New-Object System.Windows.Forms.Label
$lblHint.Text = '提示：可直接把压缩包 / 字典文件拖进窗口 · Enter 开始 · Esc 停止'
$lblHint.Location = [System.Drawing.Point]::new(0, (S 514))
$lblHint.Size = [System.Drawing.Size]::new((S 632), (S 18))
# #6B7280 on #F7F8FA = 4.5:1 contrast (the previous #A5ACB8 was 2.1:1)
$lblHint.ForeColor = [System.Drawing.Color]::FromArgb(107, 114, 128)
$lblHint.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', 8)
$lblHint.BackColor = [System.Drawing.Color]::Transparent

# anchors: inputs / labels / progress / group stretch with the window
# width; the hint line sticks to the bottom so vertical stretching adds
# space between the group and the hint
# NOTE: size the panel to its final designed size BEFORE anchoring -
# anchors snapshot the gap to the parent's current edge, and the panel
# is still at its default 200px width until the form is laid out
# (672x544 = designed client minus the 68px header band)
$content.Size = [System.Drawing.Size]::new((S 672), (S 544))
foreach ($c in @($txtArch, $txtDict, $cmbTool, $cmbThreads)) { $c.Anchor = 'Top,Left,Right' }
foreach ($c in @($btnArch, $btnDict, $btnTool)) { $c.Anchor = 'Top,Right' }
$pbTrack.Anchor = 'Top,Left,Right'
$lblStatus.Anchor = 'Top,Left,Right'
$lblCurrent.Anchor = 'Top,Left,Right'
$lblStats.Anchor = 'Top,Left,Right'
$grp.Anchor = 'Top,Left,Right'
$btnCopy.Anchor = 'Top,Right'
$btnMove.Anchor = 'Top,Right'
$lblHint.Anchor = 'Bottom,Left,Right'

$content.Controls.AddRange(@($lblArch, $txtArch, $btnArch,
                             $lblDict, $txtDict, $btnDict,
                             $lblToolSel, $cmbTool, $btnTool,
                             $lblThreads, $cmbThreads,
                             $pbTrack, $btnStart, $btnStop,
                             $lblStatus, $lblCurrent, $lblStats, $grp, $lblHint))
# add content first, header last -> header docks on top, content fills below
$form.Controls.Add($content)
$form.Controls.Add($header)
# floor = the designed size; set in Shown (handle exists -> Size is real).
# reading $form.Size before the handle is created returns a stale height
# and clamps the window to zero client height
$form.Add_Shown({ $form.MinimumSize = $form.Size })

$form.AcceptButton = $btnStart
# Esc is handled manually below: binding btnStop as form.CancelButton
# pulls it into the dialog machinery, where a plain click on it (not
# just Esc) closes the whole window
$form.KeyPreview = $true
$form.Add_KeyDown({
    if ($_.KeyCode -eq 'Escape') {
        $_.SuppressKeyPress = $true
        Request-Cancel
    }
})
# closing the window mid-run must tell the orchestrator to stop instead
# of letting process exit hard-kill the runspaces and orphan 7z children
$form.Add_FormClosing({ Request-Cancel })

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 150

# ------------------------- event handlers ----------------------------
function Set-Status([string]$text, $color) {
    $lblStatus.Text = $text
    $lblStatus.ForeColor = $color
}

# single cancellation path for Esc, the stop button and window close
function Request-Cancel {
    if (-not $sync.running) { return }
    [System.Threading.Monitor]::Enter($sync.SyncRoot)
    try { $sync.cancel = $true } finally { [System.Threading.Monitor]::Exit($sync.SyncRoot) }
    Set-Status '正在停止（等待当前测试结束）...' $cOrange
}

$btnArch.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title = '选择压缩包'
    $dlg.Filter = '压缩包 (*.rar;*.zip;*.7z)|*.rar;*.zip;*.7z|所有文件 (*.*)|*.*'
    if (-not [string]::IsNullOrWhiteSpace($txtArch.Text)) {
        try {
            $d = Split-Path -Parent $txtArch.Text
            if ($d -and (Test-Path $d)) { $dlg.InitialDirectory = $d }
        } catch { }
    }
    if ($dlg.ShowDialog() -eq 'OK') { $txtArch.Text = $dlg.FileName }
})

$btnDict.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title = '选择字典文件'
    $dlg.Filter = '文本文件 (*.txt;*.dic;*.lst)|*.txt;*.dic;*.lst|所有文件 (*.*)|*.*'
    if (-not [string]::IsNullOrWhiteSpace($txtDict.Text)) {
        try {
            $d = Split-Path -Parent $txtDict.Text
            if ($d -and (Test-Path $d)) { $dlg.InitialDirectory = $d }
        } catch { }
    }
    if ($dlg.ShowDialog() -eq 'OK') { $txtDict.Text = $dlg.FileName }
})

$btnTool.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title = '选择压缩软件（rar.exe / unrar.exe / 7z.exe）'
    $dlg.Filter = '可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*'
    $cur = ''
    if ($cmbTool.SelectedIndex -ge 0) { $cur = $toolPaths[$cmbTool.SelectedIndex] }
    if ($cur) {
        try {
            $d = Split-Path -Parent $cur
            if ($d -and (Test-Path $d)) { $dlg.InitialDirectory = $d }
        } catch { }
    }
    if ($dlg.ShowDialog() -eq 'OK') { Select-ToolPath $dlg.FileName }
})

# ---- drag & drop: archives / dictionary files straight into the form --
$form.AllowDrop = $true
$form.Add_DragEnter({
    $_.Effect = [System.Windows.Forms.DragDropEffects]::None
    if (-not $_.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) { return }
    $files = @($_.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop))
    foreach ($f in $files) {
        $e = [System.IO.Path]::GetExtension($f).ToLower()
        if ($e -eq '.rar' -or $e -eq '.zip' -or $e -eq '.7z' -or
            $e -eq '.txt' -or $e -eq '.dic' -or $e -eq '.lst') {
            $_.Effect = [System.Windows.Forms.DragDropEffects]::Copy
            return
        }
    }
})
$form.Add_DragDrop({
    $files = @($_.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop))
    $gotArch = $false; $gotDict = $false
    foreach ($f in $files) {
        $e = [System.IO.Path]::GetExtension($f).ToLower()
        if ($e -eq '.rar' -or $e -eq '.zip' -or $e -eq '.7z') { $txtArch.Text = $f; $gotArch = $true }
        elseif ($e -eq '.txt' -or $e -eq '.dic' -or $e -eq '.lst') { $txtDict.Text = $f; $gotDict = $true }
    }
    if ($gotArch -or $gotDict) {
        $msg = @(); if ($gotArch) { $msg += '已填入压缩包' }; if ($gotDict) { $msg += '已填入字典' }
        Set-Status ("拖入成功: " + ($msg -join '、')) $cSub
    } else {
        Set-Status '拖入的文件类型不受支持（需要 rar/zip/7z 或 txt/dic/lst）。' $cOrange
    }
})

$btnStart.Add_Click({
    if ([string]::IsNullOrWhiteSpace($txtArch.Text)) {
        [void][System.Windows.Forms.MessageBox]::Show($form, '请先选择压缩包文件。', 'DictCrack', 'OK', 'Warning')
        $txtArch.Focus()
        return
    }
    if ([string]::IsNullOrWhiteSpace($txtDict.Text)) {
        [void][System.Windows.Forms.MessageBox]::Show($form, '请先选择字典文件。', 'DictCrack', 'OK', 'Warning')
        $txtDict.Focus()
        return
    }
    if (-not (Test-Path $txtArch.Text)) {
        [void][System.Windows.Forms.MessageBox]::Show($form, '压缩包文件不存在，请重新选择。', 'DictCrack', 'OK', 'Warning')
        return
    }
    if (-not (Test-Path $txtDict.Text)) {
        [void][System.Windows.Forms.MessageBox]::Show($form, '字典文件不存在，请重新选择。', 'DictCrack', 'OK', 'Warning')
        return
    }
    # remember this pair (and the tool / thread choices) for the next launch
    $selTool = ''
    if ($cmbTool.SelectedIndex -ge 0) { $selTool = $toolPaths[$cmbTool.SelectedIndex] }
    $selThreads = 0
    if ($cmbThreads.SelectedIndex -ge 0) { $selThreads = $threadValues[$cmbThreads.SelectedIndex] }
    if ($selThreads -gt 0) { $script:workerCount = $selThreads }
    else { $script:workerCount = Get-AutoWorkerCount }
    try {
        [System.IO.File]::WriteAllText($cfgFile, "arch=$($txtArch.Text)`r`ndict=$($txtDict.Text)`r`ntool=$selTool`r`nthreads=$selThreads`r`n", (New-Object System.Text.UTF8Encoding($true)))
    } catch { }
    $sync.userTool = $selTool
    $sync.arch = $txtArch.Text
    $sync.dict = $txtDict.Text
    $sync.cancel = $false; $sync.done = $false; $sync.running = $true
    $sync.found = $null; $sync.error = $null; $sync.outfile = ''
    $sync.tried = 0; $sync.triedAll = 0; $sync.total = 0
    $sync.passN = 0; $sync.passTot = 1; $sync.passName = ''
    $sync.current = ''; $sync.tool = ''
    $sync.phase = 'prep'; $sync.nWorkers = 0

    $txtPwd.Text = ''; $btnCopy.Enabled = $false; $lblSave.Text = ''
    $btnMove.Enabled = $false
    $txtPwd.BackColor = [System.Drawing.Color]::White
    $txtPwd.ForeColor = $cText
    $grp.Text = '破解结果'; $grp.ForeColor = $cSub
    $pbFill.Width = 0; $pbFill.BackColor = $cPrimary
    $lblCurrent.Text = ''; $lblStats.Text = ''
    $btnStart.Enabled = $false; $btnStop.Enabled = $true
    Set-Status ('正在启动（最多 ' + $script:workerCount + ' 线程并行）...') $cText

    $script:statWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $script:rateTried = 0
    $script:rateTick = [System.Diagnostics.Stopwatch]::StartNew()
    $script:rate = 0

    $script:orchPs = [powershell]::Create().AddScript($orchestrator.ToString()).
        AddArgument($sync).AddArgument($passWorker).AddArgument($script:workerCount).AddArgument($scriptDir)
    $script:orchHandle = $script:orchPs.BeginInvoke()
    $timer.Start()
})

$btnStop.Add_Click({ Request-Cancel })

$btnCopy.Add_Click({
    if ($txtPwd.Text) { Set-Clipboard -Value $txtPwd.Text }
})

$btnMove.Add_Click({
    if (-not $sync.found) { return }
    $btnMove.Enabled = $false
    try {
        Move-PasswordToTop $sync.dict $sync.found $sync.foundEnc
        $lblSave.Text = "$($lblSave.Text)  密码已提前到字典第 1 行。"
        Set-Status '密码已提前到字典开头，下次破解将第一个尝试。' $cGreen
    } catch {
        Set-Status "移动密码到字典开头失败: $($_.Exception.Message)" $cRed
    }
})

# mm:ss (or h:mm:ss when over an hour); '--:--' when not computable
function Format-Eta([double]$sec) {
    if ($sec -lt 0 -or [double]::IsNaN($sec) -or [double]::IsInfinity($sec)) { return '--:--' }
    $t = [timespan]::FromSeconds([math]::Floor($sec))
    if ($t.TotalHours -ge 1) { return ('{0:00}:{1:00}:{2:00}' -f [int]$t.TotalHours, $t.Minutes, $t.Seconds) }
    return ('{0:00}:{1:00}' -f $t.Minutes, $t.Seconds)
}

# ---- run finish (UI side; the orchestrator writes the result file) ---
function Finish-Run {
    $timer.Stop()
    $lblCurrent.Text = ''
    $btnStart.Enabled = $true
    $btnStop.Enabled = $false
    try {
        if ($script:orchHandle) { [void]$script:orchPs.EndInvoke($script:orchHandle) }
        $script:orchPs.Dispose()
    } catch { }
    $elapsed = $script:statWatch.Elapsed
    $avg = 0
    if ($elapsed.TotalSeconds -gt 0) { $avg = $sync.triedAll / $elapsed.TotalSeconds }
    $lblStats.Text = ('总计尝试 {0} 个 · 用时 {1:00}:{2:00} · 平均 {3} 个/秒' -f `
        $sync.triedAll, [int]$elapsed.TotalMinutes, $elapsed.Seconds, ([math]::Round($avg, 1)))
    if ($sync.found) {
        $txtPwd.Text = $sync.found
        $btnCopy.Enabled = $true
        # a found password is valid even when the user cancelled during
        # the run - moving it to the top of the dictionary stays useful
        $btnMove.Enabled = $true
        $txtPwd.BackColor = $cGreenBg
        $txtPwd.ForeColor = $cGreenDk
        $grp.Text = '破解结果 — 已找到密码'
        $grp.ForeColor = $cGreen
        $pbFill.Width = $pbTrack.Width
        $pbFill.BackColor = $cGreen
        if ($sync.cancel) {
            Set-Status '已取消（取消前已找到密码）。' $cSub
        } else {
            Set-Status '找到密码！' $cGreen
        }
        if ($sync.outfile) { $lblSave.Text = "已保存到: $($sync.outfile)" }
    } elseif ($sync.error) {
        Set-Status "出错: $($sync.error)" $cRed
    } elseif ($sync.cancel) {
        Set-Status '已取消。' $cSub
    } else {
        Set-Status '未找到密码（所有编码遍历完成）。' $cOrange
    }
    $sync.running = $false
    $sync.phase = 'idle'
}

$timer.Add_Tick({
    if (-not $sync.running) { return }
    try {

    # snapshot the shared state under the same lock the orchestrator
    # uses for writing - keeps UI reads consistent with worker updates
    [System.Threading.Monitor]::Enter($sync.SyncRoot)
    try {
        $snap = @{
            tried = $sync.tried; triedAll = $sync.triedAll; total = $sync.total
            passN = $sync.passN; passTot = $sync.passTot; passName = $sync.passName
            nWorkers = $sync.nWorkers; current = $sync.current; done = $sync.done
            phase = $sync.phase
        }
    } finally { [System.Threading.Monitor]::Exit($sync.SyncRoot) }

    # total attempts = finished passes + current pass progress
    $triedAllNow = $snap.triedAll + $snap.tried

    # rolling speed over ~0.5 s windows
    if ($script:rateTick.Elapsed.TotalSeconds -ge 0.5) {
        $dt = $script:rateTick.Elapsed.TotalSeconds
        $script:rate = ($triedAllNow - $script:rateTried) / $dt
        $script:rateTried = $triedAllNow
        $script:rateTick.Restart()
    }
    $elapsed = $script:statWatch.Elapsed
    $statsLine = ('已用时 {0:00}:{1:00}' -f [int]$elapsed.TotalMinutes, $elapsed.Seconds)
    if ($script:rate -gt 0) {
        $statsLine += (' · 速度 {0} 个/秒' -f ([math]::Round($script:rate, 1)))
        if ($snap.total -gt $snap.tried) {
            $statsLine += (' · 预计剩余 {0}' -f (Format-Eta (($snap.total - $snap.tried) / $script:rate)))
        }
    }
    $lblStats.Text = $statsLine

    $threads = ''
    if ($snap.nWorkers -gt 0) { $threads = ' · ' + $snap.nWorkers + ' 线程' }
    if ($snap.passN -gt 0) {
        $lblStatus.Text = ('第 {0}/{1} 遍 ({2}){3}   已尝试 {4} / {5}' -f `
            $snap.passN, $snap.passTot, $snap.passName, $threads, $snap.tried, $snap.total)
        $lblStatus.ForeColor = $cText
    } elseif ($snap.phase -eq 'prep') {
        # tool detection / BOM probe / reading a large dictionary can take
        # a moment - say so instead of sticking at "starting..."
        $lblStatus.Text = '正在准备（检测工具 / 读取字典）...'
        $lblStatus.ForeColor = $cText
    }
    if ($snap.current) { $lblCurrent.Text = '当前尝试: ' + $snap.current }

    if ($snap.total -gt 0) {
        $pbFill.Width = [int]($pbTrack.Width * $snap.tried / $snap.total)
    }

    if ($snap.done) {
        Finish-Run
    }

    } catch {
        # safety net: an error inside a tick must never leave the window
        # frozen with a dead timer
        $sync.running = $false
        $timer.Stop()
        $btnStart.Enabled = $true
        $btnStop.Enabled = $false
        Set-Status ('内部错误: ' + $_.Exception.Message) $cRed
    }
})

# ------------------------- run ---------------------------------------
# restore last used paths (command line arguments take precedence)
$rememberTool = ''
$rememberThreads = 0
if (Test-Path $cfgFile) {
    try {
        foreach ($line in [System.IO.File]::ReadAllLines($cfgFile)) {
            $idx = $line.IndexOf('=')
            if ($idx -lt 1) { continue }
            $k = $line.Substring(0, $idx).Trim()
            $v = $line.Substring($idx + 1)
            if ($k -eq 'arch') { $txtArch.Text = $v }
            elseif ($k -eq 'dict') { $txtDict.Text = $v }
            elseif ($k -eq 'tool' -and -not $Tool) { $rememberTool = $v }
            elseif ($k -eq 'threads') { $rememberThreads = [int]$v }
        }
        if ($rememberTool -and (Test-Path $rememberTool)) { Select-ToolPath $rememberTool }
    } catch { }
}
if ($Arch) { $txtArch.Text = $Arch }
if ($Dict) { $txtDict.Text = $Dict }
if ($Tool -and (Test-Path $Tool)) { Select-ToolPath $Tool }
$initThreads = 0
if ($Threads -gt 0) { $initThreads = $Threads }
elseif ($rememberThreads -gt 0) { $initThreads = $rememberThreads }
# the cfg is plain text and can be hand-edited - clamp like the parameter
if ($initThreads -gt 32) { $initThreads = 32 }
if ($initThreads -gt 0) {
    $i = $threadValues.IndexOf($initThreads)
    if ($i -ge 0) { $cmbThreads.SelectedIndex = $i }
    else {
        [void]$cmbThreads.Items.Add(('' + $initThreads + ' 线程'))
        [void]$threadValues.Add($initThreads)
        $cmbThreads.SelectedIndex = $cmbThreads.Items.Count - 1
    }
}
if ($Arch -and $Dict) {
    # unlike a manual click, auto-start suppresses the path MessageBox -
    # surface an invalid command-line path in the status line instead of
    # failing silently
    $form.Add_Shown({
        if ((Test-Path $Arch) -and (Test-Path $Dict)) { $btnStart.PerformClick() }
        else { Set-Status '命令行指定的压缩包或字典文件不存在，请重新选择。' $cOrange }
    })
}
[void]$form.ShowDialog()
$form.Dispose()
