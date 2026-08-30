# build.ps1 -- compile dictcrack.exe (CLI) and dictcrack-gui.exe (GUI)
# with the in-box .NET Framework 4.8 C# compiler. ASCII only.
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$src  = Join-Path $root 'src'
$dist = Join-Path $root 'dist'

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
if (-not (Test-Path $csc)) { throw 'csc.exe not found (need .NET Framework 4.x)' }

if (-not (Test-Path $dist)) { New-Item -ItemType Directory -Path $dist | Out-Null }

$shared = @(
    (Join-Path $src 'Crypto.cs'),
    (Join-Path $src 'ArchiveInfo.cs'),
    (Join-Path $src 'Verifier.cs'),
    (Join-Path $src 'Attacks.cs'),
    (Join-Path $src 'Engine.cs')
)

$outCli = Join-Path $dist 'dictcrack.exe'
$outGui = Join-Path $dist 'dictcrack-gui.exe'

$cliArgs = @('/nologo', '/target:exe', '/optimize+', '/warnaserror-', '/utf8output',
    ('/out:' + $outCli),
    '/r:System.dll', '/r:System.Core.dll') + $shared + @((Join-Path $src 'Cli.cs'))

& $csc @cliArgs
if ($LASTEXITCODE -ne 0) { throw "CLI compile failed ($LASTEXITCODE)" }
Write-Output 'OK dist\dictcrack.exe'

$guiArgs = @('/nologo', '/target:winexe', '/optimize+', '/warnaserror-', '/utf8output',
    ('/out:' + $outGui),
    '/r:System.dll', '/r:System.Core.dll',
    '/r:System.Windows.Forms.dll', '/r:System.Drawing.dll') + $shared + @((Join-Path $src 'Gui.cs'))

& $csc @guiArgs
if ($LASTEXITCODE -ne 0) { throw "GUI compile failed ($LASTEXITCODE)" }
Write-Output 'OK dist\dictcrack-gui.exe'
