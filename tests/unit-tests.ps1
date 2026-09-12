# unit-tests.ps1 -- pure unit tests for DictCrack (no external tools or
# fixtures needed). Compiles the engine sources together with
# unittests.cs into one assembly so internal members are reachable.
# ASCII only. Exit code: number of failed checks.
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$src  = Join-Path $root 'src'
$dist = Join-Path $root 'dist'

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
if (-not (Test-Path $csc)) { throw 'csc.exe not found (need .NET Framework 4.x)' }
if (-not (Test-Path $dist)) { New-Item -ItemType Directory -Path $dist | Out-Null }

$out = Join-Path $dist 'dictcrack-unittest.exe'
& $csc /nologo /target:exe /optimize+ /warnaserror- /utf8output ('/out:' + $out) `
    '/r:System.dll' '/r:System.Core.dll' `
    (Join-Path $src 'Crypto.cs'),
    (Join-Path $src 'ArchiveInfo.cs'),
    (Join-Path $src 'Verifier.cs'),
    (Join-Path $src 'Attacks.cs'),
    (Join-Path $src 'Engine.cs'),
    (Join-Path $PSScriptRoot 'unittests.cs')
if ($LASTEXITCODE -ne 0) { throw "unit test compile failed ($LASTEXITCODE)" }

& $out
exit $LASTEXITCODE
