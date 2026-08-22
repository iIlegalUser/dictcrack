@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem =====================================================================
rem  dictcrack.bat -- test archive passwords from a dictionary file
rem
rem  Usage : dictcrack.bat <archive> <dictionary.txt>
rem
rem  Needs : WinRAR (rar.exe / unrar.exe, RAR only) and/or 7-Zip (7z.exe,
rem          handles RAR / ZIP / 7Z and more). Tools are auto-detected
rem          in common install paths and in PATH.
rem
rem  Dict  : one password per line, blank lines skipped,
rem          lines starting with ";" are treated as comments.
rem          Encodings handled automatically (UTF-8 has priority):
rem            - UTF-8 (no BOM)       : pass 1
rem            - UTF-8 with BOM       : BOM stripped via PowerShell, pass 1
rem            - ANSI/OEM (e.g. GBK)  : pass 2 fallback (only if pass 1
rem                                      found nothing)
rem            - UTF-16LE             : read through "type" conversion
rem
rem  Exit  : 0 = password found   1 = not found   2 = bad arguments,
rem           no tool, archive not password protected, unsupported dict
rem
rem  NOTE  : this file must stay ANSI/ASCII (no Chinese chars) so cmd.exe
rem           parses it correctly on a GBK code page system.
rem =====================================================================

if "%~1"=="" goto usage
if "%~2"=="" goto usage
if not exist "%~1" (
    echo [!] Archive not found: "%~1"
    exit /b 2
)
if not exist "%~2" (
    echo [!] Dictionary not found: "%~2"
    exit /b 2
)

set "ARCHIVE=%~f1"
set "DICT=%~f2"
set "EXT=%~x1"

rem ---- locate WinRAR / 7-Zip (common install paths first, then PATH)
set "RAREXE="
set "UNRAREXE="
set "SZEXE="

if exist "%ProgramFiles%\WinRAR\rar.exe" set "RAREXE=%ProgramFiles%\WinRAR\rar.exe"
if not defined RAREXE if exist "%ProgramW6432%\WinRAR\rar.exe" set "RAREXE=%ProgramW6432%\WinRAR\rar.exe"
if not defined RAREXE if exist "%ProgramFiles(x86)%\WinRAR\rar.exe" set "RAREXE=%ProgramFiles(x86)%\WinRAR\rar.exe"
if not defined RAREXE for /f "delims=" %%I in ('where rar.exe 2^>nul') do if not defined RAREXE set "RAREXE=%%I"

if exist "%ProgramFiles%\WinRAR\unrar.exe" set "UNRAREXE=%ProgramFiles%\WinRAR\unrar.exe"
if not defined UNRAREXE if exist "%ProgramW6432%\WinRAR\unrar.exe" set "UNRAREXE=%ProgramW6432%\WinRAR\unrar.exe"
if not defined UNRAREXE if exist "%ProgramFiles(x86)%\WinRAR\unrar.exe" set "UNRAREXE=%ProgramFiles(x86)%\WinRAR\unrar.exe"
if not defined UNRAREXE for /f "delims=" %%I in ('where unrar.exe 2^>nul') do if not defined UNRAREXE set "UNRAREXE=%%I"

if exist "%ProgramFiles%\7-Zip\7z.exe" set "SZEXE=%ProgramFiles%\7-Zip\7z.exe"
if not defined SZEXE if exist "%ProgramW6432%\7-Zip\7z.exe" set "SZEXE=%ProgramW6432%\7-Zip\7z.exe"
if not defined SZEXE if exist "%ProgramFiles(x86)%\7-Zip\7z.exe" set "SZEXE=%ProgramFiles(x86)%\7-Zip\7z.exe"
if not defined SZEXE for /f "delims=" %%I in ('where 7z.exe 2^>nul') do if not defined SZEXE set "SZEXE=%%I"

rem ---- pick a tool that can handle this archive type -----------------
rem  console rar.exe / unrar.exe support RAR archives only,
rem  ZIP / 7Z and everything else goes to 7z.exe
set "TOOL="
if /i "%EXT%"==".rar" (
    if defined RAREXE set "TOOL=%RAREXE%"
    if not defined TOOL if defined UNRAREXE set "TOOL=%UNRAREXE%"
    if not defined TOOL if defined SZEXE set "TOOL=%SZEXE%"
) else if /i "%EXT%"==".zip" (
    if defined SZEXE set "TOOL=%SZEXE%"
) else if /i "%EXT%"==".7z" (
    if defined SZEXE set "TOOL=%SZEXE%"
) else (
    if defined SZEXE set "TOOL=%SZEXE%"
    if not defined TOOL if defined RAREXE set "TOOL=%RAREXE%"
)

if not defined TOOL (
    echo [!] No tool that can handle "%EXT%" archives was found.
    echo     RAR archives     - needs WinRAR rar.exe / unrar.exe, or 7-Zip
    echo     ZIP / 7Z archives - needs 7-Zip 7z.exe
    echo     Install WinRAR or 7-Zip, or put the exe on PATH.
    exit /b 2
)

rem ---- remember the console code page (restored after pass 2) --------
set "OLDCP="
for /f "tokens=2 delims=:" %%C in ('chcp') do set /a OLDCP=%%C
if not defined OLDCP set "OLDCP=936"

rem ---- inspect dictionary encoding: hex of the first bytes -----------
rem  full path find.exe below: a bare "find" may resolve to GNU find
rem  from Git Bash / MSYS when PATH is inherited from such a shell
set "TMPHEX=%TEMP%\dictcrack_hex.tmp"
set "HEXHEAD="
certutil -encodehex "%DICT%" "%TMPHEX%" 4 >nul 2>&1
if exist "%TMPHEX%" set /p HEXHEAD=<"%TMPHEX%"
del "%TMPHEX%" >nul 2>&1
set "HEXNS=%HEXHEAD: =%"
set "BOM8=0"
if /i "%HEXNS:~0,6%"=="efbbbf" set "BOM8=1"
set "BOM16LE=0"
if /i "%HEXNS:~0,4%"=="fffe" set "BOM16LE=1"
set "BOM16BE=0"
if /i "%HEXNS:~0,4%"=="feff" set "BOM16BE=1"

if "%BOM16BE%"=="1" (
    echo [!] Dictionary is UTF-16BE which is not supported.
    echo     Re-save it as UTF-8 or ANSI and try again.
    exit /b 2
)

rem ---- count dictionary lines for the final report -------------------
set "TOTAL=0"
for /f %%C in ('%SystemRoot%\System32\find.exe /c /v "" ^< "%DICT%"') do set "TOTAL=%%C"

echo [*] Archive    : "%ARCHIVE%"
echo [*] Dictionary : "%DICT%"  (%TOTAL% lines)
if "%BOM16LE%"=="1"  echo [*] Dict type  : UTF-16LE ^(converted on the fly^)
if "%BOM8%"=="1"      echo [*] Dict type  : UTF-8 with BOM
if "%BOM16LE%"=="0" if "%BOM8%"=="0" echo [*] Dict type  : ANSI or UTF-8 without BOM ^(UTF-8 first, then ANSI^)
echo [*] Tool       : "%TOOL%"
echo.

rem ---- sanity check: is the archive really password protected? -------
"%TOOL%" t -y "%ARCHIVE%" >nul 2>&1 <nul
if not errorlevel 1 (
    echo [!] The archive is NOT password protected, nothing to test.
    exit /b 2
)

rem ---- main scan: pass 1 = UTF-8, pass 2 = ANSI/OEM fallback ---------
set /a TRIED=0
set "FOUNDPWD="
set "DICT2=%DICT%"
set "SKIP1="
title dictcrack: %~nx1

if "%BOM8%"=="1" goto prep8
goto pass1

:prep8
rem  strip the UTF-8 BOM so that line 1 can be tested too (type/find keep it)
set "TMPDICT=%TEMP%\dictcrack_utf8.tmp"
del "%TMPDICT%" >nul 2>&1
powershell -NoProfile -Command "[IO.File]::WriteAllText('%TMPDICT%',[IO.File]::ReadAllText('%DICT%'))" >nul 2>&1
set "STRIP_OK=0"
if not errorlevel 1 if exist "%TMPDICT%" set "STRIP_OK=1"
if "%STRIP_OK%"=="1" (
    set "DICT2=%TMPDICT%"
) else (
    set "SKIP1=skip=1 "
    echo [!] BOM could not be stripped - line 1 of the dictionary is skipped.
)

:pass1
echo [*] Pass 1: dictionary as UTF-8 ^(code page 65001^)
chcp 65001 >nul
rem
call :runpass
chcp %OLDCP% >nul
rem
if exist "%TEMP%\dictcrack_utf8.tmp" del "%TEMP%\dictcrack_utf8.tmp" >nul 2>&1
if defined FOUNDPWD goto found

if "%OLDCP%"=="65001" goto notfound

echo.
echo [*] Pass 2: dictionary as ANSI/OEM code page %OLDCP%
call :runpass
if defined FOUNDPWD goto found

:notfound
echo.
title %~nx0 - done
echo [-] Password NOT found. Tried %TRIED% candidates from %TOTAL% dictionary lines.
exit /b 1

:found
echo.
title %~nx0 - done
set "OUT=%~n1_password.txt"
setlocal EnableDelayedExpansion
echo [+] PASSWORD FOUND  after !TRIED! tries: !FOUNDPWD!
>>"%OUT%" echo !FOUNDPWD!
echo [+] Saved to file: "%OUT%"
echo.
echo [+] Extract it with one of:
echo     rar    x -p"!FOUNDPWD!" "!ARCHIVE!" "C:\extract here\"
echo     unrar  x -p"!FOUNDPWD!" "!ARCHIVE!" "C:\extract here\"
echo     7z     x -p"!FOUNDPWD!" -o"C:\extract here" "!ARCHIVE!"
endlocal
exit /b 0

rem ---- one scan over the dictionary ----------------------------------
rem  reads through "type": it passes ANSI/UTF-8 bytes through unchanged
rem  and converts UTF-16 input to the active code page. %SKIP1% is set
rem  only when a BOM could not be stripped (skip corrupted line 1).
:runpass
for /f "usebackq %SKIP1%delims=" %%P in (`type "%DICT2%"`) do (
    if not defined FOUNDPWD (
        set /a TRIED+=1
        title Testing: %%P
        <nul set /p "CRACKDOT=."
        "%TOOL%" t -y -p"%%P" "%ARCHIVE%" >nul 2>&1
        if not errorlevel 1 set "FOUNDPWD=%%P"
    )
)
exit /b

:usage
echo Usage: %~nx0 ^<archive^> ^<dictionary^>
echo.
echo   ^<archive^>     password protected .rar / .zip / .7z file
echo   ^<dictionary^>  text file with one password per line
echo                  lines starting with ";" are treated as comments
echo                  encoding ANSI/GBK, UTF-8 or UTF-16LE is autodetected
echo.
echo Example:
echo   %~nx0 secret.rar passwords.txt
echo.
echo Requires WinRAR ^(rar.exe / unrar.exe^) or 7-Zip ^(7z.exe^) installed.
exit /b 2
