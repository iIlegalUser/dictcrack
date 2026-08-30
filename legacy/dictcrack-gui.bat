@echo off
rem  launch the DictCrack GUI (PowerShell WinForms)
rem  NOTE: double-clicking this .bat briefly flashes a cmd window;
rem  use dictcrack-gui.vbs instead for a completely silent start
rem  -STA is required for clipboard support
rem  optional args pass through:  dictcrack-gui.bat -Arch x.rar -Dict d.txt
powershell -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0dictcrack-gui.ps1" %*
