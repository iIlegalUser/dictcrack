' DictCrack GUI launcher - starts PowerShell with NO console window at all
' Double-click THIS file for a completely silent start.
' (The .bat launcher also works but briefly flashes a cmd window)
' Optional arguments pass through:  dictcrack-gui.vbs -Arch x.rar -Dict d.txt
Set fso = CreateObject("Scripting.FileSystemObject")
baseDir = fso.GetParentFolderName(WScript.ScriptFullName)
cmdLine = "powershell -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File """ & baseDir & "\dictcrack-gui.ps1"""
For Each arg In WScript.Arguments
    cmdLine = cmdLine & " """ & arg & """"
Next
CreateObject("WScript.Shell").Run cmdLine, 0, False
