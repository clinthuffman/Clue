@setlocal enableextensions
@cd /d "%~dp0"
Powershell.exe -Version 2 -ExecutionPolicy ByPass -File MultiIcuDataAnalysis.ps1 -Path "%1"