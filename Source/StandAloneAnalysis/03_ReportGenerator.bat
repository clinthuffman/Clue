@setlocal enableextensions
@cd /d "%~dp0"
Powershell.exe -Version 2 -ExecutionPolicy ByPass -File ReportGenerator.ps1 -Path "%1"