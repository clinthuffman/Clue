@setlocal enableextensions
@cd /d %~dp0
mkdir %temp%\ClueSetup
robocopy %~dp0 %temp%\ClueSetup /S
Powershell.exe -ExecutionPolicy ByPass -NoProfile -File %temp%\ClueSetup\_setup.ps1 -IsSilentInstallation true
rmdir /S /Q %temp%\ClueSetup