@setlocal enableextensions
@cd /d %~dp0
mkdir %temp%\ClueSetup
robocopy %~dp0 %temp%\ClueSetup /S
Powershell.exe -ExecutionPolicy ByPass -NoProfile -File %temp%\ClueSetup\_Uninstall.ps1
del %public%\Desktop\InternetExplorerIsHung.bat
rmdir /S /Q %temp%\ClueSetup
