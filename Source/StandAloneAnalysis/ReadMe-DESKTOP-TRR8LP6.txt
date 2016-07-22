1. Move the ICU data to a network share or folder.
2. Make sure you have the Windows Performance Toolkit installed to the default location.
3. Make sure you have Powershell execution policy set to Unrestricted.
4. Open an admin Powershell and run each script:
	.\01_CompressIcuFolders.ps1 -Path \\server\ICU
	.\02_MultiIcuDataAnalysis.ps1 -Path \\server\ICU
	.\03_ReportGenerator.ps1 -Path \\server\ICU
An html report should be generated in the local folder.