The Clue Stand Alone analysis attempts to analyze the data in a Clue related zip file (incident zip) and rename the zip file with the most likely cause of the incident. This analysis is by industry leaders in Windows performance analysis to help solve performance problems.

Installation of the Windows Performance Toolkit (WPT) is required. 
https://msdn.microsoft.com/library/windows/hardware/dn927310%28v=vs.85%29.aspx

In order to run the Stand Alone analysis, the Powershell execution policy must be ByPass'd or set to unrestricted.
To get the current execution policy, open a Powershell session and run the following command:
	Get-ExecutionPolicy
	
To set the execution policy to unrestricted, open a Powershell session with administrator rights and run the following command:
	Set-ExecutionPolicy -ExecutionPolicy Unrestricted

To temporarily ByPass the execution policy for this script, then open a command line (cmd.exe) with administrator rights and run the following command:
	Powershell -ExecutionPolicy ByPass -File Measure-IncidentFolder.ps1 -Path AbsolutFolderPathToIncidentZips

Otherwise, open a Powershell session and run the following command:
	.\Measure-IncidentFolder.ps1 -Path AbsolutFolderPathToIncidentZips

Measure-IncidentFolder.ps1 will take a few minutes to process each zip file and then append to each zip file name the results.

After the zip files have been renamed by Measure-IncidentFolder.ps1, run ReportGenerator.ps1 to produce an HTML report.
	.\ReportGeneratory.ps1 -Path AbsolutFolderPathToIncidentZips

If you wish to rename all of the zip files to their original names (remove the findings in the name), then run ResetZipFiles.ps1.
	.\ResetZipFiles.ps1 -Path AbsolutFolderPathToIncidentZips

If there are any problems with this code, then please let me know by emailing me at clinth@microsoft.com. Thank you.
