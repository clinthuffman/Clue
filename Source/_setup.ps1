param([string] $IsSilentInstallation = 'false')
# This code is Copyright (c) 2016 Microsoft Corporation.
#
# All rights reserved.
#
# THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, 
#  INCLUDING BUT NOT LIMITED To THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
#  PARTICULAR PURPOSE.'
#
# IN NO EVENT SHALL MICROSOFT AND/OR ITS RESPECTIVE SUPPLIERS BE LIABLE FOR ANY SPECIAL, INDIRECT OR 
#  CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
#  WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION 
#  WITH THE USE OR PERFORMANCE OF THIS CODE OR INFORMATION.

[string] $Log = ([System.Environment]::ExpandEnvironmentVariables('%TEMP%') + '\ClueSetup.log')
[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null

Remove-Module * -Force
Import-Module .\Modules\General.psm1 -Force
Import-Module .\Modules\Xml.psm1 -Force
Import-Module .\Modules\FileSystem.psm1 -Force
Import-Module .\Modules\TaskScheduler.psm1 -Force

#////////////////
#// Functions //
#//////////////

Function Write-Console
{
    param([string] $sLine, [bool] $bNoNewLine = $false, [bool] $bAddDateTime = $true, [string] $Log = $Log)
    Write-Log ($sLine) -Log $Log

    if ($IsSilentInstallation -eq $false)
    {
        $TimeStamp = "$(Get-Date -format yyyyMMdd-HHmmss)"
        if ($bAddDateTime -eq $true)
        {
            [string] $sOutput = '[' + $TimeStamp + '] ' + $sLine
        }
        else
        {
            [string] $sOutput = $sLine
        }

        if ($bNoNewLine -eq $false)
        {
            Write-Host $sOutput
        }
        else
        {
            Write-Host $sOutput -NoNewline
        }        
    }    
}

Function Write-MsgBox
{
    param([string] $sLine, [string] $Log = $Log)    
    if ($IsSilentInstallation -eq $false)
    {
        Write-Console ('[PopUp] ' + $sLine)
        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
        [void] [Microsoft.VisualBasic.Interaction]::MsgBox($sLine, 0, 'Tool configuration')
    }
}

Function Set-OverallProgress
{
    param([string] $Status='', [string] $Log = $Log)

    $global:iOverallCompletion++
    $iPercentComplete = ConvertToDataType $(($global:iOverallCompletion / 13) * 100) 'integer'
    If ($iPercentComplete -gt 100){$iPercentComplete = 100}
    $sComplete = "Clue installation progress: $iPercentComplete%... $Status"
    Write-Progress -activity 'Progress: ' -status $sComplete -percentcomplete $iPercentComplete -id 1;
    $global:oOverallProgress = 'Overall progress... Status: ' + "$($Status)" + ', ' + "$($sComplete)"
}

function Get-OutputDirectory
{
    param($XmlConfig, [string] $Log = $Log)
    Write-Log ('[Get-OutputDirectory]: START') -Log $Log
    [bool] $IsDone = $false
    [string] $OutputDirectory = Get-XmlAttribute -XmlNode $XmlConfig -Name 'OutputDirectory'
    if ($OutputDirectory -eq '')
    {
        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
        $sResponse = ''
        if ($IsSilentInstallation -eq $false)
        {
            [int] $Yes = 6; [int] $No = 7;

            while ($sResponse -eq '')
            {
                Write-Console '[PopUp] Waiting for user response...' -bNoNewLine $true -bAddDateTime $false
                $sResponse = [Microsoft.VisualBasic.Interaction]::InputBox('This is where output files will go. Several gigabytes might be necessary.', 'Clue tool - Output Directory', 'C:\ClueOutput')
                Write-Log ('UserResponse: ' + $sResponse) -Log $Log

                if ($sResponse -eq '')
                {
                    $iYesNo = [Microsoft.VisualBasic.Interaction]::MsgBox('Are you sure you?', 4, 'Clue tool - Cancel Installation')
                }

                if ($iYesNo -eq $Yes)
                {
                    Exit;
                }

                while ($sResponse.Contains(' '))
                {
                    $sResponse = $sResponse.Replace(' ','')
                    $sResponse = [Microsoft.VisualBasic.Interaction]::InputBox('Please provide a folder path without spaces. This is due to how the Task Scheduler handles parameters.', 'Clue tool - Output Directory - Try Again', $sResponse)
                    Write-Log ('UserResponse: ' + $sResponse) -Log $Log
                }
            }
        }

        if ($sResponse -eq '')
        {
            Write-Console ('!!!ERROR!!! Unable to continue without an output directory. Setup has failed.')
            if ($IsSilentInstallation -eq 'false')
            {
                Write-MsgBox ('Unable to continue without an output directory. Setup has failed!')
            }
            Break;
        }

        $IsDone = New-DirectoryWithConfirm -DirectoryPath $sResponse -Log $Log
        if ($IsDone -eq $true)
        {
            $OutputDirectory = $sResponse
            Write-Log ("`t" + 'Output folder "' + $OutputDirectory + '" created or already exists.') -Log $Log
        }
        else
        {
            Write-Console ('!!!ERROR!!! Unable to create output directory ' + $sResponse + '"')
            Break;
        }
    }
    Write-Log ("`t" + 'OutputDirectory: "' + $OutputDirectory + '"') -Log $Log
    Write-Log ('[Get-OutputDirectory]: END') -Log $Log
    Return $OutputDirectory
}

function Download-SysInternalsTool
{
    param([string] $FileName, [string] $DownloadToFolderPath)
    
    $webclient = New-Object System.Net.WebClient
    [string] $FilePath = $DownloadToFolderPath + '\' + $FileName
        
    if (Test-Path -Path $FilePath)
    {
        Write-Console ($FilePath + ' is already downloaded.')
        Return $true
    }
    else
    {   
        [string] $url = 'http://live.sysinternals.com/' + $FileName
        Write-Console ('Downloading ' + $url + '...')
        $webclient.DownloadFile($url,$FilePath)
    }

    if (Test-Path -Path $FilePath)
    {
        Write-Console 'Downloaded!'
    }
    else
    {
        Write-Console 'Unable to download ' + $FileName + '. Download this SysInternals file manually from ' + $url + ' and place it in the sysint folder under the CLUE installation folder. Otherwise, the CLUE tool might not function properly.'
    }
}

function Get-UploadNetworkShare
{
    param($XmlConfig, [string] $Log = $Log)
    Write-Log ('[Get-UploadNetworkShare]: START') -Log $Log
    $UploadNetworkShare = Get-XmlAttribute -XmlNode $XmlConfig -Name 'UploadNetworkShare'
    if ($UploadNetworkShare -eq '')
    {
        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
        [int] $Yes = 6; [int] $No = 7;
        $sResponse = ''
        if ($IsSilentInstallation -eq $false)
        {
            Write-Console '[PopUp] Waiting for user response...' -bNoNewLine $true -bAddDateTime $false
            $sResponse = [Microsoft.VisualBasic.Interaction]::InputBox('This is the network share (\\server\share) where Clue will upload incident data and download updates. Grant the SYSTEM account of this computer read/write access to the network share. Leave blank if this is a stand-alone installation.', 'Clue tool - Network Share', '')
            Write-Log ('UserResponse: ' + $sResponse) -Log $Log
        }
        
        if ($sResponse -ne '')
        {
            $UploadNetworkShare = $sResponse
        }
    }
    Write-Log ("`t" + 'UploadNetworkShare: "' + $global:UploadNetworkShare + '"') -Log $Log
    Write-Log ('[Get-UploadNetworkShare]: END') -Log $Log
    Return $UploadNetworkShare
}

Function Get-EmailForReport
{
    param($XmlConfig, [string] $Log = $Log)
    Write-Log ('[Get-EmailForReport]: START') -Log $Log
    $EmailReportTo = Get-XmlAttribute -XmlNode $XmlConfig -Name 'EmailReportTo'
    if ($EmailReportTo -eq '')
    {
        $sResponse = ''
        if ($IsSilentInstallation -eq $false)
        {
            [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
            Write-Console '[PopUp] Waiting for user response...' -bNoNewLine $true -bAddDateTime $false
            $sResponse = [Microsoft.VisualBasic.Interaction]::InputBox('What email addresses (separated by semi-colon (;)) do you want the report sent to?', 'Clue tool - Email report to...', '')
            Write-Log ('UserResponse: ' + $sResponse) -Log $Log
        }
        
        if ($sResponse -ne '')
        {
            $EmailReportTo = $sResponse
        }
    }
    Write-Log ("`t" + 'EmailReportTo: "' + $EmailReportTo + '"') -Log $Log
    Write-Log ('[Get-EmailForReport]: END') -Log $Log
    Return $EmailReportTo
}

#///////////
#// Main //
#/////////
Clear-Content -Path $Log
Write-Log ('[Setup]: Start') -Log $Log
$Error.Clear()

[bool] $IsSilentInstallation = [System.Convert]::ToBoolean($IsSilentInstallation)
[string] $global:ToolName = 'Clue'
[string] $global:ScheduledTaskFolderPath = "\Microsoft\Windows\$global:ToolName"
[string] $global:SetupFolder = $PWD
[string] $global:WorkingDirectory = $PWD

[int] $global:iOverallCompletion = 0
Write-Progress -activity 'Overall progress: ' -status 'Progress: 0%' -percentcomplete 0 -id 1
Test-Error -Err $Error -Log $Log

Write-Log ('IsSilentInstallation = ' + $IsSilentInstallation.ToString()) -Log $Log
Write-Console '/////////////////////////////'
Write-Console '// Clue tool installation //'
Write-Console '///////////////////////////'
Write-Console ''
Write-Console '/////////////////////'
Write-Console '// Compatible OS? //'
Write-Console '///////////////////'
Write-Console ''

[bool] $IsOsCompatible = Test-OSCompatibility -Log $Log
Test-Error -Err $Error -Log $Log
Write-Log ('IsOsCompatible: ' + $IsOsCompatible.ToString()) -Log $Log
if ($IsOsCompatible -eq $false)
{
    Write-Log ('This software requires x86 (32-bit) or x64 (64-bit) Windows 6.1 (Windows 7 | Windows Server 2008 R2) or later.') -Log $Log
    if ($IsSilentInstallation -eq 'false')
    {
        Write-Console '[PopUp] This software requires x86 (32-bit) or x64 (64-bit) Windows 6.1 (Windows 7 | Windows Server 2008 R2) or later.'
        Write-MsgBox 'This software requires x86 (32-bit) or x64 (64-bit) Windows 6.1 (Windows 7 | Windows Server 2008 R2) or later.'
    }
    Exit;
}
Test-Error -Err $Error -Log $Log

Set-OverallProgress -Status 'Admin rights...'
Write-Console ''
Write-Console '///////////////////'
Write-Console '// Admin rights //'
Write-Console '/////////////////'
Write-Console ''

[bool] $IsElevated = Test-AdminRights -Log $Log
Test-Error -Err $Error -Log $Log
Write-Log ('IsElevated: ' + $IsElevated.ToString()) -Log $Log
if ($IsElevated -eq $false)
{
    Write-MsgBox 'Administrator rights is required. Try running setup again with Administrator rights.'
    Exit;
}

Set-OverallProgress -Status 'Windows Performance Toolkit...'
Write-Console ''
Write-Console '////////////////////////////////////////'
Write-Console '// Windows Performance Toolkit (WPT) //'
Write-Console '//////////////////////////////////////'
Write-Console ''

[string] $WptFolderPath = Get-WptFolderPath -Log $Log
Test-Error -Err $Error -Log $Log
if ($WptFolderPath -eq '')
{
    if ($IsSilentInstallation -eq $false)
    {
        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
        [string] $sMsg = 'May I install the Microsoft Windows Performance Toolkit (WPT)? It is required for this software to function. For more information, go to https://msdn.microsoft.com/library/windows/hardware/dn927310(v=vs.85).aspx'
        [string] $sYesOrNo = [Microsoft.VisualBasic.Interaction]::MsgBox($sMsg, 4, 'Clue tool')
        Write-Log ('WPT install response: ' + $sYesOrNo) -Log $Log
        if ($sYesOrNo -ne 'Yes')
        {
            Write-MsgBox 'Installation cannot continue.'
            Exit;    
        }
    }
    Install-WPT -Log $Log
    Test-Error -Err $Error -Log $Log

    [int] $TimeoutAfterXSeconds = 120
    [datetime] $StartTime = (Get-Date)
    [bool] $IsDone = $false
    [string] $WptFolderPath = ''
    Do
    {
        Write-Log ('Waiting for the Windows Performance Toolkit (WPT) to install...') -Log $Log
        Start-Sleep -Seconds 2
        [string] $WptFolderPath = Get-WptFolderPath
        Write-Log ('WptFolderPath: ' + $WptFolderPath) -Log $Log
        Test-Error -Err $Error -Log $Log
        [double] $TotalSeconds = (New-TimeSpan -Start $StartTime -End (Get-Date)).TotalSeconds
        if ($WptFolderPath -ne '') {$IsDone = $true}
        if ($TotalSeconds -gt $TimeoutAfterXSeconds) {$IsDone = $true}

    } until ($IsDone -eq $true)

    if ($WptFolderPath -eq '')
    {
        Write-Log ('Unable to get the Windows Performance Toolkit (WPT) folder path. Setup has failed!') -Log $Log
        if ($IsSilentInstallation -eq $false)
        {
            Write-MsgBox 'Unable to get the Windows Performance Toolkit (WPT) folder path. Setup has failed!'
        }
        Exit; 
    }

}

Set-OverallProgress -Status 'Delete scheduled tasks...'
Write-Console ''
Write-Console '/////////////////////////////'
Write-Console '// Delete scheduled tasks //'
Write-Console '////////////////////////////'
Write-Console ''
Write-Console 'Deleting scheduled tasks...' -bNoNewLine $true
Remove-AllScheduledTasksInToolFolder -Log $Log
Test-Error -Err $Error -Log $Log
Write-Console 'Done!' -bAddDateTime $false

Set-OverallProgress -Status 'Configuring...'
Write-Console ''
Write-Console '//////////////////////'
Write-Console '// Open Config.xml //'
Write-Console '////////////////////'
Write-Console ''

[xml] $XmlDoc = OpenConfigXml
Test-Error -Err $Error -Log $Log
if (Test-Property -InputObject $XmlDoc -Name 'Configuration')
{
    [System.Xml.XmlElement] $XmlConfig = $XmlDoc.Configuration
}
Test-Error -Err $Error -Log $Log
if ($XmlConfig -eq $null)
{
    Write-MsgBox 'Unable to get the XML configuration. Setup has failed.'
}
<#
Set-OverallProgress -Status 'Downloading Sysinternals tools...'
Write-Console ''
Write-Console '//////////////////////////////////'
Write-Console '// Download Sysinternals tools //'
Write-Console '////////////////////////////////'
Write-Console ''
[string] $DownloadFolderPath = (pwd).Path + '\sysint' 
Download-SysInternalsTool -FileName 'procdump.exe' -DownloadToFolderPath $DownloadFolderPath
#>
Set-OverallProgress -Status 'Installation folder...'
Write-Console ''
Write-Console '//////////////////////////'
Write-Console '// Installation folder //'
Write-Console '////////////////////////'
Write-Console ''
Write-Console 'Getting installation folder...' -bNoNewLine $true
$InstallationDirectory = Get-XmlAttribute -XmlNode $XmlConfig -Name 'InstallationDirectory' -Log $Log
Test-Error -Err $Error -Log $Log
if ($InstallationDirectory -eq '') {$InstallationDirectory = '%ProgramData%\Clue'}
$InstallationDirectory = [System.Environment]::ExpandEnvironmentVariables($InstallationDirectory)
Write-Console 'Done!' -bAddDateTime $false
Write-Console ("`t" + 'Installation folder: "' + $InstallationDirectory + '"')
#Remove-HandlesOnFolder -FolderPath $InstallationDirectory -Log $Log
#Test-Error -Err $Error -Log $Log
Write-Console 'Copying content to installation folder...' -bNoNewLine $true
if (Test-Path -Path $InstallationDirectory) {Remove-Item -Path $InstallationDirectory -Recurse -Force -ErrorAction SilentlyContinue}
Test-Error -Err $Error -Log $Log
Copy-Item -Path '.' -Destination $InstallationDirectory -Recurse -Force -ErrorAction SilentlyContinue
Test-Error -Err $Error -Log $Log
Write-Console 'Done!' -bAddDateTime $false
[string] $FilePathOfConfigXml = $InstallationDirectory + '\' + 'config.xml'
if (Test-Path -Path $FilePathOfConfigXml) 
{
    Write-Console ("`t" + 'Folder copy successful.')
}
else
{
    Write-Console ("`t" + 'Folder copy FAILED! See "' + $Log + '" for details.')
    Exit;
}
Write-Console ('Log: ' + $Log)
Write-Console '// Loading config.xml from installation directory //'
[xml] $XmlDoc = OpenConfigXml -XmlFilePath $FilePathOfConfigXml -Log $Log
Test-Error -Err $Error -Log $Log
if (Test-Property -InputObject $XmlDoc -Name 'Configuration' -Log $Log)
{
    [System.Xml.XmlElement] $XmlConfig = $XmlDoc.Configuration
}
Test-Error -Err $Error -Log $Log
if ($XmlConfig -eq $null)
{
    Write-MsgBox 'Unable to get the XML configuration. Setup has failed.'
    Exit;
}
[string] $global:WorkingDirectory = $InstallationDirectory
Set-Location $InstallationDirectory
Test-Error -Err $Error -Log $Log

Set-OverallProgress -Status 'Output folder...'
Write-Console ''
Write-Console '////////////////////'
Write-Console '// Output folder //'
Write-Console '//////////////////'
Write-Console ''
Write-Console 'Getting output folder...' -bNoNewLine $true
$OutputDirectory = Get-OutputDirectory -XmlConfig $XmlConfig -Log $Log
if ($OutputDirectory -eq '') {$OutputDirectory = 'C:\ClueOutput'}
Write-Console 'Done!' -bAddDateTime $false
Write-Console ("`t" + 'Output folder: "' + $OutputDirectory + '"')
Test-Error -Err $Error -Log $Log

Set-OverallProgress -Status 'Upload folder...'
Write-Console ''
Write-Console '////////////////////'
Write-Console '// Upload folder //'
Write-Console '//////////////////'
Write-Console ''
Write-Console 'Getting upload network share (optional)...' -bNoNewLine $true
$UploadNetworkShare = Get-UploadNetworkShare -XmlConfig $XmlConfig -Log $Log
Write-Console 'Done!' -bAddDateTime $false
Write-Console ("`t" + 'Upload network share: "' + $UploadNetworkShare + '"')
Test-Error -Err $Error -Log $Log
<#
Set-OverallProgress -Status 'Email address(es)...'
Write-Console ''
Write-Console '///////////////////////'
Write-Console '// Email address(es) //'
Write-Console '/////////////////////'
Write-Console ''
Write-Console '// Get email address for report //'
Write-Console 'Getting email address(es) for the end user report (optional)...' -bNoNewLine $true
$EmailReportTo = Get-EmailForReport -XmlConfig $XmlConfig -Log $Log
Write-Console 'Done!' -bAddDateTime $false
Write-Console ("`t" + 'Email report to: "' + $EmailReportTo + '"')
Test-Error -Err $Error -Log $Log
#>
Set-OverallProgress -Status 'Save changes...'
Write-Console ''
Write-Console '///////////////////'
Write-Console '// Save changes //'
Write-Console '/////////////////'
Write-Console ''
Set-XmlAttribute -XmlNode $XmlConfig -Name 'OutputDirectory' -Value $OutputDirectory -Log $Log
Test-Error -Err $Error -Log $Log
Set-XmlAttribute -XmlNode $XmlConfig -Name 'UploadNetworkShare' -Value $UploadNetworkShare -Log $Log
Test-Error -Err $Error -Log $Log
Set-XmlAttribute -XmlNode $XmlConfig -Name 'EmailReportTo' -Value $EmailReportTo -Log $Log
Test-Error -Err $Error -Log $Log
Set-XmlAttribute -XmlNode $XmlConfig -Name 'WptFolderPath' -Value $WptFolderPath -Log $Log
Test-Error -Err $Error -Log $Log
$XmlDoc.Save($FilePathOfConfigXml)
Test-Error -Err $Error -Log $Log

Set-OverallProgress -Status 'PAL collector...'
Write-Console ''
Write-Console '////////////////////'
Write-Console '// PAL Collector //'
Write-Console '//////////////////'
Write-Console ''
Write-Console 'Creating PalCollector (this may take a few minutes)...'
cd .\PalCollector
.\PalCollector.ps1 -OutputDirectory $OutputDirectory -Log $Log
cd ..
Write-Console 'Creating PalCollector (this may take a few minutes)...Done!'
Test-Error -Err $Error -Log $Log

Set-OverallProgress -Status 'Scheduled tasks...'
Write-Console ''
Write-Console '//////////////////////'
Write-Console '// Scheduled tasks //'
Write-Console '////////////////////'
Write-Console ''
Write-Console 'Creating scheduled tasks...' -bNoNewLine $true
foreach ($XmlNode in $XmlConfig.Rule)
{
    if (Test-XmlEnabled -XmlNode $XmlNode -Log $Log)
    {
        $NodeType = Get-XmlAttribute -XmlNode $XmlNode -Name 'Type' -Log $Log
        switch ($NodeType)
        {
            'Counter'
            {
                $Name = Get-XmlAttribute -XmlNode $XmlNode -Name 'Name' -Log $Log
                [string] $Arguments = '-ExecutionPolicy ByPass -File Test-CounterRule.ps1 -RuleName ' + $Name
                $IsCreated = New-Ps2ScheduledTask -ScheduledTaskFolderPath $global:ScheduledTaskFolderPath -Name $Name -Path 'powershell' -Arguments $Arguments -WorkingDirectory $global:WorkingDirectory -Description 'Performance counter data collector.' -Trigger '5' -StartImmediately $false -Log $Log
            }

            'EventLog'
            {
                $Name = Get-XmlAttribute -XmlNode $XmlNode -Name 'Name' -Log $Log
                $Description = Get-XmlAttribute -XmlNode $XmlNode -Name 'Description' -Log $Log
                $LogFile = Get-XmlAttribute -XmlNode $XmlNode -Name 'LogFile' -Log $Log
                $Source = Get-XmlAttribute -XmlNode $XmlNode -Name 'Source' -Log $Log
                $EventID = Get-XmlAttribute -XmlNode $XmlNode -Name 'EventID' -Log $Log
                $EventType = Get-XmlAttribute -XmlNode $XmlNode -Name 'EventType' -Log $Log
                [string] $Arguments = '-ExecutionPolicy ByPass -File Test-EventLogRule.ps1 -RuleName ' + $Name
                $IsCreated = New-Ps2ScheduledTask -ScheduledTaskFolderPath $global:ScheduledTaskFolderPath -Name $Name -Path 'powershell' -Arguments $Arguments -WorkingDirectory $global:WorkingDirectory -Description $Description -Trigger '5' -StartImmediately $false -Log $Log
            }

            'ScheduledTask'
            {
                [string] $Name = Get-XmlAttribute -XmlNode $XmlNode -Name 'Name' -Log $Log
                [string] $Description = Get-XmlAttribute -XmlNode $XmlNode -Name 'Description' -Log $Log
                [string] $Path = Get-XmlAttribute -XmlNode $XmlNode -Name 'Path' -Log $Log
                [string] $Arguments = Get-XmlAttribute -XmlNode $XmlNode -Name 'Arguments' -Log $Log
                [string] $Trigger = Get-XmlAttribute -XmlNode $XmlNode -Name 'Trigger' -Log $Log
                [string] $StartImmediately = Get-XmlAttribute -XmlNode $XmlNode -Name 'StartImmediately' -Log $Log
                [bool] $IsStartImmediately = [System.Convert]::ToBoolean($StartImmediately)
                $IsCreated = New-Ps2ScheduledTask -ScheduledTaskFolderPath $global:ScheduledTaskFolderPath -Name $Name -Path $Path -Arguments $Arguments -WorkingDirectory $global:WorkingDirectory -Description $Description -Trigger $Trigger -StartImmediately $IsStartImmediately -Log $Log
            }
        }
    }
    Write-Console '.' -bNoNewLine $true -bAddDateTime $false
    Test-Error -Err $Error -Log $Log
}
Write-Console 'Done!' -bAddDateTime $false

Write-Console 'Starting Invoke-OnWindowsStart...'
Start-Ps2ScheduledTask -ScheduledTaskFolderPath '\Microsoft\Windows\Clue' -TaskName 'Invoke-OnWindowsStart' -Log $Log
Write-Console 'Done!' -bAddDateTime $false

Set-Location -Path $global:SetupFolder
Test-Error -Err $Error -Log $Log

#// Disable paging executive for WPR and WPRUI
[bool] $IsPagingExecutiveDisabed = (Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -ErrorAction SilentlyContinue).DisablePagingExecutive
if ($IsPagingExecutiveDisabed -eq $False)
{
    Set-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'DisablePagingExecutive' -Value 1
    [bool] $IsPagingExecutiveDisabed = (Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -ErrorAction SilentlyContinue).DisablePagingExecutive
    if ($IsPagingExecutiveDisabed -eq $True)
    {
        if ($IsSilentInstallation -eq $false)
        {
            #Write-MsgBox -sLine 'A reboot is required. Please reboot this system at the earliest convenience' -Log $Log
        }
    }
    else
    {
        #Write-Console -sLine 'ERROR: Unable to set DisablePagingExecutive!' -Log $Log
    }
}

#// Finalize setup.
Write-Progress -activity 'Overall progress: ' -status 'Progress: 100%' -Completed -id 1
Write-Console '[PopUp] Please acknowledge installation has finished...' -bNoNewLine $true
[string] $FinalMessage = ('Installation is finished! For details see ' + $Log)
Write-Console ''
Write-Console '////////////'
Write-Console '// DONE! //'
Write-Console '//////////'
Write-Console ''
Write-MsgBox $FinalMessage
Write-Console 'Done!' -bAddDateTime $false
Write-Log ('[Setup]: End') -Log $Log