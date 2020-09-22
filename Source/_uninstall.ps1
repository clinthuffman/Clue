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

#////////////////
#// Functions //
#//////////////

Function Write-Log
{
    param($Output)
    #// Writes to the log file.
    $TimeStamp = "$(Get-Date -format yyyyMMdd-HHmmss)"

    if ($Output -eq $null) {Add-content $Log -value ('[' + $TimeStamp + '] NULL') -Encoding Unicode;Return}
    switch ($Output.GetType().FullName)
    {
        'System.String'                {Add-content -Path $Log -value ('[' + $TimeStamp + '] ' + $Output) -Encoding Unicode}
        default                        {Add-content -Path $Log -value ('[' + $TimeStamp + ']') -Encoding Unicode; $Output >> $Log}
    }
}

Function Test-Error
{
    param($Err)
    #// Tests if an error condition exists and writes it to the log.
    if ($Err.Count -gt 0)
    {
        Write-Log ('[Test-Error] Error(s) found: ' + $Err.Count)
        Write-Log ($Err)
        $Err.Clear()
    }
}

Function Test-Property
{
	param ([Parameter(Position=0,Mandatory=1)]$InputObject,[Parameter(Position=1,Mandatory=1)]$Name)
	[Bool](Get-Member -InputObject $InputObject -Name $Name -MemberType *Property)
}

Function Write-Console
{
    param([string] $sLine, [bool] $bNoNewLine = $false, [bool] $bAddDateTime = $true, [bool] $IsSilentInstallation = $false)
    Write-Log ($sLine)

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
    param([string] $sLine, [bool] $IsSilentInstallation = $false)    
    if ($IsSilentInstallation -eq $false)
    {
        Write-Console ('[PopUp] ' + $sLine)
        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
        [void] [Microsoft.VisualBasic.Interaction]::MsgBox($sLine, 0, 'Tool configuration')
    }
}

Function Set-OverallProgress
{
    param([string] $Status='')

    $global:iOverallCompletion++
    $iPercentComplete = ConvertToDataType -ValueAsDouble $(($global:iOverallCompletion / 13) * 100) -DataTypeAsString 'integer'
    If ($iPercentComplete -gt 100){$iPercentComplete = 100}
    $sComplete = "Clue installation progress: $iPercentComplete%... $Status"
    Write-Progress -activity 'Progress: ' -status $sComplete -percentcomplete $iPercentComplete -id 1;
    $global:oOverallProgress = 'Overall progress... Status: ' + "$($Status)" + ', ' + "$($sComplete)"
}

function Get-OutputDirectory
{
    param($XmlConfig)
    Write-Log ('[Get-OutputDirectory]: START')
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
                Write-Log ('UserResponse: ' + $sResponse)

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
                    Write-Log ('UserResponse: ' + $sResponse)
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

        $IsDone = New-DirectoryWithConfirm -DirectoryPath $sResponse
        if ($IsDone -eq $true)
        {
            $OutputDirectory = $sResponse
            Write-Log ("`t" + 'Output folder "' + $OutputDirectory + '" created or already exists.')
        }
        else
        {
            Write-Console ('!!!ERROR!!! Unable to create output directory ' + $sResponse + '"')
            Break;
        }
    }
    Write-Log ("`t" + 'OutputDirectory: "' + $OutputDirectory + '"')
    Write-Log ('[Get-OutputDirectory]: END')
    Return $OutputDirectory
}

function Get-UploadNetworkShare
{
    param($XmlConfig)
    Write-Log ('[Get-UploadNetworkShare]: START')
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
            Write-Log ('UserResponse: ' + $sResponse)
        }
        
        if ($sResponse -ne '')
        {
            $UploadNetworkShare = $sResponse
        }
    }
    Write-Log ("`t" + 'UploadNetworkShare: "' + $global:UploadNetworkShare + '"')
    Write-Log ('[Get-UploadNetworkShare]: END')
    Return $UploadNetworkShare
}

Function Get-EmailForReport
{
    param($XmlConfig)
    Write-Log ('[Get-EmailForReport]: START')
    $EmailReportTo = Get-XmlAttribute -XmlNode $XmlConfig -Name 'EmailReportTo'
    if ($EmailReportTo -eq '')
    {
        $sResponse = ''
        if ($IsSilentInstallation -eq $false)
        {
            Write-Console '[PopUp] Waiting for user response...' -bNoNewLine $true -bAddDateTime $false
            $sResponse = [Microsoft.VisualBasic.Interaction]::InputBox('What email addresses (separated by semi-colon (;)) do you want the report sent to?', 'Clue tool - Email report to...', '')
            Write-Log ('UserResponse: ' + $sResponse)
        }
        
        if ($sResponse -ne '')
        {
            $EmailReportTo = $sResponse
        }
    }
    Write-Log ("`t" + 'EmailReportTo: "' + $EmailReportTo + '"')
    Write-Log ('[Get-EmailForReport]: END')
    Return $EmailReportTo
}

Function Invoke-MyCmd
{
    param([string] $Cmd)
    Write-Log ($Cmd)
    $Output = Invoke-Expression -Command $Cmd
    Write-Log ($Output)
    Test-Error -Err $Error
}

Function Get-TaskSchedulerService
{
    try
    {
        $oTaskSchedulerService = New-Object -ComObject 'Schedule.Service'
        $oTaskSchedulerService.Connect()
        Return $oTaskSchedulerService
    }
    catch
    {
        Return $null
    }
}

Function Get-Ps2ScheduledTaskFolder
{
    param([string] $Path)

    $oTaskSchedulerService = Get-TaskSchedulerService

    if ($oTaskSchedulerService -eq $null)
    {
        Return $null
    }

    try
    {
        $oTaskSchedulerFolder = $oTaskSchedulerService.GetFolder($Path)
    }
    catch
    {

    }

    if ($oTaskSchedulerFolder -ne $null)
    {
        Return $oTaskSchedulerFolder
    }
    
    if ($Path.Contains('\'))
    {
        $aPath = $Path.Split('\',[StringSplitOptions]'RemoveEmptyEntries')
    }
    else
    {
        Return $null
    }
    
    [int] $iCount = 0
    For ($i = 0; $i -le $aPath.GetUpperBound(0); $i++)
    {
        [string] $sBuildPath = $sBuildPath + '\' + $aPath[$i]

        try
        {
            Write-Log ('sBuildPath: ' + $sBuildPath)
            $oTaskSchedulerFolder = $oTaskSchedulerService.GetFolder($sBuildPath)
        }
        catch
        {
            try
            {
                #// Get the parent path and create it.
                if ($oTaskSchedulerParentFolder -ne $null)
                {
                    $oTaskSchedulerFolder = $oTaskSchedulerParentFolder.CreateFolder($aPath[$i])
                }
                else
                {
                    Return $null
                }
            }
            catch
            {
                Return $null
            }
        }
        finally
        {
            $oTaskSchedulerParentFolder = $oTaskSchedulerFolder
        }
        $iCount++
    }

    if ($iCount -eq $aPath.Count)
    {
        Return $oTaskSchedulerFolder
    }
    else
    {
        Return $null
    }
}

Function Get-WorkingDirectoryFromTask
{
    param([string] $ScheduledTaskFolderPath = '\Microsoft\Windows\Clue', [string] $TaskName = 'Invoke-Rule')
    $oTaskFolder = Get-Ps2ScheduledTaskFolder -Path $ScheduledTaskFolderPath
    if ($oTaskFolder -eq $null)
    {
        Return ''
    }
    try {$oTask = $oTaskFolder.GetTask($TaskName)} catch {}
    if ($oTask -eq $null)
    {
        Return ''
    }
    foreach ($oAction in $oTask.Definition.Actions)
    {
        [string] $WorkingDirectory = $oAction.WorkingDirectory
        if ($WorkingDirectory.Length -gt 0)
        {
            Return $WorkingDirectory
        }
    }
    Return ''
}

Function Remove-AllScheduledTasksInToolFolder
{
    $oTaskSchedulerService = Get-TaskSchedulerService
    Test-Error -Err $Error

    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get task folder "\Microsoft\Windows\Clue": START')
    $oTaskSchedulerFolder = $null
    $oParentTaskSchedulerFolder = $oTaskSchedulerService.GetFolder('\Microsoft\Windows')
    $oFolders = $oParentTaskSchedulerFolder.GetFolders(0)
    :FolderLoop foreach ($oFolder in $oFolders)
    {
        if ($oFolder.Name -eq 'Clue')
        {
            $oTaskSchedulerFolder = $oFolder
            Break FolderLoop;
        }        
    }

    if ($oTaskSchedulerFolder -eq $null)
    {
        Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get task folder "\Microsoft\Windows\Clue": END')
        Return $null
    }

    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get task folder "\Microsoft\Windows\Clue": END')

    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get tasks of "\Microsoft\Windows\Clue": START')
    $oTasks = $oTaskSchedulerFolder.GetTasks(0)
    Test-Error -Err $Error
    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get tasks of "\Microsoft\Windows\Clue": END')

    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete tasks of "\Microsoft\Windows\Clue": START')
    ForEach ($oTask in $oTasks)
    {
        $oTask.Stop(0)
        Test-Error -Err $Error
        Start-Sleep -Seconds 2
        Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete task "\Microsoft\Windows\Clue\' + $oTask.Name + '": START')
        $oTaskSchedulerFolder.DeleteTask($oTask.Name, 0)
        Test-Error -Err $Error
        Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete task "\Microsoft\Windows\Clue\' + $oTask.Name + '": END')
        Write-Console '.' -bNoNewLine $true -bAddDateTime $false
    }
    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete tasks of "\Microsoft\Windows\Clue": END')
    
    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get task folder "\Microsoft\Windows\Clue": START')
    $oTaskSchedulerFolder = $oTaskSchedulerService.GetFolder('\Microsoft\Windows')
    Test-Error -Err $Error
    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get task folder "\Microsoft\Windows\Clue": END')

    if ($oTaskSchedulerFolder -is [System.__ComObject])
    {
        Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete "\Microsoft\Windows\Clue": START')
        $oTaskSchedulerFolder.DeleteFolder('Clue', 0)
        Test-Error -Err $Error
        Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete "\Microsoft\Windows\Clue": END')
    }
}

function Remove-InstallationFolder
{
    param([string] $FolderPath)
    if ((Test-Path -Path $FolderPath) -eq $true)
    {
        $oCollectionOfFilesAndFolders = Get-ChildItem $FolderPath
        foreach ($oFileOrFolder in $oCollectionOfFilesAndFolders)
        {
            If ($oFileOrFolder -is [System.IO.FileInfo])
            {
                Remove-Item -Path $oFileOrFolder.FullName -Force
            }
        }
        $oCollectionOfFilesAndFolders = Get-ChildItem $FolderPath
        foreach ($oFileOrFolder in $oCollectionOfFilesAndFolders)
        {
            If ($oFileOrFolder -is [System.IO.DirectoryInfo])
            {
                Remove-InstallationFolder -FolderPath $oFileOrFolder.FullName
            }
        }
        Remove-Item -Path $FolderPath -Recurse -Force
    }
}

#///////////
#// Main //
#/////////

New-Item -Path $Log -ItemType File -Force | Out-Null
Write-Log ('[Setup]: Start')
$Error.Clear()

Write-Console (Get-Location).Path
$InvocationFolderPath = ($SCRIPT:MyInvocation.MyCommand.Path) -replace '\\_uninstall.ps1',''
Write-Console ('InvocationFolderPath: ' + $InvocationFolderPath)

[bool] $IsSilentInstallation = [System.Convert]::ToBoolean($IsSilentInstallation)
[string] $global:ToolName = 'Clue'
[string] $global:ScheduledTaskFolderPath = "\Microsoft\Windows\$global:ToolName"

Write-Log ('IsSilentInstallation = ' + $IsSilentInstallation.ToString())
Write-Console '//////////////////////////'
Write-Console '// Clue tool uninstall //'
Write-Console '////////////////////////'
Write-Console ''

#// Run OnUninstall rule
#.\Invoke-Rule.ps1 -RuleName 'OnUninstall' -Force $true

$InstallationDirectory = Get-WorkingDirectoryFromTask
Test-Error -Err $Error

Write-Console ''
Write-Console '/////////////////////////////'
Write-Console '// Delete scheduled tasks //'
Write-Console '////////////////////////////'
Write-Console ''
Write-Console 'Deleting scheduled tasks...' -bNoNewLine $true
Remove-AllScheduledTasksInToolFolder
Test-Error -Err $Error
Write-Console 'Done!' -bAddDateTime $false

[string] $sTextFilePath = $(Get-Content env:PUBLIC) + '\Documents\ClueUserInitiated.txt'
if (Test-Path -Path $sTextFilePath)
{
    Remove-Item -Path $sTextFilePath -Force -ErrorAction SilentlyContinue
}

Write-Console ''
Write-Console '////////////////////'
Write-Console '// PAL Collector //'
Write-Console '//////////////////'
Write-Console ''
if (Test-Path -Path $InstallationDirectory\PalCollector\_uninstall.ps1)
{
    & $InstallationDirectory\PalCollector\_uninstall.ps1 -Log $Log
    Test-Error -Err $Error
}

Write-Console '//////////////////////////'
Write-Console '// Installation folder //'
Write-Console '////////////////////////'
if ($InstallationDirectory -eq '')
{
    $InstallationDirectory = 'C:\ProgramData\Clue'
}

#// Remove the ClueUserInitiatedDataCollector.bat file
$xUserInitiatedPath = ($env:PUBLIC + '\Desktop\ClueUserInitiatedDataCollector.bat')
Remove-Item -Path $xUserInitiatedPath -ErrorAction SilentlyContinue

Write-Log ('[Remove-InstallationFolder]: Start')
Remove-InstallationFolder -FolderPath $InstallationDirectory
Test-Error -Err $Error
Write-Log ('[Remove-InstallationFolder]: End')

Set-OverallProgress -Status 'Scheduled tasks...'
Write-Console ''
Write-Console '//////////////////'
Write-Console '// WMI Tracing //'
Write-Console '/////////////////'
Write-Console ''
Write-Console 'Disabling WMI Tracing...' -bNoNewLine $true
[string] $sCmd = 'Wevtutil.exe sl Microsoft-Windows-WMI-Activity/Trace /e:false /q:true'
$oOutput = Invoke-Expression -Command $sCmd
Write-Log ($oOutput) -Log $Log
Test-Error -Err $Error -Log $Log
Write-Console 'Done!' -bAddDateTime $false

#// Finalize setup.
Write-Console '[PopUp] Please acknowledge uninstall has finished...' -bNoNewLine $true
[string] $FinalMessage = ('Uninstall is finished! For details see ' + $Log)
Write-Console ''
Write-Console '////////////'
Write-Console '// DONE! //'
Write-Console '//////////'
Write-Console ''
Write-MsgBox $FinalMessage
Write-Console 'Done!' -bAddDateTime $false
Write-Log ('[Setup]: End')