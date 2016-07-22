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

[string] $Log = ((PWD).Path + '\Setup.log')

Remove-Module * -Force
Import-Module .\Modules\General.psm1 -Force
Import-Module .\Modules\Xml.psm1 -Force
Import-Module .\Modules\FileSystem.psm1 -Force
Import-Module .\Modules\TaskScheduler.psm1 -Force

[bool] $IsSilentInstallation = [System.Convert]::ToBoolean($IsSilentInstallation)
[string] $global:ToolName = 'Clue'
[string] $global:ScheduledTaskFolderPath = "\Microsoft\Windows\$global:ToolName"
[string] $global:SetupFolder = $PWD
[string] $global:WorkingDirectory = $PWD

#////////////////
#// Functions //
#//////////////

Function Write-Console
{
    param([string] $sLine, [bool] $bNoNewLine = $false, [bool] $bAddDateTime = $true, [bool] $IsSilentInstallation = $false, [string] $Log = $Log)
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
    param([string] $sLine, [bool] $IsSilentInstallation = $false, [string] $Log = $Log)    
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
    $iPercentComplete = ConvertToDataType -ValueAsDouble $(($global:iOverallCompletion / 13) * 100) -DataTypeAsString 'integer' -Log $Log
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
    [string] $OutputDirectory = Get-XmlAttribute -XmlNode $XmlConfig -Name 'OutputDirectory' -Log $Log
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
    $EmailReportTo = Get-XmlAttribute -XmlNode $XmlConfig -Name 'EmailReportTo' -Log $Log
    if ($EmailReportTo -eq '')
    {
        $sResponse = ''
        if ($IsSilentInstallation -eq $false)
        {
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

Function Invoke-MyCmd
{
    param([string] $Cmd, [string] $Log = $Log)
    Write-Log ($Cmd) -Log $Log
    $Output = Invoke-Expression -Command $Cmd
    Write-Log ($Output) -Log $Log
    Test-Error -Err $Error -Log $Log
}

#///////////
#// Main //
#/////////

$Error.Clear()
Write-Log ('[Setup]: Start') -Log $Log
Test-Error -Err $Error -Log $Log

Write-Log ('IsSilentInstallation = ' + $IsSilentInstallation.ToString()) -Log $Log
Write-Console '//////////////////////////'
Write-Console '// Clue tool uninstall //'
Write-Console '////////////////////////'
Write-Console ''

#// Run OnUninstall rule
.\Invoke-Rule.ps1 -RuleName 'OnUninstall' -Force $true

Remove-Module * -Force
Import-Module .\Modules\General.psm1 -Force
Import-Module .\Modules\Xml.psm1 -Force
Import-Module .\Modules\FileSystem.psm1 -Force
Import-Module .\Modules\TaskScheduler.psm1 -Force

$InstallationDirectory = Get-WorkingDirectoryFromTask -Log $Log
Test-Error -Err $Error -Log $Log

Write-Console ''
Write-Console '/////////////////////////////'
Write-Console '// Delete scheduled tasks //'
Write-Console '////////////////////////////'
Write-Console ''
Write-Console 'Deleting scheduled tasks...' -bNoNewLine $true
Remove-AllScheduledTasksInToolFolder -Log $Log
Test-Error -Err $Error -Log $Log
Write-Console 'Done!' -bAddDateTime $false

[string] $sTextFilePath = $(Get-Content env:PUBLIC) + '\Documents\ClueUserInitiated.txt'
Remove-Item -Path $sTextFilePath -Force -ErrorAction SilentlyContinue

Write-Console ''
Write-Console '////////////////////'
Write-Console '// PAL Collector //'
Write-Console '//////////////////'
Write-Console ''
if (Test-Path -Path '.\PalCollector\_uninstall.ps1')
{
    .\PalCollector\_uninstall.ps1 -Log $Log
    Test-Error -Err $Error -Log $Log
}

Write-Console '//////////////////////////'
Write-Console '// Installation folder //'
Write-Console '////////////////////////'
if ($InstallationDirectory -eq '')
{
    $InstallationDirectory = 'C:\ProgramData\Clue'
}

Write-Log ('[Remove-InstallationFolder]: Start') -Log $Log
Remove-InstallationFolder -FolderPath $InstallationDirectory -Log $Log
Test-Error -Err $Error -Log $Log
Write-Log ('[Remove-InstallationFolder]: End') -Log $Log

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
Write-Log ('[Setup]: End') -Log $Log