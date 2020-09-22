param([string] $Force = 'false')
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

$Error.Clear()
Remove-Module * -Force
Import-Module .\Modules\General.psm1 -Force
Import-Module .\Modules\Xml.psm1 -Force
Import-Module .\Modules\FileSystem.psm1 -Force
Import-Module .\Modules\TaskScheduler.psm1 -Force

[string] $Log = '.\Test-UserInitiated.log'

[bool] $Force = [System.Convert]::ToBoolean($Force)
Write-Log ('[Test-UserInitiated] Start') -Log $Log
[string] $sTextFilePath = $(Get-Content env:PUBLIC) + '\Documents\ClueUserInitiated.txt'
Write-Log ('[Test-UserInitiated] sTextFilePath: ' + $sTextFilePath) -Log $Log

if ($Force -eq $true)
{
    Write-Log ('[Test-UserInitiated] Forced!') -Log $Log
    Start-Ps2ScheduledTask -ScheduledTaskFolderPath '\Microsoft\Windows\Clue' -TaskName 'Invoke-Rule' -Arguments '-RuleName UserInitiated' -Log $Log
    Test-Error -Err $Error -Log $Log
    Exit;
}

[string] $DesktopBatchFile = $(Get-Content env:PUBLIC) + '\Desktop\ClueUserInitiated.bat'
Write-Log ('Desktop batch file: ' + $DesktopBatchFile) -Log $Log
$null = New-Item -Path $DesktopBatchFile -Force -ErrorAction SilentlyContinue
Add-content -Path $DesktopBatchFile -value ('@echo off') -Encoding Ascii
Add-content -Path $DesktopBatchFile -value ('echo UserInitiated >> ' + $sTextFilePath) -Encoding Ascii
Add-content -Path $DesktopBatchFile -value ('echo =========== USER INITIATED ===================') -Encoding Ascii
Add-content -Path $DesktopBatchFile -value ('echo This may take a minute or two...') -Encoding Ascii
Add-content -Path $DesktopBatchFile -value ('echo You may close this command prompt at any time.') -Encoding Ascii
Add-content -Path $DesktopBatchFile -value ('echo ==============================================') -Encoding Ascii
Add-content -Path $DesktopBatchFile -value ('pause') -Encoding Ascii

[bool] $IsModified = $false

#///////////
#// Main //
#/////////

Start-TruncateLog -FilePath $Log -Log $Log
[datetime] $dtLastLogTruncate = (Get-Date)

New-Item -Path $sTextFilePath -ItemType File
'' > $sTextFilePath
Test-Error -Err $Error -Log $Log
Write-Log ('[Test-UserInitiated] Cleared the ClueUserInitiated.txt file.') -Log $Log
Write-Log ('[Test-UserInitiated] Starting infinite loop.') -Log $Log

#// OnStart actions
[string] $OnStartActions = Get-XmlAttribute -XmlNode $XmlRuleNode -Name 'OnStartActions' -Log $Log
Test-Error -Err $Error -Log $Log

#// OnEndActions actions
[string] $OnEndActions = Get-XmlAttribute -XmlNode $XmlRuleNode -Name 'OnEndActions' -Log $Log
Test-Error -Err $Error -Log $Log

#// MaxTraceTimeInSeconds
[int] $Temp = Get-XmlAttribute -XmlNode $XmlRuleNode -Name 'MaxTraceTimeInSeconds' -Log $Log
if (Test-Numeric -Value $Temp -Log $Log) {[int] $MaxTraceTimeInSeconds = $Temp} else {Write-Log ('[Test-UserInitiated:' + $RuleName + '] MaxTraceTimeInSeconds is not found or not numeric.') -Log $Log;Exit;}
Test-Error -Err $Error -Log $Log

$CollectionLevel = 3

Do
{
    if ((Test-Path -Path $sTextFilePath) -eq $false)
    {
        '' > $sTextFilePath
        Write-Log ('[Test-UserInitiated] UserInitiated file created: ' + $sTextFilePath) -Log $Log
        Test-Error -Err $Error -Log $Log
    }

    if (Test-Path -Path $sTextFilePath)
    {
        if ((Get-Content -Path $sTextFilePath) -ne '')
        {
            Write-Log ('CollectionLevel: ' + $CollectionLevel.ToString())
            Write-Log 'Running OnstartActions...' -Log $Log
            Write-Log ('[Invoke-Rule:' + $RuleName + '] Invoke-Actions: ' + $OnStartActions) -Log $Log
            $TimeStamp = "$(Get-Date -format yyyyMMdd-HHmmss)"
            Write-Log ('[Invoke-Actions] TimeStamp: ' + $TimeStamp) -Log $Log
            $IncidentOutputFolder = Get-IncidentFolderPath -TimeStamp $TimeStamp -RuleName $RuleName -OutputDirectory $OutputDirectory
            Write-Log ('[Invoke-Actions] IncidentOutputFolder: ' + $IncidentOutputFolder) -Log $Log
            if ((New-DirectoryWithConfirm -DirectoryPath $IncidentOutputFolder -Log $Log) -eq $false)
            {
                Test-Error -Err $Error -Log $Log
                Write-Log ('[Invoke-Actions] Unable to create: ' + $IncidentOutputFolder) -Log $Log
                Exit;
            }
            New-DataCollectionInProgress -IncidentOutputFolder $IncidentOutputFolder
            Write-Log ('[Invoke-Actions] CollectionLevel before Invoke-Actions: ' + $CollectionLevel) -Log $Log
            Invoke-Actions -XmlConfig $XmlConfig -WptFolderPath $WptFolderPath -RuleName $RuleName -Actions $OnStartActions -IncidentOutputFolder $IncidentOutputFolder -CollectionLevel $CollectionLevel -Log $Log
            Test-Error -Err $Error -Log $Log
            $IsTimeoutReached = $false
            $dtTraceStartTime = (Get-date)
            Write-Log 'Running OnstartActions...Done!' -Log $Log
            Write-Log ('[Invoke-Actions] Update-Ran: ' + $RuleName) -Log $Log
            $Ran = $Ran + 1
            #Update-Ran -XmlConfig $XmlConfig -RuleName $RuleName
            Test-Error -Err $Error -Log $Log

            <#
            Write-Log ('[Test-UserInitiated] Start-Ps2ScheduledTask: Start') -Log $Log
            Start-Ps2ScheduledTask -ScheduledTaskFolderPath '\Microsoft\Windows\Clue' -TaskName 'Invoke-Rule' -Arguments '-RuleName Test-UserInitiated' -Log $Log
            Write-Log ('[Test-UserInitiated] Start-Ps2ScheduledTask: End') -Log $Log
            Test-Error -Err $Error -Log $Log
            '' > $sTextFilePath
            Test-Error -Err $Error -Log $Log
            #>

        }
    }

    [int] $RandomMinutes = Get-Random -Minimum 100 -Maximum 200
    if ((New-TimeSpan -Start $dtLastLogTruncate -End (Get-Date)).TotalMinutes -gt $RandomMinutes)
    {
        Write-Log ('[Start-TruncateLog]') -Log $Log
        Start-TruncateLog -FilePath $Log
        [datetime] $dtLastLogTruncate = (Get-Date)
    }

    Start-Sleep -Seconds 3
} until ($true -eq $false)