param([string] $RuleName='UserInitiated')
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

Remove-Module * -Force
Import-Module .\Modules\General.psm1 -Force
Import-Module .\Modules\TaskScheduler.psm1 -Force
Import-Module .\Modules\Xml.psm1 -Force
Import-Module .\Modules\FileSystem.psm1 -Force

[string] $Log = '.\' + $RuleName + '.log'

#////////////////
#// Functions //
#//////////////

function Get-CollectionLevelFromRegistry
{
    [int] $iCollectionLevel = 1
    $IsFound = Test-Path -Path 'HKLM:\SOFTWARE\Clue'
    If ($IsFound -eq $true)
    {
        $RegCollectionLevel = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Clue').CollectionLevel
        $iCollectionLevel = $RegCollectionLevel
        if (($iCollectionLevel -ge 0) -and ($iCollectionLevel -le 3))
        {
            Return $iCollectionLevel
        }
    }
}

#///////////
#// Main //
#/////////

$Error.Clear()
Write-Log ('[Test-UserInitiated:' + $RuleName + '] Started') -Log $Log

#//////////////////////
#// Open config.xml //
#////////////////////

[xml] $XmlDoc = OpenConfigXml -Log $Log
Test-Error -Err $Error -Log $Log
if (Test-Property -InputObject $XmlDoc -Name 'Configuration' -Log $Log)
{
    [System.Xml.XmlElement] $XmlConfig = $XmlDoc.Configuration
}

$XmlRuleNode = Get-MatchingNodeByAttribute -XmlConfig $XmlConfig -NodeName 'Rule' -Attribute 'Name' -Value $RuleName -Log $Log
Test-Error -Err $Error -Log $Log

if ((Test-XmlEnabled -XmlNode $XmlRuleNode -Log $Log) -eq $false)
{
    Exit;
}

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

$CollectionLevel = Get-CollectionLevelFromRegistry

Write-Log ('[Test-UserInitiated] Start-TruncateLog') -Log $Log
Start-TruncateLog -FilePath $Log -Log $Log
Test-Error -Err $Error -Log $Log
Write-Log ('[Test-UserInitiated] Start-TruncateLog...Done!') -Log $Log
[datetime] $dtLastLogTruncate = (Get-Date)

#////////////////////////////////////
#// Search and confirm WPT folder //
#//////////////////////////////////

[string] $WptFolderPath = ''
if (Test-Property -InputObject $XmlConfig -Name 'WptFolderPath' -Log $Log)
{
    [string] $WptFolderPath = Get-WptFolderPath -SuggestedPath $XmlConfig.WptFolderPath -Log $Log
}
else
{
    [string] $WptFolderPath = Get-WptFolderPath -Log $Log
}
Test-Error -Err $Error -Log $Log
if ($WptFolderPath -eq '')
{
    Write-Log ('[Invoke-Rule:' + $RuleName + '] Unable to find WptFolderPath. Unable to continue.') -Log $Log
}

#//////////////////////////
#// Get OutputDirectory //
#////////////////////////

[string] $OutputDirectory = ''
[string] $OutputDirectory = Get-XmlAttribute -XmlNode $XmlConfig -Name 'OutputDirectory' -Log $Log
Test-Error -Err $Error -Log $Log

if ($OutputDirectory -ne '')
{
    if ((New-DirectoryWithConfirm -DirectoryPath $OutputDirectory -Log $Log) -eq $false)
    {
        Test-Error -Err $Error -Log $Log
        Write-Log ('[Invoke-Rule:' + $RuleName + '] Unable to create: ' + $OutputDirectory) -Log $Log
        Exit;
    }
}

[datetime] $dtTraceStartTime = (Get-date)
[bool] $IsCollecting = $false
[bool] $IsTimeoutReached = $false
[string] $IncidentOutputFolder = ''
[int] $CollectionLevel = 3
$CollectionLevel = Get-CollectionLevelFromRegistry
Write-Log ('CollectionLevel: ' + $CollectionLevel) -Log $Log

Write-Log ('[Test-UserInitiated] Start') -Log $Log
[string] $sTextFilePath = $(Get-Content env:PUBLIC) + '\Documents\ClueUserInitiated.txt'
Write-Log ('[Test-UserInitiated] sTextFilePath: ' + $sTextFilePath) -Log $Log

New-Item -Path $sTextFilePath -ItemType File
'' > $sTextFilePath
Test-Error -Err $Error -Log $Log
Write-Log ('[Test-UserInitiated] Cleared the ClueUserInitiated.txt file.') -Log $Log

[string] $DesktopBatchFile = $(Get-Content env:PUBLIC) + '\Desktop\ClueUserInitiated.bat'
Write-Log ('Desktop batch file: ' + $DesktopBatchFile) -Log $Log
$null = New-Item -Path $DesktopBatchFile -Force -ErrorAction SilentlyContinue
Add-content -Path $DesktopBatchFile -value ('@echo off') -Encoding Ascii
Add-content -Path $DesktopBatchFile -value ('echo UserInitiated >> ' + $sTextFilePath) -Encoding Ascii
Add-content -Path $DesktopBatchFile -value ('echo =========== USER INITIATED ================================') -Encoding Ascii
Add-content -Path $DesktopBatchFile -value ('echo    Data collection is in progress for the next 60 seconds.') -Encoding Ascii
Add-content -Path $DesktopBatchFile -value ('echo    Try to reproduce the problem at this time.') -Encoding Ascii
Add-content -Path $DesktopBatchFile -value ('echo    Press any key to close this command prompt.') -Encoding Ascii
Add-content -Path $DesktopBatchFile -value ('echo ===========================================================') -Encoding Ascii
Add-content -Path $DesktopBatchFile -value ('pause') -Encoding Ascii


[bool] $IsModified = $false
[bool] $IsThresholdBroken = $false

Write-Log ('Starting infinite loop...') -Log $Log
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
            $IsThresholdBroken = $true
            '' > $sTextFilePath
        }
    }

    if (($IsThresholdBroken -eq $True) -and ($IsCollecting -eq $false))
    {
        $IsCollecting = $True
        Write-Log ('/////////////////////////////') -Log $Log
        Write-Log ('// Invoke OnStart Actions //') -Log $Log
        Write-Log ('///////////////////////////') -Log $Log

        if ($OnStartActions -ne '')
        {
            Write-Log ('Get-CollectionLevelFromRegistry::Start')
            $CollectionLevel = Get-CollectionLevelFromRegistry
            Write-Log ('CollectionLevel: ' + $CollectionLevel.ToString())
            Write-Log ('Get-CollectionLevelFromRegistry::End')
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
            Test-Error -Err $Error -Log $Log
        }
        else
        {
            Write-Log ('[Invoke-Rule:' + $RuleName + '] OnStartActions is blank.') -Log $Log
        }
    }

    #// Is MaxTraceTime hit?
    if ($IsCollecting -eq $True)
    {
        $TraceElapedSeconds = (New-TimeSpan -Start $dtTraceStartTime -End (Get-Date)).TotalSeconds
        if ($TraceElapedSeconds -gt $MaxTraceTimeInSeconds)
        {
            $IsTimeoutReached = $True
            Write-Log ('MaxTraceTimeInSeconds: ' + $MaxTraceTimeInSeconds.ToString())
            Write-Log ('MaxTraceTimeInSeconds reached!')
            Write-Log ('dtTraceStartTime: ' + $dtTraceStartTime.ToString())
            Write-Log ('dtCurrentTime: ' + (Get-Date).ToString())
        }
        else
        {
            $IsTimeoutReached = $false
        }
    }

    if ((($IsThresholdBroken -eq $false) -and ($IsCollecting -eq $True)) -or $IsTimeoutReached -eq $True)
    {
        Write-Log ('///////////////////////////') -Log $Log
        Write-Log ('// Invoke OnEnd Actions //') -Log $Log
        Write-Log ('/////////////////////////') -Log $Log

        if ($OnEndActions -ne '')
        {

            Write-Log ('Get-CollectionLevelFromRegistry::Start')
            $CollectionLevel = Get-CollectionLevelFromRegistry
            Write-Log ('CollectionLevel: ' + $CollectionLevel.ToString())
            Write-Log ('Get-CollectionLevelFromRegistry::End')
            Write-Log 'Running OnEndActions...' -Log $Log
            Write-Log ('[Invoke-Rule:' + $RuleName + '] Invoke-Actions: ' + $OnEndActions) -Log $Log
            Invoke-Actions -XmlConfig $XmlConfig -WptFolderPath $WptFolderPath -RuleName $RuleName -Actions $OnEndActions -IncidentOutputFolder $IncidentOutputFolder -CollectionLevel $CollectionLevel -Log $Log
            Test-Error -Err $Error -Log $Log
            $IsCollecting = $false
            Write-Log 'Running OnEndActions...Done!' -Log $Log
            Remove-DataCollectionInProgress -IncidentOutputFolder $IncidentOutputFolder
        }
        else
        {
            Write-Log ('[Invoke-Rule:' + $RuleName + '] OnEndActions is blank.') -Log $Log
        }
        $IsThresholdBroken = $false
        $IsTimeoutReached = $false

    }

    [int] $RandomMinutes = Get-Random -Minimum 100 -Maximum 200
    if ((New-TimeSpan -Start $dtLastLogTruncate -End (Get-Date)).TotalMinutes -gt $RandomMinutes)
    {
        Write-Log ('[Test-UserInitiated] Start-TruncateLog') -Log $Log
        Start-TruncateLog -FilePath $Log -Log $Log
        Test-Error -Err $Error -Log $Log
        [datetime] $dtLastLogTruncate = (Get-Date)
        Write-Log ('[Test-UserInitiated] Start-TruncateLog...Done!') -Log $Log
    }

    Start-Sleep -Seconds 1
} Until ($false -eq $true)
Write-Log ('[/Test-UserInitiated:' + $RuleName + ']') -Log $Log