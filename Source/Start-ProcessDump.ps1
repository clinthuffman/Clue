param([string] $ProcessName = 'iexplore')
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

[string] $ProcessName = $ProcessName -replace '.exe',''
[string] $ProcessName = $ProcessName -replace "`'",''
[string] $ProcessName = $ProcessName -replace '"',''
[string] $ProcessName = $ProcessName -replace '"',''
[string] $Log = '.\Start-ProcessDump-' + $ProcessName + '.log'

Start-TruncateLog -FilePath $Log -Log $Log
[datetime] $dtLastLogTruncate = (Get-Date)

$error.Clear()
Write-Log ('Start Log') -Log $Log
Write-Log ('Written by Clint Huffman (clinth@microsoft.com)') -Log $Log

Write-Log ('ProcessName: ' + $ProcessName) -Log $Log

[string] $sTextFilePath = $(Get-Content env:PUBLIC) + '\Documents\ClueUserInitiatedDump-' + $ProcessName +  '.txt'
Write-Log ('sTextFilePath: ' + $sTextFilePath) -Log $Log
'' | Out-File -FilePath $sTextFilePath -Encoding ascii

Write-Log ('Opening config.xml...') -Log $Log
[xml] $XmlDoc = OpenConfigXml -Log $Log
Test-Error -Err $Error -Log $Log
if (Test-Property -InputObject $XmlDoc -Name 'Configuration' -Log $Log)
{
    [System.Xml.XmlElement] $XmlConfig = $XmlDoc.Configuration
}
Write-Log ('Opening config.xml...Done!') -Log $Log

[string] $RuleName = 'Start-ProcessDump'
Write-Log ('Getting rule' + $RuleName + '...') -Log $Log
$XmlRuleNode = Get-MatchingNodeByAttribute -XmlConfig $XmlConfig -NodeName 'Rule' -Attribute 'Name' -Value $RuleName -Log $Log
Test-Error -Err $Error -Log $Log
Write-Log ('Getting rule' + $RuleName + '...Done!') -Log $Log

Write-Log ('Getting WptFolderPath...') -Log $Log
[string] $WptFolderPath = ''
if (Test-Property -InputObject $XmlConfig -Name 'WptFolderPath' -Log $Log)
{
    [string] $WptFolderPath = Get-WptFolderPath -SuggestedPath $XmlConfig.WptFolderPath -Log $Log
}
else
{
    [string] $WptFolderPath = Get-WptFolderPath -Log $Log
}
Write-Log ('WptFolderPath: ' + $WptFolderPath) -Log $Log
Write-Log ('Getting WptFolderPath...Done!') -Log $Log

Write-Log ('Getting OutputDirectory...') -Log $Log
[string] $OutputDirectory = ''
if (Test-Property -InputObject $XmlConfig -Name 'OutputDirectory' -Log $Log)
{
    [string] $OutputDirectory = $XmlConfig.OutputDirectory
}

if ($OutputDirectory -eq '')
{
    $OutputDirectory = 'C:\ClueOutput'
}
Write-Log ('OutputDirectory: ' + $OutputDirectory) -Log $Log
Write-Log ('Getting OutputDirectory...Done!') -Log $Log

Write-Log ('Process enumeration test (all)...') -Log $Log
$oProcesses = @(Get-Process)
Test-Error -Err $error -Log $Log
Write-Log ('Count: ' + $oProcesses.Count) -Log $Log
Write-Log ('Process enumeration test (all)...Done!') -Log $Log

Write-Log ('Process enumeration test (by ProcessName)...') -Log $Log
Write-Log ('ProcessName: ' + $ProcessName) -Log $Log
$oProcesses = @((Get-Process) | Where {$_.Name -eq $ProcessName})
Test-Error -Err $error -Log $Log
Write-Log ('Count: ' + $oProcesses.Count) -Log $Log
Write-Log ('Process enumeration test (by ProcessName)...Done!') -Log $Log

[string] $WprTraceMark = 'Dumping ' + $ProcessName + ' processes...'

[string] $DesktopBatchFile = $(Get-Content env:PUBLIC) + '\Desktop\Dump-' + $ProcessName + '.bat'
Write-Log ('Desktop batch file: ' + $DesktopBatchFile) -Log $Log
Add-content -Path $DesktopBatchFile -value ('@echo off') -Encoding Ascii
Add-content -Path $DesktopBatchFile -value ('echo UserInitiated >> ' + $sTextFilePath) -Encoding Ascii
Add-content -Path $DesktopBatchFile -value ('echo =========== USER INITIATED ===================') -Encoding Ascii
Add-content -Path $DesktopBatchFile -value ('echo Dumping processes... This may take a minute or two...') -Encoding Ascii
Add-content -Path $DesktopBatchFile -value ('echo You may close this command prompt at any time.') -Encoding Ascii
Add-content -Path $DesktopBatchFile -value ('echo ==============================================') -Encoding Ascii
Add-content -Path $DesktopBatchFile -value ('pause') -Encoding Ascii

Write-Log ('Starting loop...') -Log $Log
Do
{
    $oProcesses = @((Get-Process) | Where {$_.Name -eq $ProcessName})
    Test-Error -Err $error -Log $Log

    if ((Test-Path -Path $sTextFilePath) -eq $false)
    {
        Write-Log ('!!! Text file doesnt exist !!!') -Log $Log
        '' | Out-File -FilePath $sTextFilePath -Encoding ascii
        Write-Log ('UserInitiated file created: ' + $sTextFilePath) -Log $Log
    }

    if (Test-Path -Path $sTextFilePath)
    {
        if ((Get-Content -Path $sTextFilePath) -ne '')
        {
            Test-Error -Err $error -Log $Log

            #// Create incident folder
            Write-Log ('Creating incident folder...') -Log $Log
            $TimeStamp = "$(Get-Date -format yyyyMMdd-HHmmss)"
            Write-Log ('TimeStamp: ' + $TimeStamp) -Log $Log
            Write-Log ('OutputDirectory: ' + $OutputDirectory) -Log $Log
            [string] $RuleName = $ProcessName + '-Dump'
            Write-Log ('RuleName: ' + $RuleName) -Log $Log
            $IncidentOutputFolder = Get-IncidentFolderPath -TimeStamp $TimeStamp -RuleName $RuleName -OutputDirectory $OutputDirectory -Log $Log
            Write-Log ('IncidentOutputFolder: ' + $IncidentOutputFolder) -Log $Log
            if ((New-DirectoryWithConfirm -DirectoryPath $IncidentOutputFolder -Log $Log) -eq $false)
            {
                Test-Error -Err $Error -Log $Log
                Write-Log ('Unable to create: ' + $IncidentOutputFolder) -Log $Log
                Write-Log ('Creating incident folder...Done!') -Log $Log
            }
            else
            {
                Write-Log ('Creating incident folder...Done!') -Log $Log

                #//////////////////
                #// Take action //
                #////////////////

                Write-Log ('Creating data collection in progress text file...') -Log $Log
                New-DataCollectionInProgress -IncidentOutputFolder $IncidentOutputFolder -Log $Log
                Write-Log ('Creating data collection in progress text file...Done!') -Log $Log

                #// Dump processes
                
                Write-Log ('Adding WprTraceMark ...') -Log $Log
                Write-Log ('WprTraceMark: ' + $WprTraceMark) -Log $Log
                Add-WprTraceMarkerCH -Name $WprTraceMark -Log $Log
                Write-Log ('Adding WprTraceMark...Done!') -Log $Log

                Write-Log 'Dumping processes...' -Log $Log
                Write-Log ('ProcessName: ' + $ProcessName) -Log $Log
                Write-Log ('OutputDirectory: ' + $OutputDirectory) -Log $Log
                Start-ProcDumpOnProcessNameCH -ProcessName $ProcessName -OutputFolder $IncidentOutputFolder -Log $Log
                Write-Log 'Dumping processes...Done!' -Log $Log

                Write-Log ('Adding WprTraceMark ...') -Log $Log
                Write-Log ('WprTraceMark: ' + $WprTraceMark + 'Done!') -Log $Log
                Add-WprTraceMarkerCH -Name ($WprTraceMark + 'Done!') -Log $Log
                Write-Log ('Adding WprTraceMark...Done!') -Log $Log

                Write-Log ('Removing data collection in progress text file...') -Log $Log
                Remove-DataCollectionInProgress -IncidentOutputFolder $IncidentOutputFolder -Log $Log
                Write-Log ('Removing data collection in progress text file...Done!') -Log $Log

                #// Tasklist
                Write-Log ('Getting tasklist...') -Log $Log
                [string] $sCmd = 'Tasklist /svc /FO CSV > "' + $IncidentOutputFolder + '\Tasklist.csv"'
                Write-Log ($sCmd) -Log $Log
                $oOutput = Invoke-Expression -Command $sCmd    
                Write-Log ($oOutput) -Log $Log
                Write-Log ('Getting tasklist...Done!') -Log $Log

                #// Tool config
                Write-Log ('Getting config file...') -Log $Log
                Copy-Item -Path '.\config.xml' -Destination $IncidentOutputFolder -ErrorAction SilentlyContinue
                Write-Log ('Getting config file...Done!') -Log $Log

                #// Tool logs
                Write-Log ('Getting tool logs...') -Log $Log
                Copy-Item -Path 'C:\ProgramData\Clue\*.log' -Destination $IncidentOutputFolder -ErrorAction SilentlyContinue
                Write-Log ('Getting tool logs...Done!') -Log $Log
            }

            Write-Log ('Wiping user initated text file...') -Log $Log
            '' | Out-File -FilePath $sTextFilePath -Encoding ascii
            Write-Log ('Wiping user initated text file...Done!') -Log $Log
        }
    }

    [int] $RandomMinutes = Get-Random -Minimum 100 -Maximum 200
    if ((New-TimeSpan -Start $dtLastLogTruncate -End (Get-Date)).TotalMinutes -gt $RandomMinutes)
    {
        Write-Log ('Truncate log...') -Log $Log
        Write-Log ('RandomMinutes: ' + $RandomMinutes) -Log $Log
        Start-TruncateLog -FilePath $Log
        [datetime] $dtLastLogTruncate = (Get-Date)
        Write-Log ('dtLastLogTruncate: ' + $dtLastLogTruncate) -Log $Log
        Write-Log ('Truncate log...Done!') -Log $Log
    }
    Start-Sleep -Seconds 3
} Until ($false -eq $true)
