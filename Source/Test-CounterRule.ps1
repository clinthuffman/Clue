param([string] $RuleName='Counter-ProcessorTimeGt90')
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

[string] $Log = $RuleName + '.log'
[int] $iSleepAfterActionsInSeconds = 600

#////////////////
#// Functions //
#//////////////

Function Test-CounterInstanceExclusion
{
    param([string] $Exclude, [string] $CounterInstanceName, [string] $Log = $Log)
    
    if ($Exclude -eq '')
    {
        Return $false
    }

    [string[]] $aExclude = $Exclude.Split(',',[StringSplitOptions]'RemoveEmptyEntries')

    foreach ($sExclude in $aExclude)
    {
        if ($CounterInstanceName -imatch $sExclude)
        {
            Return $True
        }
    }
    Return $false
}

function Measure-PerformanceCounter
{
    param([string] $RuleName = 'Testing',[string] $CounterPath, [int] $SampleInterval = 1, [int] $MaxSamples = 3, [string] $Operator, [double] $Threshold, [string] $Exclude = '', [string] $Log = $Log)

    $oCounterData = @(Get-Counter -Counter $CounterPath -SampleInterval $SampleInterval -MaxSamples $MaxSamples)
    foreach ($Sample in ($oCounterData.CounterSamples))
    {
        if ($Sample.Status -ne 0)
        {
            Write-Log ('[Test-CounterRule: Sample Status: ' + $RuleName + ']: ' + $Sample.Status) -Log $Log
            Return $false
        }
    }

    Test-Error -Err $Error -Log $Log
    If ((Test-Property -InputObject $oCounterData -Name 'Count' -Log $Log) -eq $False)
    {
        Write-Log ('[Test-CounterRule:' + $RuleName + '] No data!') -Log $Log
        Return $false
    }
    else
    {
        Write-Log ('[Test-CounterRule:' + $RuleName + '] CounterData.Count: ' + $oCounterData.Count) -Log $Log
    }
    $uCounterData = $oCounterData.GetUpperBound(0)
    $uCounterSamples = $oCounterData[0].CounterSamples.GetUpperBound(0)
    Test-Error -Err $Error -Log $Log
    For ($a = 0;$a -le $uCounterSamples;$a++)
    {
        [bool] $IsWithinThreshold = $false
        [bool] $IsThresholdBrokenAtLeastOnce = $false
        :SampleDataLoop For ($b = 0; $b -le $uCounterData;$b++)
        {
            $oTime = $oCounterData[$b]
            $oCounterInstance = $oCounterData[$b].CounterSamples[$a]

            if ((Test-CounterInstanceExclusion -Exclude $Exclude -CounterInstanceName $oCounterInstance.InstanceName -Log $Log) -eq $false)
            {
                Write-Log ($oCounterInstance.Path + ', CookedValue: ' + $oCounterInstance.CookedValue) -Log $Log
                switch ($Operator)
                {
                    'gt'
                    {
                        If (($oCounterInstance.CookedValue) -gt $Threshold)
                        {$IsThresholdBrokenAtLeastOnce = $true} else {$IsWithinThreshold = $true;Break SampleDataLoop;}
                    }
                    'ge'
                    {
                        If (($oCounterInstance.CookedValue) -ge $Threshold) 
                        {$IsThresholdBrokenAtLeastOnce = $true} else {$IsWithinThreshold = $true;Break SampleDataLoop;}
                    }
                    'lt'
                    {
                        If (($oCounterInstance.CookedValue) -lt $Threshold)
                        {$IsThresholdBrokenAtLeastOnce = $true} else {$IsWithinThreshold = $true;Break SampleDataLoop;}
                    }
                    'le'
                    {
                        If (($oCounterInstance.CookedValue) -le $Threshold)
                        {$IsThresholdBrokenAtLeastOnce = $true} else {$IsWithinThreshold = $true;Break SampleDataLoop;}
                    }
                    'eq'
                    {
                        If (($oCounterInstance.CookedValue) -eq $Threshold)
                        {$IsThresholdBrokenAtLeastOnce = $true} else {$IsWithinThreshold = $true;Break SampleDataLoop;}
                    }
                    default
                    {
                        If (($oCounterInstance.CookedValue) -gt $Threshold)
                        {$IsThresholdBrokenAtLeastOnce = $true} else {$IsWithinThreshold = $true;Break SampleDataLoop;}
                    }
    	        }
                Test-Error -Err $Error -Log $Log
            }
            else
            {
                #// Write-Log ('Counter instance is excluded!') -Log $Log
            }
        }

        if (($IsThresholdBrokenAtLeastOnce -eq $true) -and ($IsWithinThreshold -eq $false))
        {
            $sCounterName = ($oCounterData[0].CounterSamples[$a]).Path
            Write-Log ($sCounterName + ' <= Exceeded the threshold') -Log $Log
            Return $true
        }
    }
    Return $False
}

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
Write-Log ('[Test-CounterRule:' + $RuleName + '] Started') -Log $Log

#//////////////////////
#// Open config.xml //
#////////////////////

[xml] $XmlDoc = OpenConfigXml -Log $Log
Test-Error -Err $Error -Log $Log
if (Test-Property -InputObject $XmlDoc -Name 'Configuration' -Log $Log)
{
    [System.Xml.XmlElement] $XmlConfig = $XmlDoc.Configuration
}

$InstallationDirectory = $XmlConfig.InstallationDirectory
$InstallationDirectory = [System.Environment]::ExpandEnvironmentVariables($InstallationDirectory)
$OutputDirectory = $XmlConfig.OutputDirectory
$OutputDirectory = [System.Environment]::ExpandEnvironmentVariables($OutputDirectory)
$UploadNetworkShare = $XmlConfig.UploadNetworkShare
$EmailReportTo = $XmlConfig.EmailReportTo
$WptFolderPath = $XmlConfig.WptFolderPath
$CollectionLevel = $XmlConfig.CollectionLevel

$XmlRuleNode = Get-MatchingNodeByAttribute -XmlConfig $XmlConfig -NodeName 'Rule' -Attribute 'Name' -Value $RuleName -Log $Log
Test-Error -Err $Error -Log $Log

if ((Test-XmlEnabled -XmlNode $XmlRuleNode -Log $Log) -eq $false)
{
    Exit;
}

#// CounterPath
[string] $CounterPath = Get-XmlAttribute -XmlNode $XmlRuleNode -Name 'CounterPath' -Log $Log
Test-Error -Err $Error -Log $Log

#// Exclude
[string] $Exclude = Get-XmlAttribute -XmlNode $XmlRuleNode -Name 'Exclude' -Log $Log
Test-Error -Err $Error -Log $Log

#// SampleInterval
[string] $Temp = Get-XmlAttribute -XmlNode $XmlRuleNode -Name 'SampleInterval' -Log $Log
if (Test-Numeric -Value $Temp -Log $Log) {[int] $SampleInterval = $Temp} else {[int] $SampleInterval = -1}
Test-Error -Err $Error -Log $Log

#// MaxSamples
[string] $Temp = Get-XmlAttribute -XmlNode $XmlRuleNode -Name 'MaxSamples' -Log $Log
if (Test-Numeric -Value $Temp -Log $Log) {[int] $MaxSamples = $Temp} else {Write-Log ('[Test-CounterRule:' + $RuleName + '] MaxSamples is not found or not numeric.') -Log $Log;Exit;}
Test-Error -Err $Error -Log $Log

#// Operator
[string] $Operator = Get-XmlAttribute -XmlNode $XmlRuleNode -Name 'Operator' -Log $Log
#if (($Operator -ne 'gt') -and ($Operator -ne 'lt')) {Write-Log ('[Test-CounterRule:' + $RuleName + '] Operator is not found or greater than or less than sign.') -Log $Log;Exit;}
switch ($Operator)
{
    'gt' {}
    'ge' {}
    'lt' {}
    'le' {}
    'eq' {}
    default {Write-Log ('[Test-CounterRule:' + $RuleName + '] Operator is not found or greater than or less than sign.') -Log $Log;Exit;}
}
Test-Error -Err $Error -Log $Log

#// Threshold
[string] $Temp = Get-XmlAttribute -XmlNode $XmlRuleNode -Name 'Threshold' -Log $Log
if (Test-Numeric -Value $Temp -Log $Log) {[double] $Threshold = $Temp} else {Write-Log ('[Test-CounterRule:' + $RuleName + '] Threshold is not found or not numeric.') -Log $Log;Exit;}
Test-Error -Err $Error -Log $Log

#// OnStart actions
[string] $OnStartActions = Get-XmlAttribute -XmlNode $XmlRuleNode -Name 'OnStartActions' -Log $Log
Test-Error -Err $Error -Log $Log

#// OnEndActions actions
[string] $OnEndActions = Get-XmlAttribute -XmlNode $XmlRuleNode -Name 'OnEndActions' -Log $Log
Test-Error -Err $Error -Log $Log

#// MaxTraceTimeInSeconds
[int] $Temp = Get-XmlAttribute -XmlNode $XmlRuleNode -Name 'MaxTraceTimeInSeconds' -Log $Log
if (Test-Numeric -Value $Temp -Log $Log) {[int] $MaxTraceTimeInSeconds = $Temp} else {Write-Log ('[Test-CounterRule:' + $RuleName + '] MaxTraceTimeInSeconds is not found or not numeric.') -Log $Log;Exit;}
Test-Error -Err $Error -Log $Log

#// RunLimit
[int] $Ran = 0
[int] $RunLimit = 3
[int] $Temp = Get-XmlAttribute -XmlNode $XmlRuleNode -Name 'RunLimit' -Log $Log
if (Test-Numeric -Value $Temp -Log $Log) {[int] $RunLimit = $Temp} else {Write-Log ('[Test-CounterRule:' + $RuleName + '] RunLimit is not found or not numeric.') -Log $Log;Exit;}
Test-Error -Err $Error -Log $Log

#// Code
if (Test-Property -InputObject $XmlRuleNode -Name 'CODE' -Log $Log)
{
    $oDataCollector = New-Object pscustomobject
    Add-Member -InputObject $oDataCollector -MemberType NoteProperty -Name 'Name' -Value ''
    Add-Member -InputObject $oDataCollector -MemberType NoteProperty -Name 'CounterPath' -Value ''
    Add-Member -InputObject $oDataCollector -MemberType NoteProperty -Name 'Exclude' -Value ''
    Add-Member -InputObject $oDataCollector -MemberType NoteProperty -Name 'SampleInterval' -Value '1'
    Add-Member -InputObject $oDataCollector -MemberType NoteProperty -Name 'MaxSamples' -Value '3'
    Add-Member -InputObject $oDataCollector -MemberType NoteProperty -Name 'Operator' -Value 'gt'
    Add-Member -InputObject $oDataCollector -MemberType NoteProperty -Name 'Threshold' -Value ''
    Add-Member -InputObject $oDataCollector -MemberType NoteProperty -Name 'OnStartActions' -Value ''
    Add-Member -InputObject $oDataCollector -MemberType NoteProperty -Name 'OnEndActions' -Value ''
    Add-Member -InputObject $oDataCollector -MemberType NoteProperty -Name 'Code' -Value ''

    if ((Test-Property -InputObject $XmlRuleNode -Name 'Name' -Log $Log) -eq $True)           {$oDataCollector.Name           = $XmlRuleNode.Name}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'CounterPath' -Log $Log) -eq $True)    {$oDataCollector.CounterPath    = $XmlRuleNode.CounterPath}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'Exclude' -Log $Log) -eq $True)        {$oDataCollector.Exclude        = $XmlRuleNode.Exclude}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'SampleInterval' -Log $Log) -eq $True) {$oDataCollector.SampleInterval = $XmlRuleNode.SampleInterval}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'MaxSamples' -Log $Log) -eq $True)     {$oDataCollector.MaxSamples     = $XmlRuleNode.MaxSamples}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'Operator' -Log $Log) -eq $True)       {$oDataCollector.Operator       = $XmlRuleNode.Operator}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'Threshold' -Log $Log) -eq $True)      {$oDataCollector.Threshold      = $XmlRuleNode.Threshold}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'OnStartActions' -Log $Log) -eq $True) {$oDataCollector.OnStartActions = $XmlRuleNode.OnStartActions}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'OnEndActions' -Log $Log) -eq $True)   {$oDataCollector.OnEndActions   = $XmlRuleNode.OnEndActions}

    $oDataCollector.Code = $XmlRuleNode.CODE.get_innertext()
    $oDataCollector = Invoke-CounterRuleCode -DataCollector $oDataCollector -Log $Log

    $XmlRuleNode.Name = $oDataCollector.Name
    $XmlRuleNode.CounterPath = $oDataCollector.CounterPath
    $XmlRuleNode.Exclude = $oDataCollector.Exclude
    $XmlRuleNode.SampleInterval = $oDataCollector.SampleInterval
    $XmlRuleNode.MaxSamples = $oDataCollector.MaxSamples
    $XmlRuleNode.Operator = $oDataCollector.Operator
    $XmlRuleNode.Threshold = $oDataCollector.Threshold
    $XmlRuleNode.OnStartActions = $oDataCollector.OnStartActions
    $XmlRuleNode.OnEndActions = $oDataCollector.OnEndActions
    [bool] $IsDone = $false
    [int] $i = 0
    Do
    {
        $Error.Clear()
        $XmlDoc.Save('.\config.xml')
        if ($Error.Count -eq 0)
        {
            Write-Log ('Changes saved to config.xml.') -Log $Log
            $IsDone = $true
        }
        else
        {
            if ($i -ge 10) {$IsDone = $true;Write-Log ('config.xml save timeout reached!') -Log $Log} else {$i++}
            Start-Sleep -Seconds 1
        }
    } Until ($IsDone -eq $true)
    
}

$CollectionLevel = Get-CollectionLevelFromRegistry

[string] $Temp = Get-XmlAttribute -XmlNode $XmlRuleNode -Name 'Threshold' -Log $Log
if (Test-Numeric -Value $Temp -Log $Log) {[double] $Threshold = $Temp} else {Write-Log ('[Test-CounterRule:' + $RuleName + '] Threshold is not found or not numeric.') -Log $Log;Exit;}
Test-Error -Err $Error -Log $Log

Write-Log ('[Test-CounterRule] Start-TruncateLog') -Log $Log
Start-TruncateLog -FilePath $Log -Log $Log
Test-Error -Err $Error -Log $Log
Write-Log ('[Test-CounterRule] Start-TruncateLog...Done!') -Log $Log
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
$OutputDirectory = [System.Environment]::ExpandEnvironmentVariables($OutputDirectory)
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
[int] $CollectionLevel = 1
$CollectionLevel = Get-CollectionLevelFromRegistry
Write-Log ('CollectionLevel: ' + $CollectionLevel) -Log $Log

Write-Log ('Starting infinite loop...') -Log $Log
Do
{
    [bool] $IsThresholdBroken = $false
    $IsThresholdBroken = Measure-PerformanceCounter -RuleName $RuleName -CounterPath $CounterPath -SampleInterval $SampleInterval -MaxSamples $MaxSamples -Operator $Operator -Threshold $Threshold -Exclude $Exclude -Log $Log

    if (($IsThresholdBroken -eq $True) -and ($IsCollecting -eq $false))
    {
        if ($Ran -ge $RunLimit)
        {
            Write-Log ('///////////////////') -Log $Log
            Write-Log ('// RunLimit Hit //') -Log $Log
            Write-Log ('/////////////////') -Log $Log
            Write-Log ('Ran: ' + $Ran + ' / RunLimit: ' + $RunLimit)
            Write-Log 'Runlimit hit! Disabling this task.' -Log $Log
            Disable-ScheduledTask -TaskName $RuleName -Log $Log
            Write-Log ('!!! Stopping this task !!!')
            Stop-Ps2ScheduledTask -TaskName $RuleName -Log $Log
        }
        else
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
                Write-Log ('[Invoke-Actions] Update-Ran: ' + $RuleName) -Log $Log
                $Ran = $Ran + 1
                #Update-Ran -XmlConfig $XmlConfig -RuleName $RuleName
                Test-Error -Err $Error -Log $Log
            }
            else
            {
                Write-Log ('[Invoke-Rule:' + $RuleName + '] OnStartActions is blank.') -Log $Log
            }
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
            Write-Log ('Sleeping after Invoke Actions...')
            Start-Sleep -Seconds $iSleepAfterActionsInSeconds
            Write-Log ('Done sleeping.')            
        }
        else
        {
            Write-Log ('[Invoke-Rule:' + $RuleName + '] OnEndActions is blank.') -Log $Log
        }
        $IsTimeoutReached = $false
    }

    [int] $RandomMinutes = Get-Random -Minimum 100 -Maximum 200
    if ((New-TimeSpan -Start $dtLastLogTruncate -End (Get-Date)).TotalMinutes -gt $RandomMinutes)
    {
        Write-Log ('[Test-CounterRule] Start-TruncateLog') -Log $Log
        Start-TruncateLog -FilePath $Log -Log $Log
        Test-Error -Err $Error -Log $Log
        [datetime] $dtLastLogTruncate = (Get-Date)
        Write-Log ('[Test-CounterRule] Start-TruncateLog...Done!') -Log $Log
    }

    Start-Sleep -Seconds 1
} Until ($false -eq $true)
Write-Log ('[/Test-CounterRule:' + $RuleName + ']') -Log $Log