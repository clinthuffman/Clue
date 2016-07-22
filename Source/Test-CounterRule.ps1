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

[string] $Log = '.\' + $RuleName + '.log'

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
if (($Operator -ne 'gt') -and ($Operator -ne 'lt')) {Write-Log ('[Test-CounterRule:' + $RuleName + '] Operator is not found or greater than or less than sign.') -Log $Log;Exit;}
Test-Error -Err $Error -Log $Log

#// Threshold
[string] $Temp = Get-XmlAttribute -XmlNode $XmlRuleNode -Name 'Threshold' -Log $Log
if (Test-Numeric -Value $Temp -Log $Log) {[double] $Threshold = $Temp} else {Write-Log ('[Test-CounterRule:' + $RuleName + '] Threshold is not found or not numeric.') -Log $Log;Exit;}
Test-Error -Err $Error -Log $Log

#// Actions
[string] $Actions = Get-XmlAttribute -XmlNode $XmlRuleNode -Name 'Actions' -Log $Log
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
    Add-Member -InputObject $oDataCollector -MemberType NoteProperty -Name 'Actions' -Value ''
    Add-Member -InputObject $oDataCollector -MemberType NoteProperty -Name 'Code' -Value ''

    if ((Test-Property -InputObject $XmlRuleNode -Name 'Name' -Log $Log) -eq $True)           {$oDataCollector.Name           = $XmlRuleNode.Name}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'CounterPath' -Log $Log) -eq $True)    {$oDataCollector.CounterPath    = $XmlRuleNode.CounterPath}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'Exclude' -Log $Log) -eq $True)        {$oDataCollector.Exclude        = $XmlRuleNode.Exclude}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'SampleInterval' -Log $Log) -eq $True) {$oDataCollector.SampleInterval = $XmlRuleNode.SampleInterval}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'MaxSamples' -Log $Log) -eq $True)     {$oDataCollector.MaxSamples     = $XmlRuleNode.MaxSamples}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'Operator' -Log $Log) -eq $True)       {$oDataCollector.Operator       = $XmlRuleNode.Operator}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'Threshold' -Log $Log) -eq $True)      {$oDataCollector.Threshold      = $XmlRuleNode.Threshold}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'Actions' -Log $Log) -eq $True)        {$oDataCollector.Actions        = $XmlRuleNode.Actions}

    $oDataCollector.Code = $XmlRuleNode.CODE.get_innertext()
    $oDataCollector = Invoke-CounterRuleCode -DataCollector $oDataCollector -Log $Log

    $XmlRuleNode.Name = $oDataCollector.Name
    $XmlRuleNode.CounterPath = $oDataCollector.CounterPath
    $XmlRuleNode.Exclude = $oDataCollector.Exclude
    $XmlRuleNode.SampleInterval = $oDataCollector.SampleInterval
    $XmlRuleNode.MaxSamples = $oDataCollector.MaxSamples
    $XmlRuleNode.Operator = $oDataCollector.Operator
    $XmlRuleNode.Threshold = $oDataCollector.Threshold
    $XmlRuleNode.Actions = $oDataCollector.Actions    
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

[string] $Temp = Get-XmlAttribute -XmlNode $XmlRuleNode -Name 'Threshold' -Log $Log
if (Test-Numeric -Value $Temp -Log $Log) {[double] $Threshold = $Temp} else {Write-Log ('[Test-CounterRule:' + $RuleName + '] Threshold is not found or not numeric.') -Log $Log;Exit;}
Test-Error -Err $Error -Log $Log

Write-Log ('[Test-CounterRule] Start-TruncateLog') -Log $Log
Start-TruncateLog -FilePath $Log -Log $Log
Test-Error -Err $Error -Log $Log
Write-Log ('[Test-CounterRule] Start-TruncateLog...Done!') -Log $Log
[datetime] $dtLastLogTruncate = (Get-Date)

Write-Log ('Starting infinite loop...') -Log $Log
Do
{
    $oCounterData = @(Get-Counter -Counter $CounterPath -SampleInterval $SampleInterval -MaxSamples $MaxSamples)
    Test-Error -Err $Error -Log $Log

    If ((Test-Property -InputObject $oCounterData -Name 'Count' -Log $Log) -eq $False)
    {
        Write-Log ('[Test-CounterRule:' + $RuleName + '] No data!') -Log $Log
        Break;
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
        [bool] $DidAnySampleNotBreakTheThreshold = $false
        [bool] $IsThresholdBrokenAtLeastOnce = $false
        :SampleDataLoop For ($b = 0; $b -le $uCounterData;$b++)
        {
            $oTime = $oCounterData[$b]
            $oCounterInstance = $oCounterData[$b].CounterSamples[$a]

            Write-Log ($oCounterInstance.Path + ', CookedValue: ' + $oCounterInstance.CookedValue) -Log $Log
            Test-Error -Err $Error -Log $Log

            if ((Test-CounterInstanceExclusion -Exclude $Exclude -CounterInstanceName $oCounterInstance.InstanceName -Log $Log) -eq $false)
            {
                switch ($Operator)
                {
                    'gt'
                    {
                        If (($oCounterInstance.CookedValue) -gt $Threshold) 
                        {$IsThresholdBrokenAtLeastOnce = $True} Else {$DidAnySampleNotBreakTheThreshold = $true;Break SampleDataLoop;}
                    }
                    'ge'
                    {
                        If (($oCounterInstance.CookedValue) -ge $Threshold) 
                        {$IsThresholdBrokenAtLeastOnce = $True} Else {$DidAnySampleNotBreakTheThreshold = $true;Break SampleDataLoop;}
                    }
                    'lt'
                    {
                        If (($oCounterInstance.CookedValue) -lt $Threshold)
                        {$IsThresholdBrokenAtLeastOnce = $True} Else {$DidAnySampleNotBreakTheThreshold = $true;Break SampleDataLoop;}
                    }
                    'le'
                    {
                        If (($oCounterInstance.CookedValue) -le $Threshold)
                        {$IsThresholdBrokenAtLeastOnce = $True} Else {$DidAnySampleNotBreakTheThreshold = $true;Break SampleDataLoop;}
                    }
                    default
                    {
                        If (($oCounterInstance.CookedValue) -gt $Threshold)
                        {$IsThresholdBrokenAtLeastOnce = $True} Else {$DidAnySampleNotBreakTheThreshold = $true;Break SampleDataLoop;}
                    }
    	        }
                Test-Error -Err $Error -Log $Log
            }
            else
            {
                Write-Log ('Counter instance is excluded!') -Log $Log
                $DidAnySampleNotBreakTheThreshold = $true
            }
        }

        [bool] $IsActionNeeded = $false

        If ($DidAnySampleNotBreakTheThreshold -eq $False) 
        {
            $IsActionNeeded = $True
        }

        If ($IsActionNeeded -eq $True)
        {
            Write-Log '###############' -Log $Log
            For ($b = 0; $b -le $uCounterData;$b++)
            {
                Write-Log ('[Test-CounterRule:' + $RuleName + '] [' + (($oCounterData[$b]).Timestamp) + '] ' + (($oCounterData[$b].CounterSamples[$a]).Path) + ': ' + (($oCounterData[$b].CounterSamples[$a]).CookedValue)) -Log $Log
            }
            Write-Log 'ActionNeeded!!!' -Log $Log
            Write-Log '###############' -Log $Log
            [string] $Arguments = "-RuleName $RuleName"

            if (Test-RunLimit -XmlConfig $XmlConfig -RuleName $Rulename -Log $Log)
            {
                Write-Log 'Runlimit hit! No action.' -Log $Log
            }
            else
            {
                Write-Log 'Running Invoke-Rule...' -Log $Log
                Start-Ps2ScheduledTask -ScheduledTaskFolderPath '\Microsoft\Windows\Clue' -TaskName 'Invoke-Rule' -Arguments $Arguments -Log $Log
                Write-Log 'Running Invoke-Rule...Done!' -Log $Log
                Test-Error -Err $Error -Log $Log
                Write-Log ('Running Update-Ran...') -Log $Log
                Update-Ran -XmlConfig $XmlConfig -Actions $Actions -Log $Log
                Write-Log ('Running Update-Ran...Done') -Log $Log
                Write-Log ('Sleeping...') -Log $Log
                Start-Sleep -Seconds 300
                Write-Log ('Sleeping...Done!') -Log $Log
            }
        }
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