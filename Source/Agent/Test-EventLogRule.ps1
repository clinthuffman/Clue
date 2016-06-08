param([string] $RuleName='EventLog-Test')
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

[string] $Log = '.\' + $RuleName + '.log'

#////////////////
#// Functions //
#//////////////

Function Test-CounterInstanceExclusion
{
    param([string] $Exclude, [string] $CounterInstanceName, [string] $Log = $Log)
    
    [string[]] $aExclude = $Exclude.Split(',')

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
Write-Log ('[Test-EventLogRule:' + $RuleName + '] Started') -Log $Log

#//////////////////////
#// Open config.xml //
#////////////////////

[xml] $XmlDoc = OpenConfigXml -Log $Log
Test-Error -Err $Error -Log $Log
if (Test-Property -InputObject $XmlDoc -Name 'Configuration' -Log $Log)
{
    [System.Xml.XmlElement] $XmlConfig = $XmlDoc.Configuration
}

if ($XmlConfig -is [System.Xml.XmlElement])
{
    Write-Log ('[Test-EventLogRule:' + $RuleName + '] XmlConfig opened.') -Log $Log
}

$XmlRuleNode = Get-MatchingNodeByAttribute -XmlConfig $XmlConfig -NodeName 'Rule' -Attribute 'Name' -Value $RuleName -Log $Log
Test-Error -Err $Error -Log $Log
Write-Log ('[Test-EventLogRule:' + $RuleName + '] XmlRule opened.') -Log $Log

if ((Test-XmlEnabled -XmlNode $XmlRuleNode -Log $Log) -eq $false)
{
    Write-Log ('[Test-EventLogRule:' + $RuleName + '] XmlRule is disabled. Exiting!') -Log $Log
    Exit;
}

if ((Test-Property -InputObject $XmlRuleNode -Name 'Name' -Log $Log) -eq $True)            {$Name            = $XmlRuleNode.Name}
if ((Test-Property -InputObject $XmlRuleNode -Name 'LogFile' -Log $Log) -eq $True)         {$LogFile         = $XmlRuleNode.LogFile}
if ((Test-Property -InputObject $XmlRuleNode -Name 'Source' -Log $Log) -eq $True)          {$Source          = $XmlRuleNode.Source}
if ((Test-Property -InputObject $XmlRuleNode -Name 'EventID' -Log $Log) -eq $True)         {$EventID         = $XmlRuleNode.EventID}
if ((Test-Property -InputObject $XmlRuleNode -Name 'EventType' -Log $Log) -eq $True)       {$EventType       = $XmlRuleNode.EventType}
if ((Test-Property -InputObject $XmlRuleNode -Name 'StringInMessage' -Log $Log) -eq $True) {$StringInMessage = $XmlRuleNode.StringInMessage}

Write-Log ('[Test-EventLogRule:' + $RuleName + '] Name: ' + $Name + ', LogFile: ' + $LogFile + ', Source: ' + $Source + ', EventID: ' + $EventID + ', EventType: ' + $EventType + ', StringInMessage: ' + $StringInMessage) -Log $Log

switch ($EventType)
{
    'Error' {[int] $EventType = 1}
    'Warning' {[int] $EventType = 2}
    'Information' {[int] $EventType = 3}
    'Security Audit Success' {[int] $EventType = 4}
    'Security Audit Failure' {[int] $EventType = 5}
    default {[string] $EventType = ''}
}
Write-Log ('[Test-EventLogRule:' + $RuleName + '] EventType: ' + $EventType.ToString()) -Log $Log


<#
#// Code
if (Test-Property -InputObject $XmlRuleNode -Name 'CODE')
{
    $oDataCollector = New-Object pscustomobject
    Add-Member -InputObject $oDataCollector -MemberType NoteProperty -Name 'Name' -Value ''
    Add-Member -InputObject $oDataCollector -MemberType NoteProperty -Name 'LogFile' -Value ''
    Add-Member -InputObject $oDataCollector -MemberType NoteProperty -Name 'Source' -Value ''
    Add-Member -InputObject $oDataCollector -MemberType NoteProperty -Name 'EventID' -Value ''
    Add-Member -InputObject $oDataCollector -MemberType NoteProperty -Name 'EventType' -Value ''
    Add-Member -InputObject $oDataCollector -MemberType NoteProperty -Name 'StringInMessage' -Value ''
    Add-Member -InputObject $oDataCollector -MemberType NoteProperty -Name 'Code' -Value ''

    if ((Test-Property -InputObject $XmlRuleNode -Name 'Name') -eq $True)            {$oDataCollector.Name            = $XmlRuleNode.Name}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'LogFile') -eq $True)         {$oDataCollector.LogFile         = $XmlRuleNode.LogFile}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'Source') -eq $True)          {$oDataCollector.Source          = $XmlRuleNode.Source}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'EventID') -eq $True)         {$oDataCollector.EventID         = $XmlRuleNode.EventID}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'EventType') -eq $True)       {$oDataCollector.EventType       = $XmlRuleNode.EventType}
    if ((Test-Property -InputObject $XmlRuleNode -Name 'StringInMessage') -eq $True) {$oDataCollector.StringInMessage = $XmlRuleNode.StringInMessage}

    $oDataCollector.Code = $XmlRuleNode.CODE.get_innertext()
    $oDataCollector = Invoke-CounterRuleCode -DataCollector $oDataCollector

    $XmlRuleNode.Name = $oDataCollector.Name
    $XmlRuleNode.LogFile = $oDataCollector.LogFile
    $XmlRuleNode.Source = $oDataCollector.Source
    $XmlRuleNode.EventID = $oDataCollector.EventID
    $XmlRuleNode.EventType = $oDataCollector.EventType
    $XmlRuleNode.StringInMessage = $oDataCollector.StringInMessage
    $XmlDoc.Save('.\config.xml')
}
#>

    #Start-Ps2ScheduledTask -ScheduledTaskFolderPath '\Microsoft\Windows\Clue' -TaskName 'Invoke-Rule' -Arguments $Arguments

$ActionEvent = {
    Write-Log ('[Test-EventLogRule] Name: ' + $Name) -Log $Log
    Write-Log ('[Test-EventLogRule] LogFile: ' + $LogFile) -Log $Log
    Write-Log ('[Test-EventLogRule] Source: ' + $Source) -Log $Log
    Write-Log ('[Test-EventLogRule] EventID: ' + $EventID) -Log $Log
    Write-Log ('[Test-EventLogRule] EventType: ' + $EventType) -Log $Log
    Write-Log ('[Test-EventLogRule] StringInMessage: ' + $StringInMessage) -Log $Log
    Write-Log ('[Test-EventLogRule] TargetInstance.Source: ' + $event.SourceEventArgs.NewEvent.TargetInstance.SourceName) -Log $Log
    Write-Log ('[Test-EventLogRule] TargetInstance.EventType: ' + $event.SourceEventArgs.NewEvent.TargetInstance.EventType) -Log $Log
    Write-Log ('[Test-EventLogRule] TargetInstance.EventId: ' + $event.SourceEventArgs.NewEvent.TargetInstance.EventId) -Log $Log
    Write-Log ('[Test-EventLogRule] TargetInstance.Message: ' + $event.SourceEventArgs.NewEvent.TargetInstance.Message) -Log $Log

    #/////////////
    #// Source //
    #///////////

    [bool] $IsSourceMet = $false
    if (($Source -eq '') -or ($Source -eq '*'))
    {
        [bool] $IsSourceMet = $True
    }
    else
    {        
        if ($event.SourceEventArgs.NewEvent.TargetInstance.SourceName -eq $Source)
        {
            [bool] $IsSourceMet = $True
        }
    }
    Write-Log ('[Test-EventLogRule] IsSourceMet: ' + $IsSourceMet.ToString()) -Log $Log

    #////////////////
    #// EventType //
    #//////////////

    [bool] $IsEventTypeMet = $false
    if ($EventType -is [string])
    {
        if (($EventType -eq '') -or ($EventType -eq '*'))
        {
            [bool] $IsEventTypeMet = $True
        }
    }
    else
    {        
        if ($event.SourceEventArgs.NewEvent.TargetInstance.EventType -eq $EventType)
        {
            [bool] $IsEventTypeMet = $True
        }
    }
    Write-Log ('[Test-EventLogRule] IsEventTypeMet: ' + $IsEventTypeMet.ToString()) -Log $Log

    #//////////////
    #// EventID //
    #////////////

    [bool] $IsEventIdMet = $false
    if (($EventId -eq '') -or ($EventId -eq '*'))
    {
        [bool] $IsEventIdMet = $True
    }
    else
    {        
        if ($event.SourceEventArgs.NewEvent.TargetInstance.EventCode -eq $EventId)
        {
            [bool] $IsEventIdMet = $True
        }
    }
    Write-Log ('[Test-EventLogRule] IsEventIdMet: ' + $IsEventIdMet.ToString()) -Log $Log

    #//////////////////////
    #// StringInMessage //
    #////////////////////

    [bool] $IsStringInMessageMet = $false
    if (($StringInMessage -eq '') -or ($StringInMessage -eq '*'))
    {
        [bool] $IsStringInMessageMet = $True
    }
    else
    {        
        if (($event.SourceEventArgs.NewEvent.TargetInstance.Message) -imatch $StringInMessage)
        {
            [bool] $IsStringInMessageMet = $True
        }
    }
    Write-Log ('[Test-EventLogRule] IsStringInMessageMet: ' + $IsStringInMessageMet.ToString()) -Log $Log

    #///////////////
    #// Evaluate //
    #/////////////

    if (($IsSourceMet -eq $true) -and ($IsEventTypeMet -eq $true) -and ($IsEventIdMet -eq $true) -and ($IsStringInMessageMet -eq $true))
    {
        Write-Log ('[Test-EventLogRule] All conditions met!') -Log $Log
        $Arguments = '-RuleName ' + $RuleName
        Start-Ps2ScheduledTask -ScheduledTaskFolderPath '\Microsoft\Windows\Clue' -TaskName 'Invoke-Rule' -Arguments $Arguments -Log $Log
    }
}
[string] $Wql = 'SELECT * FROM __InstanceCreationEvent WITHIN 3 WHERE TargetInstance ISA "Win32_NTLogEvent" AND TargetInstance.LogFile = "' + $LogFile + '" AND TargetInstance.SourceName = "' + $Source + '" AND TargetInstance.EventType = ' + $EventType + ' AND TargetInstance.EventCode = ' + $EventID
Write-Log $Wql -Log $Log
Register-WmiEvent -Query $Wql -SourceIdentifier 'Win32NtLogEvent.CreationEvent' -Action $ActionEvent
Test-Error -Err $Error -Log $Log

Start-TruncateLog -FilePath $Log -Log $Log
[datetime] $dtLastLogTruncate = (Get-Date)

Do
{
    [int] $RandomMinutes = Get-Random -Minimum 100 -Maximum 200
    if ((New-TimeSpan -Start $dtLastLogTruncate -End (Get-Date)).TotalMinutes -gt $RandomMinutes)
    {
        Write-Log ('[Start-TruncateLog]') -Log $Log
        Start-TruncateLog -FilePath $Log -Log $Log
        [datetime] $dtLastLogTruncate = (Get-Date)
    }
    Start-Sleep 1
} Until ($false -eq $true)