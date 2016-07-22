param([string] $RuleName='UserInitiated', [string] $Force = 'false')
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
Import-Module .\Modules\Xml.psm1 -Force
Import-Module .\Modules\FileSystem.psm1 -Force

[string] $Log = '.\Invoke-Rule.log'

#///////////
#// Main //
#/////////

$Error.Clear()
Write-Log ('[Invoke-Rule:' + $RuleName + ']') -Log $Log

#//////////////////////
#// Open config.xml //
#////////////////////

[xml] $XmlDoc = OpenConfigXml
Test-Error -Err $Error -Log $Log
if (Test-Property -InputObject $XmlDoc -Name 'Configuration' -Log $Log)
{
    [System.Xml.XmlElement] $XmlConfig = $XmlDoc.Configuration
}

#////////////////////////////
#// Get actions from rule //
#//////////////////////////

[string] $Actions = ''
[string] $Actions = Get-ActionsFromRule -XmlConfig $XmlConfig -Rule $RuleName -Log $Log
Test-Error -Err $Error -Log $Log
if ($Actions -eq '')
{
    Write-Log ('[Invoke-Rule:' + $RuleName + '] No actions found for: ' + $RuleName) -Log $Log
    Write-Log ('[/Invoke-Rule:' + $RuleName + ']') -Log $Log
    Exit;
}

#/////////////////////
#// Test-RunLimits //
#///////////////////

if ($Force -eq $false)
{
    if (Test-RunLimit -XmlConfig $XmlConfig -RuleName $RuleName -Log $Log)
    {
        Test-Error -Err $Error -Log $Log
        Write-Log ('!!! RUNLIMIT HIT for: "' + $RuleName + '" !!!') -Log $Log
        Exit;
    }
}
    #// Update-Ran is executed during Invoke-Actions.

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

#/////////////////////
#// Invoke actions //
#///////////////////

if ($Actions -ne '')
{
    Write-Log ('[Invoke-Rule:' + $RuleName + '] Invoke-Actions: ' + $Actions) -Log $Log
    Invoke-Actions -XmlConfig $XmlConfig -WptFolderPath $WptFolderPath -RuleName $RuleName -Actions $Actions -OutputDirectory $OutputDirectory -Log $Log
}
else
{
    Write-Log ('[Invoke-Rule:' + $RuleName + '] Actions is blank.') -Log $Log
}
Test-Error -Err $Error -Log $Log

#////////////
#// OnEnd //
#//////////

Write-Log ('[/Invoke-Rule:' + $RuleName + ']') -Log $Log
Start-TruncateLog -FilePath $Log -Log $Log