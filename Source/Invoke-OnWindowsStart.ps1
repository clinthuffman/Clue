param()
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

[string] $Log = '.\Invoke-OnWindowsStart.log'

Start-TruncateLog -FilePath $Log -Log $Log

Write-Log '[Invoke-OnWindowsStart] Started' -Log $Log
[xml] $XmlDoc = OpenConfigXml -Log $Log
Test-Error -Err $Error -Log $Log
if (Test-Property -InputObject $XmlDoc -Name 'Configuration' -Log $Log)
{
    [System.Xml.XmlElement] $XmlConfig = $XmlDoc.Configuration
}

[string] $ToolScheduledTaskFolderPath = '\Microsoft\Windows\Clue'
<#
Write-Log '[Invoke-OnWindowsStart] Invoke-Rule -RuleName Invoke-OnWindowsStart' -Log $Log
Start-Ps2ScheduledTask -ScheduledTaskFolderPath $ToolScheduledTaskFolderPath -TaskName 'Invoke-Rule' -Arguments '-RuleName Invoke-OnWindowsStart'

foreach ($XmlRule in $XmlConfig.Rule)
{
    if (Test-XmlEnabled -XmlNode $XmlRule)
    {
        [string] $sTrigger = Get-XmlAttribute -XmlNode $XmlRule -Name 'Trigger'
        [string] $sType = Get-XmlAttribute -XmlNode $XmlRule -Name 'Type'
        if (($sTrigger -eq '5') -or ($sType -eq 'EventLog') -or ($sType -eq 'Counter'))
        {
            if (Test-Property -InputObject $XmlRule -Name 'Name')
            {
                [string] $sCmd = 'schtasks /Run /TN \Microsoft\Windows\Clue\' + $XmlRule.Name
                Write-Log ('[Invoke-OnWindowsStart] ' + $sCmd) -Log $Log
                $aOutput = Invoke-Expression -Command $sCmd
                Write-Log ($aOutput) -Log $Log
                Start-Sleep -Seconds 5
            }
        }
    }
}
#>