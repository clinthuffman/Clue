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

$Error.Clear()
Remove-Module * -Force
Import-Module .\Modules\General.psm1 -Force
Import-Module .\Modules\Xml.psm1 -Force
Import-Module .\Modules\FileSystem.psm1 -Force
Import-Module .\Modules\TaskScheduler.psm1 -Force

[string] $Log = '.\Test-IeHang.log'

Start-TruncateLog -FilePath $Log -Log $Log
[datetime] $dtLastLogTruncate = (Get-Date)

$error.Clear()
Write-Log ('Start Log') -Log $Log
Write-Log ('Written by Clint Huffman (clinth@microsoft.com)') -Log $Log

[string] $sTextFilePath = $(Get-Content env:PUBLIC) + '\Documents\ClueIeHangUserInitiated.txt'
Write-Log ('[Test-IeHang] sTextFilePath: ' + $sTextFilePath) -Log $Log
'' | Out-File -FilePath $sTextFilePath -Encoding ascii

[xml] $XmlDoc = OpenConfigXml -Log $Log
Test-Error -Err $Error -Log $Log
if (Test-Property -InputObject $XmlDoc -Name 'Configuration' -Log $Log)
{
    [System.Xml.XmlElement] $XmlConfig = $XmlDoc.Configuration
}

[string] $RuleName = 'Test-IeHang'
$XmlRuleNode = Get-MatchingNodeByAttribute -XmlConfig $XmlConfig -NodeName 'Rule' -Attribute 'Name' -Value $RuleName -Log $Log
Test-Error -Err $Error -Log $Log

[string] $WptFolderPath = ''
if (Test-Property -InputObject $XmlConfig -Name 'WptFolderPath' -Log $Log)
{
    [string] $WptFolderPath = Get-WptFolderPath -SuggestedPath $XmlConfig.WptFolderPath -Log $Log
}
else
{
    [string] $WptFolderPath = Get-WptFolderPath -Log $Log
}

[string] $OutputDirectory = ''
if (Test-Property -InputObject $XmlConfig -Name 'OutputDirectory' -Log $Log)
{
    [string] $OutputDirectory = $XmlConfig.OutputDirectory
}

if ($OutputDirectory -eq '')
{
    $OutputDirectory = 'C:\ClueOutput'
}

[bool] $Global:IsTracing = $false
Do
{
    $oProcesses = @((Get-Process) | Where {$_.Name -eq 'iexplore'})
    Test-Error -Err $error -Log $Log

    if ($oProcesses.Count -eq 0)
    {
        if ($Global:IsTracing -eq $true)
        {
            Write-Log 'Stop tracing. No save.' -Log $Log
            Stop-Wpr -WptFolderPath $WptFolderPath -Log $Log
            Test-Error -Err $error -Log $Log
            [bool] $Global:IsTracing = $false
        }
    }
    else
    {
        if ($Global:IsTracing -eq $false)
        {
            Write-Log 'Start tracing' -Log $Log
            [bool] $Global:IsTracing = $true
            Stop-Wpr -WptFolderPath $WptFolderPath -Log $Log
            Write-Log 'Ignore any errors *previous* of this line.' -Log $Log
            [string] $CmdArgs = '-start DesktopComposition -start InternetExplorer -recordtempto "' + $OutputDirectory + '"'
            Start-Wpr -WptFolderPath $WptFolderPath -Arguments $CmdArgs -Log $Log
            Test-Error -Err $error -Log $Log
        }
    }

    if ((Test-Path -Path $sTextFilePath) -eq $false)
    {
        '' | Out-File -FilePath $sTextFilePath -Encoding ascii
        Write-Log ('[Test-IeHang] UserInitiated file created: ' + $sTextFilePath) -Log $Log
    }

    if (Test-Path -Path $sTextFilePath)
    {
        if ((Get-Content -Path $sTextFilePath) -ne '')
        {
            Test-Error -Err $error -Log $Log
            if ($Global:IsTracing -eq $true)
            {
                Write-Log 'Stop tracing and SAVE.' -Log $Log
                [bool] $Global:IsTracing = $false
                $TimeStamp = "$(Get-Date -format yyyyMMdd-HHmmss)"

                [string] $Arguments = '-RuleName Test-IeHang -Log ' + $Log

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
                Write-Log ('Wiping IE user initated text file...')
                '' | Out-File -FilePath $sTextFilePath -Encoding ascii
                Write-Log ('Wiping IE user initated text file...Done!')
            }            
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
} Until ($false -eq $true)
