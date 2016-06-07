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

[string] $Log = '.\Test-ProcessAddressSpace.log'
[int] $WaitInSeconds = 60

[System.Version] $SystemVersion = (Get-WmiObject -Class 'Win32_OperatingSystem').Version -as [System.Version]
Test-Error -Err $Error -Log $Log
if ($SystemVersion -eq $null)
{
    Write-Log '[Test-ProcessAddressSpace] SystemVersion is NULL. Exiting!' -Log $Log
    Exit;
}

#// Test OS compatibility
[bool] $IsOsCompatible = $false
if (($SystemVersion.Major -eq 8) -and ($SystemVersion.Minor -ge 1))
{
    [bool] $IsOsCompatible = $true
}

if ($SystemVersion.Major -ge 10)
{
    [bool] $IsOsCompatible = $true
}
Write-Log ('[Test-ProcessAddressSpace] IsOsCompatible: ' + $IsOsCompatible.ToString()) -Log $Log
if ($IsOsCompatible -eq $false)
{
    Write-Log '[Test-ProcessAddressSpace] OS is not compatible for Win32_Process.GetAvailableVirtualSize(). Exiting!' -Log $Log
    Write-Log '[Test-ProcessAddressSpace] Disabling \Microsoft\Windows\Clue\Test-ProcessAddressSpace scheduled job.' -Log $Log
    .\schtasks /Change /TN \Microsoft\Windows\Clue\Test-ProcessAddressSpace /DISABLE
    Exit;
}
Test-Error -Err $Error -Log $Log

Start-TruncateLog -FilePath $Log -Log $Log
[datetime] $dtLastLogTruncate = (Get-Date)

Write-Log '[Test-ProcessAddressSpace] Starting infinite loop.' -Log $Log
Do
{
    [bool] $WasTriggered = $false
    $dtStartTime = (Get-Date)
    $oProcesses = Get-WmiObject -Query 'SELECT * FROM Win32_Process WHERE VirtualSize > 1073741824 AND VirtualSize < 4509715660'
    Test-Error -Err $Error -Log $Log
    ForEach($oProcess in $oProcesses)
    {
        [bool] $ShouldCheck = $false
        if ($oProcess -is [System.Management.ManagementObject])
        {
            if (($oProcess.VirtualSize -gt 1GB) -and ($oProcess.VirtualSize -lt 4GB))
            {
                $ShouldCheck = $true 
            }

            if ($ShouldCheck -eq $true)
            {
                if ([bool] (Get-Member -InputObject $oProcess -Name 'GetAvailableVirtualSize' -MemberType *Method))
                {
                    Write-Log ('[Test-ProcessAddressSpace] Process.GetAvailableVirtualSize(): ' + $oProcess.Name) -Log $Log
                    try
                    {
                        $oMem = $oProcess.GetAvailableVirtualSize()
                    }
                    catch {Test-Error -Err $Error -Log $Log}

                    if ($oMem -ne $null)
                    {
                        if ([bool] (Get-Member -InputObject $oMem -Name 'AvailableVirtualSize' -MemberType *Property))
                        {
                            if ($oMem.AvailableVirtualSize -ne $null)
                            {
                                $iAvailableVirtualSize = $oMem.AvailableVirtualSize
                                [double] $iAvailableGBytes = [Math]::Round(($iAvailableVirtualSize / 1GB),2)
                                Write-Log ('[Test-ProcessAddressSpace] ' + $oProcess.Name  + ': iAvailableGBytes: ' + $iAvailableGBytes + ' GB') -Log $Log
                                if ($iAvailableVirtualSize -lt 1GB)
                                {
                                    Write-Log ('[Test-ProcessAddressSpace] ' + $oProcess.Name + ': ' + $iAvailableGBytes.ToString() + ' GB of process virtual address space available.') -Log $Log
                                    Start-Ps2ScheduledTask -ScheduledTaskFolderPath '\Microsoft\Windows\Clue' -TaskName 'Invoke-Rule' -Arguments '-RuleName Test-ProcessAddressSpace' -Log $Log
                                    [bool] $WasTriggered = $True
                                }
                            }
                            else
                            {
                                Write-Log ('[Test-ProcessAddressSpace] oMem.AvailableVirtualSize: NULL') -Log $Log
                            }
                        }
                        else
                        {
                            Write-Log ('[Test-ProcessAddressSpace] oMem.AvailableVirtualSize(): method doesnt exist') -Log $Log
                        }
                    }
                    else
                    {
                        Write-Log ('[Test-ProcessAddressSpace] oMem: NULL') -Log $Log
                    }
                }
            }
        }
    }

    [int] $RandomMinutes = Get-Random -Minimum 100 -Maximum 200
    if ((New-TimeSpan -Start $dtLastLogTruncate -End (Get-Date)).TotalMinutes -gt $RandomMinutes)
    {
        Write-Log ('[Start-TruncateLog]') -Log $Log
        Start-TruncateLog -FilePath $Log -Log $Log
        [datetime] $dtLastLogTruncate = (Get-Date)
    }

    [int] $iDiffInSeconds = (New-TimeSpan -Start $dtStartTime -End (Get-Date)).TotalSeconds
    Write-Log ('[Test-ProcessAddressSpace] Enumeration took: ' + $iDiffInSeconds + ' seconds.') -Log $Log

    if ($WasTriggered -eq $true)
    {
        Write-Log ('[Test-ProcessAddressSpace] Sleeping for 1 hour...') -Log $Log
        Start-Sleep -Seconds 3600
    }
    else
    {
        Start-Sleep -Seconds $WaitInSeconds
    }
} Until ($true -eq $false)