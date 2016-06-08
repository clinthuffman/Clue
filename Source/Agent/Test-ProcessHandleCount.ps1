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

[string] $Log = '.\Test-ProcessHandleCount.log'

[string] $sArch = Get-ClintOsArchitecture -Log $Log

#////////////////
#// Functions //
#//////////////

Function Invoke-MyCmd
{
    param([string] $Cmd, [string] $Log = $Log)
    Write-Log $Cmd -Log $Log
    $Output = Invoke-Expression -Command $Cmd
    Write-Log $Output -Log $Log
    Test-Error -Err $Error -Log $Log
}

Function Get-ProcessUserObjectCount
{
    param([System.IntPtr] $pHandle, [string] $Log = $Log)
    [string] $MethodDefinition = '[DllImport("User32", ExactSpelling = true, CharSet = CharSet.Auto)] public static extern int GetGuiResources(IntPtr hProcess, int uiFlags);'
    if ($Kernel32 -eq $null)
    {
        $Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -Namespace 'Win32' -PassThru
    }
    Return $Kernel32::GetGuiResources($pHandle,1)
}

Function Test-HandleCountThreshold
{
    param([string] $ProcessName, [int] $HandleCount, [string] $Log = $Log)
    $ProcessName = $ProcessName.ToLower()
    $aDoNotDump = @('explorer','system','taskmgr','csrss')
    if ($aDoNotDump -Contains $ProcessName)
    {
        Return $false
    }
    if ($sArch -eq $null)
    {
        [string] $sArch = Get-ClintOsArchitecture -Log $Log
    }
    [int] $iThreshold = 2500
    switch ($sArch)
    {
        '32-bit'
        {
            switch ($ProcessName)
            {
                'system'  {[int] $iThreshold = 10000}
                'lsass'   {[int] $iThreshold = 30000}
                'store'   {[int] $iThreshold = 30000}
                'sqlsrvr' {[int] $iThreshold = 30000}
                default   {[int] $iThreshold = 2500}
            }
            
        }
        
        '64-bit'
        {
            switch ($ProcessName)
            {
                'system'  {[int] $iThreshold = 20000}
                'lsass'   {[int] $iThreshold = 50000}
                'store'   {[int] $iThreshold = 50000}
                'sqlsrvr' {[int] $iThreshold = 50000}
                default   {[int] $iThreshold = 3000}
            }
        }
        default {Return $false}
    }
    if ($HandleCount -gt $iThreshold)
    {
        Return $true
    } else {Return $false}
}

#///////////
#// Main //
#/////////
Write-Log ('[Test-ProcessHandleCount] UserObjectCountThreshold: ' + $UserObjectCountThreshold) -Log $Log

[xml] $xmlDoc = OpenConfigXml -Log $Log
if ((Test-Property -InputObject $xmlDoc -Name 'Configuration' -Log $Log) -eq $True)
{
    $XmlConfig = $xmlDoc.Configuration
}
Test-Error -Err $Error -Log $Log

[string] $OutputDirectory = ''
[string] $OutputDirectory = Get-XmlAttribute -XmlNode $XmlConfig -Name 'OutputDirectory' -Log $Log
Write-Log ('[Test-ProcessHandleCount] OutputDirectory: ' + $OutputDirectory) -Log $Log
Test-Error -Err $Error -Log $Log
if ($OutputDirectory -ne '')
{
    if ((New-DirectoryWithConfirm -DirectoryPath $OutputDirectory -Log $Log) -eq $false)
    {
        Test-Error -Err $Error -Log $Log
        Write-Log ('[Test-ProcessHandleCount] Unable to create: ' + $OutputDirectory) -Log $Log
        Exit;
    }
}

Start-TruncateLog -FilePath $Log -Log $Log
[datetime] $dtLastLogTruncate = (Get-Date)

Write-Log '[Test-ProcessHandleCount] Starting infinite loop.' -Log $Log
Do
{
    $aObjects = @()
    $oProcesses = Get-Process | Select Name, Handle, HandleCount, Id | Where-Object {$_.HandleCount -gt $UserObjectCountThreshold}
    Test-Error -Err $Error -Log $Log
    foreach ($oProcess in $oProcesses)
    {
        [bool] $IsThresholdBroken = Test-HandleCountThreshold -ProcessName $oProcess.Name -HandleCount $oProcess.HandleCount
        if ($IsThresholdBroken -eq $true)
        {
            Write-Log ('ProcessName: ' + $oProcess.Name + ', HandleCount: ' + $oProcess.HandleCount + ', IsThresholdBroken: ' + $IsThresholdBroken.ToString()) -Log $Log
		    $oObject = New-Object pscustomobject
		    Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'Name' -Value $([string] $oProcess.Name)
            Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'Pid' -Value $([Int] $oProcess.Id)
            Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'HandleCount' -Value $([Int] $oProcess.HandleCount)
            $aObjects += @($oObject)
        }
    }
    Test-Error -Err $Error -Log $Log

    if ($aObjects.Count -gt 0)
    {
        $TimeStamp = "$(Get-Date -format yyyyMMdd-HHmmss)"
        $IncidentOutputFolder = Get-IncidentFolderPath -TimeStamp $TimeStamp -RuleName 'Test-ProcessHandleCount' -OutputDirectory $OutputDirectory -Log $Log
        Test-Error -Err $Error -Log $Log
        Write-Log ('[Test-ProcessHandleCount] IncidentOutputFolder: ' + $IncidentOutputFolder) -Log $Log
        if ((New-DirectoryWithConfirm -DirectoryPath $IncidentOutputFolder) -eq $false)
        {
            Test-Error -Err $Error -Log $Log
            Write-Log ('[Test-ProcessHandleCount] Unable to create: ' + $IncidentOutputFolder) -Log $Log
            Exit;
        }

        New-DataCollectionInProgress -IncidentOutputFolder $IncidentOutputFolder -Log $Log
        foreach ($oObject in $aObjects)
        {
            Write-Log ('[Test-ProcessHandleCount] Name: ' + $oObject.Name + ', Pid: ' + $oObject.Pid + ', HandleCount: ' + $oObject.HandleCount) -Log $Log
            [string] $sCmd = '.\sysint\procdump -ma -o -a -r ' + ($oObject.Pid) + ' ' + $IncidentOutputFolder + '\' + $TimeStamp + '-' + $oObject.Name + '-Pid' + $oObject.Pid + '-HandleCount' + $oObject.HandleCount + '.dmp -accepteula'
            Invoke-MyCmd -Cmd $sCmd
        }
        Remove-DataCollectionInProgress -IncidentOutputFolder $IncidentOutputFolder -Log $Log
        Start-Sleep -Seconds 14400 #// Wait for 4 hours before collecting again.
    }

    [int] $RandomMinutes = Get-Random -Minimum 100 -Maximum 200
    if ((New-TimeSpan -Start $dtLastLogTruncate -End (Get-Date)).TotalMinutes -gt $RandomMinutes)
    {
        Write-Log ('[Start-TruncateLog]') -Log $Log
        Start-TruncateLog -FilePath $Log -Log $Log
        [datetime] $dtLastLogTruncate = (Get-Date)
    }
    Start-Sleep -Seconds 60
} Until ($true -eq $false)