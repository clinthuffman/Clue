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

[string] $Log = '.\Start-DetectIeHang.log'

Start-TruncateLog -FilePath $Log -Log $Log
[datetime] $dtLastLogTruncate = (Get-Date)

$error.Clear()
Write-Log ('Start Log') -Log $Log
Write-Log ('Written by Clint Huffman (clinth@microsoft.com)') -Log $Log

[string] $sTextFilePath = $(Get-Content env:PUBLIC) + '\Documents\ClueIeHangUserInitiated.txt'
Write-Log ('[Test-IeHang] sTextFilePath: ' + $sTextFilePath) -Log $Log

$aIePids = New-Object System.Collections.Generic.List[int]

Write-Output 'Internet Explorer hang detection started...'

$oPreviousIeProcesses = @((Get-Process) | Where {$_.Name -eq 'iexplore'})

Do
{
    $oIeProcesses = @((Get-Process) | Where {$_.Name -eq 'iexplore'})
    Test-Error -Err $error

    $oCompared = Compare-Object -ReferenceObject $oPreviousIeProcesses -DifferenceObject $oIeProcesses

    foreach ($oInstance in $oCompared)
    {
        if ($oInstance.SideIndicator -eq '=>')
        {
            # Added
            Write-Host ('New instance of Internet Explorer detected. PID: ' + $oInstance.InputObject.Id)
        }
        else
        {
            # Removed
            Write-Host ('An instance of Internet Explorer exited. PID: ' + $oInstance.InputObject.Id)
        }
    }
    $oPreviousIeProcesses = $oIeProcesses

    [int] $iRunningInstances = $oProcesses.Count
    Test-Error -Err $error
    $oHungInstances = @($oIeProcesses | Where {$_.Responding -eq $False})
    Test-Error -Err $error

    foreach ($oInstance in $oHungInstances)
    {
        $TimeStamp = "$(Get-Date -format yyyyMMdd-HHmmss)"
        Write-Host ('[' + $TimeStamp + '] ' + 'Internet Explorer hang detected in PID: (' + $oInstance.Id + '). Dumping trace data. This may take a minute or two. Please close the slow/hung Internet Explorer at this time and continue using your system normally. Thank you!') -ForegroundColor Yellow
        Add-content $sTextFilePath -value ('[' + $TimeStamp + ']') -Encoding Unicode
        $oInstance | SELECT * >> $sTextFilePath
        Do
        {
            (Get-Content -Path $sTextFilePath).Length
            Start-Sleep -Seconds 5
        } until ((Get-Content -Path $sTextFilePath).Length -eq 0)
        Write-Host ('[' + $TimeStamp + '] ' + 'Resuming Internet Explorer hang detection...')        
    }

    Start-Sleep -Seconds 3
} Until ($false -eq $true)
