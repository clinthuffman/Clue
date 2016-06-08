param([string] $WorkingDirectory)
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

[string] $Log = '.\Test-CustomError.log'

Set-Location -Path $WorkingDirectory

[string] $TraceCommand = 'xperf.exe -on Base+Diag+Latency+FileIO+DPC+DISPATCHER+Pool -stackwalk Profile+CSwitch+ReadyThread+ThreadCreate+PoolAlloc+PoolAllocSession+VirtualAlloc -BufferSize 1024 -MinBuffers 256 -MaxBuffers 256 -MaxFile 256 -FileMode Circular'

Function wl
{
    param($Output)
    #// Writes to the log file.
    $TimeStamp = "$(Get-Date -format yyyyMMdd-HHmmss)"    
    if ($Output -eq $null) {Add-content $Log -value ('[' + $TimeStamp + '] NULL') -Encoding Unicode;Return}
    Do
    {
        $Error.Clear()
        try 
        {
            switch ($Output.GetType().FullName)
            {
                'System.String'                {Add-content -Path $Log -value ('[' + $TimeStamp + '] ' + $Output) -Encoding Unicode}
                default                        {Add-content -Path $Log -value ('[' + $TimeStamp + ']') -Encoding Unicode; $Output >> $Log}
            }
        }
        catch
        {
            Start-Sleep -Milliseconds 100
        }
    } until ($Error.Count -eq 0)
    $Output
}

Function Test-Error
{
    param($Err)
    #// Tests if an error condition exists and writes it to the log.
    if ($Err.Count -gt 0)
    {
        wl ('[Test-Error] Error(s) found: ' + $Err.Count)
        wl ($Err)
        wl ($Error)
        $Err.Clear()
        $Error.Clear()        
    }
}

Function wh
{
    param($Output)
    #// Writes to the log file.
    $TimeStamp = "$(Get-Date -format yyyyMMdd-HHmmss)"
    if ($Output -eq $null) {Write-Output ('[' + $TimeStamp + '] NULL')}
    switch ($Output.GetType().FullName)
    {
        'System.String'                {Write-Output ('[' + $TimeStamp + '] ' + $Output)}
        'System.Collections.ArrayList' {Write-Output ('[' + $TimeStamp + ']'); $Output}
        default                        {Write-Output ('[' + $TimeStamp + '] ' + $Output)}
    }
}

$error.Clear()
'Start Log' > $Log
wl ('Written by Clint Huffman (clinth@microsoft.com)')

wl ('Confirming xperf.exe is local...')
#// Confirm xperf.exe is local.
if (((Test-Path -Path '.\xperf.exe') -eq $false) -or ((Test-Path -Path '.\perfctrl.dll') -eq $false))
{
    wl 'Unable to find xperf.exe! Make sure that xperf.exe and perfctrl.dll are in the local folder. Exiting!'
    Exit;
}
wl ('Confirming xperf.exe is local...Done!')


[string] $sTextFilePath = $(Get-Content env:PUBLIC) + '\Documents\ClueUserInitiated.txt'
wl ('[Test-CustomError] sTextFilePath: ' + $sTextFilePath)
'' > $sTextFilePath

xperf -on Base+Diag+Latency+FileIO+DPC+DISPATCHER+Pool -stackwalk Profile+CSwitch+ReadyThread+ThreadCreate+PoolAlloc+PoolAllocSession+VirtualAlloc -BufferSize 1024 -MinBuffers 256 -MaxBuffers 256 -MaxFile 256 -FileMode Circular

[bool] $Global:IsTracing = $false
gc -Wait O:\RM\Log\RM_05-06-16-Fri.LOG | sls -Pattern "^\d{2}:\d{2}:\d{2}:\d{3}\s+DivertStatus\s+App125 Error\s+BOSS Induction disabled for scanner: 5." | % {
    Write-Host -ForegroundColor Red "Stopping Xperf"
    Send-MailMessage -SmtpServer mail2.homedepot.com -To "kevin_mcwilliams@homedepot.com" -From "kevin_mcwilliams@homedepot.com" -Subject "WCS No Assignment Occured" -Body $_.line
    $date = (Get-Date).ToString("mmddyy_hhMMss")
    xperf -stop -d General_$date.etl
}