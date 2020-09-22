param([string] $WorkingDirectory = 'C:\Program Files\Clue', [string] $IncidentOutputFolder = 'C:\ClueOutput')

Set-Location -Path $WorkingDirectory

$resDir = $IncidentOutputFolder

[string] $Log = $IncidentOutputFolder + '\Get-WmiProviders.log'

Function Write-Log
{
    param($Output)
    #// Writes to the log file.
    $TimeStamp = "$(Get-Date -format yyyyMMdd-HHmmss)"

    if ($Output -eq $null) {Add-content $Log -value ('[' + $TimeStamp + '] NULL') -Encoding Unicode;Return}
    switch ($Output.GetType().FullName)
    {
        'System.String'                {Add-content -Path $Log -value ('[' + $TimeStamp + '] ' + $Output) -Encoding Unicode}
        default                        {Add-content -Path $Log -value ('[' + $TimeStamp + ']') -Encoding Unicode; $Output >> $Log}
    }
}

#Write-Log ('Collecting details of provider hosts') -Log $Log
#Write-Log ('WorkingDirectory: ' + $WorkingDirectory) -Log $Log
#Write-Log ('IncidentOutputFolder: ' + $IncidentOutputFolder) -Log $Log
New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR -ErrorAction SilentlyContinue | Out-Null

"Coupled providers (WMIPrvSE.exe processes)" | Out-File -FilePath ($IncidentOutputFolder + "\ProviderHosts.txt") -Append

$totMem = 0

$prov = Get-WmiObject -NameSpace "root\cimv2" -Query "select HostProcessIdentifier, Provider, Namespace, User from MSFT_Providers"
if ($prov) {
  $proc = Get-WmiObject -NameSpace "root\cimv2" -Query "select ProcessId, HandleCount, ThreadCount, PrivatePageCount, CreationDate, KernelModeTime, UserModeTime from Win32_Process where name = 'wmiprvse.exe'"
  foreach ($prv in $proc) {
    $provhost = $prov | Where-Object {$_.HostProcessIdentifier -eq $prv.ProcessId}

    if (($provhost | measure).count -gt 0) {
        $ut = New-TimeSpan -Start $prv.ConvertToDateTime($prv.CreationDate)

      $uptime = ($ut.Days.ToString() + "d " + $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00"))

      $ks = $prv.KernelModeTime / 10000000
      $kt = [timespan]::fromseconds($ks)
      $kh = $kt.Hours.ToString("00") + ":" + $kt.Minutes.ToString("00") + ":" + $kt.Seconds.ToString("00")

      $us = $prv.UserModeTime / 10000000
      $ut = [timespan]::fromseconds($us)
      $uh = $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00")

      "PID" + " " + $prv.ProcessId + " (" + [String]::Format("{0:x}", $prv.ProcessId) + ") Handles:" + $prv.HandleCount +" Threads:" + $prv.ThreadCount + " Private KB:" + ($prv.PrivatePageCount/1kb) + " KernelTime:" + $kh + " UserTime:" + $uh + " Uptime:" + $uptime | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append
      $totMem = $totMem + $prv.PrivatePageCount
    } else {
      Write-Log ("No provider found for the WMIPrvSE process with PID " +  $prv.ProcessId)
    }

    foreach ($provname in $provhost) {
      $provdet = Get-WmiObject -NameSpace $provname.Namespace -Query ("select * from __Win32Provider where Name = """ + $provname.Provider + """")
      $hm = $provdet.hostingmodel
      $clsid = $provdet.CLSID
      $dll = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKCR:\CLSID\" + $clsid + "\InprocServer32")).'(default)' 2>>$errfile
      $dll = $dll.Replace("""","")
      $file = Get-Item ($dll)
      $dtDLL = $file.CreationTime
      $verDLL = $file.VersionInfo.FileVersion

      $provname.Namespace + " " + $provname.Provider + " " + $dll + " " + $hm + " " + $provname.user + " " + $dtDLL + " " + $verDLL 2>>$errfile | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append
    }
    " " | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append
  }
}
"Total memory used by coupled providers: " + ($totMem/1kb) + " KB" | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append
" " | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append

# Details of decoupled providers
$list = Get-Process
foreach ($proc in $list) {
  $prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "wmidcprv.dll"} 
  if (($prov | measure).count -gt 0) {
    if (-not $hdr) {
      "Decoupled providers" | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append
      " " | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append
      $hdr = $true
    }

    $prc = Get-WmiObject -Namespace "root\cimv2" -Query ("select ProcessId, CreationDate, HandleCount, ThreadCount, PrivatePageCount, ExecutablePath, KernelModeTime, UserModeTime from Win32_Process where ProcessId = " +  $proc.id)
      $ut= New-TimeSpan -Start $prc.ConvertToDateTime($prc.CreationDate)

    $uptime = ($ut.Days.ToString() + "d " + $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00"))

    $ks = $prc.KernelModeTime / 10000000
    $kt = [timespan]::fromseconds($ks)
    $kh = $kt.Hours.ToString("00") + ":" + $kt.Minutes.ToString("00") + ":" + $kt.Seconds.ToString("00")

    $us = $prc.UserModeTime / 10000000
    $ut = [timespan]::fromseconds($us)
    $uh = $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00")

    $svc = Get-WmiObject -Namespace "root\cimv2" -Query ("select Name from Win32_Service where ProcessId = " +  $prc.ProcessId)
    $svclist = ""
    if ($svc) {
      foreach ($item in $svc) {
        $svclist = $svclist + $item.name + " "
      }
      $svc = " Service: " + $svclist
    } else {
      $svc = ""
    }

    ($prc.ExecutablePath + $svc) | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append
    "PID " + $prc.ProcessId  + " (" + [String]::Format("{0:x}", $prc.ProcessId) + ")  Handles: " + $prc.HandleCount + " Threads: " + $prc.ThreadCount + " Private KB: " + ($prc.PrivatePageCount/1kb) + " KernelTime:" + $kh + " UserTime:" + $uh + " Uptime:" + $uptime | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append

    $Keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Wbem\Transports\Decoupled\Client
    $Items = $Keys | Foreach-Object {Get-ItemProperty $_.PsPath }
    ForEach ($key in $Items) {
      if ($key.ProcessIdentifier -eq $prc.ProcessId) {
        ($key.Scope + " " + $key.Provider) | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append
      }
    }
    " " | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append
  }
}
