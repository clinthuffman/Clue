##############
## General ##
############
Import-Module .\Modules\Registry.psm1 -Force

Function Write-Log
{
    param($Output, [string] $Log = '.\Clue.log')
    #// Writes to the log file.
    $TimeStamp = "$(Get-Date -format yyyyMMdd-HHmmss)"

    if ($Output -eq $null) {Add-content $Log -value ('[' + $TimeStamp + '] NULL') -Encoding Unicode;Return}
    switch ($Output.GetType().FullName)
    {
        'System.String'                {Add-content -Path $Log -value ('[' + $TimeStamp + '] ' + $Output) -Encoding Unicode}
        default                        {Add-content -Path $Log -value ('[' + $TimeStamp + ']') -Encoding Unicode; $Output >> $Log}
    }
}

Function Test-Error
{
    param($Err, [string] $Log = '.\Clue.log')
    #// Tests if an error condition exists and writes it to the log.
    if ($Err.Count -gt 0)
    {
        Write-Log ('[Test-Error] Error(s) found: ' + $Err.Count) -Log $Log
        Write-Log ($Err) -Log $Log
        $Err.Clear()
    }
}

Function Test-Property
{
	param ([Parameter(Position=0,Mandatory=1)]$InputObject,[Parameter(Position=1,Mandatory=1)]$Name, [string] $Log = '.\Clue.log')
	[Bool](Get-Member -InputObject $InputObject -Name $Name -MemberType *Property)
}

Function Get-WptFolderPath
{
    param([string] $SuggestedPath='C:\Program Files\Clue', [string] $Log = '.\Clue.log')
    #// Searches for the WPT install folder path and confirms it.
        #// Depends on .\Modules\Registry.psm1
        #// HKEY_CLASSES_ROOT\wpa or #HKEY_LOCAL_MACHINE\SOFTWARE\Classes\wpa

    [string] $Temp = (Get-RegistryKey -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\wpa' -Log $Log).FriendlyTypeName
    if ($Temp.Contains(','))
    {
        [System.String[]] $aTemp = @($Temp.Split(',',[StringSplitOptions]'RemoveEmptyEntries'))
        $Temp = $aTemp[0]
    }
    Write-Log ('[Get-WptFolderPath] RegistryKeyValue: ' + $Temp) -Log $Log
    [string] $RegFolderPath = Get-FolderPathFromFilePath -FilePath $Temp -Log $Log

    $aWptFolderPaths = @($SuggestedPath,$RegFolderPath,'C:\Windows\System32','C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit','C:\Program Files\Windows Kits\10\Windows Performance Toolkit')

    foreach ($FolderPath in $aWptFolderPaths)
    {
        if ($FolderPath -ne '')
        {
            [bool] $IsWprExist = $true

            [string] $s = $FolderPath + '\wpr.exe'
            Write-Log ('[Get-WptFolderPath] ' + $s) -Log $Log
            if (Test-Path -Path $s) 
            {
                Write-Log ('[Get-WptFolderPath] wpr.exe found.') -Log $Log
            }
            else
            {
                $IsWprExist = $false
                Write-Log ('[Get-WptFolderPath] wpr.exe not found!') -Log $Log
            }

            if ($IsWprExist -eq $true)
            {
                Write-Log ('[Get-WptFolderPath] WptFolderPath: ' + $FolderPath) -Log $Log
                Write-Log ('[Get-WptFolderPath] WPT folder path is confirmed.') -Log $Log
                Return $FolderPath
            }
        }
    }
}

Function Test-Numeric
{
    param($Value, [string] $Log = '.\Clue.log')
    [double] $number = 0
    Return [double]::TryParse($Value, [REF]$number)
}

function Test-AdminRights
{
    param([string] $Log = '.\Clue.log')
    [string] $sLine = ''
    $oOutput = Invoke-Expression -Command 'logman create counter AdminTest1234 -c "\Processor(*)\% Processor Time"'
    foreach ($sLine in $oOutput)
    {
        if ($sLine.Contains('command completed successfully'))
        {
            $oOutput = Invoke-Expression -Command 'logman delete AdminTest1234'
            Return $true
        }
    }
    Return $false
}

Function Test-OSCompatibility
{
    param([string] $Log = '.\Clue.log')
    [int] $iMajorVersion = 0
    [int] $iMinorVersion = 0

    $oWmiOs = Get-WmiObject -Query 'SELECT * FROM Win32_OperatingSystem'
    Write-Log ('[Test-OSCompatibility] OS Version: ' + $oWmiOs.Version) -Log $Log
    $aVersion = @($oWmiOs.Version.Split('.'))

    if ($aVersion.GetUpperBound(0) -ge 0)
    {
        $iMajorVersion = $aVersion[0]
    }

    if ($aVersion.GetUpperBound(0) -ge 1)
    {
        $iMinorVersion = $aVersion[1]
    }

    if ($iMajorVersion -eq 6)
    {
        if ($iMinorVersion -eq 0)
        {
            Return $false
        }
    }

    [int] $x86 = 0
    [int] $x64 = 9
    $iArch = @(Get-WmiObject -Query 'SELECT * FROM Win32_Processor')[0].Architecture
    Write-Log ('OS Architecture (0=x86) (9=x64): ' + $iArch) -Log $Log
    if (($iArch -ne $x86) -and ($iArch -ne $x64))
    {
        Return $false
    }

    Return $true
}

Function Install-WPT
{
    param([string] $Log = '.\Clue.log')
    Write-Log ('[Install-WPT] Installing WPT...') -Log $Log
    switch ($Env:PROCESSOR_ARCHITECTURE)
    {
        'x86'   {.\x86\WPTx86-x86_en-us.msi /quiet}
        'AMD64' {.\x64\WPTx64-x86_en-us.msi /quiet}
        'ARM'   {.\ARM\WPTarm-arm_en-us.msi /quiet}
        default {.\x86\WPTx86-x86_en-us.msi /quiet}
    }
    Write-Log ('[Install-WPT] Installing WPT...Done!') -Log $Log
}

Function ConvertToDataType
{
	param([double] $ValueAsDouble, [string] $DataTypeAsString = 'integer', [string] $Log = '.\Clue.log')
	$sDateType = $DataTypeAsString.ToLower()

    If ((Test-Numeric -Value $ValueAsDouble -Log $Log) -eq $True)
    {
    	switch ($sDateType)
    	{
    		'integer' {[Math]::Round($ValueAsDouble,0)}
    		'round1' {[Math]::Round($ValueAsDouble,1)}
    		'round2' {[Math]::Round($ValueAsDouble,2)}
    		'round3' {[Math]::Round($ValueAsDouble,3)}
    		'round4' {[Math]::Round($ValueAsDouble,4)}
    		'round5' {[Math]::Round($ValueAsDouble,5)}
    		'round6' {[Math]::Round($ValueAsDouble,6)}
    		default {$ValueAsDouble}
    	}
    }
    Else
    {
        $ValueAsDouble
    }
}

Function New-PoolmonLog
{
    param([string] $OutputDirectory = 'C:\ClueOutput', [string] $Log = '.\Clue.log')

    $OutputFilePath = $OutputDirectory + '\poolmon.log'
    $oArch = gwmi Win32_OperatingSystem | Select OSArchitecture
    Test-Error -Err $Error -Log $Log

    if ($oArch -isnot [System.Management.Automation.PSCustomObject])
    {
        Return ''
    }
    [string] $sBit = $oArch.OSArchitecture.ToString()
    [string] $sTimeStamp = "$(Get-Date -Format 'yyyy.MM.dd-HH:mm:ss') $([TimeZoneInfo]::Local.ID) (local time of the PC where this was collected)"
    $sTimeStamp | Set-Content $OutputFilePath -Encoding Ascii
    Test-Error -Err $Error -Log $Log
    If ($sBit -eq '64-bit')
    {
        [string] $sCmd = '.\x64\poolmon.exe -n ' + $OutputFilePath + ' -b -r'
    }
    Else
    {
        [string] $sCmd = '.\x86\poolmon.exe -n ' + $OutputFilePath + ' -b -r'
    }
    Write-Log ('[Get-PoolmonLog] sCmd: ' + $sCmd) -Log $Log
    Invoke-Expression -Command $sCmd
    Test-Error -Err $Error -Log $Log
    Return $OutputFilePath
}

Function Get-TopPoolTags
{
    param([string] $OutputDirectory = 'C:\ClueOutput', [Int] $iTopTags = 2, [string] $Log = '.\Clue.log')

    #// Returns a hash table of the top pool tags
    #// xperf allows up to 4 pool tags. $iTopTags of 2 is two tags from Paged and Nonp.

    If ($iTopTags -le 0) {Return ''}

    $htPoolTags = @{}

    [string] $sFilePathToPoolSnapLog = New-PoolmonLog -OutputDirectory $OutputDirectory -Log $Log

    If (Test-Path -Path $sFilePathToPoolSnapLog)
    {
        $oPoolSnapLog = Get-Content -Path $sFilePathToPoolSnapLog
    }
    Else
    {
        Return ''
    }

    $PoolPagedTags = New-Object System.Collections.ArrayList
    $PoolNonPagedTags = New-Object System.Collections.ArrayList

    :PoolSnapLogLoop ForEach ($Line in $oPoolSnapLog)
    {
        If (($PoolPagedTags.Count -lt $iTopTags) -or ($PoolNonPagedTags.Count -lt $iTopTags))
        {
            If ($Line.Contains('Paged'))
            {
                If ($PoolPagedTags.Count -lt $iTopTags)
                {
                    $aLine = $Line.Split('',[StringSplitOptions]'RemoveEmptyEntries')
                    [string] $sTag = $aLine[0]
                    [void] $PoolPagedTags.Add($sTag)
                }
            }

            If ($Line.Contains('Nonp'))
            {
                If ($PoolNonPagedTags.Count -lt $iTopTags)
                {
                    $aLine = $Line.Split('',[StringSplitOptions]'RemoveEmptyEntries')
                    [string] $sTag = $aLine[0]
                    [void] $PoolNonPagedTags.Add($sTag)
                }
            }
        }
        Else
        {
            Break PoolSnapLogLoop;
        }
    }

    [string] $sPoolPagedTags = $PoolPagedTags -join '+'
    [string] $sPoolNonPagedTags = $PoolNonPagedTags -join '+'
    [string] $sTopPoolTags = [string]::Join('+', ($sPoolPagedTags,$sPoolNonPagedTags))
    Return $sTopPoolTags
}

Function Get-TagsToDrivers
{
    param([string] $Tags, [string] $Log = '.\Clue.log')
    #// expecting TAG+TAG+TAG
    $oDrivers = @()
    $aTags = $Tags.Split('+',[StringSplitOptions]'RemoveEmptyEntries')
    foreach ($sTag in $aTags)
    {
        $aDriverFilePaths = Get-WmiObject -Query 'SELECT PathName FROM Win32_SystemDriver' | foreach {$_.PathName -replace '\\\?\?\\',''}
        $oDriverFiles = $aDriverFilePaths | foreach {Get-ChildItem $_}
        foreach ($oDriverFile in $oDriverFiles)
        {
            if (Select-String -Path $oDriverFile.FullName -Pattern $sTag -CaseSensitive -Quiet)
            {
                [string] $sWmiFilePath = $oDriverFile.FullName -replace '\\','\\'
                [string] $sWql = 'SELECT * FROM CIM_DataFile WHERE Name = "' + $sWmiFilePath + '"'
                $oMatchedDrivers = Get-WmiObject -Query $sWql | Select Manufacturer, Version, LastModified
                foreach ($oMatchedDriver in $oMatchedDrivers)
                {
                    $oNewObject = New-Object System.Object
                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'PoolTag' -Value $([System.String] $sTag)
                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Path' -Value $([System.String] $oDriverFile.FullName)
                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Manufacturer' -Value $([System.String] $oMatchedDriver.Manufacturer)
                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Version' -Value $([System.String] $oMatchedDriver.Version)
                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'LastModified' -Value $([System.String] $oMatchedDriver.LastModified)
                    $oDrivers += $oNewObject
                }
            }
        }
    }
    $oDrivers
    #$oDrivers | Export-Csv -Path $OutputFilePath -NoTypeInformation
}

Function Convert-UncPathToObject
{
    param([string] $UncPath, [string] $Log = '.\Clue.log')

    $pattern = '\\\\(?<srv>[^\(^\)]*)\\(?<shr>.*\s?(\(.*\))?)'

    If ($UncPath -match $pattern)
    {
        [string] $sComputer = $matches["srv"]
        [string] $sShare = $matches["shr"]
        $oUnc = New-Object System.Object
        Add-Member -InputObject $oUnc -MemberType NoteProperty -Name 'Computer' -Value $matches["srv"]
        Add-Member -InputObject $oUnc -MemberType NoteProperty -Name 'Share' -Value $matches["shr"]
        Return $oUnc
    }    
}

Function Test-UncPath
{
    param([string] $UncPath, [string] $Log = '.\Clue.log')
    $oUnc = Convert-UncPathToObject -UncPath $UncPath
    If ($oUnc -eq $null)
    {
        Return $false
    }

    If (($oUnc.Computer -eq '') -or ($oUnc.Share -eq ''))
    {
        Return $false
    }
    Else
    {
        Return $true
    }
}

Function Test-MyProcessExit
{
    param([int] $iPid, [string] $Log = '.\Clue.log')

    if (Test-Numeric -Value $iPid -Log $Log)
    {
        Do
        {
            Start-Sleep -Seconds 1
        } Until (@(Get-Process | Where {$_.Id -eq $iPid}).Count -eq 0)
    }
}

Function Get-ClintOsArchitecture
{
    param([string] $Log = '.\Clue.log')
    $oOs = Get-WmiObject -Query 'SELECT * FROM Win32_OperatingSystem' -ErrorAction SilentlyContinue
    if ($oOs -is [System.Management.ManagementObject])
    {
        Return $oOs.OSArchitecture
    } else {Return 0}
}

Function Start-ProcDumpOnProcessNameCH
{
    param([string] $ProcessName, [string] $OutputFolder = 'C:\ClueOutput', [string] $Log)
    Write-Log ('[Start-ProcDumpOnProcessNameCH] ProcessName: ' + $ProcessName) -Log $Log
    Write-Log ('[Start-ProcDumpOnProcessNameCH] OutputFolder: ' + $OutputFolder) -Log $Log
    Write-Log ('[Start-ProcDumpOnProcessNameCH] Log: ' + $Log) -Log $Log
    $ProcessName = $ProcessName -replace '.exe',''
    $oProcesses = Get-Process | Where-Object {$_.Name -eq $ProcessName}
    ForEach ($oProcess in $oProcesses)
    {
        [string] $sCmd = '.\sysint\procdump.exe -ma ' + $oProcess.Id + ' "' + $OutputFolder + '\' + $ProcessName + '-' + $oProcess.Id + '.dmp" -accepteula'
        Write-Log ('[Start-ProcDumpOnProcessNameCH] sCmd: ' + $sCmd) -Log $Log
        $Output = Invoke-Expression -Command $sCmd
        Write-Log ($Output) -Log $Log
        Test-Error -Err $Error -Log $Log
    }
}

Function Add-WprTraceMarkerCH
{
    param([string] $Name ,[string] $Log)
    Write-Log ('[Add-WprTraceMarkerCH] Name: ' + $Name) -Log $Log
    Write-Log ('[Add-WprTraceMarkerCH] Log: ' + $Log) -Log $Log
    [string] $sCmd = 'wpr.exe -marker "' + $Name + '"'
    Write-Log ('[Add-WprTraceMarkerCH] sCmd: ' + $sCmd) -Log $Log
    $Output = Invoke-Expression -Command $sCmd -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    Write-Log ($Output) -Log $Log
    Test-Error -Err $Error -Log $Log
}