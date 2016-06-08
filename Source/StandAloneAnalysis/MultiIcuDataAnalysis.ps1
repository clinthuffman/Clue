#requires -Version 2.0
<#
    .SYNOPSIS
    Opens ICU zip files, analyzes the data, and appends the root causes to the name of the zip file.
    .DESCRIPTION
    Point this script to a folder that contains ICU zip files. It opens each ICU zip file, analyzes the data, and appends the root causes to the name of the zip file.
    .EXAMPLE
    .\02_MultiIcuDataAnalysis.ps1 -Path \\server\ICU
    This will open each zip file under \\server\ICU, analyze the data in the zip file, and append the causes to the file name.
    .Parameter Path
    This parameters is required and is expected to be a folder path or a path to a network share. Do not put a backslash on the end.
    .Notes
    Name: 02_MultiIcuDataAnalysis.ps1
    Author: Clint Huffman (clinth@microsoft.com)
    LastEdit: June 11th, 2015
	Version: 1.0
    Keywords: PowerShell, ICU
#>
param([string] $Path)

$global:WpaExporterFolder = ''
$global:alCauses = New-Object System.Collections.ArrayList

Function PostProcessing
{
    
    $alFilteredCauses = New-Object System.Collections.ArrayList
    for ($c = 0; $c -lt $global:alCauses.Count;$c++)
    {
        $alSubFilteredCauses = New-Object System.Collections.ArrayList
        [string] $sEntry = $global:alCauses[$c]

        $aLine = $sEntry.Split('+',[StringSplitOptions]'RemoveEmptyEntries')

        for ($i = 0; $i -le $aLine.GetUpperBound(0); $i++)
        {
            [string] $sText = $aLine[$i]

            [bool] $bOmitItem = $false
            $aNullList = @('system','kernel','N/A','idle','ICU','xperf','Nicholas','HarddiskVolume1','{')
            foreach ($n in $aNullList)
            {
                if ($sText -match $n)
                {
                    $bOmitItem = $true
                }
            }

            $sText = $sText -ireplace 'Unknown (0x0)','Unknown'
            $sText = $sText -ireplace '\$mft','SymantecRescan'
            $sText = $sText -ireplace 'wuauserv','WindowsUpdate'
            $sText = $sText -ireplace 'ccsvchst','SymantecCcSvcHst'
            $sText = $sText -ireplace 'symefa','SymantecSymEfaDb'
            $sText = $sText -ireplace 'atpi','SymantecAtpiDb'
            $sText = $sText -ireplace 'virscan7','SymantecVirScanDat'

            if ($bOmitItem -eq $false)
            {
                [void] $alSubFilteredCauses.Add($sText)
            }

        }

        if ($alSubFilteredCauses.Count -gt 1)
        {
            [string] $sEntry = $alSubFilteredCauses -join '+'
            [void] $alFilteredCauses.Add($sEntry)
        }
    }
    Return $alFilteredCauses -join ','
}

Function AddToCauses
{
    param([string] $Item)
    
    if ($global:alCauses.Contains($Item) -eq $false)
    {
        [void] $global:alCauses.Add($Item)
    }
}

Function TrimCharacter
{
    param([string] $TextString, [string] $Char)

    if (($TextString -eq '') -or ($TextString.Length -eq 0))
    {
        Return $TextString
    }

    Do
    {
        if ($TextString.Length -lt 1)
        {
            Return ''
        }

        [string] $FirstChar = $TextString.Substring(0,1)
        if ($FirstChar -eq $Char)
        {
            $TextString = $TextString.Substring(1)
        }
    } until (($FirstChar -ne $Char))

    Do
    {
        if ($TextString.Length -lt 1)
        {
            Return ''
        }

        [int] $iLen = $TextString.Length - 1
        [string] $LastChar = $TextString.Substring($iLen,1)
        if ($LastChar -eq $Char)
        {
            $TextString = $TextString.Substring(0,$iLen)
        }
    } until ($LastChar -ne $Char)

    Return $TextString
}

Function ResolveIcuRuleText
{
    param([string] $RuleText)

    if ($RuleText -imatch 'DiskLatency') {$RuleText = 'DiskLatency'}
    if ($RuleText -imatch 'DiskCapacity') {$RuleText = 'DiskCapacity'}
    if ($RuleText -imatch 'DiskFree') {$RuleText = 'DiskCapacity'}
    if ($RuleText -imatch 'Processor') {$RuleText = 'Processor'}
    if ($RuleText -imatch 'Privileged') {$RuleText = 'Processor'}
    if ($RuleText -imatch 'PhysicalMemory') {$RuleText = 'PhysicalMemory'}
    if ($RuleText -imatch 'AvailableMBytes') {$RuleText = 'PhysicalMemory'}
    if ($RuleText -imatch 'Committed') {$RuleText = 'CommittedMemory'}
    if ($RuleText -imatch 'Pool') {$RuleText = 'MemoryPool'}
    if ($RuleText -imatch 'Network') {$RuleText = 'Network'}
    if ($RuleText -imatch 'UserInitiated') {$RuleText = 'UserInitiated'}
    Return $RuleText.ToLower()
}

Function GetTopPoolTags
{
    param([int] $iPoolType = 2, [Int] $iTopTags = 3)

    #// $iPoolType: 0 = Nonp, 1 = Paged, 2+ = both

    #// Returns a hash table of the top pool tags
    #// xperf allows up to 4 pool tags. $iTopTags of 2 is two tags from Paged and Nonp.

    $oPoolSnapFile = Get-ChildItem $global:sTempFolder\*poolsnap.log -Recurse
    if ($oPoolSnapFile -eq $null)
    {
        Return ''
    }

    $sFilePathToPoolSnapLog = $oPoolSnapFile.FullName

    If ($iTopTags -le 0) {Return ''}

    $htPoolTags = @{}

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

    [bool] $IsLessThanThreshold = $false
    :PoolSnapLogLoop ForEach ($Line in $oPoolSnapLog)
    {
        If (($PoolPagedTags.Count -lt $iTopTags) -or ($PoolNonPagedTags.Count -lt $iTopTags))
        {
            If ($Line.Contains('Paged'))
            {
                If (($PoolPagedTags.Count -lt $iTopTags) -and ($IsLessThanThreshold -eq $false))
                {
                    $aLine = $Line.Split(' ',[StringSplitOptions]'RemoveEmptyEntries')

                    if ($aLine.Count -gt 0)
                    {
                        [string] $sTag = $aLine[0]
                    }

                    if ($aLine.Count -gt 5)
                    {
                        [uint64] $Bytes = $aLine[5]
                        if ($Bytes -gt 100MB)
                        {
                            [void] $PoolPagedTags.Add($sTag)
                        }
                        Else
                        {
                            $IsLessThanThreshold = $true
                        }
                    }
                }
            }

            If ($Line.Contains('Nonp'))
            {
                If (($PoolNonPagedTags.Count -lt $iTopTags) -and ($IsLessThanThreshold -eq $false))
                {
                    $aLine = $Line.Split(' ',[StringSplitOptions]'RemoveEmptyEntries')

                    if ($aLine.Count -gt 0)
                    {
                        [string] $sTag = $aLine[0]
                        if ($sTag -ne 'EtwB')
                        {
                            if ($aLine.Count -gt 5)
                            {
                                [uint64] $Bytes = $aLine[5]
                                if ($Bytes -gt 100MB)
                                {
                                    [void] $PoolNonPagedTags.Add($sTag)
                                }
                                Else
                                {
                                    $IsLessThanThreshold = $true
                                }
                            }
                        }
                    }
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

    switch ($iPoolType)
    {
        0 {[string] $sTopPoolTags = [string]::Join('+', $sPoolNonPagedTags)}
        1 {[string] $sTopPoolTags = [string]::Join('+', $sPoolPagedTags)}
        2 {[string] $sTopPoolTags = [string]::Join('+', ($sPoolPagedTags,$sPoolNonPagedTags))}
        Else {[string] $sTopPoolTags = [string]::Join('+', ($sPoolPagedTags,$sPoolNonPagedTags))}
    }
    TrimCharacter -TextString $sTopPoolTags -Char '+'
}

Function IsNumeric
{
    param($Value)
    [double]$number = 0
    $result = [double]::TryParse($Value, [REF]$number)
    $result
}

Function Get-UserTempDirectory()
{
	$DirectoryPath = Get-ChildItem env:temp	
	Return $DirectoryPath.Value
}

Function TasklistTxtToObject
{
    param([string] $PathToTasklistTxt = '') 

    if ($PathToTasklistTxt -eq '') {Return $null}

    if ($(Test-Path -Path $PathToTasklistTxt) -eq $false) {Return $null}

    $oTaskListFile = Get-Content $PathToTasklistTxt
    [int] $iLenImageName = 0
    [int] $iLenPid = 0
    [int] $iLenServices = 0
    [string] $sImageName = ''
    [string] $sPid = ''
    [string] $sServices = ''

    [string] $sPrevImageName = ''
    [string] $sPrevPid = ''

    $oProcesses = @()

    foreach ($sLine in $oTasklistFile)
    {
        if (($iLenImageName -gt 0) -and ($iLenPid -gt 0) -and ($iLenServices -gt 0))
        {
            [int] $iBeginOfImageName = 0
            [int] $iBeginOfPid = $iBeginOfImageName + $iLenImageName + 1
            [int] $iBeginOfServices = $iBeginOfPid + $iLenPid + 1
            [string] $sTempImageName = $sLine.Substring($iBeginOfImageName,$iLenImageName).Trim()
            [string] $sTempPid = $sLine.Substring($iBeginOfPid,$iLenPid).Trim()
            [string] $sTempServices = $sLine.Substring($iBeginOfServices,$iLenServices).Trim()

            if ($sTempImageName -ne '')
            {
                if ($sImageName -ne '')
                {
                    $oProcess = New-Object pscustomobject
                    Add-Member -InputObject $oProcess -MemberType NoteProperty -Name 'ImageName' -Value $([string] $sImageName.Trim())
                    Add-Member -InputObject $oProcess -MemberType NoteProperty -Name 'PID' -Value $([string] $sPid.Trim())
                    Add-Member -InputObject $oProcess -MemberType NoteProperty -Name 'Services' -Value $([string] $sServices.Trim())
                    $oProcesses += $oProcess
                }
                [string] $sImageName = $sTempImageName
                [string] $sPid = $sTempPid
                [string] $sServices = $sTempServices
            }
            else
            {
                $sServices = $sServices + $sTempServices
            }
        }

        if ($sLine -match '========')
        {
            $aLine = $sLine.Split(' ',[StringSplitOptions]'RemoveEmptyEntries')
            [int] $iLenImageName = $aLine[0].Length
            [int] $iLenPid = $aLine[1].Length
            [int] $iLenServices = $aLine[2].Length
        }
    }

    #// For the last line
    $oProcess = New-Object pscustomobject
    Add-Member -InputObject $oProcess -MemberType NoteProperty -Name 'ImageName' -Value $([string] $sImageName)
    Add-Member -InputObject $oProcess -MemberType NoteProperty -Name 'PID' -Value $([string] $sPid)
    Add-Member -InputObject $oProcess -MemberType NoteProperty -Name 'Services' -Value $([string] $sServices)
    $oProcesses += $oProcess

    Return $oProcesses
}

Function LookUpSvchost
{
    param([string] $sPid)
    $sSearchPath = $sTempFolder + '\*Tasklist.csv'
    $oTasklist = Get-ChildItem -Path $sSearchPath -Recurse
    if ($oTasklist -eq $null)
    {
        $sSearchPath = $sTempFolder + '\*Tasklist.txt'    
        $oTasklist = Get-ChildItem -Path $sSearchPath -Recurse

        if ($oTasklist -eq $null)
        {
            Return New-Object System.Collections.ArrayList
        }
    }

    if ($oTasklist.Extension -eq '.txt')
    {
        $oSvcs = TasklistTxtToObject -PathToTasklistTxt $oTasklist.FullName
        $oRecord = $oSvcs | WHERE {$_.PID -eq $sPid}
        [string] $sSvcs = $oRecord.Services
        $sSvcs = $sSvcs -replace ' ',''
        $aSvcs = $sSvcs.Split(',',[StringSplitOptions]'RemoveEmptyEntries')
        Return $aSvcs
    }

    if ($oTasklist.Extension -eq '.csv')
    {
        $oCsv = Import-Csv -Path $oTaskList.FullName
        $oRecord = $oCsv | WHERE {$_.PID -eq $sPid}
        [string] $sSvcs = $oRecord.Services
        $aSvcs = $sSvcs.Split(',',[StringSplitOptions]'RemoveEmptyEntries')
        Return $aSvcs
    }
}

Function RemoveFileExt
{
    param([string] $sText)
    
    if ($sText.Contains('.'))
    {
        $aText = $sText.Split('.')
        Return $aText[0].Trim()
    }
    Else
    {
        Return $sText.Trim()
    }
}

Function RemoveParensAndExeFromProcess
{
    param([string] $sText)

    [string] $sNewString = ''
    if ($sText -match '\(' )
    {
        $aText = $sText.Split('\(')
        $sNewString = $aText[0]
        if ($sNewString.Contains('svchost'))
        {
            $sPid = $aText[1].Replace(')','')
            $aSvcs = @(LookUpSvchost -sPid $sPid)
            $sNewString = $aSvcs -join '+'
            if ($sNewString.Contains('CscService'))
            {
                $sNewString = 'CscService'
            }

            if ($sNewString.Contains('wuauserv'))
            {
                $sNewString = 'wuauserv'
            }

            if ($sNewString.Contains('Winmgmt'))
            {
                $sNewString = 'Winmgmt'
            }

            if ($sNewString.Contains('+'))
            {
                [string] $sSvcs = 'Svc+'
                foreach ($s in $aSvcs)
                {
                    $c = $s.Substring(0,1)
                    $sSvcs = $sSvcs + $c
                }
                $sNewString = $sSvcs
            }
        }
        Else
        {
            $sNewString = RemoveFileExt -sText $sNewString
        }
    }
    Else
    {
        $sNewString = $sText
    }

    $sNewString = TrimCharacter -TextString $sNewString -Char '+'
    $sNewString = TrimCharacter -TextString $sNewString -Char ','
    $sNewString = $sNewString.Trim()
    Return $sNewString
}

Function ParseCpuTopProcesses
{
    param([string] $sFilePath)
    [string] $sReturn = ''
    if (Test-Path -Path $sFilePath)
    {
        $aLines = Get-Content -Path $sFilePath -TotalCount 4 | SELECT -Skip 1
        foreach ($sLine in $aLines)
        {
            $aLine = $sLine -split ','
            [string] $sProcess = $aLine[0]
            [double] $dValue = $aLine[1]

            if ($dValue -gt 10)
            {
                $sProcess = RemoveParensAndExeFromProcess -sText $sProcess
                if ($sProcess -ne 'Idle')
                {
                    $sReturn = $sReturn + $sProcess + '+'
                }            
            }
        }
    }
    $sReturn = TrimCharacter -TextString $sReturn -Char '+'
    Return $sReturn
}

Function ParseDiskTopProcesses
{
    param([string] $sFilePath)
    [string] $sReturn = ''

    if ($sFilePath -ne '')
    {
        if (Test-Path -Path $sFilePath)
        {    
            $aLines = Get-Content -Path $sFilePath -TotalCount 4 | SELECT -Skip 1
            foreach ($sLine in $aLines)
            {
                $aLine = $sLine -split ','
                [string] $sProcess = $aLine[0]
                [double] $dValue = $aLine[1]

                if ($dValue -gt 2000000)
                {
                    $sProcess = RemoveParensAndExeFromProcess -sText $sProcess
                    $sReturn = $sReturn + $sProcess + '+'
                }
            }
        }
    }
    $sReturn = TrimCharacter -TextString $sReturn -Char '+'
    Return $sReturn
}

Function ParseDiskTopFiles
{
    param([string] $sFilePath)
    [string] $sReturn = ''

    if ($sFilePath -ne '')
    {
        if (Test-Path -Path $sFilePath)
        {
            $aLines = Get-Content -Path $sFilePath -TotalCount 4 | SELECT -Skip 1
            foreach ($sLine in $aLines)
            {
                $aLine = $sLine -split ','
                [string] $sPath = $aLine[0]
                [double] $dValue = $aLine[1]

                $aPath = $sPath -split '\\'
                $u = $aPath.GetUpperBound(0)
                $sFile = $aPath[$u]

                if ($dValue -gt 2000000)
                {
                    $sFile = RemoveFileExt -sText $sFile
                    $sReturn = $sReturn + $sFile + '+'
                }
            }
        }
    }
    $sReturn = TrimCharacter -TextString $sReturn -Char '+'
    Return $sReturn
}

Function EtlAnalysis
{
    param($oEtls,[string] $sIcuTrigger)

    [string] $WorkingDirectory = $PWD

    if ($global:WpaExporterFolder -eq '')
    {
        $oWpaExporterExeFile = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\8.1\Windows Performance Toolkit\wpaexporter.exe'
        if ($oWpaExporterExeFile -eq $null)
        {
            $oWpaExporterExeFile = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\*wpaexporter.exe' -Recurse
        }

        if ($oWpaExporterExeFile -eq $null)
        {
            #[void] $global:alCauses.Add('Etl+ErrorNoWpaExporter')
            AddToCauses -Item 'Etl+ErrorNoWpaExporter'
            Return
            #Return 'ERROR+NoWpaExporter'
        }
        else
        {
            [string] $global:WpaExporterFolder = $oWpaExporterExeFile.DirectoryName
        }
    }
    Set-Location $global:WpaExporterFolder
    [string] $sReturn = ''

    foreach ($oFile in $oEtls)
    {
        if ($oFile.FullName -notmatch 'EventLogs')
        {
            [string] $sEtlFilePath = $oFile.FullName

            switch ($sIcuTrigger)
            {
                'disklatency' 
                {
                    [string] $sOutputFolder = $oFile.DirectoryName + '\DiskTopProcesses'
                    [string] $WpaProfileFilePath = $WorkingDirectory + '\DiskTopProcesses.wpaProfile'
                    [string] $sCmd = '.\wpaexporter.exe -i "' + $sEtlFilePath + '" -profile "' + $WpaProfileFilePath  + '" -outputfolder "' + $sOutputFolder + '" -tti'
                    $null = Invoke-Expression -Command $sCmd -ErrorAction SilentlyContinue
                    $oCsvFile = Get-ChildItem $sOutputFolder\*.csv
                    if ($oCsvFile -ne $null)
                    {
                        $sDiskTopProcesses = ParseDiskTopProcesses -sFilePath $oCsvFile.FullName
                        if ($sDiskTopProcesses -ne '')
                        {
                            $sDiskTopProcesses = 'DiskProcesses+' + $sDiskTopProcesses
                            $sDiskTopProcesses = TrimCharacter -TextString $sDiskTopProcesses -Char '+'
                            $sDiskTopProcesses = TrimCharacter -TextString $sDiskTopProcesses -Char ','
                            #[void] $global:alCauses.Add($sDiskTopProcesses)
                            AddToCauses -Item $sDiskTopProcesses
                        }
                    }
                    else
                    {
                        $sDiskTopProcesses = 'DiskProcesses+ErrorEtlParsing'
                        #[void] $global:alCauses.Add($sDiskTopProcesses)
                        AddToCauses -Item $sDiskTopProcesses
                    }

                    [string] $sOutputFolder = $oFile.DirectoryName + '\DiskTopFiles'
                    [string] $WpaProfileFilePath = $WorkingDirectory + '\DiskTopFiles.wpaProfile'
                    [string] $sCmd = '.\wpaexporter.exe -i "' + $sEtlFilePath + '" -profile "' + $WpaProfileFilePath  + '" -outputfolder "' + $sOutputFolder + '" -tti'
                    $null = Invoke-Expression -Command $sCmd -ErrorAction SilentlyContinue
                    $oCsvFile = Get-ChildItem $sOutputFolder\*.csv
                    if ($oCsvFile -ne $null)
                    {
                        $sDiskTopFiles = ParseDiskTopFiles -sFilePath $oCsvFile.FullName
                        if ($sDiskTopFiles -ne '')
                        {
                            $sDiskTopFiles = 'DiskFiles+' + $sDiskTopFiles
                            $sDiskTopFiles = TrimCharacter -TextString $sDiskTopFiles -Char '+'
                            $sDiskTopFiles = TrimCharacter -TextString $sDiskTopFiles -Char ','
                            #[void] $global:alCauses.Add($sDiskTopFiles)
                            AddToCauses -Item $sDiskTopFiles
                        }
                    }
                    else
                    {
                        $sDiskTopFiles = 'DiskFiles+ErrorEtlParsing'
                        #[void] $global:alCauses.Add($sDiskTopFiles)
                        AddToCauses -Item $sDiskTopFiles
                    }
                }

                'processor'
                {
                    [string] $sOutputFolder = $oFile.DirectoryName + '\CpuTopProcesses'
                    [string] $WpaProfileFilePath = $WorkingDirectory + '\CpuTopProcesses.wpaProfile'
                    [string] $sCmd = '.\wpaexporter.exe -i "' + $sEtlFilePath + '" -profile "' + $WpaProfileFilePath  + '" -outputfolder "' + $sOutputFolder + '" -tti'
                    $null = Invoke-Expression -Command $sCmd -ErrorAction SilentlyContinue
                    $oCsvFile = Get-ChildItem $sOutputFolder\*.csv
                    if ($oCsvFile -ne $null)
                    {
                        $sCpuTopProcesses = ParseCpuTopProcesses -sFilePath $oCsvFile.FullName
                        if ($sCpuTopProcesses -ne '')
                        {
                            $sCpuTopProcesses = 'CpuProcesses+' + $sCpuTopProcesses
                            $sCpuTopProcesses = TrimCharacter -TextString $sCpuTopProcesses -Char ','
                            $sCpuTopProcesses = TrimCharacter -TextString $sCpuTopProcesses -Char '+'
                            #[void] $global:alCauses.Add($sCpuTopProcesses)
                            AddToCauses -Item $sCpuTopProcesses
                        }
                    }
                }
            }
        }
    }

    Set-Location $WorkingDirectory
    Return $sReturn
}

Function CounterPathToObject
{
    param($sCounterPath)

    $pattern = '(?<srv>\\\\[^\\]*)?\\(?<obj>[^\(^\)]*)(\((?<inst>.*(\(.*\))?)\))?\\(?<ctr>.*\s?(\(.*\))?)'

    $oCtr = New-Object System.Object

    If ($sCounterPath -match $pattern)
    {
        [string] $sComputer = $matches["srv"]
        If ($sComputer -ne '')
        {$sComputer = $sComputer.Substring(2)}
        Add-Member -InputObject $oCtr -MemberType NoteProperty -Name 'Computer' -Value $sComputer
        Add-Member -InputObject $oCtr -MemberType NoteProperty -Name 'Object' -Value $matches["obj"]
        Add-Member -InputObject $oCtr -MemberType NoteProperty -Name 'Instance' -Value $matches["inst"]
        Add-Member -InputObject $oCtr -MemberType NoteProperty -Name 'Name' -Value $matches["ctr"]
    }
    Return $oCtr
}

Function ExtractZip
{
    param([string] $sZipFilePath, [string] $sExtractFolder)
    $shell = new-object -com shell.application
    $zip = $shell.NameSpace($sZipFilePath)
    foreach($item in $zip.items())
    {
        $shell.Namespace($sExtractFolder).copyhere($item)
    }
}

Function BlgAnalysis
{
    param($oBlgs, [string] $sIcuTrigger)

        [string] $sAppendToZipFile = ''

        $alInstances = New-Object System.Collections.ArrayList
        $alProcessNamesOrServices = New-Object System.Collections.ArrayList
        $htInstanceToPid = @{}

        foreach ($oFile in $oBlgs)
        {
            switch ($sIcuTrigger)
            {
                'physicalmemory'
                {
                    [bool] $IsPoolPagedHigh = $false
                    [bool] $IsPoolNonPagedHigh = $false
                    [bool] $IsHighSystemCache = $false
                    [bool] $IsWindowsUpdate = $false

                    Try
                    {
                        [bool] $IsLogLoaded = $false
                        [string] $sCounterLogFilePath = $ofile.FullName
                        $oLog = Import-counter -Path $sCounterLogFilePath -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

                        foreach ($oCounterSample in $oLog.CounterSamples)
                        {
                            $IsLogLoaded = $true
                            if ($oCounterSample.Path -match 'id process')
                            {
                                if ($htInstanceToPid.ContainsKey($oCounterSample.Path) -eq $false)
                                {
                                    [void] $htInstanceToPid.Add($oCounterSample.Path,$oCounterSample.CookedValue)
                                }
                            }

                            if ($oCounterSample.Path -match 'working set')
                            {
                                if (($oCounterSample.InstanceName -ne '_total') -and ($oCounterSample.Path -notmatch 'peak'))
                                {
                                    If ($oCounterSample.CookedValue -gt 500MB)
                                    {
                                        If ($alInstances.Contains($oCounterSample.Path) -eq $false)
                                        {
                                            [void] $alInstances.Add($oCounterSample.Path)
                                        }
                                    }
                                }
                            }

                            If ($IsPoolPagedHigh -eq $false)
                            {
                                if ($oCounterSample.Path -match 'pool paged resident bytes')
                                {
                                    If ($oCounterSample.CookedValue -gt 500MB)
                                    {
                                        $IsPoolPagedHigh = $true
                                    }
                                }
                            }

                            If ($IsPoolNonPagedHigh -eq $false)
                            {
                                if ($oCounterSample.Path -match 'pool nonpaged bytes')
                                {
                                    If ($oCounterSample.CookedValue -gt 500MB)
                                    {
                                        $IsPoolNonPagedHigh = $true
                                    }
                                }
                            }

                            If ($IsHighSystemCache -eq $false)
                            {
                                if ($oCounterSample.Path -match 'system cache resident bytes')
                                {
                                    If ($oCounterSample.CookedValue -gt 500MB)
                                    {
                                        $IsHighSystemCache = $true
                                    }
                                }
                            }
                        }

                        foreach ($sCounterInstance in $alInstances)
                        {
                            $oCtrOfWorkingSet = CounterPathToObject -sCounterPath $sCounterInstance
                            if ($sCounterInstance.Contains('svchost') -eq $true)
                            {
                                :PidLookup foreach ($sKey in $htInstanceToPid.Keys)
                                {
                                    $oCtrOfIdProcess = CounterPathToObject -sCounterPath $sKey
                                    If ($oCtrOfWorkingSet.Instance -eq $oCtrOfIdProcess.Instance)
                                    {
                                        $sPid = $htInstanceToPid[$sKey]
                                        Break PidLookup;
                                    }
                                }
                                $aSvcs = @(LookUpSvchost -sPid $sPid)

                                foreach ($sSvc in $aSvcs)
                                {
                                    if ($alProcessNamesOrServices.Contains($sSvc) -eq $false)
                                    {
                                        [void] $alProcessNamesOrServices.Add($sSvc)
                                    }
                                }
                            }
                            Else
                            {
                                if ($alProcessNamesOrServices.Contains($oCtrOfWorkingSet.Instance) -eq $false)
                                {
                                    [void] $alProcessNamesOrServices.Add($oCtrOfWorkingSet.Instance)
                                }
                            }
                        }

                        if ($IsLogLoaded -eq $false)
                        {
                            $sAppendToZipFile = 'PerfLog+ERROR,'
                        }
                    }
                    Catch
                    {
                        $sAppendToZipFile = 'PerfLog+ERROR,'
                    }

                    If ($IsHighSystemCache -eq $true)
                    {
                        #$sAppendToZipFile = $sAppendToZipFile + 'HighSystemCache' + ','
                        if ($global:alCauses.Contains('HighSystemCache') -eq $false)
                        {
                            #[void] $global:alCauses.Add('HighSystemCache')
                            AddToCauses -Item 'HighSystemCache'
                        }
                    }

                    [string] $sProcessesAndServices = 'PhysicalMemory+'
                    if ($alProcessNamesOrServices.Count -eq 0)
                    {
                        [string] $sProcessesAndServices = $sProcessesAndServices + 'LotsOfSmallProcesses'
                        if ($global:alCauses.Contains('sProcessesAndServices') -eq $false)
                        {
                            #[void] $global:alCauses.Add($sProcessesAndServices)
                            AddToCauses -Item $sProcessesAndServices
                        }
                    }

                    foreach ($ProcessOrService in $alProcessNamesOrServices)
                    {
                        [string] $sText = $ProcessOrService
                        if ($sText.Contains('#'))
                        {
                            $aText = $sText -split '#'
                            $sText = $aText[0]
                        }            
                        $sProcessesAndServices = $sProcessesAndServices + $sText + '+'
                    }
                    $sProcessesAndServices = TrimCharacter -TextString $sProcessesAndServices -Char '+'
                    #$sAppendToZipFile = $sAppendToZipFile + ',' + $sProcessesAndServices
                    #[void] $global:alCauses.Add($sProcessesAndServices)
                    AddToCauses -Item $sProcessesAndServices
                }

                'committedmemory'
                {
                    [bool] $IsPoolPagedHigh = $false
                    [bool] $IsPoolNonPagedHigh = $false
                    [bool] $IsHighSystemCache = $false
                    [bool] $IsWindowsUpdate = $false

                    Try
                    {
                        [bool] $IsLogLoaded = $false
                        [string] $sCounterLogFilePath = $ofile.FullName
                        $oLog = Import-counter -Path $sCounterLogFilePath -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

                        foreach ($oCounterSample in $oLog.CounterSamples)
                        {
                            $IsLogLoaded = $true
                            if ($oCounterSample.Path -match 'id process')
                            {
                                if ($htInstanceToPid.ContainsKey($oCounterSample.Path) -eq $false)
                                {
                                    [void] $htInstanceToPid.Add($oCounterSample.Path,$oCounterSample.CookedValue)
                                }
                            }

                            if ($oCounterSample.Path -match 'private bytes')
                            {
                                if ($oCounterSample.InstanceName -ne '_total')
                                {
                                    If ($oCounterSample.CookedValue -gt 500MB)
                                    {
                                        If ($alInstances.Contains($oCounterSample.Path) -eq $false)
                                        {
                                            [void] $alInstances.Add($oCounterSample.Path)
                                        }
                                    }
                                }
                            }

                            If ($IsPoolPagedHigh -eq $false)
                            {
                                if ($oCounterSample.Path -match 'pool paged bytes')
                                {
                                    If ($oCounterSample.CookedValue -gt 500MB)
                                    {
                                        $IsPoolPagedHigh = $true
                                    }
                                }
                            }

                            If ($IsPoolNonPagedHigh -eq $false)
                            {
                                if ($oCounterSample.Path -match 'pool nonpaged bytes')
                                {
                                    If ($oCounterSample.CookedValue -gt 500MB)
                                    {
                                        $IsPoolNonPagedHigh = $true
                                    }
                                }
                            }
                        }

                        foreach ($sCounterInstance in $alInstances)
                        {
                            $oCtrOfPrivateBytes = CounterPathToObject -sCounterPath $sCounterInstance
                            if ($sCounterInstance.Contains('svchost') -eq $true)
                            {
                                :PidLookup foreach ($sKey in $htInstanceToPid.Keys)
                                {
                                    $oCtrOfIdProcess = CounterPathToObject -sCounterPath $sKey
                                    If ($oCtrOfPrivateBytes.Instance -eq $oCtrOfIdProcess.Instance)
                                    {
                                        $sPid = $htInstanceToPid[$sKey]
                                        Break PidLookup;
                                    }
                                }
                                $aSvcs = @(LookUpSvchost -sPid $sPid)

                                foreach ($sSvc in $aSvcs)
                                {
                                    if ($alProcessNamesOrServices.Contains($sSvc) -eq $false)
                                    {
                                        [void] $alProcessNamesOrServices.Add($sSvc)
                                    }
                                }
                            }
                            Else
                            {
                                if ($alProcessNamesOrServices.Contains($oCtrOfPrivateBytes.Instance) -eq $false)
                                {
                                    [void] $alProcessNamesOrServices.Add($oCtrOfPrivateBytes.Instance)
                                }
                            }
                        }

                        if ($IsLogLoaded -eq $false)
                        {
                            #$sAppendToZipFile = 'PerfLog+ERROR'
                            if ($global:alCauses.Contains('PerfLog+ERROR') -eq $false)
                            {
                                #[void] $global:alCauses.Add('PerfLog+ERROR')
                                AddToCauses -Item 'PerfLog+Error'
                            }
                        }
                    }
                    Catch
                    {
                        if ($global:alCauses.Contains('PerfLog+ERROR') -eq $false)
                        {
                            #[void] $global:alCauses.Add('PerfLog+ERROR')
                            AddToCauses -Item 'PerfLog+Error'
                        }
                    }

                    [string] $sProcessesAndServices = 'CommittedMemory+'
                    if ($alProcessNamesOrServices.Count -eq 0)
                    {
                        [string] $sProcessesAndServices = $sProcessesAndServices + 'LotsOfSmallProcesses'
                        #[void] $global:alCauses.Add($sProcessesAndServices)
                        AddToCauses -Item $sProcessesAndServices
                    }

                    foreach ($ProcessOrService in $alProcessNamesOrServices)
                    {
                        [string] $sText = $ProcessOrService
                        if ($sText.Contains('#'))
                        {
                            $aText = $sText -split '#'
                            $sText = $aText[0]
                        }            
                        $sProcessesAndServices = $sProcessesAndServices + $sText + '+'
                    }
                    $sProcessesAndServices = TrimCharacter -TextString $sProcessesAndServices -Char '+'
                    #$sAppendToZipFile = $sAppendToZipFile + ',' + $sProcessesAndServices
                    #[void] $global:alCauses.Add($sProcessesAndServices)
                    AddToCauses -Item $sProcessesAndServices
                }
            }
            $oLog = $null
        }

        If ($IsPoolPagedHigh -eq $true)
        {
            $sTags = GetTopPoolTags -iPoolType 1 -iTopTags 3
            $sTags = TrimCharacter -TextString $sTags -Char '+'
            if ($sTags -eq '')
            {
                #$sAppendToZipFile = $sAppendToZipFile + 'HighPoolPaged,'
                #[void] $global:alCauses.Add('HighPoolPaged')
                AddToCauses -Item 'HighPoolPaged'
            }
            Else
            {
                #$sAppendToZipFile = $sAppendToZipFile + 'HighPoolPaged+' + $sTags  + ','
                [string] $sTemp = 'HighPoolPaged+' + $sTags
                #[void] $global:alCauses.Add($sTemp)
                AddToCauses -Item $sTemp
            }
        }

        If ($IsPoolNonPagedHigh -eq $true)
        {
            $sTags = GetTopPoolTags -iPoolType 0 -iTopTags 3
            $sTags = TrimCharacter -TextString $sTags -Char '+'
            if ($sTags -eq '')
            {
                #$sAppendToZipFile = $sAppendToZipFile + 'HighPoolNonPaged,'
                #[void] $global:alCauses.Add('HighPoolNonPaged')
                AddToCauses -Item 'HighPoolNonPaged'
            }
            Else
            {
                #$sAppendToZipFile = $sAppendToZipFile + 'HighPoolNonPaged+' + $sTags  + ','
                [string] $sTemp = 'HighPoolNonPaged+' + $sTags
                #[void] $global:alCauses.Add($sTemp)
                AddToCauses -Item $sTemp
            }
        }

        <#
        if ($sAppendToZipFile -eq '')
        {
            $sAppendToZipFile = 'PerfLog+LotsOfSmallProcesses'
        }

        $sAppendToZipFile = TrimCharacter -TextString $sAppendToZipFile -Char ','
        $sAppendToZipFile = TrimCharacter -TextString $sAppendToZipFile -Char '+'
        Return $sAppendToZipFile
        #>
}

$oCollectionOfZipFiles = Get-ChildItem $Path\*.zip

$TimeStamp = "$(Get-Date -format yyyyMMdd-HHmmss)"

[string] $global:sTempFolder = Get-UserTempDirectory
[string] $global:sTempFolder = $global:sTempFolder + '\Icu_' + $TimeStamp
if ($(Test-Path -Path $global:sTempFolder) -eq $false)
{
    $oFolder = New-Item -Path $global:sTempFolder -type directory -ErrorAction SilentlyContinue
}

[string] $sBlgFilesInTempFolder = $global:sTempFolder + '\*.blg'
[string] $sEtlFilesInTempFolder = $global:sTempFolder + '\*.etl'

Remove-Item $global:sTempFolder\* -Recurse -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

foreach ($oZipFile in $oCollectionOfZipFiles)
{
    $global:alCauses = New-Object System.Collections.ArrayList

    [string] $sZipFileName = $oZipFile.Name
    $aZipFile = $sZipFileName -Split '_'

    If ($aZipFile.Count -eq 3)
    {
        $oZipFile.Name
        [string] $sIcuTriggerInFileName = $aZipFile[2]
        [string] $IcuTrigger = ResolveIcuRuleText -RuleText $sIcuTriggerInFileName

        ExtractZip -sZipFilePath $oZipFile.FullName -sExtractFolder $sTempFolder

        [string] $sEtlStringResults = ''
        [string] $sBlgStringResults = ''

        switch ($IcuTrigger)
        {
            'disklatency'
            {
                #// Analyze ETL trace for disk latency
                $oEtls = @(Get-ChildItem -Path $sEtlFilesInTempFolder -Recurse)
                #[string] $sEtlStringResults = EtlAnalysis -oEtls $oEtls -sIcuTrigger 'disklatency'
                EtlAnalysis -oEtls $oEtls -sIcuTrigger 'disklatency'

                for ($c = 0; $c -lt $global:alCauses.Count; $c++)
                {
                    $sEntry = $global:alCauses[$c]
                    if ($sEntry -imatch 'pagefile')
                    {
                        $oBlgs = @(Get-ChildItem -Path $sBlgFilesInTempFolder -Recurse)
                        BlgAnalysis -oBlgs $oBlgs -sIcuTrigger 'committedmemory'
                    }
                }
            }

            'diskcapacity'
            {
                #// nothing for this yet
            }

            'processor'
            {
                #// Analyze ETL trace
                $oEtls = @(Get-ChildItem -Path $sEtlFilesInTempFolder -Recurse)
                EtlAnalysis -oEtls $oEtls -sIcuTrigger 'processor'
            }

            'physicalmemory'
            {
                #// Analyze BLG counter log
                $oBlgs = @(Get-ChildItem -Path $sBlgFilesInTempFolder -Recurse)
                BlgAnalysis -oBlgs $oBlgs -sIcuTrigger 'physicalmemory'
            }

            'committedmemory'
            {
                #// Analyze BLG counter log
                $oBlgs = @(Get-ChildItem -Path $sBlgFilesInTempFolder -Recurse)
                BlgAnalysis -oBlgs $oBlgs -sIcuTrigger 'committedmemory'
            }

            'memorypool'
            {
                #// Analyze BLG counter log
                $oBlgs = @(Get-ChildItem -Path $sBlgFilesInTempFolder -Recurse)
                BlgAnalysis -oBlgs $oBlgs -sIcuTrigger 'committedmemory'
            }

            'network'
            {
                #// nothing for this yet
            }

            'userinitiated'
            {

                #// Analyze ETL trace
                $oEtls = @(Get-ChildItem -Path $sEtlFilesInTempFolder -Recurse)
                EtlAnalysis -oEtls $oEtls -sIcuTrigger 'processor'

                #// Analyze ETL trace for disk latency
                $oEtls = @(Get-ChildItem -Path $sEtlFilesInTempFolder -Recurse)
                EtlAnalysis -oEtls $oEtls -sIcuTrigger 'disklatency'

                #// if pagefile is found, then process as a memory issue.
                for ($c = 0; $c -lt $global:alCauses.Count; $c++)
                {
                    $sEntry = $global:alCauses[$c]
                    if ($sEntry -imatch 'pagefile')
                    {
                        $oBlgs = @(Get-ChildItem -Path $sBlgFilesInTempFolder -Recurse)
                        BlgAnalysis -oBlgs $oBlgs -sIcuTrigger 'committedmemory'
                    }
                }                                
            }

            default 
            {
                #// Analyze ETL trace
                $oEtls = @(Get-ChildItem -Path $sEtlFilesInTempFolder -Recurse)
                EtlAnalysis -oEtls $oEtls -sIcuTrigger 'processor'

                #// Analyze ETL trace for disk latency
                $oEtls = @(Get-ChildItem -Path $sEtlFilesInTempFolder -Recurse)
                EtlAnalysis -oEtls $oEtls -sIcuTrigger 'disklatency'

                #// if pagefile is found, then process as a memory issue.
                for ($c = 0; $c -lt $global:alCauses.Count; $c++)
                {
                    $sEntry = $global:alCauses[$c]
                    if ($sEntry -imatch 'pagefile')
                    {
                        $oBlgs = @(Get-ChildItem -Path $sBlgFilesInTempFolder -Recurse)
                        BlgAnalysis -oBlgs $oBlgs -sIcuTrigger 'committedmemory'
                    }
                }
            }
        }

        $sAppendToZipFile = PostProcessing
        $sAppendToZipFile = '_' + $sAppendToZipFile
        $sAppendToZipFile = $sAppendToZipFile.Replace('_,','_')

        [string] $sNewName = $oZipFile.BaseName + $sAppendToZipFile + '.zip'
        $sNewName = $sNewName.Replace(',.zip','.zip')
        $sNewName

        if ($sNewName.Length -gt 250)
        {
            $sNewName = $sNewName.Substring(0,250)
        }

        $oZipFile | Rename-Item -NewName $sNewName        
        Remove-Item $sTempFolder\* -Recurse -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
}







