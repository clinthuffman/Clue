<#
    .SYNOPSIS
    Analyzes the data in Clue tool zip files and appends the root causes to the name of each zip file.
    .DESCRIPTION
    Point this script to a folder path or network share that contains Clue zip files. For each zip file, it extracts the contents to a local %temp% folder, analyzes the data, and then appends the root cause to the name of the zip file. Deletes the extracted data.
    .EXAMPLE
    .\Measure-IncidentFolder.ps1 -Path \\server\Clue
    This will open each zip file under \\server\Clue or another file system folder path, analyze the Clue zip files, and append the causes to the file name.
    .Parameter Path
    This parameters is required and is expected to be a folder path or a folder path or network share that contains Clue zip files.
    .Notes
    Name: Measure-IncidentFolder.ps1
    Author: Clint Huffman (clinth@microsoft.com)
	Version: 1.0
    Keywords: PowerShell, Clue
#>
param([string] $Path)

function Convert-FileSystemPathToObjectCH
{
    param([string] $Path)

    [System.Object] $oFile = New-Object System.Object
    Add-Member -InputObject $oFile -MemberType NoteProperty -Name 'FilePath' -Value ([string] '')
    Add-Member -InputObject $oFile -MemberType NoteProperty -Name 'Drive' -Value ([string] '')
    Add-Member -InputObject $oFile -MemberType NoteProperty -Name 'FolderPath' -Value ([string] '')
    Add-Member -InputObject $oFile -MemberType NoteProperty -Name 'FileName' -Value ([string] '')
    Add-Member -InputObject $oFile -MemberType NoteProperty -Name 'FileNameNoExtension' -Value ([string] '')
    Add-Member -InputObject $oFile -MemberType NoteProperty -Name 'Extension' -Value ([string] '')
    Add-Member -InputObject $oFile -MemberType NoteProperty -Name 'Type' -Value ([string] '')

    [string] $oFile.FilePath = $Path
    if ($Path.IndexOf('.') -ge 0)
    {
        #// File
        [string] $oFile.Type = 'File'
        [string] $oFile.FilePath = $Path
    }
    else
    {
        #// Folder
        [string] $oFile.Type = 'Folder'
        [string] $oFile.FolderPath = $Path
    }

    if ($Path.IndexOf('\') -ge 0)
    {
        [System.Object[]] $aLine = $Path.Split('\',[StringSplitOptions]'RemoveEmptyEntries')
        [string] $oFile.Drive = $aLine[0]
        [int] $u = $aLine.GetUpperBound(0)
        $oFile.FileName = $aLine[$u]
        if ($oFile.Type -eq 'File')
        {
            [System.Object[]] $aName = $oFile.FileName.Split('.',[StringSplitOptions]'RemoveEmptyEntries')
            [int] $n = $aName.GetUpperBound(0)
            [string] $oFile.Extension = $aName[$n]
            [string] $oFile.FileNameNoExtension = $aName[0]
            if ($n -gt 1)
            {
                [int] $n = $n - 1
                $aName[1..$n] | ForEach-Object {$oFile.FileNameNoExtension = $oFile.FileNameNoExtension + '.' + $_}
            }
            [string] $FolderPath = $aLine[0]
            if ($u -gt 1)
            {
                [int] $u = $u - 1
                $aLine[1..$u] | ForEach-Object {$FolderPath = $FolderPath + '\' + $_}
            }
            [string] $oFile.FolderPath = $FolderPath
        }
        else
        {
            [string] $oFile.FolderPath = $Path
        }
    }
    Return $oFile
}

function Get-FolderPathOfFilePathCH
{
    param([string] $FilePath)
    [string] $FolderPath = ''
    $aLine = $FilePath.Split('\',[StringSplitOptions]'RemoveEmptyEntries')
    [int] $u = $aLine.GetUpperBound(0) - 1
    $FolderPath = $aLine[0]
    if ($u -gt 0)
    {
        $aLine[1..$u] | ForEach-Object {$FolderPath = $FolderPath + '\' + $_}
    }
    Return $FolderPath
}

function Convert-CounterPathToObjectCH
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

function Remove-InvalidFileNameCharactersCH
{
    param([string] $Text)
    # Remove invalid file name characters
    $Text = $Text -ireplace '\\',''
    $Text = $Text -ireplace '/',''
    $Text = $Text -ireplace ':',''
    $Text = $Text -ireplace '\*',''
    $Text = $Text -ireplace '\?',''
    $Text = $Text -ireplace '"',''
    $Text = $Text -ireplace '<',''
    $Text = $Text -ireplace '>',''
    $Text = $Text -ireplace '|',''
    Return $Text
}

function Replace-SpecialCharactersCH
{
    param([string] $Text)
    # Remove invalid file name characters
    $Text = $Text -ireplace '\?','Unknown'
    Return $Text
}

Function Start-ExtractZipCH
{
    param([string] $FilePath, [string] $OutputFolderPath)
    $shell = new-object -com shell.application
    $zip = $shell.NameSpace($FilePath)
    foreach($item in $zip.items())
    {
        $shell.Namespace($OutputFolderPath).copyhere($item)
    }
}

function ConvertTo-BlgObjectCH
{
    param([string] $FilePath)
    [string] $Cmd = 'relog "' + $FilePath + '"'
    [System.Object[]] $Output = Invoke-Expression -Command $Cmd

    [string] $DateTimeFormat = (Get-Culture).DateTimeFormat.ShortDatePattern + ' H:mm:ss'

    $oBlg = New-Object pscustomobject

    Add-Member -InputObject $oBlg -MemberType NoteProperty -Name 'Path' -Value ([string] $FilePath)

    foreach ($item in $Output)
    {
        [string] $Line = $item
        if ($Line -match 'Begin:')
        {
            [System.String[]] $aLine = $Line.Split(' ',[StringSplitOptions]'RemoveEmptyEntries')
            [string] $TempDateTimeString = $aLine[1] + ' ' + $aLine[2]
            [datetime] $Begin = [datetime]::ParseExact($TempDateTimeString,$DateTimeFormat, [System.Globalization.CultureInfo]::InvariantCulture)
            Add-Member -InputObject $oBlg -MemberType NoteProperty -Name 'Begin' -Value ([datetime] $Begin)
        }

        if ($Line -match 'End:')
        {
            [System.String[]] $aLine = $Line.Split(' ',[StringSplitOptions]'RemoveEmptyEntries')
            [string] $TempDateTimeString = $aLine[1] + ' ' + $aLine[2]
            [datetime] $End = [datetime]::ParseExact($TempDateTimeString,$DateTimeFormat, [System.Globalization.CultureInfo]::InvariantCulture)
            Add-Member -InputObject $oBlg -MemberType NoteProperty -Name 'End' -Value $End
        }

        if ($Line -match 'Samples:')
        {
            [System.String[]] $aLine = $Line.Split(' ',[StringSplitOptions]'RemoveEmptyEntries')
            [string] $Samples = $aLine[1]
            Add-Member -InputObject $oBlg -MemberType NoteProperty -Name 'Samples' -Value ([int] $Samples)
        }        
    }
    $oBlg
}

function New-FolderCH
{
    param([string] $FolderPath,[int] $TimeoutInSeconds = 3)
    $null = New-Item -Path $FolderPath -ItemType 'Directory' -Force -ErrorAction SilentlyContinue;
    [int] $iCount = 0
    Do
    {
        #// Wait until the folder is created.
        Start-Sleep -Seconds 1
        if (Test-Path -Path $FolderPath) {Return $true}
        if ($iCount -gt $TimeoutInSeconds) {Return $false}
    } until ($true -eq $false)
}

function Test-IncidentZipFileNameCH
{
    param([string] $ZipFileName)
    [System.String[]] $aZip = $ZipFileName.Split('.',[StringSplitOptions]'RemoveEmptyEntries')
    if (($aZip[$aZip.GetUpperBound(0)]) -eq 'zip')
    {
        [System.String[]] $aZip = $ZipFileName.Split('_',[StringSplitOptions]'RemoveEmptyEntries')
        if ($aZip.Count -eq 3)
        {
            Return $true
        }
    }
    Return $false
}

function ConvertTo-IncidentObjectCH
{
    param([string] $FileName)
    $FileName = $FileName.Replace('.zip','')
    [System.String[]] $aLine = $FileName.Split('_',[StringSplitOptions]'RemoveEmptyEntries')
    $oObject = New-Object pscustomobject
    [datetime] $IncidentDateTime = [datetime]::ParseExact($aLine[0],'yyyyMMdd-HHmmss', [System.Globalization.CultureInfo]::InvariantCulture)
    Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'OriginalDateTime' -Value ([string] $aLine[0])
    Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'OriginalComputer' -Value ([string] $aLine[1])
    Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'OriginalRule' -Value ([string] $aLine[2])
    Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'DateTime' -Value ([datetime] $IncidentDateTime)
    Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'Computer' -Value ([string] $aLine[1])
    Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'Rule' -Value ([string] $aLine[2])

    $oObject
}

function Get-LastMinutesOfBlgCH
{
    param([string] $BlgFilePath, [int] $Minutes = 3)

    [string] $DateTimeFormat = (Get-Culture).DateTimeFormat.ShortDatePattern + ' H:mm:ss'
    $NegativeMinutes = -$Minutes
    $oBlg = ConvertTo-BlgObjectCH -FilePath $BlgFilePath
    $dtDiff = New-TimeSpan -Start $oBlg.Begin -End $oBlg.End
    if ($dtDiff.TotalMinutes -gt $Minutes)
    {
        [datetime] $dtNewBegin = $oBlg.End.AddMinutes($NegativeMinutes)
        $oLog = Import-Counter -Path $BlgFilePath -StartTime $dtNewBegin -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
    else
    {
        $oLog = Import-Counter -Path $BlgFilePath -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
    Return $oLog
}

function Get-LastMinutesOfBlgCH-Old
{
    param([string] $BlgFilePath, [int] $Minutes = 3)

    [string] $DateTimeFormat = (Get-Culture).DateTimeFormat.ShortDatePattern + ' H:mm:ss'
    $NegativeMinutes = -$Minutes
    $oBlg = ConvertTo-BlgObjectCH -FilePath $BlgFilePath
    [string] $OutBlgPath = (Get-FolderPathOfFilePathCH -FilePath $BlgFilePath) + '\LastMinutes.blg'

    $dtDiff = New-TimeSpan -Start $oBlg.Begin -End $oBlg.End
    if ($dtDiff.TotalMinutes -gt $Minutes)
    {
        [datetime] $dtNewBegin = $oBlg.End.AddMinutes($NegativeMinutes)
        [string] $sNewBegin = $dtNewBegin.ToString($DateTimeFormat)
        [string] $Cmd = 'relog "' + $BlgFilePath + '" -b "' + $sNewBegin + '" -f bin -o "' + $OutBlgPath + '" -y'
        [System.Object[]] $Output = Invoke-Expression -Command $Cmd
    }
    else
    {
        [string] $Cmd = 'relog "' + $BlgFilePath + '" -f bin -o "' + $OutBlgPath + '" -y'
        [System.Object[]] $Output = Invoke-Expression -Command $Cmd
    }
    Start-Sleep -Seconds 1
    if (Test-Path -Path $OutBlgPath)
    {
        Return (Get-ChildItem -Path $OutBlgPath).FullName
    }
    else
    {
        Return ''
    }
}

function ConvertTo-RuleCategoryCH
{
    param([string] $Rule)
    if ($Rule -imatch 'DiskLatency')     {$Rule = 'DiskLatency'}
    if ($Rule -imatch 'DiskCapacity')    {$Rule = 'DiskCapacity'}
    if ($Rule -imatch 'DiskFree')        {$Rule = 'DiskCapacity'}
    if ($Rule -imatch 'Processor')       {$Rule = 'Processor'}
    if ($Rule -imatch 'CPU')             {$Rule = 'Processor'}
    if ($Rule -imatch 'Privileged')      {$Rule = 'Processor'}
    if ($Rule -imatch 'PhysicalMemory')  {$Rule = 'MemoryPhysical'}
    if ($Rule -imatch 'AvailableMBytes') {$Rule = 'MemoryPhysical'}
    if ($Rule -imatch 'Committed')       {$Rule = 'MemoryCommitted'}
    if ($Rule -imatch 'Pool')            {$Rule = 'MemoryPool'}
    if ($Rule -imatch 'Network')         {$Rule = 'Network'}
    if ($Rule -imatch 'UserInitiated')   {$Rule = 'UserInitiated'}
    Return $Rule.ToLower()
}

function Start-BlgProcessorAnalysisCH
{
    param([System.Object[]] $oLog)

    [bool] $IsConfirmed = $false
    $oCounters = $oLog.CounterSamples | Where-Object {(($_.Path -match '\\processor information\(') -and ($_.Path -match '\\% processor time'))}
    $aInstances = $oCounters | Select InstanceName -Unique
    [string] $sHighestInstance = ''
    :LoopProcessors foreach ($oInstance in $aInstances)
    {
        if ($oInstance.InstanceName -notmatch '_Total')
        {
            $oMeasure = $oCounters | Where-Object {$_.InstanceName -eq $oInstance.InstanceName} | Measure-Object -Property CookedValue -Maximum
            if ($oMeasure.Maximum -gt 90)
            {
                [bool] $IsConfirmed = $true
                Break LoopProcessors
            }
        }
    }

    if ($IsConfirmed -eq $false)
    {
        Return 'Blg+FalsePositive'
    }

    $oCounters = $oLog.CounterSamples | Where-Object {(($_.Path -match '\\process\(') -and ($_.Path -match '\\% processor time'))}
    $aInstances = $oCounters | Select Path -Unique
    $oStats = @()

    foreach ($oInstance in $aInstances)
    {
        $oCtr = Convert-CounterPathToObjectCH -sCounterPath $oInstance.Path
        if (($oCtr.Instance -ne 'idle') -and ($oCtr.Instance -ne '_total'))
        {
            $oMeasure = $oCounters | Where-Object {$_.Path -eq $oInstance.Path} | Measure-Object -Property CookedValue -Average
            $oObject = New-Object pscustomobject
            Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'Path' -Value ([string] $oInstance.Path)
            Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'Average' -Value ([double] $oMeasure.Average)
            $oStats += $oObject
        }
    }
    $oTop = $oStats | Sort-Object -Property Average -Descending | Select -First 1
    $oCtr = Convert-CounterPathToObjectCH -sCounterPath $oTop.Path
    $sHighestInstance = 'Blg+' + $oCtr.Instance
    Return $sHighestInstance
}

function Start-BlgDiskLatencyCH
{
    param([System.Object[]] $oLog)

    [bool] $IsConfirmed = $false
    $oCounters = $oLog.CounterSamples | Where-Object {(($_.Path -match '\\LogicalDisk\(') -and ($_.Path -match '\\avg. disk sec/transfer'))}
    $aInstances = $oCounters | Select InstanceName -Unique
    [string] $sHighestInstance = ''
    :LoopIndicators foreach ($sInstance in $aInstances)
    {
        if ($sInstance.InstanceName -notmatch '_Total')
        {
            $oMeasure = $oCounters | Where-Object {$_.InstanceName -eq $sInstance.InstanceName} | Measure-Object -Property CookedValue -Maximum
            if ($oMeasure.Maximum -gt 0.035)
            {
                [bool] $IsConfirmed = $true
                Break LoopIndicators
            }
        }
    }

    if ($IsConfirmed -eq $false)
    {
        Return 'Blg+FalsePositive'
    }

    $oStats = @()
    $oCounters = $oLog.CounterSamples | Where-Object {(($_.Path -match '\\process\(') -and ($_.Path -match '\\io data operations/sec'))}
    $aInstances = $oCounters | Select InstanceName -Unique
    foreach ($sInstance in $aInstances)
    {
        if (($sInstance.InstanceName -ne 'Idle') -and ($sInstance.InstanceName -ne '_Total'))
        {
            $oMeasure = $oCounters | Where-Object {$_.InstanceName -eq $sInstance.InstanceName} | Measure-Object -Property CookedValue -Average
            $oObject = New-Object pscustomobject
            Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'InstanceName' -Value ([string] $sInstance.InstanceName)
            Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'Average' -Value ([double] $oMeasure.Average)
            $oStats += $oObject
        }
    }
    $oTop = $oStats | Sort-Object -Property Average -Descending | Select -First 1
    $sHighestInstance = 'Blg+' + $oTop.InstanceName
    Return $sHighestInstance
}

function Start-BlgMemoryPhysicalCH
{
    param([System.Object[]] $oLog)

    $oStats = @()
    $oCounters = $oLog.CounterSamples | Where-Object {(($_.Path -match '\\Memory\\') -and ($_.Path -match '\\pool nonpaged bytes'))}
    $oMeasure = $oCounters | Measure-Object -Property CookedValue -Maximum
    $oObject = New-Object pscustomobject
    Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'InstanceName' -Value ([string] 'PoolNonPaged')
    Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'Maximum' -Value ([double] $oMeasure.Maximum)
    $oStats += $oObject

    $oCounters = $oLog.CounterSamples | Where-Object {(($_.Path -match '\\Memory\\') -and ($_.Path -match '\\pool paged resident bytes'))}
    $oMeasure = $oCounters | Measure-Object -Property CookedValue -Maximum
    $oObject = New-Object pscustomobject
    Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'InstanceName' -Value ([string] 'PoolPaged')
    Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'Maximum' -Value ([double] $oMeasure.Maximum)
    $oStats += $oObject

    $oCounters = $oLog.CounterSamples | Where-Object {(($_.Path -match '\\Memory\\') -and ($_.Path -match '\\system cache resident bytes'))}
    $oMeasure = $oCounters | Measure-Object -Property CookedValue -Maximum
    $oObject = New-Object pscustomobject
    Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'InstanceName' -Value ([string] 'SystemCache')
    Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'Maximum' -Value ([double] $oMeasure.Maximum)
    $oStats += $oObject

    $oCounters = $oLog.CounterSamples | Where-Object {(($_.Path -match '\\process\(') -and ($_.Path -match '\\working set'))}
    $aInstances = $oCounters | Select InstanceName -Unique
    foreach ($sInstance in $aInstances)
    {
        if (($sInstance.InstanceName -ne 'Idle') -and ($sInstance.InstanceName -ne '_Total'))
        {
            $oMeasure = $oCounters | Where-Object {$_.InstanceName -eq $sInstance.InstanceName} | Measure-Object -Property CookedValue -Maximum
            $oObject = New-Object pscustomobject
            Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'InstanceName' -Value ([string] $sInstance.InstanceName)
            Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'Maximum' -Value ([double] $oMeasure.Maximum)
            $oStats += $oObject
        }
    }
    $oTop = $oStats | Sort-Object -Property Maximum -Descending | Select -First 1
    $sHighestInstance = 'Blg+' + $oTop.InstanceName
    Return $sHighestInstance
}

function Start-BlgMemoryCommittedCH
{
    param([System.Object[]] $oLog)

    $oStats = @()
    $oCounters = $oLog.CounterSamples | Where-Object {(($_.Path -match '\\Memory\\') -and ($_.Path -match '\\pool nonpaged bytes'))}
    $oMeasure = $oCounters | Measure-Object -Property CookedValue -Maximum
    $oObject = New-Object pscustomobject
    Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'InstanceName' -Value ([string] 'PoolNonPaged')
    Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'Maximum' -Value ([double] $oMeasure.Maximum)
    $oStats += $oObject

    $oCounters = $oLog.CounterSamples | Where-Object {(($_.Path -match '\\Memory\\') -and ($_.Path -match '\\pool paged bytes'))}
    $oMeasure = $oCounters | Measure-Object -Property CookedValue -Maximum
    $oObject = New-Object pscustomobject
    Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'InstanceName' -Value ([string] 'PoolPaged')
    Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'Maximum' -Value ([double] $oMeasure.Maximum)
    $oStats += $oObject

    $oCounters = $oLog.CounterSamples | Where-Object {(($_.Path -match '\\process\(') -and ($_.Path -match '\\private bytes'))}
    $aInstances = $oCounters | Select InstanceName -Unique
    foreach ($sInstance in $aInstances)
    {
        if (($sInstance.InstanceName -ne 'Idle') -and ($sInstance.InstanceName -ne '_Total'))
        {
            $oMeasure = $oCounters | Where-Object {$_.InstanceName -eq $sInstance.InstanceName} | Measure-Object -Property CookedValue -Maximum
            $oObject = New-Object pscustomobject
            Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'InstanceName' -Value ([string] $sInstance.InstanceName)
            Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'Maximum' -Value ([double] $oMeasure.Maximum)
            $oStats += $oObject
        }
    }
    $oTop = $oStats | Sort-Object -Property Maximum -Descending | Select -First 1
    $sHighestInstance = 'Blg+' + $oTop.InstanceName
    Return $sHighestInstance
}

function Start-BlgAnalysisCH
{
    param($oBlgs, [string] $Rule)
    [string] $Result = ''  
    [string] $LastMinutesBlgFilePath = ''
    #// relog to last 2 minutes and convert to CSV file
    foreach ($oBlg in $oBlgs)
    {
        if ($oBlgs.Name -eq 'PalCollector.blg')
        {
            [System.Object[]] $oLog = Get-LastMinutesOfBlgCH -BlgFilePath $oBlg.FullName
                
            switch ($Rule)
            {
                'processor'       {[string] $Result = Start-BlgProcessorAnalysisCH -oLog $oLog;$global:IsAnalyzed = $true}
                'memoryphysical'  {[string] $Result = Start-BlgMemoryPhysicalCH -oLog $oLog;$global:IsAnalyzed = $true}
                'memorycommitted' {[string] $Result = Start-BlgMemoryCommittedCH -oLog $oLog;$global:IsAnalyzed = $true}
                'memorypool'      {}
                'network'         {}
                'diskcapacity'    {}
                'disklatency'     {[string] $Result = Start-BlgDiskLatencyCH -oLog $oLog;$global:IsAnalyzed = $true}
                'userinitiated'   {}
                default           {}
            }
            Return $Result
        }
    }
}

function Start-WpaExporterCH
{
    param([string] $EtlFilePath, [string] $WpaProfileFilePath, [string] $OutputFolderPath, [string] $OutputFileName, [int] $TimeoutInSeconds = 10)

    [string] $OutputFilePath = $OutputFolderPath + '\' + $OutputFileName
    Remove-Item -Path $OutputFilePath -ErrorAction SilentlyContinue
    [string] $Cmd = 'wpaexporter.exe "' + $EtlFilePath + '" -profile "' + $WpaProfileFilePath + '" -OutputFolder "' + $OutputFolderPath + '" -tti 2>&1'
    Write-Host '.' -NoNewline
    $null = Invoke-Expression -Command $Cmd -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
    Write-Host '.' -NoNewline
    Start-Sleep -Seconds 1    
    if (Test-Path -Path $OutputFilePath)
    {
        $oCsv = Import-Csv -Path $OutputFilePath
        Return $oCsv
    }
    else
    {
        Return $null
    }
}

function Start-EtlProcessorAnalysisCH
{
    param([System.Object[]] $oEtl)

    [string] $ProfileFolderPath = $global:OriginalLocation + '\Profiles'
    [string] $TempFolderPath = $global:TempFolderPath
    [string] $OutputFolderPath = $TempFolderPath + '\Output'
    $oOutputFolder = New-Item -Path $OutputFolderPath -ItemType Directory -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

    #///////////////////
    #// Clue Top CPU //
    #/////////////////
    [string] $TopCpuResult = ''
    [string] $WpaProfileFilePath = $ProfileFolderPath + '\ClueTopCpu.wpaProfile'
    [string] $OutputFileName = 'CPU_Usage_(Sampled)_ClueTopCpu.csv'
    $oCsv = Start-WpaExporterCH -EtlFilePath $oEtl.FullName -WpaProfileFilePath $WpaProfileFilePath -OutputFolderPath $OutputFolderPath -OutputFileName $OutputFileName
    [string] $TopCpuResult = ($oCsv | Select -First 1).CPU

    #///////////////////////
    #// Clue Top Process //
    #/////////////////////
    [string] $TopProcessResult = ''
    [string] $WpaProfileFilePath = $ProfileFolderPath + '\ClueTopCpuProcessesOfCpuX.wpaProfile'
    [string] $UniqueWpaProfileFilePath = $global:TempFolderPath + '\ClueTopCpuProcessesOfCpuX.wpaProfile'
    Copy-Item -Path $WpaProfileFilePath -Destination $UniqueWpaProfileFilePath
    [string] $FindThis = 'InitialFilterQuery="\[CPU\]:=&quot;xxx&quot;"'
    [string] $ReplaceWith = 'InitialFilterQuery="[CPU]:=&quot;' + $TopCpuResult + '&quot;"'
    (Get-Content -Path $UniqueWpaProfileFilePath) -replace $FindThis, $ReplaceWith | Set-Content -Path $UniqueWpaProfileFilePath

    [string] $OutputFileName = 'CPU_Usage_(Sampled)_ClueTopCpuProcessesOfCpuX.csv'
    $oCsv = Start-WpaExporterCH -EtlFilePath $oEtl.FullName -WpaProfileFilePath $UniqueWpaProfileFilePath -OutputFolderPath $OutputFolderPath -OutputFileName $OutputFileName
    [string] $TopProcessResult = ($oCsv | Select -First 1).Process
    if ($TopProcessResult.IndexOf('Idle') -ge 0)
    {
        [string] $TopProcessResult = ($oCsv[1]).Process   
    }

    if ($TopProcessResult.IndexOf(' (') -ge 0)
    {
        [System.Object[]] $aLine = $TopProcessResult.Split(' (',[StringSplitOptions]'RemoveEmptyEntries')
        $TopProcessNameResult = $aLine[0]
    }

    #//////////////////////
    #// Clue Top Module //
    #////////////////////
    [string] $TopModuleResult = ''
    [string] $WpaProfileFilePath = $ProfileFolderPath + '\ClueTopCpuModulesOfCpuXProcessY.wpaProfile'
    [string] $UniqueWpaProfileFilePath = $global:TempFolderPath + '\ClueTopCpuModulesOfCpuXProcessY.wpaProfile'
    Copy-Item -Path $WpaProfileFilePath -Destination $UniqueWpaProfileFilePath
    [string] $FindThis = 'InitialFilterQuery="\[CPU\]:=&quot;xxx&quot; \[Process\]:=&quot;yyy&quot;"'
    [string] $ReplaceWith = 'InitialFilterQuery="[CPU]:=&quot;' + $TopCpuResult + '&quot; [Process]:=&quot;' + $TopProcessResult + '&quot;"'
    (Get-Content -Path $UniqueWpaProfileFilePath) -replace $FindThis, $ReplaceWith | Set-Content -Path $UniqueWpaProfileFilePath

    [string] $OutputFileName = 'CPU_Usage_(Sampled)_ClueTopCpuModulesOfCpuXProcessY.csv'
    $oCsv = Start-WpaExporterCH -EtlFilePath $oEtl.FullName -WpaProfileFilePath $UniqueWpaProfileFilePath -OutputFolderPath $OutputFolderPath -OutputFileName $OutputFileName
    [string] $TopModuleResult = ($oCsv | Select -First 1).Module

    [string] $Result = 'Etl+' + $TopProcessNameResult + '+' + $TopModuleResult 
    Return $Result
}

function Start-EtlDiskLatencyAnalysisCH
{
    param([System.Object[]] $oEtl)

    [string] $ProfileFolderPath = $global:OriginalLocation + '\Profiles'
    [string] $TempFolderPath = $global:TempFolderPath
    [string] $OutputFolderPath = $TempFolderPath + '\Output'
    $oOutputFolder = New-Item -Path $OutputFolderPath -ItemType Directory -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

    #////////////////////
    #// Clue Top Disk //
    #//////////////////
    [string] $TopDiskResult = ''
    [string] $WpaProfileFilePath = $ProfileFolderPath + '\ClueTopDisk.wpaProfile'
    [string] $OutputFileName = 'Disk_Usage_ClueTopDisk.csv'
    $oCsv = Start-WpaExporterCH -EtlFilePath $oEtl.FullName -WpaProfileFilePath $WpaProfileFilePath -OutputFolderPath $OutputFolderPath -OutputFileName $OutputFileName
    [string] $TopDiskResult = ($oCsv | Select -First 1).Disk

    #///////////////////////
    #// Clue Top Process //
    #/////////////////////
    [string] $TopProcessResult = ''
    [string] $WpaProfileFilePath = $ProfileFolderPath + '\ClueTopDiskProcessesOfDiskX.wpaProfile'
    [string] $UniqueWpaProfileFilePath = $global:TempFolderPath + '\ClueTopDiskProcessesOfDiskX.wpaProfile'
    Copy-Item -Path $WpaProfileFilePath -Destination $UniqueWpaProfileFilePath
    [string] $FindThis = 'InitialFilterQuery="\[Disk\]:=&quot;xxx&quot;"'
    [string] $ReplaceWith = 'InitialFilterQuery="[Disk]:=&quot;' + $TopDiskResult + '&quot;"'
    (Get-Content -Path $UniqueWpaProfileFilePath) -replace $FindThis, $ReplaceWith | Set-Content -Path $UniqueWpaProfileFilePath
    [string] $OutputFileName = 'Disk_Usage_ClueTopDiskProcessesOfDiskX.csv'
    $oCsv = Start-WpaExporterCH -EtlFilePath $oEtl.FullName -WpaProfileFilePath $UniqueWpaProfileFilePath -OutputFolderPath $OutputFolderPath -OutputFileName $OutputFileName
    [string] $TopProcessWithPidResult = ($oCsv | Select -First 1).Process

    if ($TopProcessResult.IndexOf('Idle') -ge 0)
    {
        [string] $TopProcessResult = ($oCsv[1]).Process   
    }

    if ($TopProcessWithPidResult.IndexOf(' (') -ge 0)
    {
        [System.Object[]] $aLine = $TopProcessWithPidResult.Split(' (',[StringSplitOptions]'RemoveEmptyEntries')
        $TopProcessNameResult = $aLine[0]
    }

    #/////////////////////
    #// Clue Top Files //
    #///////////////////
    [string] $TopFileResult = ''
    [string] $WpaProfileFilePath = $ProfileFolderPath + '\ClueTopDiskFilesOfDiskXProcessY.wpaProfile'
    [string] $UniqueWpaProfileFilePath = $global:TempFolderPath + '\ClueTopDiskFilesOfDiskXProcessY.wpaProfile'
    Copy-Item -Path $WpaProfileFilePath -Destination $UniqueWpaProfileFilePath
    [string] $FindThis = 'InitialFilterQuery="\[Disk\]:=&quot;xxx&quot; \[Process\]:=&quot;xxx&quot;"'
    [string] $ReplaceWith = 'InitialFilterQuery="[Disk]:=&quot;' + $TopDiskResult + '&quot; [Process]:=&quot;' + $TopProcessWithPidResult + '&quot;"'
    (Get-Content -Path $UniqueWpaProfileFilePath) -replace $FindThis, $ReplaceWith | Set-Content -Path $UniqueWpaProfileFilePath
    [string] $OutputFileName = 'Disk_Usage_ClueTopDiskFilesOfDiskXProcessY.csv'
    $oCsv = Start-WpaExporterCH -EtlFilePath $oEtl.FullName -WpaProfileFilePath $UniqueWpaProfileFilePath -OutputFolderPath $OutputFolderPath -OutputFileName $OutputFileName
    [string] $TopFileResult = ($oCsv | Select -First 1).'Path Name'
    
    $oTopFile = Convert-FileSystemPathToObjectCH -Path $TopFileResult
    [string] $Result = 'Etl+' + $TopProcessNameResult + '+' + $oTopFile.FileName
    Return $Result
}

function Start-EtlAnalysisCH
{
    param($oEtls, [string] $Rule)
    [string] $Result = ''  
    foreach ($oEtl in $oEtls)
    {
        if ($oEtl.Name -match '[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9].etl')
        {
            switch ($Rule)
            {
                'processor'       {[string] $Result = Start-EtlProcessorAnalysisCH -oEtl $oEtl;$global:IsAnalyzed = $true}
                'memoryphysical'  {}
                'memorycommitted' {}
                'memorypool'      {}
                'network'         {}
                'diskcapacity'    {}
                'disklatency'     {[string] $Result = Start-EtlDiskLatencyAnalysisCH -oEtl $oEtl;$global:IsAnalyzed = $true}
                'userinitiated'   {}
                default           {}
            }
            Return $Result
        }
    }    
}

#///////////
#// Main //
#/////////

$global:OriginalLocation = (Get-Location).Path

if ($Path.Length -gt 1)
{
    [string] $LastCharacter = $Path.Substring($Path.Length - 1)
    if ($LastCharacter -eq '\')
    {
        [string] $Path = $Path.Substring(0,$Path.Length - 1)
    }
}
else
{
    Write-Host ('Path parameter is missing or invalid.')
    Exit;
}

if ((Test-Path -Path $Path) -eq $false)
{
    Write-Host ('Folder path does not exist: ' + $Path)
    Exit;
}

[string] $SessionGuid = ([GUID]::NewGUID()).Guid

Write-Host ('Create temporary folder...') -NoNewline
[string] $global:TempFolderPath = (Get-ChildItem -Path 'env:temp').Value
[string] $global:TempFolderPath = $global:TempFolderPath + '\' + $SessionGuid
if ((New-FolderCH -FolderPath $global:TempFolderPath) -eq $false)
{
    Write-Host ('Failed to create temporary folder: ' + $global:TempFolderPath)
    Write-Host ('Exiting!')
    Exit;
}
Write-Host ('Done!')
Write-Host ('')
Write-Host ('TemporaryFolder: ' + $global:TempFolderPath)
Write-Host ('')

[System.Object[]] $oCollectionOfZipFiles = Get-ChildItem -Path "$Path\*.zip"

for ([int] $z = 0;$z -le $oCollectionOfZipFiles.GetUpperBound(0);$z++)
{
    if ($oCollectionOfZipFiles[$z] -is [System.IO.FileInfo])
    {
        [System.IO.FileInfo] $oZipFile = $oCollectionOfZipFiles[$z]
    
        Write-Host ($oZipFile.Name)
        [bool] $global:IsAnalyzed = $false

        if (Test-IncidentZipFileNameCH -ZipFileName $oZipFile.Name)
        {
            Write-Host ("`tPreparing data...") -NoNewline
            #// Get file name properties
            $global:Incident = ConvertTo-IncidentObjectCH -FileName $oZipFile.Name
            #// Identify rule
            [string] $Rule = ConvertTo-RuleCategoryCH -Rule $global:Incident.Rule
            Remove-Item -Path "$global:TempFolderPath\*" -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
            Write-Host ('Done!')

            [bool] $IsAnalysisRuleEnabled = $false
            switch ($Rule)
            {
                'processor'       {$IsAnalysisRuleEnabled = $true}
                'memoryphysical'  {$IsAnalysisRuleEnabled = $true}
                'memorycommitted' {$IsAnalysisRuleEnabled = $true}
                'memorypool'      {$IsAnalysisRuleEnabled = $false}
                'network'         {$IsAnalysisRuleEnabled = $false}
                'diskcapacity'    {$IsAnalysisRuleEnabled = $false}
                'disklatency'     {$IsAnalysisRuleEnabled = $true}
                'userinitiated'   {$IsAnalysisRuleEnabled = $false}
                default           {$IsAnalysisRuleEnabled = $false}
            }

            if ($IsAnalysisRuleEnabled -eq $true)
            {
                #// Extract to temp folder
                Write-Host ("`tExtracting zip to temporary folder...") -NoNewline
                Start-ExtractZipCH -FilePath $oZipFile.FullName -OutputFolderPath $global:TempFolderPath
                [bool] $IsDataInZip = $false
                if ((Get-Childitem -Path $global:TempFolderPath).Count -eq 0)
                {
                    Write-Host ('!!!ERROR!!! No data or corrupted...') -NoNewline
                    Write-Host ('Done!')
                    $Result = 'CORRUPTED'
                }
                else
                {
                    [bool] $IsDataInZip = $true
                    Write-Host ('Done!')

                    #// Start BLG analysis
                    Write-Host ("`tAnalyzing BLG...") -NoNewline
                    [string] $BlgResult = ''
                    [System.Object[]] $oCollectionOfBlgFiles = Get-ChildItem -Path "$TempFolderPath\*.blg"
                    [string] $BlgResult = Start-BlgAnalysisCH -oBlgs $oCollectionOfBlgFiles -Rule $Rule
                    Write-Host ('Done!')

                    [string] $EtlResult = ''
                    if (($BlgResult -ne '') -and ($BlgResult -ne 'FalsePositive'))
                    {
                        #// Start ETL analysis
                        Write-Host ("`tAnalyzing ETL...") -NoNewline
                        [System.Object[]] $oCollectionOfEtlFiles = @(Get-ChildItem -Path "$TempFolderPath\*.etl")
                        [string] $EtlResult = Start-EtlAnalysisCH -oEtls $oCollectionOfEtlFiles -Rule $Rule
                        Write-Host ('Done!')
                    }

                    [string] $Result = ''

                    if (($BlgResult -ne '') -and ($EtlResult -ne ''))
                    {[string] $Result = $BlgResult + '-' + $EtlResult}
                    else
                    {
                        if ($BlgResult -ne '')
                        {[string] $Result = $BlgResult}
                        else 
                        {[string] $Result = $EtlResult}
                    }
                    [string] $Result = Replace-SpecialCharactersCH -Text $Result
                    [string] $Result = Remove-InvalidFileNameCharactersCH -Text $Result
                }

                #// Clean up temp folder
                Write-Host ("`tCleaning temporary folder...") -NoNewline
                Get-ChildItem -Path $global:TempFolderPath | Remove-Item -Recurse -Force
                Write-Host ('Done!')

                #// Rename zip file
                if (($global:IsAnalyzed -eq $true) -or ($IsDataInZip -eq $false))
                {
                    Write-Host ("`tRenaming zip file...") -NoNewline
                    [string] $NewName = $global:Incident.OriginalDateTime + '_' + $global:Incident.OriginalComputer + '_' + $global:Incident.OriginalRule + '_' + $Result + '.zip'
                    $oZipFile | Rename-Item -NewName $NewName
                    Write-Host ('Done!')
                    Write-Host ($NewName)
                }
                else
                {
                    Write-Host ("`t!!! Not analyzed !!!")
                }

            }
            else
            {
                Write-Host ("`t!!! Analysis rule is not implemented yet !!!")            
            }
        }
        else
        {
            Write-Host ("`t!!! Not an incident file or already processed !!!")
        }
        Write-Host ('')
    }
}

Write-Host ('')
Write-Host ('Deleting temporary folder...') -NoNewline
Remove-Item -Path $global:TempFolderPath -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ('Done!')