#//////////////////
#// File system //
#////////////////

Function Remove-FileSystemIllegalCharacters
{
    param([string] $Name, [string] $Log = '.\Clue.log')
    if ($Name -ne '')
    {
        $Name = $Name.Replace('\','')
        $Name = $Name.Replace('/','')
        $Name = $Name.Replace(':','')
        $Name = $Name.Replace('*','')
        $Name = $Name.Replace('?','')
        $Name = $Name.Replace('"','')
        $Name = $Name.Replace('<','')
        $Name = $Name.Replace('>','')
        $Name = $Name.Replace('|','')
    }
    Return $Name
}

Function New-DirectoryWithConfirm
{
    param([string] $DirectoryPath, [string] $Log = '.\Clue.log')

    Write-Log ('[New-DirectoryWithConfirm] DirectoryPath: ' + $DirectoryPath) -Log $Log
    if ((Test-Path -Path $DirectoryPath) -eq $False)
    {
        $aFolderPath = $DirectoryPath.Split('\',[StringSplitOptions]'RemoveEmptyEntries')
        [string] $sPartialPath = ''
        [string] $sParentPath = ''
        ForEach ($sPath in $aFolderPath)
        {
            if ($sPartialPath -eq '')
            {
                $sPartialPath = $sPath
                $sParentPath = $sPath + '\'
            }
            else
            {
                $sParentPath = $sPartialPath + '\'
                $sPartialPath = $sPartialPath + '\' + $sPath
            }

            if ((Test-Path -Path $sPartialPath) -eq $False)
            {
                $oNull = New-Item -Path $sParentPath -Name $sPath -type directory
            }
        }
    }
    Return (Test-Path -Path $DirectoryPath)
}

Function Get-FolderPathFromFilePath
{
    param([string] $FilePath, [string] $Log = '.\Clue.log')
    Write-Log ('[Get-FolderPathFromFilePath] FilePath: ' + $FilePath) -Log $Log
    if ($FilePath -ne '')
    {
        [string] $NewPath = ''
        [System.String[]] $aTemp = @($FilePath.Split('\',[StringSplitOptions]'RemoveEmptyEntries'))
        for ($i=0;$i -lt $aTemp.GetUpperBound(0);$i++)
        {
            $NewPath = $NewPath + $aTemp[$i] + '\'
        }
        $NewPath = $NewPath.Substring(0,($NewPath.Length - 1))
        Write-Log ('[Get-FolderPathFromFilePath] NewPath: ' + $NewPath) -Log $Log
        Return $NewPath
    }
    else {Return ''}
}

function CopyFolderRecusively
{
    param([string] $sSourceFolderPath, [string] $sDestinationFolderPath, [string] $Log = '.\Clue.log')

    if ((Test-Path -Path $sSourceFolderPath) -eq $false)
    {
        Write-Log ('SourceFolder "' + $sSourceFolderPath + '" does not exist.') -Log $Log
        Return
    }

    if ((Test-Path -Path $sDestinationFolderPath) -eq $false)
    {
        Create-Directory -sDirectoryPath $sDestinationFolderPath
    }

    [string] $sSourcePath = $sSourceFolderPath + '\*.*'
    Copy-Item -Path $sSourcePath -Destination $sDestinationFolderPath

    $oCollectionOfSourceFilesAndFolders = Get-ChildItem $sSourceFolderPath

    foreach ($oSourceFileOrFolder in $oCollectionOfSourceFilesAndFolders)
    {
        If ($oSourceFileOrFolder -is [System.IO.DirectoryInfo])
        {
            [string] $sSubDestinationFolderPath = $sDestinationFolderPath + '\' + $oSourceFileOrFolder.Name
            [string] $sSubSourceFolderPath = $oSourceFileOrFolder.FullName
            $Null = Create-Directory -sDirectoryPath $sSubDestinationFolderPath
            CopyFolderRecusively -sSourceFolderPath $sSubSourceFolderPath -sDestinationFolderPath $sSubDestinationFolderPath
        }
    }
}

Function New-DataCollectionInProgress
{
    param([string] $IncidentOutputFolder, [string] $Log = '.\Clue.log')
    [string] $FilePath = $IncidentOutputFolder + '\_DATA_COLLECTION_IN_PROGRESS.txt'
    New-Item -Path $FilePath -Type File
    Test-Error -Err $Error -Log $Log
}

Function Remove-DataCollectionInProgress
{
    param([string] $IncidentOutputFolder, [string] $Log = '.\Clue.log')
    [string] $FilePath = $IncidentOutputFolder + '\_DATA_COLLECTION_IN_PROGRESS.txt'
    Remove-Item -Path $FilePath
    Test-Error -Err $Error -Log $Log
}

Function Get-FileModificationDate
{
    param([string] $FilePath, [string] $Log = '.\Clue.log')
    if (Test-Path -Path $FilePath)
    {
        Return (Get-Item -Path $FilePath).LastWriteTime
    }
    Test-Error -Err $Error -Log $Log
}

Function Test-IsFileModified
{
    param([string] $FilePath, [DateTime] $LastModificationTime, [string] $Log = '.\Clue.log')
    if (Test-Path -Path $FilePath)
    {
        $dtCurrentModTime = (Get-Item -Path $FilePath).LastWriteTime
        if ($LastModificationTime -ne $dtCurrentModTime)
        {
            Return $true
        }
    }
    Return $false
}

Function Test-DataCollectionInProgress
{
    param([string] $FolderPath, [string] $Log = '.\Clue.log')
    $oFiles = Get-ChildItem $FolderPath
    :FileSearchLoop foreach ($oFile in $oFiles)
    {
        If ($oFile -is [System.IO.FileInfo])
        {
            If ($oFile.Name -eq '_DATA_COLLECTION_IN_PROGRESS.txt')
            {
                Return $true
                Break FileSearchLoop;
            }
        }
    }
    Return $false
}

function Add-Zip
{
    param([string] $FolderPathToCompress, [string] $ZipFilePath, [bool] $DeleteSource = $false, [string] $Log = '.\Clue.log')

    if (Test-Path $ZipFilePath) 
    {
        Remove-Item $ZipFilePath -force
    }

    Add-Type -AssemblyName 'system.io.compression.filesystem' | Out-Null
    [System.IO.Compression.ZipFile]::CreateFromDirectory($FolderPathToCompress, $ZipFilePath)

    [int] $Attempts = 0
    [int] $Length = 0
    Do
    {
        $Length = (Get-Item -Path $ZipFilePath).Length
        $Attempts++
        Start-Sleep -Seconds 1
    } until (($Length -gt 100) -or ($Attempts -gt 2))

    if ($DeleteSource -eq $true)
    {
        Remove-Item -Path $FolderPathToCompress -Recurse -Force -ErrorAction SilentlyContinue
    }
    Return $Length
}

Function Old-Add-Zip
{
    param([string] $FolderPathToCompress, [string] $ZipFilePath, [bool] $DeleteSource = $false, [string] $Log = '.\Clue.log')

    If ((Test-Path $ZipFilePath) -eq $false)
    {
        Set-Content $ZipFilePath ('PK' + [char]5 + [char]6 + ("$([char]0)" * 18))
        (Get-ChildItem $ZipFilePath).IsReadOnly = $false
    }

    $oShell = New-Object -COM Shell.Application
    $oZipFile = $oShell.NameSpace($ZipFilePath)

    $oCollectionOfFilesAndFolders = @(Get-ChildItem $FolderPathToCompress)
    [int] $iNumOfSourceFiles = $oCollectionOfFilesAndFolders.Count
    [int] $iNumOfFiles = 0
    if ($iNumOfSourceFiles -gt 0)
    {
        ForEach($oFileOrFolder in $oCollectionOfFilesAndFolders)
        {
            [datetime] $dtBeginTime = (Get-Date)
            $oZipFile.CopyHere($oFileOrFolder.FullName)
            $iNumOfFiles++
            Do 
            {
                Start-sleep -milliseconds 500
                $dtDuration = New-TimeSpan -Start $dtBeginTime -End (Get-Date)
                if ($dtDuration.TotalSeconds -gt 600)
                {
                    Write-Log ('[Add-Zip] Timeout reached!') -Log $Log
                    Return
                }
            } Until ($oZipFile.Items().Count -ge $iNumOfFiles)
        }
    }
    else
    {
        'No files in source folder.' >> $Log
    }

    $oZipFile = $oShell.NameSpace($ZipFilePath)
    if (($oZipFile.Items().Count -eq $iNumOfFiles) -and ($DeleteSource -eq $true))
    {
        Remove-Item $FolderPathToCompress -Recurse -Force -ErrorAction SilentlyContinue
    }
    [string] '[' + (Get-Date) + '][IncidentFolderManagement.ps1] Add-Zip: End' >> $Log
}

Function Test-IsIncidentFolder
{
    param([string] $FolderName, [string] $Log = '.\Clue.log')
    if ($FolderName.Contains('_'))
    {
        $aString = $FolderName.Split('_')
        if ($aString.Count -ge 3)
        {
            Return $true
        }
    }
    Return $False
}

function Remove-InstallationFolder
{
    param([string] $FolderPath, [string] $Log = '.\Clue.log')
    if ((Test-Path -Path $FolderPath) -eq $true)
    {
        $oCollectionOfFilesAndFolders = Get-ChildItem $FolderPath
        foreach ($oFileOrFolder in $oCollectionOfFilesAndFolders)
        {
            If ($oFileOrFolder -is [System.IO.FileInfo])
            {
                Remove-Item -Path $oFileOrFolder.FullName -Force
            }
        }
        $oCollectionOfFilesAndFolders = Get-ChildItem $FolderPath
        foreach ($oFileOrFolder in $oCollectionOfFilesAndFolders)
        {
            If ($oFileOrFolder -is [System.IO.DirectoryInfo])
            {
                Remove-InstallationFolder -FolderPath $oFileOrFolder.FullName
            }
        }
        Remove-Item -Path $FolderPath -Recurse -Force
    }
}
function Get-FileNameFromFilePath
{
    param([string] $Path)

    $aPath = $Path.Split('\')
    $u = $aPath.GetUpperBound(0)
    Return $aPath[$u]
}
Function Start-TruncateLog
{
    param($FilePath, [int] $Threshold = 10000, [int] $TruncateTo = 1000, [string] $Log = '.\Clue.log')
    
    Write-Log ('[Start-TruncateLog] START') -Log $Log
    if ((Test-Path -Path $FilePath) -eq $false)
    {
        Write-Log ('[Start-TruncateLog] Path not found: ' + $FilePath) -Log $Log
        Return;
    }

    Write-Log ('[Start-TruncateLog] Getting content...') -Log $Log
    $OriginalContent = Get-Content -Path $FilePath
    Test-Error -Err $Error -Log $Log

    Write-Log ('[Start-TruncateLog] Getting content...Done!') -Log $Log
    Write-Log ('[Start-TruncateLog] OriginalContent.Length: ' + $OriginalContent.Length) -Log $Log
    Write-Log ('[Start-TruncateLog] Threshold: ' + $Threshold) -Log $Log
    if ($OriginalContent.Length -lt $Threshold)
    {
        Return;
    }

    Write-Log ('[Start-TruncateLog] TruncateTo: ' + $Threshold) -Log $Log

    if ($OriginalContent.Length -gt $TruncateTo)
    {
        $OriginalContent | Select -Last 1000 | Out-File $Log -Force
        Write-Log ('[Start-TruncateLog] Log truncated!') -Log $Log
        #[string] $TempFileName = ((([GUID]::NewGuid()).Guid) + '.tmp')
        #Write-Log ('[Start-TruncateLog] TempFileName: ' + $TempFileName) -Log $Log
        #$NewFile = New-Item -Path $TempFileName -ItemType File
        #Test-Error -Err $Error -Log $Log
        #[int] $OffSet = $OriginalContent.Length - $TruncateTo
        #Write-Log ('[Start-TruncateLog] Adding content to temp file...') -Log $Log
        #for ($i = $OffSet; $i -lt $OriginalContent.Length; $i++)
        #{
        #    Add-Content -Path $NewFile -Value $OriginalContent[$i] -Encoding Unicode              
        #}
        #Test-Error -Err $Error -Log $Log
        #Write-Log ('[Start-TruncateLog] Adding content to temp file...Done!') -Log $Log
    }
    #Write-Log ('[Start-TruncateLog] Removing original file...') -Log $Log
    #Remove-Item -Path $FilePath -Force
    #Test-Error -Err $Error -Log $Log
    #Write-Log ('[Start-TruncateLog] Removing original file...Done!') -Log $Log
    #Write-Log ('[Start-TruncateLog] Renaming temp file...') -Log $Log
    #Rename-Item -Path $NewFile -NewName $FilePath
    #Test-Error -Err $Error -Log $Log
    #Write-Log ('[Start-TruncateLog] Renaming temp file...Done!') -Log $Log
    #Add-Content -Path $FilePath -Value '[Start-TruncateLog] Log truncated!'
    Write-Log ('[Start-TruncateLog] END') -Log $Log
}

<#
Function UpdateClue
{
    param([string] $WorkingDirectory, [string] $UploadSharePath, [string] $Log = '.\Clue.log')
    
    [bool] $IsRestartRequired = $false
    [string] $sClueCentralConfigPath = $UploadSharePath + '\Clue'
    If (Test-Path -Path $sClueCentralConfigPath)
    {
        [string] $sCmd = 'Robocopy.exe "' + $sClueCentralConfigPath + '" "' + $WorkingDirectory + '" /S /IPG:300 /R:0'
        [string] '[' + (Get-Date) + '][UpdateClue] $sCmd: ' + $sCmd >> $Log
        $aOutput = Invoke-Expression -Command $sCmd
        $aOutput >> $Log
        
        [bool] $IsRobocopyFinished = $false
        foreach ($sLine in $aOutput)
        {
            If (($sLine.Contains('Total')) -and ($sLine.Contains('Total')) -and ($sLine.Contains('Copied')) -and ($sLine.Contains('Skipped')) -and ($sLine.Contains('Mismatch')) -and ($sLine.Contains('FAILED')) -and ($sLine.Contains('Extras')))
            {
                $IsRobocopyFinished = $true            
            }
            
            If ($IsRobocopyFinished -eq $true)
            {
                If ($sLine.Contains('Files :'))
                {
                    $aLine = $sLine.Split('',[StringSplitOptions]'RemoveEmptyEntries')
                    [int] $iCopied = $aLine[3]
                    [string] '[' + (Get-Date) + '][UpdateClue] $iCopied: ' + $iCopied >> $Log
                    If ($iCopied -gt 0)
                    {
                        #// Restart Clue jobs. This will terminate all Clue jobs including this one and restart them.
                        [string] $sCmd = 'start "' + $WorkingDirectory + '\RestartClueScheduledTasks.bat"'
                        [string] '[' + (Get-Date) + '][UpdateClue] $sCmd: ' + $sCmd >> $Log
                        Invoke-Expression -Command $sCmd
                        Break;
                    }
                }        
            }
        }
    }
    Else
    {
        [string] '[' + (Get-Date) + '][IncidentFolderManagement.ps1] Clue update folder path does not exist.' >> $Log
    }
}
#>