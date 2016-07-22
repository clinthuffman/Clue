param([string] $OutputDirectory='%systemdrive%\Perflogs', [string] $Log = '.\Setup.log')
<#
    .SYNOPSIS
    Looks for a PAL tool threshold file that best matches your system and creates a data collector set based on the threshold file.
    .DESCRIPTION
    Looks for a PAL tool threshold file that best matches your system and creates a data collector set based on the threshold file.
    .EXAMPLE
    .\PalCollector.ps1
    .Notes
    Name: PalCollector.ps1
    Author: Clint Huffman (clinth@microsoft.com)
    Created: 2013-01-08
    Keywords: PowerShell, PAL
#>
# Requires -Version 2.0
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

Function Write-Log
{
    param($Output, [string] $Log = '.\Setup.log')
    #// Writes to the log file.
    $TimeStamp = "$(Get-Date -format yyyyMMdd-HHmmss)"    
    if ($Output -eq $null) {Add-content $Log -value ('[' + $TimeStamp + '] NULL') -Encoding Unicode;Return}
    switch ($Output.GetType().FullName)
    {
        'System.String'                {Add-content -Path $Log -value ('[' + $TimeStamp + '] ' + $Output) -Encoding Unicode}
        'System.Collections.ArrayList' {Add-content -Path $Log -value ('[' + $TimeStamp + ']') -Encoding Unicode; $Output >> $Log}
        default                        {Add-content -Path $Log -value ('[' + $TimeStamp + '] ' + $Output) -Encoding Unicode}
    }
}

Function Test-Error
{
    param($Err)
    #// Tests if an error condition exists and writes it to the log.
    if ($Err.Count -gt 0)
    {
        Write-Log ('[Test-Error] Error(s) found: ' + $Err.Count) -Log $Log
        Write-Log ($Err) -Log $Log
        $Err.Clear()
    }
}

Function Test-FileExists
{
    param($Path)
    If ($Path -eq '')
    {
        Return $false
    }
    Else
    {
        Return Test-Path -Path $Path
    }
}

Function Test-Property 
{
    #// Function provided by Jeffrey Snover
    #// Tests if a property is a memory of an object.
	param ([Parameter(Position=0,Mandatory=1)]$InputObject,[Parameter(Position=1,Mandatory=1)]$Name)
	[Bool](Get-Member -InputObject $InputObject -Name $Name -MemberType *Property)
}

Function RemoveCounterComputer
{
    param($sCounterPath)
    
	#'\\IDCWEB1\Processor(_Total)\% Processor Time"
	[string] $sString = ""
	#// Remove the double backslash if exists
	If ($sCounterPath.substring(0,2) -eq "\\")
	{		
		$sComputer = $sCounterPath.substring(2)
		$iLocThirdBackSlash = $sComputer.IndexOf("\")
		$sString = $sComputer.substring($iLocThirdBackSlash)
	}
	Else
	{
		$sString = $sCounterPath
	}		
		Return $sString	
}

Function RemoveCounterNameAndComputerName
{
    param($sCounterPath)
    
    If ($sCounterPath.substring(0,2) -eq "\\")
    {
    	$sCounterObject = RemoveCounterComputer $sCounterPath
    }
    Else
    {
        $sCounterObject = $sCounterPath
    }
	# \Paging File(\??\C:\pagefile.sys)\% Usage Peak
	# \(MSSQL|SQLServer).*:Memory Manager\Total Server Memory (KB)
	$aCounterObject = $sCounterObject.split("\")
	$iLenOfCounterName = $aCounterObject[$aCounterObject.GetUpperBound(0)].length
	$sCounterObject = $sCounterObject.substring(0,$sCounterObject.length - $iLenOfCounterName)
	$sCounterObject = $sCounterObject.Trim("\")
    Return $sCounterObject 	    
}

Function ReadThresholdFileIntoMemory
{
	param($sThresholdFilePath)
	
	[xml] (Get-Content $sThresholdFilePath)	
}

Function RemoveCounterComputer
{
    param($sCounterPath)
    
	#'\\IDCWEB1\Processor(_Total)\% Processor Time"
	[string] $sString = ""
	#// Remove the double backslash if exists
	If ($sCounterPath.substring(0,2) -eq "\\")
	{		
		$sComputer = $sCounterPath.substring(2)
		$iLocThirdBackSlash = $sComputer.IndexOf("\")
		$sString = $sComputer.substring($iLocThirdBackSlash)
	}
	Else
	{
		$sString = $sCounterPath
	}		
		Return $sString	
}

Function RemoveCounterNameAndComputerName
{
    param($sCounterPath)
    
    If ($sCounterPath.substring(0,2) -eq "\\")
    {
    	$sCounterObject = RemoveCounterComputer $sCounterPath
    }
    Else
    {
        $sCounterObject = $sCounterPath
    }
	# \Paging File(\??\C:\pagefile.sys)\% Usage Peak
	# \(MSSQL|SQLServer).*:Memory Manager\Total Server Memory (KB)
	$aCounterObject = $sCounterObject.split("\")
	$iLenOfCounterName = $aCounterObject[$aCounterObject.GetUpperBound(0)].length
	$sCounterObject = $sCounterObject.substring(0,$sCounterObject.length - $iLenOfCounterName)
	$sCounterObject = $sCounterObject.Trim("\")
    Return $sCounterObject 	    
}

Function GetCounterComputer
{
    param($sCounterPath)
    
	#'\\IDCWEB1\Processor(_Total)\% Processor Time"
	[string] $sComputer = ""
	
	If ($sCounterPath.substring(0,2) -ne "\\")
	{
		Return ""
	}
	$sComputer = $sCounterPath.substring(2)
	$iLocThirdBackSlash = $sComputer.IndexOf("\")
	$sComputer = $sComputer.substring(0,$iLocThirdBackSlash)
	Return $sComputer
}

Function GetCounterObject
{
    param($sCounterPath)
    
	$sCounterObject = RemoveCounterNameAndComputerName $sCounterPath
	
	#// "Paging File(\??\C:\pagefile.sys)"
	$Char = $sCounterObject.Substring(0,1)
	If ($Char -eq "`\")
	{
		$sCounterObject = $sCounterObject.SubString(1)
	}	
	
	$Char = $sCounterObject.Substring($sCounterObject.Length-1,1)	
	If ($Char -ne "`)")
	{
		Return $sCounterObject
	}	
	$iLocOfCounterInstance = 0
	For ($a=$sCounterObject.Length-1;$a -gt 0;$a = $a - 1)
	{			
		$Char = $sCounterObject.Substring($a,1)
		If ($Char -eq "`)")
		{
			$iRightParenCount = $iRightParenCount + 1
		}
		If ($Char -eq "`(")
		{
			$iRightParenCount = $iRightParenCount - 1
		}
		$iLocOfCounterInstance = $a
		If ($iRightParenCount -eq 0){break}
	}
	Return $sCounterObject.Substring(0,$iLocOfCounterInstance)
}

Function GetCounterInstance
{
    param($sCounterPath)
    
	$sCounterObject = RemoveCounterNameAndComputerName $sCounterPath	
	#// "Paging File(\??\C:\pagefile.sys)"
	$Char = $sCounterObject.Substring(0,1)	
	If ($Char -eq "`\")
	{
		$sCounterObject = $sCounterObject.SubString(1)
	}
	$Char = $sCounterObject.Substring($sCounterObject.Length-1,1)	
	If ($Char -ne "`)")
	{
		Return ""
	}

	$iLocOfCounterInstance = 0
	For ($a=$sCounterObject.Length-1;$a -gt 0;$a = $a - 1)
	{			
		$Char = $sCounterObject.Substring($a,1)
		If ($Char -eq "`)")
		{
			$iRightParenCount = $iRightParenCount + 1
		}
		If ($Char -eq "`(")
		{
			$iRightParenCount = $iRightParenCount - 1
		}
		$iLocOfCounterInstance = $a
		If ($iRightParenCount -eq 0){break}
	}
	$iLenOfInstance = $sCounterObject.Length - $iLocOfCounterInstance - 2
	Return $sCounterObject.Substring($iLocOfCounterInstance+1, $iLenOfInstance)
}

Function GetCounterName
{
    param($sCounterPath)
    
	$aCounterPath = $sCounterPath.Split("\")
	Return $aCounterPath[$aCounterPath.GetUpperBound(0)]
}

Function Get-GUID()
{
	Return "{" + [System.GUID]::NewGUID() + "}"
}

Function ConvertCounterExpressionToVarName($sCounterExpression)
{
	$sCounterObject = GetCounterObject $sCounterExpression
	$sCounterName = GetCounterName $sCounterExpression
	$sCounterInstance = GetCounterInstance $sCounterExpression	
	If ($sCounterInstance -ne "*")
	{
		$sResult = $sCounterObject + $sCounterName + $sCounterInstance
	}
	Else
	{
		$sResult = $sCounterObject + $sCounterName + "ALL"
	}
	$sResult = $sResult -replace "/", ""
	$sResult = $sResult -replace "\.", ""
	$sResult = $sResult -replace "%", "Percent"
	$sResult = $sResult -replace " ", ""
	$sResult = $sResult -replace "\.", ""
	$sResult = $sResult -replace ":", ""
	$sResult = $sResult -replace "\(", ""
	$sResult = $sResult -replace "\)", ""
	$sResult = $sResult -replace "-", ""
	$sResult
}

Function InheritFromThresholdFiles
{
    param($sThresholdFilePath)
    
    $XmlThresholdFile = [xml] (Get-Content $sThresholdFilePath)
    #// Add it to the threshold file load history, so that we don't get into an endless loop of inheritance.
    If ($global:alThresholdFilePathLoadHistory.Contains($sThresholdFilePath) -eq $False)
    {
        [void] $global:alThresholdFilePathLoadHistory.Add($sThresholdFilePath)
    }
    
    #// Inherit from other threshold files.
    ForEach ($XmlInheritance in $XmlThresholdFile.SelectNodes("//INHERITANCE"))
    {
        If ($(Test-FileExists $XmlInheritance.FilePath) -eq $True)
        {
            $XmlInherited = [xml] (Get-Content $XmlInheritance.FilePath)
            ForEach ($XmlInheritedAnalysisNode in $XmlInherited.selectNodes("//ANALYSIS"))
            {
                $bFound = $False            
                ForEach ($XmlAnalysisNode in $global:XmlAnalysis.selectNodes("//ANALYSIS"))
                {
                    If ($XmlInheritedAnalysisNode.ID -eq $XmlAnalysisNode.ID)
                    {
                        $bFound = $True
                        Break
                    }
                    If ($XmlInheritedAnalysisNode.NAME -eq $XmlAnalysisNode.NAME)
                    {
                        $bFound = $True
                        Break
                    }                
                }
                If ($bFound -eq $False)
                {            
                    [void] $global:XmlAnalysis.PAL.AppendChild($global:XmlAnalysis.ImportNode($XmlInheritedAnalysisNode, $True))                
                }
            }
    		If ($global:alThresholdFilePathLoadHistory.Contains($XmlInheritance.FilePath) -eq $False)
    		{
    			InheritFromThresholdFiles $XmlInheritance.FilePath
    		}
        }
    }	 
}

Function Get-UserTempDirectory()
{
	$DirectoryPath = Get-ChildItem env:temp	
	Return $DirectoryPath.Value
}

Function Test-LogicalDiskFreeSpace
{
    param([string] $DriveLetterOrPath, [Int] $FreeSpaceInMB)
    If ($DriveLetterOrPath.Length -ne 1)
    {
        $DriveLetterOrPath = $DriveLetterOrPath.Substring(0,1) + ':'
    }
    Else
    {
        $DriveLetterOrPath = $DriveLetterOrPath + ':'
    }
    $DriveLetterOrPath = $DriveLetterOrPath.ToUpper()
    
    $sWql = 'SELECT DeviceID, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType = 3 AND DeviceID = "' + $DriveLetterOrPath + '"'
    
    $ColOfLogicalDisk = Get-WmiObject -Query $sWql | SELECT DeviceID, Size, FreeSpace

    ForEach ($oLogicalDisk in $ColOfLogicalDisk)
    {
        $LogicalDiskSizeInMB = $oLogicalDisk.Size / 1MB
        $LogicalDiskFreeSpaceInMB = $oLogicalDisk.FreeSpace / 1MB
    }

    [Int] $iLeftOverFreeSpace = $LogicalDiskFreeSpaceInMB - $FreeSpaceInMB
    [Int] $iPercentageOfFreeSpaceLeftOver = "{0:N0}" -f (($iLeftOverFreeSpace / $LogicalDiskSizeInMB) * 100)


    If ($FreeSpaceInMB -le $LogicalDiskFreeSpaceInMB)
    {
        If ($iPercentageOfFreeSpaceLeftOver -le 10)
        {
            Write-Warning "$iPercentageOfFreeSpaceLeftOver% of free space will be left over on $DriveLetterOrPath drive!"
        }
        
        Return $true
    }
    Else
    {
        Return $false
    }
}

Function IsNumeric
{
    param($Value)
    [double]$number = 0
    $result = [double]::TryParse($Value, [REF]$number)
    $result
}

Function ConvertToDataType
{
	param($ValueAsDouble, $DataTypeAsString="integer")
	$sDateType = $DataTypeAsString.ToLower()

    If ($(IsNumeric -Value $ValueAsDouble) -eq $True)
    {
    	switch ($sDateType)
    	{
    		#'absolute' {[Math]::Abs($ValueAsDouble)}
    		#'double' {[double]$ValueAsDouble}
    		'integer' {[Math]::Round($ValueAsDouble,0)}
    		#'long' {[long]$ValueAsDouble}
    		#'single' {[single]$ValueAsDouble}
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

Function ExtractSqlCounterObject
{
    param([string] $sText)

    $sText = $sText.ToUpper()

    if (($sText.Contains('SQLSERVER')) -or ($sText.Contains('MSSQL')))
    {
        $aTemp = $sText.Split(':')
        [int] $u = $aTemp.GetUpperBound(0)
        Return $aTemp[$u]
    }
    Else
    {
        Return $sText
    }
}

Function IsCounterObjectMatch
{
    param([string] $sFromTemplate, [string] $sFromSystem)

    $sFromSystem = ExtractSqlCounterObject -sText $sFromSystem
    $sFromTemplate = ExtractSqlCounterObject -sText $sFromTemplate

    if ($sFromSystem -eq $sFromTemplate)
    {
        Return $true
    }
    Else
    {
        Return $false
    }
}

Function Get-DataSourceCounterObjectsFromXml
{
    param([xml] $XmlAnalyses)

    $alCounterObjects = New-Object System.Collections.ArrayList

    ForEach ($XmlDataSource in $global:XmlAnalysis.SelectNodes('//DATASOURCE'))
    {
        $oCtr = CounterPathToObject -sCounterPath $XmlDataSource.EXPRESSIONPATH
        if ($alCounterObjects.Contains($oCtr.Object) -eq $False)
        {
            [void] $alCounterObjects.Add($oCtr.Object)
        }
    }
    Return $alCounterObjects
}

Function GetDataCollectorSetNames
{
    Write-Log ('[GetDataCollectorSetNames]: START') -Log $Log
    [string] $sLine = ''
    [bool] $IsPastHeader = $false
    $oCollectionOfDataCollectorNames = New-Object System.Collections.ArrayList

    [string] $sCmd = 'logman query'
    $oOutput = Invoke-Expression -Command $sCmd

    For ($L = 0;$L -lt $oOutput.GetUpperBound(0);$L++ )
    {
        $sLine = $oOutput[$L]
        if ($oOutput[$L].Contains('----------'))
        {
            $IsPastHeader = $true
            $L++
            $sLine = $oOutput[$L]
        }

        if ($IsPastHeader -eq $true)
        {
            $aLine = $sLine.Split()
            [void] $oCollectionOfDataCollectorNames.Add($aLine[0])
        }
    }
    Write-Log ('[GetDataCollectorSetNames]: END') -Log $Log
    Return $oCollectionOfDataCollectorNames
}

Function New-DirectoryWithConfirm
{
    param([string] $DirectoryPath)

    if ((Test-Path -Path $DirectoryPath) -eq $False)
    {
        $aFolderPath = $DirectoryPath.Split('\')
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
                $null = New-Item -Path $sParentPath -Name $sPath -type directory
            }
        }
    }
    Return [bool] (Test-Path -Path $DirectoryPath)
}

#//////////
#// Main //
#//////////

Write-Log '[Start]' -Log $Log

[string] $sDataCollectorSetName = 'PalCollector'

if ($OutputDirectory -eq '') {$OutputDirectory = '%systemdrive%\Perflogs'}

#// Test is output directory exists.
$OutputDirectory = [System.Environment]::ExpandEnvironmentVariables($OutputDirectory)
[bool] $IsCreated = New-DirectoryWithConfirm -DirectoryPath $OutputDirectory
Test-Error -Err $Error -Log $Log
if ($IsCreated -eq $False)
{
    Write-Log ('Unable to create output folder: ' + $OutputDirectory) -Log $Log
    Exit;
}

#// Test if output logical drive has enough free disk space.
#//$OutputDriveLetter = $OutputDirectory.Substring(0,1) + ':'
#//$OutputDriveLetter = $OutputDriveLetter.ToUpper()
#//If ((Test-LogicalDiskFreeSpace -DriveLetterOrPath $OutputDirectory -FreeSpaceInMB 200) -eq $False)
#//{
#//    Write-Warning "Not enough free space on $OutputDriveLetter drive! Select another location with more free space."
#//    #Break;
#//}

$global:alCounterList = New-Object System.Collections.ArrayList
$oCounterObjectsOnLocalSystem = Get-Counter -ListSet * | SELECT CounterSetName, CounterSetType | Sort-Object CounterSetName
Test-Error -Err $Error -Log $Log

If ((Test-Path -Path .\CounterObjectList.txt) -eq $False)
{
    $oFiles = Get-ChildItem -Path $WorkingDirectory\*.xml
    $global:alCounterList = New-Object System.Collections.ArrayList

    $alCounterObjectsFromThresholdFiles = New-Object System.Collections.ArrayList

    ForEach ($oFile in $oFiles)
    {
        Write-Log ($oFile.Name) -Log $Log
        $iMatches = 0
        $iCounters = 0

        [xml] $global:XmlAnalysis = "<PAL></PAL>"
        $global:alThresholdFilePathLoadHistory = New-Object System.Collections.ArrayList
        $global:XmlAnalysis = ReadThresholdFileIntoMemory -sThresholdFilePath $($oFile.FullName)

        ForEach ($XmlDataSource in $global:XmlAnalysis.SelectNodes('//DATASOURCE'))
        {
            $oCtr = CounterPathToObject -sCounterPath $XmlDataSource.EXPRESSIONPATH
            if ($alCounterObjectsFromThresholdFiles.Contains($oCtr.Object) -eq $False)
            {
                [void] $alCounterObjectsFromThresholdFiles.Add($oCtr.Object)
            }
        }
    }

    $alCounterObjectsFromThresholdFiles = $alCounterObjectsFromThresholdFiles.GetEnumerator() | Sort-Object
    $alCounterObjectsFromThresholdFiles > .\CounterObjectList.txt
}
Test-Error -Err $Error -Log $Log

If ((Test-Path -Path .\CounterObjectList.txt) -eq $False)
{
    Write-Host 'Unable to find CounterList.txt!'
    Break;
}

$aFile = Get-Content -Path .\CounterObjectList.txt
$alCounterObjectsFromPalThresholdFiles = New-Object System.Collections.ArrayList(,$aFile)
Test-Error -Err $Error -Log $Log

ForEach ($oCounterObjectOnLocalSystem in $oCounterObjectsOnLocalSystem)
{
    $sCounterObjectOnComputer = $oCounterObjectOnLocalSystem.CounterSetName

    [bool] $IsMatch = $False
    if ($alCounterObjectsFromPalThresholdFiles.Contains($sCounterObjectOnComputer))
    {
        $IsMatch = $true
    }

    if ($IsMatch -eq $False)
    {
        $sFromSystem = ExtractSqlCounterObject -sText $sCounterObjectOnComputer
        $sFromSystem = 'SQLServer:' + $sFromSystem
        if ($alCounterObjectsFromPalThresholdFiles.Contains($sFromSystem))
        {
            $IsMatch = $true
        }
    }
        
	If ($IsMatch -eq $true)
    {
        If ($oCounterObjectOnLocalSystem.CounterSetType -eq 'MultiInstance')
        {
            [string] $sCounterObjectPath = '\' + $oCounterObjectOnLocalSystem.CounterSetName + '(*)\*'
        }
        Else
        {
            [string] $sCounterObjectPath = '\' + $oCounterObjectOnLocalSystem.CounterSetName + '\*'
        }

        If ($global:alCounterList.Contains($sCounterObjectPath) -eq $False)
        {
            [void] $global:alCounterList.Add($sCounterObjectPath)
        }
    }
}
Test-Error -Err $Error -Log $Log

$global:alCounterList = $global:alCounterList.GetEnumerator() | Sort-Object
Write-Log ($global:alCounterList) -Log $Log
Test-Error -Err $Error -Log $Log

$UserTempDirectory = Get-UserTempDirectory
Test-Error -Err $Error -Log $Log
[string] $sCounterListFilePath = $UserTempDirectory + '\counterlist.txt'
$global:alCounterList | Out-File -FilePath $sCounterListFilePath -Force

Write-Log '' -Log $Log
[string] $sCmd = 'logman query'
Write-Log ($sCmd) -Log $Log
$oOutput = Invoke-Expression -Command $sCmd
Write-Log ($oOutput) -Log $Log
Write-Log ('') -Log $Log

ForEach ($sLine in $oOutput)
{
    $aLine = $sLine.Split()
    $sDataCollectorSet = $aLine[0]
    $sStatus = $aLine[2]

    if ($sDataCollectorSet.Contains('PalCollector'))
    {
        if ($sStatus -eq 'Running')
        {
            Write-Log ('') -Log $Log
            [string] $sCmd = 'logman stop ' + $sDataCollectorSet
            Write-Log ($sCmd) -Log $Log
            Write-Log (Invoke-Expression -Command $sCmd) -Log $Log
            Write-Log ('') -Log $Log
        }

        Write-Log ('') -Log $Log
        [string] $sCmd = 'logman delete ' + $sDataCollectorSet
        Write-Log ($sCmd) -Log $Log
        Write-Log (Invoke-Expression -Command $sCmd) -Log $Log
        Write-Log ('') -Log $Log
    }
}

[string] $sOutputFilePath = $OutputDirectory + '\' + $sDataCollectorSetName + '.blg'

    [string] $sName = ''
    [string] $sCmd = ''
    [string] $sLine = ''
    [bool] $IsPastHeader = $false

    [string] $sCmd = 'logman query' 
    $oOutput = Invoke-Expression -Command $sCmd
    Write-Log ($oOutput) -Log $Log

    foreach ($sLine in $oOutput)
    {
        if ($IsPastHeader -eq $true)
        {
            [string] $sName = ''
            $aLine = $sLine.Split('',[StringSplitOptions]'RemoveEmptyEntries')
            switch ($aLine.GetUpperBound(0))
            {
                0 {$sName = $aLine[0];$sStatus = 'Running'}
                1 {$sName = $aLine[0];$sStatus = 'Running'}
                2 {$sName = $aLine[0];$sStatus = $aLine[2]}
            }

            if ($sName.Contains('PalCollector'))
            {
                if ($sStatus -ne 'Stopped')
                {
                    Write-Log ('Stopping "' + $sName + '"') -Log $Log
                    $sCmd = 'logman stop "' + $sName + '"'
                    $oOutput = Invoke-Expression -Command $sCmd
                    Write-Log ($oOutput) -Log $Log
                }

                Write-Log ('Deleting "' + $sName + '"') -Log $Log
                $sCmd = 'logman delete "' + $sName + '"'
                $oOutput = Invoke-Expression -Command $sCmd
                Write-Log ($oOutput) -Log $Log
            }
        }

        if ($sLine.Contains('----------'))
        {
            $IsPastHeader = $true
        }
    }

[string] $sCmd = 'logman create counter ' + $sDataCollectorSetName + ' -cf "' + $UserTempDirectory + '\counterlist.txt" -f bincirc -max 100 -si 00:00:05 -o "' + $sOutputFilePath + '" -ow --v'
Write-Log ($sCmd) -Log $Log
Write-Log (Invoke-Expression -Command $sCmd) -Log $Log
Write-Log ('') -Log $Log


[string] $sCmd = 'logman start ' + $sDataCollectorSetName
Write-Log ($sCmd) -Log $Log
Write-Log (Invoke-Expression -Command $sCmd) -Log $Log
Write-Log ('') -Log $Log

Remove-Item -Path $sCounterListFilePath -ErrorAction SilentlyContinue

[string] $sCmd = 'schtasks /create /tn \Microsoft\Windows\PLA\PalCollector-OnWindowsStart /sc onstart /tr "logman start PalCollector" /ru system /F'
Write-Log ($sCmd) -Log $Log
Write-Log (Invoke-Expression -Command $sCmd) -Log $Log
Write-Log ('') -Log $Log
Write-Log ('A Performance Monitor data collector called "' + $sDataCollectorSetName + '" has been created in a binary circular log and is scheduled to start upon reboot. Go to Start, Run, "Perfmon", <Enter>, then navigate User Defined data collector sets to see the data collector.') -Log $Log
Write-Log ('Done!') -Log $Log