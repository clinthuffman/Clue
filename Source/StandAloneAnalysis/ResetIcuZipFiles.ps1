#requires -Version 2.0
<#
    .SYNOPSIS
    Renames each ICU zip file in a folder or network share to the original name - removes the causes from the file name.
    .DESCRIPTION
    Point this script to a folder that contains ICU zip files. Renames each ICU zip file in a folder or network share to the original name - removes the causes from the file name.
    .EXAMPLE
    .\ResetIcuZipFiles.ps1 -Path \\server\ICU
    This will open each zip file under \\server\ICU and rename each file back to the original name.
    .Parameter Path
    This parameters is required and is expected to be a folder path or a path to a network share. Do not put a backslash on the end.
    .Notes
    Name: ResetIcuZipFiles.ps1
    Author: Clint Huffman (clinth@microsoft.com)
    LastEdit: June 11th, 2015
	Version: 1.0
    Keywords: PowerShell, ICU
#>
param([string] $Path)

if ($Path -ne '')
{
    $oFiles = Get-ChildItem $Path

    foreach ($oFile in $oFiles)
    {
        [string] $NewName = $oFile.BaseName
        $aString = $NewName.Split('_')

        [string] $sDateTime = $aString[0]
        [string] $sComputer = $aString[1]
        [string] $sTrigger = $aString[2]
        [string] $sCause = $aString[3]
        $NewName = $sDateTime + '_' + $sComputer + '_' + $sTrigger + '.zip'

        $oFile | Rename-Item -NewName $NewName
    }
}