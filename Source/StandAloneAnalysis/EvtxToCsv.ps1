#requires -Version 2.0
<#
    .SYNOPSIS
    Converts EVTX files in a folder path to CSV files with the same name.
    .DESCRIPTION
    Point this script to a folder that contains event logs in EVTX format and an EVTX file extension. This script converts EVTX files in a folder path to CSV files with the same name.
    .EXAMPLE
    .\EvtxToCsv.ps1 -Path .\EventLogs
    This will convert every EVTX file under .\EventLogs and create a same-named CSV file. This makes parsing/analyzing the event log easier.
    .Parameter Path
    This parameters is required and is expected to be a folder path or a path to a network share. Do not put a backslash on the end.
    .Notes
    Name: EvtxToCsv.ps1
    Author: Clint Huffman (clinth@microsoft.com)
    LastEdit: June 15th, 2015
	Version: 1.0
    Keywords: PowerShell, ICU
#>
param([string] $Path)

[string] $EvtxFileSearchPath = $Path + '\*.evtx'

$oCollectionOfEvtxFiles = Get-ChildItem $EvtxFileSearchPath

foreach ($oFile in $oCollectionOfEvtxFiles)
{
    $oFile.Name
    [string] $NewCsvFilePath = $oFile.DirectoryName + '\' + $oFile.BaseName + '.csv'
    Get-WinEvent -Path $oFile.FullName | SELECT TimeCreated, MachineName, ProviderName, Id, UserId, Message | Export-Csv -Path $NewCsvFilePath -NoTypeInformation
    $NewCsvFilePath
}

