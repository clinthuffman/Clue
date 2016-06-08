#requires -Version 2.0
<#
    .SYNOPSIS
    Parses the names of ICU zip files and creates a CSV file with the results.
    .DESCRIPTION
    Parses the names of ICU zip files and creates a CSV file with the results.
    .EXAMPLE
    .\03_FileNameParser.ps1 -Path \\server\ICU
    This will parse the file name of each zip file under \\server\ICU and create a CSV file with the results.
    .Parameter Path
    This parameters is required and is expected to be a folder path or a path to a network share. Do not put a backslash on the end.
    .Notes
    Name: 03_FileNameParser.ps1
    Author: Clint Huffman (clinth@microsoft.com)
    LastEdit: June 11th, 2015
	Version: 1.0
    Keywords: PowerShell, ICU
#>
param([string] $Path)

Function IsNumeric
{
    param($Value)
    [double]$number = 0
    Return [double]::TryParse($Value, [REF]$number)
}

Function GetWeekOfYear
{
    param($Date)
    # Note: first day of week is Sunday
    $intDayOfWeek = (get-date -date $Date).DayOfWeek.value__
    $daysToWednesday = (3 - $intDayOfWeek)
    $wednesdayCurrentWeek = ((get-date -date $Date)).AddDays($daysToWednesday)

    # %V basically gets the amount of '7 days' that have passed this year (starting at 1)
    $weekNumber = get-date -date $wednesdayCurrentWeek -uFormat %V

    return $weekNumber
}

[string] $Path = $Path + '\*'

$IncidentItems = Get-ChildItem $Path

$aFolderObjects = @()
$alFolderObjects = New-Object System.Collections.ArrayList

foreach ($oFolderOrFile in $IncidentItems)
{
    If ($alFolderObjects.Contains($oFolderOrFile.Name) -eq $false)
    {
        [void] $alFolderObjects.Add($oFolderOrFile.Name)
        [string] $sLine = $oFolderOrFile.Name
        $sLine

        If ($(IsNumeric -Value $sLine.Substring(0,8)))
        {
            [int] $u = 0
            if ($sLine -match '_')
            {
                $aLine = $sLine -split('_')
                [int] $u = $aLine.GetUpperBound(0)
            }

            [string] $sDateTime = ''
            if ($u -gt 0)
            {
                $sDateTime = $aLine[0]
                $aDateTime = $sDateTime -split('-')
                [datetime] $dtDateTime = [datetime]::ParseExact($sDateTime,'yyyyMMdd-HHmmss',$null)
                [int] $iWeekOfYear = GetWeekOfYear -Date $dtDateTime
                [int] $iYear = $dtDateTime.Year
                [int] $iMonth = $dtDateTime.Month
                [int] $iDay = $dtDateTime.Day
            }

            [string] $sComputer = ''
            if ($u -ge 1)
            {
                [string] $sComputer = $aLine[1]
            }

            [string] $sRule = ''
            if ($u -ge 2)
            {
                [string] $sRule = $aLine[2]
            }
            
            [string] $sCause = ''
            if ($u -ge 3)
            {
                [string] $sCause = $aLine[3]
                $sCause = $sCause -replace '.zip', ''
            }
            
            If ($sCause.Contains(','))
            {
                    $aCause = @($sCause.Split(',',[StringSplitOptions]'RemoveEmptyEntries'))

                    foreach ($sSubCause in $aCause)
                    {
                        if ($sSubCause.Contains('+'))
                        {
                            $aSubCause = @($sSubCause.Split('+',[StringSplitOptions]'RemoveEmptyEntries'))
                            if ($aSubCause.GetUpperBound(0) -ge 1)
                            {
                                $sCategory = $aSubCause[0]
                                for ($c = 1;$c -le $aSubCause.GetUpperBound(0);$c++)
                                {
                                    [string] $sSubSubCause = $sCategory + '+' + $aSubCause[$c]
                                    $oNewObject = New-Object System.Object
                                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'DateTime' -Value $([datetime] $dtDateTime)
                                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'WeekOfYear' -Value $([int] $iWeekOfYear)
                                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Year' -Value $([int] $iYear)
                                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Month' -Value $([int] $iMonth)
                                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Day' -Value $([int] $iDay)
                                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Computer' -Value $([string] $sComputer)
                                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Rule' -Value $([string] $sRule)
                                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Cause' -Value $([string] $sSubSubCause)
                                    $aFolderObjects += $oNewObject
                                }
                            }
                        }
                        else
                        {
                            $oNewObject = New-Object System.Object
                            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'DateTime' -Value $([datetime] $dtDateTime)
                            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'WeekOfYear' -Value $([int] $iWeekOfYear)
                            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Year' -Value $([int] $iYear)
                            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Month' -Value $([int] $iMonth)
                            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Day' -Value $([int] $iDay)
                            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Computer' -Value $([string] $sComputer)
                            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Rule' -Value $([string] $sRule)
                            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Cause' -Value $([string] $sSubCause)
                            $aFolderObjects += $oNewObject
                        }
                    }
            }
            Else
            {
                        if ($sCause.Contains('+'))
                        {
                            $aSubCause = @($sCause.Split('+',[StringSplitOptions]'RemoveEmptyEntries'))
                            if ($aSubCause.GetUpperBound(0) -gt 1)
                            {
                                $sCategory = $aSubCause[0]
                                for ($c = 1;$c -lt $aSubCause.GetUpperBound(0);$c++)
                                {
                                    [string] $sSubSubCause = $sCategory + '+' + $aSubCause[$c]
                                    $oNewObject = New-Object System.Object
                                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'DateTime' -Value $([datetime] $dtDateTime)
                                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'WeekOfYear' -Value $([int] $iWeekOfYear)
                                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Year' -Value $([int] $iYear)
                                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Month' -Value $([int] $iMonth)
                                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Day' -Value $([int] $iDay)
                                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Computer' -Value $([string] $sComputer)
                                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Rule' -Value $([string] $sRule)
                                    Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Cause' -Value $([string] $sSubSubCause)
                                    $aFolderObjects += $oNewObject
                                }
                            }
                        }
                        else
                        {
                            $oNewObject = New-Object System.Object
                            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'DateTime' -Value $([datetime] $dtDateTime)
                            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'WeekOfYear' -Value $([int] $iWeekOfYear)
                            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Year' -Value $([int] $iYear)
                            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Month' -Value $([int] $iMonth)
                            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Day' -Value $([int] $iDay)
                            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Computer' -Value $([string] $sComputer)
                            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Rule' -Value $([string] $sRule)
                            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Cause' -Value $([string] $sCause)
                            $aFolderObjects += $oNewObject
                        }
            }
        }
    }
}

$aFolderObjects | Format-Table -AutoSize
$aFolderObjects | Export-Csv -Path '.\IncidentFolderStats.csv' -NoTypeInformation