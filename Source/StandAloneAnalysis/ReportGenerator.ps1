#requires -Version 2.0
<#
    .SYNOPSIS
    Parses the names of ICU zip files, creates a CSV file with the results, and creates charts of the data.
    .DESCRIPTION
    Parses the names of ICU zip files and creates a CSV file with the results, and creates charts of the data.
    .EXAMPLE
    .\04_ReportGenerator.ps1 -Path \\server\ICU
    This will parse the file name of each zip file under \\server\ICU, creates a CSV file with the results, and creates charts of the data.
    .Parameter Path
    This parameters is required and is expected to be a folder path or a path to a network share. Do not put a backslash on the end.
    .Notes
    Name: 04_ReportGenerator.ps1
    Author: Clint Huffman (clinth@microsoft.com)
    LastEdit: June 11th, 2015
	Version: 1.0
    Keywords: PowerShell, ICU
#>
param([string] $Path)

$global:WorkingDirectory = $PWD.Path

$global:sDateTimePattern = 'yyyy.MM.dd-HH:mm:ss'
$global:Charts = @{}
$global:Tables = @{}
#$SessionTimeStamp = "$(Get-Date -format yyyyMMdd-HHmmss)"
#[string] $OutputFolder = '.\' + $SessionTimeStamp
#[string] $HtmlReportPath = '.\' + $SessionTimeStamp + '.htm'

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

Function CalculatePercentage
{
    param($Number,$Total)

    If (($Total -eq 0) -or ($Total -eq $null))
    {
        Return 100
    }

    If (($Number -eq 0) -or ($Number -eq $null))
    {
        Return 0
    }

    $Result = ($Number * 100) / $Total
    $Result = [Math]::Round($Result,0)
    $Result
}

Function GenerateMSBarChart
{
    param($sChartTitle, $sSaveFilePath, $htOfSeriesObjects)
    
	#// GAC the Microsoft Chart Controls just in case it is not GAC'd.
	#// Requires the .NET Framework v3.5 Service Pack 1 or greater.
	$oPALChart = New-Object System.Windows.Forms.DataVisualization.Charting.Chart
	$oPALChartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea
	$fontNormal = new-object System.Drawing.Font("Courier New",10,[Drawing.FontStyle]'Regular')

    #$oCulture = (Get-Culture)
	#$sFormat = "#" + $oCulture.NumberFormat.NumberGroupSeparator + "###" + $oCulture.NumberFormat.NumberDecimalSeparator + "###"		
	#$oPALChartArea.AxisX.LabelStyle.Format = $sFormat
	$oPALChartArea.AxisX.LabelStyle.Font = $fontNormal
 
    $oPALChartArea.AxisX.Interval = 1
    $oPALChartArea.AxisX.LabelAutoFitMinFontSize = 10
    $oGrid = New-Object System.Windows.Forms.DataVisualization.Charting.Grid
    $oGrid.LineWidth = 0
    $oPALChartArea.AxisX.MajorGrid = $oGrid
	$oPALChart.ChartAreas["Default"] = $oPALChartArea
	
    #// Add each of the Series objects to the chart.
    [int] $iNumOfItems = 0
	ForEach ($Series in $htOfSeriesObjects)
	{
		$oPALChart.Series[$Series.Name] = $Series
        if ($Series.Points.Count -gt $iNumOfItems)
        {
            $iNumOfItems = $Series.Points.Count
        }
	}
	
	#// Chart size
	$oChartSize = New-Object System.Drawing.Size
	$oChartSize.Width = 800
	$oChartSize.Height = ($iNumOfItems * 20) + 100
	$oPALChart.Size = $oChartSize
	
	#// Chart Title
    $oChartTitle = $oPALChart.Titles.Add($sChartTitle)
    $oFontSize = 12
    $oChartTitle.Font = New-Object System.Drawing.Font($oChartTitle.Font.Name, $oFontSize, $oChartTitle.Font.Style, $oChartTitle.Font.Unit)
	
	#// Chart Legend
	#$oLegend = New-Object System.Windows.Forms.DataVisualization.Charting.Legend
    #$oLegend.Docking = "Bottom"
    #$oLegend.LegendStyle = "Table"
	#[Void] $oPALChart.Legends.Add($oLegend)

	#// Save the chart image to a PNG file. PNG files are better quality images.
	$oPALChartImageFormat = [System.Windows.Forms.DataVisualization.Charting.ChartImageFormat]"Png"
    $sSaveFilePath
	[Void] $oPALChart.SaveImage($sSaveFilePath, $oPALChartImageFormat)
}

Function GenerateMsPieChart
{
    param($sChartTitle, $sSaveFilePath, $htOfSeriesObjects)
    
	#// GAC the Microsoft Chart Controls just in case it is not GAC'd.
	#// Requires the .NET Framework v3.5 Service Pack 1 or greater.
	$oPALChart = New-Object System.Windows.Forms.DataVisualization.Charting.Chart
	$oPALChartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea
	$fontNormal = new-object System.Drawing.Font("Courier New",10,[Drawing.FontStyle]'Regular')

    #$oCulture = (Get-Culture)
	#$sFormat = "#" + $oCulture.NumberFormat.NumberGroupSeparator + "###" + $oCulture.NumberFormat.NumberDecimalSeparator + "###"		
	#$oPALChartArea.AxisX.LabelStyle.Format = $sFormat
	$oPALChartArea.AxisX.LabelStyle.Font = $fontNormal
    $oPALChartArea.Area3DStyle.Enable3D = $false
    $oPALChartArea.AlignmentOrientation = 'Vertical'
 
    #$oPALChartArea.AxisX.Interval = 1

	$oPALChart.ChartAreas["Default"] = $oPALChartArea
	
    #// Add each of the Series objects to the chart.
    [int] $iNumOfItems = 0
	ForEach ($Series in $htOfSeriesObjects)
	{
        $Series.Sort(1)
		$oPALChart.Series[$Series.Name] = $Series
        if ($Series.Points.Count -gt $iNumOfItems)
        {
            $iNumOfItems = $Series.Points.Count
        }
	}
	
	#// Chart size
	$oChartSize = New-Object System.Drawing.Size
	$oChartSize.Width = 600
	$oChartSize.Height = 300
	$oPALChart.Size = $oChartSize
	
	#// Chart Title
    $oChartTitle = $oPALChart.Titles.Add($sChartTitle)
    $oFontSize = $oChartTitle.Font.Size
    $oFontSize = 12
    $oChartTitle.Font = New-Object System.Drawing.Font($oChartTitle.Font.Name, $oFontSize, $oChartTitle.Font.Style, $oChartTitle.Font.Unit)
	
	#// Chart Legend
	$oLegend = New-Object System.Windows.Forms.DataVisualization.Charting.Legend
    #$oLegend.Docking = "Bottom"
    $oLegend.LegendStyle = "Column"
	[Void] $oPALChart.Legends.Add($oLegend)

	#// Save the chart image to a PNG file. PNG files are better quality images.
	$oPALChartImageFormat = [System.Windows.Forms.DataVisualization.Charting.ChartImageFormat]"Png"
    $sSaveFilePath
	[Void] $oPALChart.SaveImage($sSaveFilePath, $oPALChartImageFormat)	
}

Function WriteHtmlSection
{
    param($oFilteredCharts, [string] $Title, [string] $HREF, [string] $h)

    '<H1><A NAME="#' + $HREF + '">' + $Title + '</A></H1>' >> $h
    '<CENTER>' >> $h
    switch ($oFilteredCharts.GetType().FullName)
    {
        'System.Object[]'
        {
            
            foreach ($oChart in $oFilteredCharts)
            {
                [string] '<IMG SRC="' + $oChart.Value + '"><BR>' >> $h
                if ($($global:Tables.Contains($oChart.Name)) -eq $true)
                {
                    [string] '<TABLE BORDER=1>' >> $h
                    $oCsv = Import-Csv -Path $global:Tables[$oChart.Name]
                    '<TR><TH>Name</TH><TH>Value</TH><TH>Percent</TH></TR>' >> $h
                    foreach ($oRecord in $oCsv)
                    {
                        '<TR><TD>' + $oRecord.Name + '</TD><TD>' + $oRecord.Value + '</TD><TD>' + $oRecord.Percent + '</TD></TR>' >> $h    
                    }
                    '</TABLE><BR><BR><BR><BR>' >> $h
                }
            }
        }

        'System.Collections.Hashtable'
        {
            foreach ($Key in $oFilteredCharts.Keys)
            {
                [string] '<IMG SRC="' + $oFilteredCharts[$Key] + '"><BR>' >> $h
                if ($($global:Tables.Contains($Key)) -eq $true)
                {
                    [string] '<TABLE BORDER=1>' >> $h
                    $oCsv = Import-Csv -Path $global:Tables[$Key]
                    '<TR><TH>Name</TH><TH>Value</TH><TH>Percent</TH></TR>' >> $h
                    foreach ($oRecord in $oCsv)
                    {
                        '<TR><TD>' + $oRecord.Name + '</TD><TD>' + $oRecord.Value + '</TD><TD>' + $oRecord.Percent + '</TD></TR>' >> $h    
                    }
            
                    '</TABLE><BR><BR><BR><BR>' >> $h
                }
            }
        }
    }
    '</CENTER><BR><BR><BR><BR>' >> $h
}

Function WriteHtmlReport
{
    param([string] $Path)

    [string] $h = $Path

    #///////////////////////
    #// Header
    #///////////////////////    
    '<HTML>' > $h
    '<HEAD>' >> $h
    '<STYLE TYPE="text/css" TITLE="currentStyle" MEDIA="screen">' >> $h
    'body {' >> $h
    '   font: normal 8pt/16pt Verdana;' >> $h
    '   color: #000000;' >> $h
    '   margin: 10px;' >> $h
    '   }' >> $h
    'p {font: 8pt/16pt Verdana;margin-top: 0px;}' >> $h
    'h1 {font: 20pt Verdana;margin-bottom: 0px;color: #000000;}' >> $h
    'h2 {font: 15pt Verdana;margin-bottom: 0px;color: #000000;}' >> $h
    'h3 {font: 13pt Verdana;margin-bottom: 0px;color: #000000;}' >> $h
    'td {font: normal 8pt Verdana;}' >> $h
    'th {font: bold 8pt Verdana;}' >> $h
    'blockquote {font: normal 8pt Verdana;}' >> $h
    '</STYLE>' >> $h
    '</HEAD>' >> $h
    '<BODY LINK="Black" VLINK="Black">' >> $h
    '<TABLE CELLPADDING=10 WIDTH="100%"><TR><TD BGCOLOR="#000000">' >> $h
    '<FONT COLOR="#FFFFFF" FACE="Tahoma" SIZE="5"><STRONG>' + $global:Title + ' ICU data analysis</STRONG></FONT><BR><BR>' >> $h
    '<FONT COLOR="#FFFFFF" FACE="Tahoma" SIZE="2"><STRONG>Report Generated at: ' + "$((get-date).tostring($global:sDateTimePattern))" + '</STRONG></FONT>' >> $h
    '</TD><TD><FONT COLOR="#000000" FACE="Tahoma" SIZE="10">ICU</FONT><FONT COLOR="#000000" FACE="Tahoma" SIZE="5">v1</FONT></FONT>' >> $h
    '</TD></TR></TABLE>' >> $h
    '<BR>' >> $h

    #///////////////////////
    #// Table of Contents
    #///////////////////////

    $aKeyWordCategories = @('All','Computer','Rule','Cause')

    '<H4>On This Page</H4>' >> $h
    '<UL>' >> $h
    foreach ($sKey in $aKeyWordCategories)
    {
        '<LI><A HREF="#' + $sKey + '">Breakout by ' + $sKey + '</A></LI>' >> $h
    }
    '<UL>' >> $h

    foreach ($sKey in $aKeyWordCategories)
    {
        $FilteredCharts = $global:Charts | Where-Object {$_.Name -match $sKey}
        [string] $TempTitle = 'Breakout by ' + $sKey
        WriteHtmlSection -oFilteredCharts $FilteredCharts -Title $TempTitle -HREF $sKey -h $h
    }

    <#

    $FilteredCharts = $global:Charts | Where-Object {$_.Name -match 'All'}
    WriteHtmlSection -oFilteredCharts $FilteredCharts -Title 'Overall Statistics' -HREF '#All' -h $h

    $FilteredCharts = $global:Charts | Where-Object {$_.Name -match 'Computer'}
    WriteHtmlSection -oFilteredCharts $FilteredCharts -Title 'Computer' -HREF '#Computer' -h $h

    $FilteredCharts = $global:Charts | Where-Object {$_.Name -match 'Rule'}
    WriteHtmlSection -oFilteredCharts $FilteredCharts -Title 'Rule' -HREF '#Rule' -h $h

    $FilteredCharts = $global:Charts | Where-Object {$_.Name -match 'Cause'}
    WriteHtmlSection -oFilteredCharts $FilteredCharts -Title 'Cause' -HREF '#Cause' -h $h
    
    switch ($global:Charts.GetType().FullName)
    {
        'System.Object[]'
        {
            foreach ($oChart in $global:Charts)
            {
                [string] '<CENTER><IMG SRC="' + $oChart.Value + '"><BR>' >> $h
                if ($($global:Tables.Contains($oChart.Name)) -eq $true)
                {
                    [string] '<TABLE BORDER=1>' >> $h
                    $oCsv = Import-Csv -Path $global:Tables[$oChart.Name]
                    '<TR><TH>Name</TH><TH>Value</TH><TH>Percent</TH></TR>' >> $h
                    foreach ($oRecord in $oCsv)
                    {
                        '<TR><TD>' + $oRecord.Name + '</TD><TD>' + $oRecord.Value + '</TD><TD>' + $oRecord.Percent + '</TD></TR>' >> $h    
                    }
            
                    '</TABLE>' >> $h
                    '</CENTER><BR><BR><BR><BR>' >> $h
                }
            }
        }

        'System.Collections.Hashtable'
        {
            foreach ($Key in $global:Charts.Keys)
            {
                [string] '<CENTER><IMG SRC="' + $oFilteredCharts[$Key] + '"><BR>' >> $h
                if ($($global:Tables.Contains($Key)) -eq $true)
                {
                    [string] '<TABLE BORDER=1>' >> $h
                    $oCsv = Import-Csv -Path $global:Tables[$Key]
                    '<TR><TH>Name</TH><TH>Value</TH><TH>Percent</TH></TR>' >> $h
                    foreach ($oRecord in $oCsv)
                    {
                        '<TR><TD>' + $oRecord.Name + '</TD><TD>' + $oRecord.Value + '</TD><TD>' + $oRecord.Percent + '</TD></TR>' >> $h    
                    }
                    '</TABLE>' >> $h
                    '</CENTER><BR><BR><BR><BR>' >> $h
                }
            }
        }
        
    }
    #>

    '</HTML>' >> $h

    Invoke-Expression -Command "&'$h'"

}

Function IcuXChart
{
    param([string] $PropertyName, [string] $Title, [string] $FileName, [string] $ChartType = 'Bar', [bool] $DistinctIncidents = $true, [string] $SortBy = 'Count', [string] $Sort = 'DESC', [bool] $AddTable = $true)

    $oPropertyNames = $aFolderObjects | Select $PropertyName -Unique
    $alSeries = New-Object System.Collections.ArrayList

	$SeriesOfCounterValues = New-Object System.Windows.Forms.DataVisualization.Charting.Series
    $SeriesOfCounterValues.ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]$ChartType
    $SeriesOfCounterValues.Name = 'Total'
    $SeriesOfCounterValues.IsValueShownAsLabel = $true

    switch ($Sort)
    {
        'NONE'
        {
            $oPropertySeries = @($aFolderObjects | Select $PropertyName | Group-Object -Property $PropertyName | Sort-Object -Property $SortBy)
        }

        'DESC'
        {
            $oPropertySeries = @($aFolderObjects | Select $PropertyName | Group-Object -Property $PropertyName | Sort-Object -Property $SortBy -Descending)
        }

        'ASC'
        {
            $oPropertySeries = @($aFolderObjects | Select $PropertyName | Group-Object -Property $PropertyName | Sort-Object -Property $SortBy)
        }
    }

    foreach ($oRecord in $oPropertySeries)
    {
        $oRecord.Name
        $oRecord.Count
        [Void] $SeriesOfCounterValues.Points.AddXY($oRecord.Name, $oRecord.Count)
    }

    [int] $iTotal = $($SeriesOfCounterValues.Points | ForEach-Object {$_.YValues[0]} | Measure-Object -Sum).Sum

    if ($AddTable -eq $true)
    {
        $u = $SeriesOfCounterValues.Points.Count - 1
        $oObjects = @()
        for ($p = $u; $p -ge 0; $p--)
        {
            if ($SeriesOfCounterValues.Points[$p].AxisLabel -ne '')
            {
                [string] $Name = $SeriesOfCounterValues.Points[$p].AxisLabel
            }
            else
            {
                [string] $Name = $SeriesOfCounterValues.Points[$p].XValue
            }
        
            [int] $iValue = $SeriesOfCounterValues.Points[$p].YValues[0]
            [int] $iPercent = CalculatePercentage -Number $iValue -Total $iTotal

            $oNewObject = New-Object System.Object
            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Name' -Value $([string] $Name)
            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Value' -Value $([int] $iValue)
            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Percent' -Value $([int] $iPercent)
            $oObjects += $oNewObject
        }

        $oObjects | Format-Table -AutoSize
        [string] $sOutputFilePath = $global:sResourceFolderPath + '\' + $FileName + '.csv'
        $oObjects | Export-Csv -Path $sOutputFilePath -NoTypeInformation
        [void] $global:Tables.Add($Title,$sOutputFilePath)
    }

    [Void] $alSeries.Add($SeriesOfCounterValues)
    [string] $sOutputFilePath = $global:sResourceFolderPath + '\' + $FileName + '.png'

    switch ($ChartType)
    {
        'Bar'
        {
            GenerateMSBarChart $Title $sOutputFilePath $alSeries
        }

        'Pie'
        {
            GenerateMsPieChart $Title $sOutputFilePath $alSeries
        }

        Default
        {
            GenerateMSBarChart $Title $sOutputFilePath $alSeries
        }
    }
    
    [void] $global:Charts.Add($Title,$sOutputFilePath)
}

Function IcuXByChart
{
    param([string] $PropertyName, [string] $ByPropertyName, [string] $ByPropertyValue, [string] $Title, [string] $FileName, [string] $ChartType = 'Bar', [bool] $DistinctIncidents = $true, [bool] $AddTable = $true)
    $alSeries = New-Object System.Collections.ArrayList

	$SeriesOfCounterValues = New-Object System.Windows.Forms.DataVisualization.Charting.Series
    $SeriesOfCounterValues.ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]$ChartType
    $SeriesOfCounterValues.Name = 'Total'
    $SeriesOfCounterValues.IsValueShownAsLabel = $true

    $oPropertySeries = @($aFolderObjects | Select $PropertyName, $ByPropertyName | Where-Object {$_.$($ByPropertyName) -eq $ByPropertyValue} | Group-Object -Property $PropertyName | Sort-Object -Property Count -Descending)
    #$oPropertySeries = @($aFolderObjects | Select Cause, Rule | Where-Object {$_.Rule -eq 'DiskLatencyGt35ms'} | Group-Object -Property Cause | Sort-Object -Property Count -Descending)

    foreach ($oRecord in $oPropertySeries)
    {
        $oRecord.Name
        $oRecord.Count
        [Void] $SeriesOfCounterValues.Points.AddXY($oRecord.Name, $oRecord.Count)
    }

    if ($AddTable -eq $true)
    {
        [int] $iTotal = $($SeriesOfCounterValues.Points | ForEach-Object {$_.YValues[0]} | Measure-Object -Sum).Sum
        $SeriesOfCounterValues.Sort(1)
        $u = $SeriesOfCounterValues.Points.Count - 1
        $oObjects = @()
        for ($p = 0; $p -le $u; $p++)
        {
            [string] $Name = $SeriesOfCounterValues.Points[$p].AxisLabel
            [int] $iValue = $SeriesOfCounterValues.Points[$p].YValues[0]
            [int] $iPercent = CalculatePercentage -Number $iValue -Total $iTotal

            $oNewObject = New-Object System.Object
            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Name' -Value $([string] $Name)
            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Value' -Value $([int] $iValue)
            Add-Member -InputObject $oNewObject -MemberType NoteProperty -Name 'Percent' -Value $([int] $iPercent)
            $oObjects += $oNewObject
        }
        $oObjects | Format-Table -AutoSize
        [string] $sOutputFilePath = $global:sResourceFolderPath + '\' + $FileName + '.csv'
        $oObjects | Export-Csv -Path $sOutputFilePath -NoTypeInformation
        [void] $global:Tables.Add($Title,$sOutputFilePath)
    }

    $SeriesOfCounterValues.Sort(0)
    [Void] $alSeries.Add($SeriesOfCounterValues)
    [string] $sOutputFilePath = $global:sResourceFolderPath + '\' + $FileName + '.png'

    switch ($ChartType)
    {
        'Bar'
        {
            GenerateMSBarChart $Title $sOutputFilePath $alSeries
        }

        'Pie'
        {
            GenerateMsPieChart $Title $sOutputFilePath $alSeries
        }

        Default
        {
            GenerateMSBarChart $Title $sOutputFilePath $alSeries
        }
    }
    
    [void] $global:Charts.Add($Title,$sOutputFilePath)
}

Function ChartPropertyByProperty
{
    param([string] $Property,[string] $ByProperty, [bool] $UseDistinctIncidents = $true, [bool] $AddTable = $true)
    $oUniqueObjects = $aFolderObjects | Select $ByProperty -Unique
    foreach ($oObject in $oUniqueObjects)
    {
        [string] $TempTitle = 'ICU Incident ' + $Property  + '(s) of ' + $ByProperty + ' ' + $oObject.$($ByProperty)
        [string] $TempFileName = $Property + 'Of' + $oObject.$($ByProperty)
        IcuXByChart -PropertyName $Property -ByPropertyName $ByProperty -ByPropertyValue $oObject.$($ByProperty) -Title $TempTitle -FileName $TempFileName -DistinctIncidents $UseDistinctIncidents -AddTable $AddTable
    }
}

#/////////////////////
#// MAIN
#////////////////////

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
        #$sLine

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

[string] $global:OutputFolder = ''

if([Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms.DataVisualization") -eq $null)
{
    #// ... then the Microsoft Chart Controls are not installed.
    [void][reflection.assembly]::Load("System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089")
    [void][System.Windows.Forms.MessageBox]::Show("Microsoft Chart Controls for Microsoft .NET 3.5 Framework is required", "Microsoft Chart Controls Required")
    #Open the URL
    WriteErrorToHtmlAndShow -sError 'Microsoft Chart Controls for Microsoft .NET 3.5 Framework is required. Download and install for free at http://www.microsoft.com/downloads/en/details.aspx?familyid=130F7986-BF49-4FE5-9CA8-910AE6EA442C&displaylang=en'
    [System.Diagnostics.Process]::Start("http://www.microsoft.com/downloads/en/details.aspx?familyid=130F7986-BF49-4FE5-9CA8-910AE6EA442C&displaylang=en");
    Break;
}

$aDateTimes = $aFolderObjects | Select DateTime | Sort-Object DateTime
[string] $sFirstDt = $aDateTimes[0].DateTime.ToString('yyyyMMdd')
[int] $u = $aDateTimes.GetUpperBound(0)
[string] $sLastDt = $aDateTimes[$u].DateTime.ToString('yyyyMMdd')
[string] $global:Title = $sFirstDt + '-' + $sLastDt
[string] $global:sResourceFolderPath = $global:WorkingDirectory + '\' + $global:Title

[string] $TempPath = $global:sResourceFolderPath + '\IncidentFolderStats.csv'
$aFolderObjects | Export-Csv -Path $TempPath -NoTypeInformation

if ($(Test-Path -Path $global:sResourceFolderPath) -eq $false)
{
    New-Item -Path $global:sResourceFolderPath -ItemType Directory -Force
}

#// Overall/All single charts by X
IcuXChart -PropertyName 'WeekOfYear' -Title 'All ICU Incidents by WeekOfYear' -FileName 'AllWeekOfYear' -DistinctIncidents $True -ChartType 'Bar' -SortBy 'Name' -Sort 'NONE'
IcuXChart -PropertyName 'Rule' -Title 'All ICU Incidents by Trigger/Rule' -FileName 'RuleCount' -ChartType 'Bar' -DistinctIncidents $True -SortBy 'Count' -Sort 'ASC' -AddTable $True
IcuXChart -PropertyName 'Computer' -Title 'All ICU Incidents by Computer' -FileName 'ComputerCount' -ChartType 'Bar' -DistinctIncidents $True -SortBy 'Count' -Sort 'ASC' -AddTable $True
IcuXChart -PropertyName 'Cause' -Title 'All ICU Incidents by Cause' -FileName 'CauseCount' -ChartType 'Bar' -DistinctIncidents $false -SortBy 'Count' -Sort 'ASC' -AddTable $True

#// Breakout charts Causes of each rule/trigger
ChartPropertyByProperty -Property 'Cause' -ByProperty 'Rule' -UseDistinctIncidents $false -AddTable $true

#// Breakout charts Causes of each computer
ChartPropertyByProperty -Property 'Cause' -ByProperty 'Computer' -UseDistinctIncidents $false -AddTable $false

#// Breakout charts Rules of each computer
ChartPropertyByProperty -Property 'Rule' -ByProperty 'Computer' -UseDistinctIncidents $True -AddTable $false

#// Breakout charts Incidents on each computer by WeekOfYear
ChartPropertyByProperty -Property 'WeekOfYear' -ByProperty 'Computer' -UseDistinctIncidents $True -AddTable $false

$global:charts = @($global:charts.GetEnumerator() | Sort-Object Name)

[string] $global:sHtmlReportPath = $global:WorkingDirectory + '\' + $global:Title + ' ICU data analysis.htm'

WriteHtmlReport -Path $global:sHtmlReportPath
