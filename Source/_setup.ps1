param([string] $IsSilentInstallation = 'false')
# This code is Copyright (c) 2016 Microsoft Corporation.
#
# All rights reserved.
#
# THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, 
# �INCLUDING BUT NOT LIMITED To THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
#  PARTICULAR PURPOSE.'
#
# IN NO EVENT SHALL MICROSOFT AND/OR ITS RESPECTIVE SUPPLIERS BE LIABLE FOR ANY SPECIAL, INDIRECT OR 
# �CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
#  WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION 
# �WITH THE USE OR PERFORMANCE OF THIS CODE OR INFORMATION.

[string] $Log = ([System.Environment]::ExpandEnvironmentVariables('%TEMP%') + '\ClueSetup.log')
[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null

#////////////////
#// Functions //
#//////////////

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

Function Test-Error
{
    param($Err)
    #// Tests if an error condition exists and writes it to the log.
    if ($Err.Count -gt 0)
    {
        Write-Log ('[Test-Error] Error(s) found: ' + $Err.Count)
        Write-Log ($Err)
        $Err.Clear()
    }
}

Function Test-Property
{
	param ([Parameter(Position=0,Mandatory=1)]$InputObject,[Parameter(Position=1,Mandatory=1)]$Name)
	[Bool](Get-Member -InputObject $InputObject -Name $Name -MemberType *Property)
}

Function Write-Console
{
    param([string] $sLine, [bool] $bNoNewLine = $false, [bool] $bAddDateTime = $true, [string] $Log = $Log)
    Write-Log ($sLine)

    if ($IsSilentInstallation -eq $false)
    {
        $TimeStamp = "$(Get-Date -format yyyyMMdd-HHmmss)"
        if ($bAddDateTime -eq $true)
        {
            [string] $sOutput = '[' + $TimeStamp + '] ' + $sLine
        }
        else
        {
            [string] $sOutput = $sLine
        }

        if ($bNoNewLine -eq $false)
        {
            Write-Host $sOutput
        }
        else
        {
            Write-Host $sOutput -NoNewline
        }        
    }    
}

Function Write-MsgBox
{
    param([string] $sLine, [string] $Log = $Log)    
    if ($IsSilentInstallation -eq $false)
    {
        Write-Console ('[PopUp] ' + $sLine)
        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
        [void] [Microsoft.VisualBasic.Interaction]::MsgBox($sLine, 0, 'Tool configuration')
    }
}

Function Test-Numeric
{
    param($Value)
    [double] $number = 0
    Return [double]::TryParse($Value, [REF]$number)
}

Function ConvertTo-DataType
{
	param([double] $ValueAsDouble, [string] $DataTypeAsString = 'integer')
	$sDateType = $DataTypeAsString.ToLower()
    If ((Test-Numeric -Value $ValueAsDouble) -eq $True)
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

Function Set-OverallProgress
{
    param([string] $Status='')
    $global:iOverallCompletion++
    $iPercentComplete = ConvertTo-DataType $(($global:iOverallCompletion / 14) * 100) 'integer'
    If ($iPercentComplete -gt 100){$iPercentComplete = 100}
    $sComplete = "Clue installation progress: $iPercentComplete%... $Status"
    Write-Progress -activity 'Progress: ' -status $sComplete -percentcomplete $iPercentComplete -id 1;
    $global:oOverallProgress = 'Overall progress... Status: ' + "$($Status)" + ', ' + "$($sComplete)"
}

Function OpenConfigXml
{
    param([string] $XmlFilePath='.\config.xml')
    #// Opens config.xml
    If (Test-Path -Path $XmlFilePath)
    {
        Return (Get-Content -Path $XmlFilePath)
    }
    Else
    {
        Return $null
    }
}

Function Test-XmlEnabled
{
    param($XmlNode)
    #// Tests if an XML atribute is enabled or not and returns a boolean value.
    If ((Test-Property -InputObject $XmlNode -Name 'Enabled') -eq $True)
    {
        If ($XmlNode.Enabled -eq 'True')
        {Return $true} Else {Return $false}
    }
    Else
    {
        Return $false
    }
}

Function Get-XmlAttribute
{
    param([System.Xml.XmlElement] $XmlNode, [string] $Name)
    if (Test-Property -InputObject $XmlNode -Name $Name)
    {
        Return [string] $XmlNode.$Name
    }
    else
    {Return [string] ''}
}

Function Set-XmlAttribute
{
    param([System.Xml.XmlElement] $XmlNode, [string] $Name, [string] $Value)
    if (Test-Property -InputObject $XmlNode -Name $Name)
    {
        $XmlNode.$Name = $Value
    }
}

function Get-OutputDirectory
{
    param($XmlConfig, [string] $Log = $Log)
    Write-Log ('[Get-OutputDirectory]: START')
    [bool] $IsDone = $false
    [string] $OutputDirectory = Get-XmlAttribute -XmlNode $XmlConfig -Name 'OutputDirectory'
    if ($OutputDirectory -eq '')
    {
        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
        $sResponse = ''
        if ($IsSilentInstallation -eq $false)
        {
            [int] $Yes = 6; [int] $No = 7;

            while ($sResponse -eq '')
            {
                Write-Console '[PopUp] Waiting for user response...' -bNoNewLine $true -bAddDateTime $false
                $sResponse = [Microsoft.VisualBasic.Interaction]::InputBox('This is where output files will go. Several gigabytes might be necessary.', 'Clue tool - Output Directory', 'C:\ClueOutput')
                Write-Log ('UserResponse: ' + $sResponse)

                if ($sResponse -eq '')
                {
                    $iYesNo = [Microsoft.VisualBasic.Interaction]::MsgBox('Are you sure you?', 4, 'Clue tool - Cancel Installation')
                }

                if ($iYesNo -eq $Yes)
                {
                    Exit;
                }

                while ($sResponse.Contains(' '))
                {
                    $sResponse = $sResponse.Replace(' ','')
                    $sResponse = [Microsoft.VisualBasic.Interaction]::InputBox('Please provide a folder path without spaces. This is due to how the Task Scheduler handles parameters.', 'Clue tool - Output Directory - Try Again', $sResponse)
                    Write-Log ('UserResponse: ' + $sResponse)
                }
            }
        }

        if ($sResponse -eq '')
        {
            Write-Console ('!!!ERROR!!! Unable to continue without an output directory. Setup has failed.')
            if ($IsSilentInstallation -eq 'false')
            {
                Write-MsgBox ('Unable to continue without an output directory. Setup has failed!')
            }
            Break;
        }

        $OutputDirectory = $sResponse
    }
    Write-Log ("`t" + 'OutputDirectory: "' + $OutputDirectory + '"')
    Write-Log ('[Get-OutputDirectory]: END')
    Return $OutputDirectory
}

function Download-SysInternalsTool
{
    param([string] $FileName, [string] $DownloadToFolderPath)
    
    $webclient = New-Object System.Net.WebClient
    [string] $FilePath = $DownloadToFolderPath + '\' + $FileName
        
    if (Test-Path -Path $FilePath)
    {
        Write-Console ($FilePath + ' is already downloaded.')
        Return $true
    }
    else
    {   
        [string] $url = 'http://live.sysinternals.com/' + $FileName
        Write-Console ('Downloading ' + $url + '...')
        $webclient.DownloadFile($url,$FilePath)
    }

    if (Test-Path -Path $FilePath)
    {
        Write-Console 'Downloaded!'
    }
    else
    {
        Write-Console 'Unable to download ' + $FileName + '. Download this SysInternals file manually from ' + $url + ' and place it in the sysint folder under the CLUE installation folder. Otherwise, the CLUE tool might not function properly.'
    }
}

function Get-UploadNetworkShare
{
    param($XmlConfig, [string] $Log = $Log)
    Write-Log ('[Get-UploadNetworkShare]: START')
    $UploadNetworkShare = Get-XmlAttribute -XmlNode $XmlConfig -Name 'UploadNetworkShare'
    if ($UploadNetworkShare -eq '')
    {
        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
        [int] $Yes = 6; [int] $No = 7;
        $sResponse = ''
        if ($IsSilentInstallation -eq $false)
        {
            Write-Console '[PopUp] Waiting for user response...' -bNoNewLine $true -bAddDateTime $false
            $sResponse = [Microsoft.VisualBasic.Interaction]::InputBox('This is the network share (\\server\share) where Clue will upload incident data and download updates. Grant the SYSTEM account of this computer read/write access to the network share. Leave blank if this is a stand-alone installation.', 'Clue tool - Network Share', '')
            Write-Log ('UserResponse: ' + $sResponse)
        }
        
        if ($sResponse -ne '')
        {
            $UploadNetworkShare = $sResponse
        }
    }
    Write-Log ("`t" + 'UploadNetworkShare: "' + $global:UploadNetworkShare + '"')
    Write-Log ('[Get-UploadNetworkShare]: END')
    Return $UploadNetworkShare
}

Function Get-EmailForReport
{
    param($XmlConfig, [string] $Log = $Log)
    Write-Log ('[Get-EmailForReport]: START')
    $EmailReportTo = Get-XmlAttribute -XmlNode $XmlConfig -Name 'EmailReportTo'
    if ($EmailReportTo -eq '')
    {
        $sResponse = ''
        if ($IsSilentInstallation -eq $false)
        {
            [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
            Write-Console '[PopUp] Waiting for user response...' -bNoNewLine $true -bAddDateTime $false
            $sResponse = [Microsoft.VisualBasic.Interaction]::InputBox('What email addresses (separated by semi-colon (;)) do you want the report sent to?', 'Clue tool - Email report to...', '')
            Write-Log ('UserResponse: ' + $sResponse)
        }
        
        if ($sResponse -ne '')
        {
            $EmailReportTo = $sResponse
        }
    }
    Write-Log ("`t" + 'EmailReportTo: "' + $EmailReportTo + '"')
    Write-Log ('[Get-EmailForReport]: END')
    Return $EmailReportTo
}

Function Get-RegistryKey
{
    param([string] $Path)
    #// Example: (Get-RegistryKey -Path 'HKEY_CURRENT_USER\SOFTWARE\Sysinternals\Handle').EulaAccepted
    $Path = 'Registry::' + $Path
    if (Test-Path -Path $Path)
    {
        Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    }
    else
    {
        Return $null
    }
}

function Get-CollectionLevel
{
    param($XmlConfig, [string] $Log = $Log)
    Write-Log ('[Get-CollectionLevel]: START')
    $CollectionLevel = Get-XmlAttribute -XmlNode $XmlConfig -Name 'CollectionLevel'
    if ($CollectionLevel -eq '')
    {
        $CollectionLevel = 1
    }
    Write-Log ("`t" + 'CollectionLevel: "' + $global:CollectionLevel + '"')
    Write-Log ('[Get-CollectionLevel]: END')
    Return $CollectionLevel
}

Function Get-FolderPathFromFilePath
{
    param([string] $FilePath)
    Write-Log ('[Get-FolderPathFromFilePath] FilePath: ' + $FilePath)
    if ($FilePath -ne '')
    {
        [string] $NewPath = ''
        [System.String[]] $aTemp = @($FilePath.Split('\',[StringSplitOptions]'RemoveEmptyEntries'))
        for ($i=0;$i -lt $aTemp.GetUpperBound(0);$i++)
        {
            $NewPath = $NewPath + $aTemp[$i] + '\'
        }
        $NewPath = $NewPath.Substring(0,($NewPath.Length - 1))
        Write-Log ('[Get-FolderPathFromFilePath] NewPath: ' + $NewPath)
        Return $NewPath
    }
    else {Return ''}
}

function ConvertTo-SoftwareVersion
{
    param([string] $SoftwareVersion)
    $aSplit = @($SoftwareVersion.Split('.'))
    switch ($aSplit.Count)
    {
        1       {[system.version] $NewVersion = $SoftwareVersion + '.0.0.0'}
        2       {[system.version] $NewVersion = $SoftwareVersion + '.0.0'}
        3       {[system.version] $NewVersion = $SoftwareVersion + '.0'}
        default {[system.version] $NewVersion = $SoftwareVersion}
    }
    Return $NewVersion
}

function Test-IsExecutableFileFound
{
    param([string] $FileName, [string] $StartingFolderPath = '')

    $IsStartingPathValid = $false
    if ($StartingFolderPath -ne '')
    {
        if (Test-Path -Path $StartingFolderPath)
        {
            $IsStartingPathValid = $true
        }
    }

    if ($IsStartingPathValid -eq $true)
    {
        $aOutput = @(Get-childitem -Path $StartingFolderPath -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $FileName })
        if ($aOutput.Count -gt 0)
        {
            Return $true
        }
    }
    else
    {
        $aPaths = @($env:path.split(';') + (pwd).path)
        foreach ($Path in $aPaths)
        {
            $aOutput = @(Get-childitem -Path $Path -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $FileName })
            if ($aOutput.Count -gt 0)
            {
                Return $true
            }
        }
    }    
    Return $false
}

Function Test-OSCompatibility
{
    #[System.Version] $VersionCompatible = '10.0.15063.0'

    $oWmiOs = Get-WmiObject -Query 'SELECT * FROM Win32_OperatingSystem'
    Write-Log ('[Test-OSCompatibility] OS Version: ' + $oWmiOs.Version)
    #$VersionOs = ConvertTo-SoftwareVersion -SoftwareVersion $oWmiOs.Version

    <#
    if ($VersionOs -lt $VersionCompatible)
    {
        Return $false
    }
    #>

    [int] $x86 = 0
    [int] $x64 = 9
    $iArch = @(Get-WmiObject -Query 'SELECT * FROM Win32_Processor')[0].Architecture
    Write-Log ('OS Architecture (0=x86) (9=x64): ' + $iArch)
    if ($iArch -ne $x64)
    {
        Return $false
    }

    Return $true
}

function Test-AdminRights
{
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

Function Get-TaskSchedulerService
{
    try
    {
        $oTaskSchedulerService = New-Object -ComObject 'Schedule.Service'
        $oTaskSchedulerService.Connect()
        Return $oTaskSchedulerService
    }
    catch
    {
        Return $null
    }
}

Function Remove-AllScheduledTasksInToolFolder
{
    $oTaskSchedulerService = Get-TaskSchedulerService
    Test-Error -Err $Error

    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get task folder "\Microsoft\Windows\Clue": START')
    $oTaskSchedulerFolder = $null
    $oParentTaskSchedulerFolder = $oTaskSchedulerService.GetFolder('\Microsoft\Windows')
    $oFolders = $oParentTaskSchedulerFolder.GetFolders(0)
    :FolderLoop foreach ($oFolder in $oFolders)
    {
        if ($oFolder.Name -eq 'Clue')
        {
            $oTaskSchedulerFolder = $oFolder
            Break FolderLoop;
        }        
    }

    if ($oTaskSchedulerFolder -eq $null)
    {
        Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get task folder "\Microsoft\Windows\Clue": END')
        Return $null
    }

    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get task folder "\Microsoft\Windows\Clue": END')

    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get tasks of "\Microsoft\Windows\Clue": START')
    $oTasks = $oTaskSchedulerFolder.GetTasks(0)
    Test-Error -Err $Error
    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get tasks of "\Microsoft\Windows\Clue": END')

    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete tasks of "\Microsoft\Windows\Clue": START')
    ForEach ($oTask in $oTasks)
    {
        $oTask.Stop(0)
        Test-Error -Err $Error
        Start-Sleep -Seconds 2
        Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete task "\Microsoft\Windows\Clue\' + $oTask.Name + '": START')
        $oTaskSchedulerFolder.DeleteTask($oTask.Name, 0)
        Test-Error -Err $Error
        Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete task "\Microsoft\Windows\Clue\' + $oTask.Name + '": END')
        Write-Console '.' -bNoNewLine $true -bAddDateTime $false
    }
    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete tasks of "\Microsoft\Windows\Clue": END')
    
    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get task folder "\Microsoft\Windows\Clue": START')
    $oTaskSchedulerFolder = $oTaskSchedulerService.GetFolder('\Microsoft\Windows')
    Test-Error -Err $Error
    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get task folder "\Microsoft\Windows\Clue": END')

    if ($oTaskSchedulerFolder -is [System.__ComObject])
    {
        Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete "\Microsoft\Windows\Clue": START')
        $oTaskSchedulerFolder.DeleteFolder('Clue', 0)
        Test-Error -Err $Error
        Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete "\Microsoft\Windows\Clue": END')
    }
}

Function New-DirectoryWithConfirm
{
    param([string] $DirectoryPath)

    Write-Log ('[New-DirectoryWithConfirm] DirectoryPath: ' + $DirectoryPath)
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

Function Get-TaskSchedulerService
{
    param([string] $Log = '.\Clue.log')
    try
    {
        $oTaskSchedulerService = New-Object -ComObject 'Schedule.Service'
        $oTaskSchedulerService.Connect()
        Return $oTaskSchedulerService
    }
    catch
    {
        Return $null
    }
}

Function Get-Ps2ScheduledTaskFolder
{
    param([string] $Path)

    $oTaskSchedulerService = Get-TaskSchedulerService

    if ($oTaskSchedulerService -eq $null)
    {
        Return $null
    }

    try
    {
        $oTaskSchedulerFolder = $oTaskSchedulerService.GetFolder($Path)
    }
    catch
    {

    }

    if ($oTaskSchedulerFolder -ne $null)
    {
        Return $oTaskSchedulerFolder
    }
    
    if ($Path.Contains('\'))
    {
        $aPath = $Path.Split('\',[StringSplitOptions]'RemoveEmptyEntries')
    }
    else
    {
        Return $null
    }
    
    [int] $iCount = 0
    For ($i = 0; $i -le $aPath.GetUpperBound(0); $i++)
    {
        [string] $sBuildPath = $sBuildPath + '\' + $aPath[$i]

        try
        {
            Write-Log ('sBuildPath: ' + $sBuildPath)
            $oTaskSchedulerFolder = $oTaskSchedulerService.GetFolder($sBuildPath)
        }
        catch
        {
            try
            {
                #// Get the parent path and create it.
                if ($oTaskSchedulerParentFolder -ne $null)
                {
                    $oTaskSchedulerFolder = $oTaskSchedulerParentFolder.CreateFolder($aPath[$i])
                }
                else
                {
                    Return $null
                }
            }
            catch
            {
                Return $null
            }
        }
        finally
        {
            $oTaskSchedulerParentFolder = $oTaskSchedulerFolder
        }
        $iCount++
    }

    if ($iCount -eq $aPath.Count)
    {
        Return $oTaskSchedulerFolder
    }
    else
    {
        Return $null
    }
}

Function New-Ps2ScheduledTask
{
    param([string] $ScheduledTaskFolderPath, [string] $Name, [string] $Description, [string] $Path, [string] $Arguments, [string] $Trigger, [string] $WorkingDirectory, [string] $StartImmediately = 'true', [string] $Priority = 'normal')

    $TASK_TRIGGER_TIME = 1
    $TASK_TRIGGER_BOOT = 8
    $EXECUTABLE_OR_SCRIPT = 0
    $CREATE_OR_UPDATE = 6
    $TASK_LOGON_SERVICE_ACCOUNT = 5
    $TASK_LOGON_PASSWORD = 1
    $HIGH_PRIORITY_CLASS = 1
    $THREAD_PRIORITY_LOW = 8

    Write-Log ('[New-Ps2ScheduledTask]: START')
    Write-Log ('[New-Ps2ScheduledTask]: ' + $ScheduledTaskFolderPath + ',' + $Name + ',' + $Description + ',' + $Path + ',' + $Arguments + ',' + $Trigger + ',' + $WorkingDirectory + ',' + $StartImmediately)

    $oTaskSchedulerFolder = Get-Ps2ScheduledTaskFolder -Path $ScheduledTaskFolderPath

    if ($oTaskSchedulerFolder -eq $null)
    {
        Return $false
    }

    $oTaskSchedulerService = Get-TaskSchedulerService
    $oTaskDefinition = $oTaskSchedulerService.NewTask(0)

    $oTaskDefinition.RegistrationInfo.Description = $Description
    $oTaskDefinition.RegistrationInfo.Author = 'Clint Huffman (clinth@microsoft.com)'
    $oTaskDefinition.Settings.StartWhenAvailable = $true
    $oTaskDefinition.Settings.ExecutionTimeLimit = 'PT0S'
    $oTaskDefinition.Settings.AllowHardTerminate = $false
    $oTaskDefinition.Settings.StopIfGoingOnBatteries = $false
    $oTaskDefinition.Settings.DisallowStartIfOnBatteries = $false
    
    $oTaskDefinition.Settings.IdleSettings.StopOnIdleEnd = $false

    if ($Priority -eq 'high')
    {
        $oTaskDefinition.Settings.Priority = $HIGH_PRIORITY_CLASS
    }

    if ($Priority -eq 'low')
    {
        $oTaskDefinition.Settings.Priority = $THREAD_PRIORITY_LOW
    }

    if (($Trigger -eq 'onstart') -or ($Trigger -eq '0'))
    {
        $oNewTrigger = $oTaskDefinition.Triggers.Create($TASK_TRIGGER_BOOT)
    }

    if (Test-Numeric -Value $Trigger)
    {
        [string] $sTriggerInterval = 'PT' + $Trigger + 'M'
        $oNewTrigger = $oTaskDefinition.Triggers.Create($TASK_TRIGGER_TIME)
        $oNewTrigger.Repetition.Interval = $sTriggerInterval
        $oNewTrigger.StartBoundary = '2015-01-01T10:00:00'
    }

    $oNewAction = $oTaskDefinition.Actions.Create($EXECUTABLE_OR_SCRIPT)

    $oNewAction.Path = $Path
    $oNewAction.Arguments = $ExecutionContext.InvokeCommand.ExpandString($Arguments)
    
    $oNewAction.WorkingDirectory = $WorkingDirectory
    $oTask = $oTaskSchedulerFolder.RegisterTaskDefinition($Name, $oTaskDefinition, $CREATE_OR_UPDATE, 'SYSTEM', $null, $TASK_LOGON_SERVICE_ACCOUNT)

    if ($StartImmediately -eq 'true')
    {
        Start-Sleep -Seconds 2
        [void] $oTask.Run('')
    }
    Write-Log ('[New-Ps2ScheduledTask]: END')
}

Function Start-Ps2ScheduledTask
{
    param([string] $ScheduledTaskFolderPath, [string] $TaskName, [string] $Arguments)

    [string] $TaskPath = $ScheduledTaskFolderPath + '\' + $TaskName
    Write-Log ('[Start-Ps2ScheduledTask: ' + $TaskPath + ']: START')
    Write-Log ('[Start-Ps2ScheduledTask: ' + $TaskPath + ']: Getting folder path...')
    $oTaskSchedulerFolder = Get-Ps2ScheduledTaskFolder -Path $ScheduledTaskFolderPath
    Test-Error -Err $Error
    Write-Log ('[Start-Ps2ScheduledTask: ' + $TaskPath + ']: Getting folder path...Done!')
    if ($oTaskSchedulerFolder -eq $null)
    {
        Return $false
    }
    Write-Log ('[Start-Ps2ScheduledTask: ' + $TaskPath + ']: Getting task...')
    $oTask = $oTaskSchedulerFolder.GetTask($TaskName)
    Write-Log ('[Start-Ps2ScheduledTask: ' + $TaskPath + ']: Getting task...Done!')
    Test-Error -Err $Error
    Write-Log ('[Start-Ps2ScheduledTask: ' + $TaskPath + ']: Running task...')
    $oTaskInstance = $oTask.Run($Arguments)
    Test-Error -Err $Error
    Write-Log ('[Start-Ps2ScheduledTask: ' + $TaskPath + ']: Running task...Done!')
    Write-Log ('[Start-Ps2ScheduledTask: ' + $TaskPath + ']: END')
}

Function Remove-Ps2ScheduledTask
{
    param([string] $Folder, [string] $Task)
    $oTaskSchedulerService = Get-TaskSchedulerService
    $oTaskSchedulerFolder = $oTaskSchedulerService.GetFolder($Folder)
    $oTaskSchedulerFolder.DeleteTask($Task, 0)
}

Function Remove-Ps2ToolScheduledTaskFolder
{
    param([string] $Folder, [string] $Task)
    $oTaskSchedulerService = Get-TaskSchedulerService
    $oTaskSchedulerFolder = $oTaskSchedulerService.GetFolder($Folder)
    $oTasks = $oTaskSchedulerFolder.GetTasks(0)
    ForEach ($oTask in $oTasks)
    {
        $oTaskSchedulerFolder.DeleteTask($oTask.Name, 0)

    }
}

Function Remove-AllScheduledTasksInToolFolder
{
    $oTaskSchedulerService = Get-TaskSchedulerService
    Test-Error -Err $Error

    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get task folder "\Microsoft\Windows\Clue": START')
    $oTaskSchedulerFolder = $null
    $oParentTaskSchedulerFolder = $oTaskSchedulerService.GetFolder('\Microsoft\Windows')
    $oFolders = $oParentTaskSchedulerFolder.GetFolders(0)
    :FolderLoop foreach ($oFolder in $oFolders)
    {
        if ($oFolder.Name -eq 'Clue')
        {
            $oTaskSchedulerFolder = $oFolder
            Break FolderLoop;
        }        
    }

    if ($oTaskSchedulerFolder -eq $null)
    {
        Return $null
    }

    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get task folder "\Microsoft\Windows\Clue": END')

    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get tasks of "\Microsoft\Windows\Clue": START')
    $oTasks = $oTaskSchedulerFolder.GetTasks(0)
    Test-Error -Err $Error
    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get tasks of "\Microsoft\Windows\Clue": END')

    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete tasks of "\Microsoft\Windows\Clue": START')
    ForEach ($oTask in $oTasks)
    {
        $oTask.Stop(0)
        Test-Error -Err $Error
        Start-Sleep -Seconds 2
        Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete task "\Microsoft\Windows\Clue\' + $oTask.Name + '": START')
        $oTaskSchedulerFolder.DeleteTask($oTask.Name, 0)
        Test-Error -Err $Error
        Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete task "\Microsoft\Windows\Clue\' + $oTask.Name + '": END')
        Write-Console '.' -bNoNewLine $true -bAddDateTime $false
    }
    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete tasks of "\Microsoft\Windows\Clue": END')
    
    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get task folder "\Microsoft\Windows\Clue": START')
    $oTaskSchedulerFolder = $oTaskSchedulerService.GetFolder('\Microsoft\Windows')
    Test-Error -Err $Error
    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get task folder "\Microsoft\Windows\Clue": END')

    if ($oTaskSchedulerFolder -is [System.__ComObject])
    {
        Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete "\Microsoft\Windows\Clue": START')
        $oTaskSchedulerFolder.DeleteFolder('Clue', 0)
        Test-Error -Err $Error
        Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete "\Microsoft\Windows\Clue": END')
    }
}

Function New-Ps2EventLogScheduledTask
{
    param([string] $ScheduledTaskFolderPath, [string] $Name, [string] $Description, [string] $Path, [string] $LogFile, [string] $Source, [string] $EventType, [string] $EventID,  [string] $Arguments, [string] $WorkingDirectory, [string] $Priority = 'normal')

    Write-Log ('[New-Ps2EventLogScheduledTask]: START')
    Write-Log ('[New-Ps2EventLogScheduledTask]: ' + $ScheduledTaskFolderPath + ',' + $Name + ',' + $Description + ',' + $Path + ',' + $LogFile + ',' + $Source + ',' + $EventID + ',' + $EventType + ',' + $Arguments + ',' + $Trigger + ',' + $WorkingDirectory + ',' + $StartImmediately)

    $TASK_TRIGGER_TIME = 1
    $TASK_TRIGGER_BOOT = 8
    $EXECUTABLE_OR_SCRIPT = 0
    $CREATE_OR_UPDATE = 6
    $TASK_LOGON_SERVICE_ACCOUNT = 5
    $TASK_LOGON_PASSWORD = 1
    $HIGH_PRIORITY_CLASS = 1
    $THREAD_PRIORITY_LOW = 8
    $TRIGGER_TYPE_EVENT = 0

    $oTaskSchedulerFolder = Get-Ps2ScheduledTaskFolder -Path $ScheduledTaskFolderPath

    if ($oTaskSchedulerFolder -eq $null)
    {
        Return $false
    }

    $oTaskSchedulerService = Get-TaskSchedulerService
    $oTaskDefinition = $oTaskSchedulerService.NewTask(0)

    $oTaskDefinition.RegistrationInfo.Description = $Description
    $oTaskDefinition.RegistrationInfo.Author = 'Clint Huffman (clinth@microsoft.com)'
    $oTaskDefinition.Settings.StartWhenAvailable = $true
    $oTaskDefinition.Settings.ExecutionTimeLimit = 'PT0S'
    $oTaskDefinition.Settings.AllowHardTerminate = $false
    $oTaskDefinition.Settings.StopIfGoingOnBatteries = $false
    $oTaskDefinition.Settings.DisallowStartIfOnBatteries = $false

    if ($Priority -eq 'high')
    {
        $oTaskDefinition.Settings.Priority = $HIGH_PRIORITY_CLASS
    }

    if ($Priority -eq 'low')
    {
        $oTaskDefinition.Settings.Priority = $THREAD_PRIORITY_LOW
    }

    $oNewTrigger = $oTaskDefinition.Triggers.Create($TRIGGER_TYPE_EVENT)
    switch ($EventType)
    {
        'Critical'    {$EventType = 1}
        'Error'       {$EventType = 2}
        'Warning'     {$EventType = 3}
        'Information' {$EventType = 4}
        'Verbose'     {$EventType = 5}
        default       {$EventType = 2}
    }

    [string] $Query = '*[System[(Level="' + $EventType + '") and EventID="' + $EventID + '"]]'
    $Subscription = "<QueryList><Query Id=`"1`"><Select Path=`"$Source`">$Query</Select></Query></QueryList>"
    $oNewTrigger.Subscription = $Subscription

    $oNewAction = $oTaskDefinition.Actions.Create($EXECUTABLE_OR_SCRIPT)

    $oNewAction.Path = $Path
    $oNewAction.Arguments = $ExecutionContext.InvokeCommand.ExpandString($Arguments)
    
    $oNewAction.WorkingDirectory = $WorkingDirectory
    $oTask = $oTaskSchedulerFolder.RegisterTaskDefinition($Name, $oTaskDefinition, $CREATE_OR_UPDATE, 'SYSTEM', $null, $TASK_LOGON_SERVICE_ACCOUNT)
    Write-Log ('[New-Ps2EventLogScheduledTask]: END')
}

Function Get-WorkingDirectoryFromTask
{
    param([string] $ScheduledTaskFolderPath = '\Microsoft\Windows\Clue', [string] $TaskName = 'Invoke-Rule')
    $oTaskFolder = Get-Ps2ScheduledTaskFolder -Path $ScheduledTaskFolderPath
    if ($oTaskFolder -eq $null)
    {
        Return ''
    }
    try {$oTask = $oTaskFolder.GetTask($TaskName)} catch {}
    if ($oTask -eq $null)
    {
        Return ''
    }
    foreach ($oAction in $oTask.Definition.Actions)
    {
        [string] $WorkingDirectory = $oAction.WorkingDirectory
        if ($WorkingDirectory.Length -gt 0)
        {
            Return $WorkingDirectory
        }
    }
    Return ''
}

Function Start-Wpr
{
    param([string] $WptFolderPath, [string] $Arguments = '-start GeneralProfile', [string] $Log = '.\Clue.log')
    $OriginalDirectory = (PWD).Path
    [string] $sCmd = '.\wpr.exe ' + $Arguments
    Write-Log ('[Start-Wpr] ' + $sCmd) -Log $Log
    Set-Location -Path $WptFolderPath
    $oOutput = Invoke-Expression -Command $sCmd
    Write-Log ($oOutput) -Log $Log
    Test-Error -Err $Error -Log $Log
    Set-Location -Path $OriginalDirectory
}

#///////////
#// Main //
#/////////
New-Item -Path $Log -ItemType File -Force | Out-Null
Write-Log ('[Setup]: Start')
$Error.Clear()

Write-Console (Get-Location).Path
$InvocationFolderPath = ($SCRIPT:MyInvocation.MyCommand.Path) -replace '\\_setup.ps1',''
Write-Console ('InvocationFolderPath: ' + $InvocationFolderPath)

[bool] $IsSilentInstallation = [System.Convert]::ToBoolean($IsSilentInstallation)
[string] $global:ToolName = 'Clue'
[string] $global:ScheduledTaskFolderPath = "\Microsoft\Windows\$global:ToolName"

[int] $global:iOverallCompletion = 0
Write-Progress -activity 'Overall progress: ' -status 'Progress: 0%' -percentcomplete 0 -id 1
Test-Error -Err $Error

Write-Log ('IsSilentInstallation = ' + $IsSilentInstallation.ToString())
Write-Console '/////////////////////////////'
Write-Console '// Clue tool installation //'
Write-Console '///////////////////////////'
Write-Console ''

Write-Console '/////////////////////'
Write-Console '// Compatible OS? //'
Write-Console '///////////////////'

[bool] $IsOsCompatible = Test-OSCompatibility
Test-Error -Err $Error
Write-Console ('IsOsCompatible: ' + $IsOsCompatible.ToString())
if ($IsOsCompatible -eq $false)
{
    Write-Log ('This software requires x64 (64-bit) Windows or Windows Server.')
    if ($IsSilentInstallation -eq 'false')
    {
        Write-Console '[PopUp] This software requires x64 (64-bit) Windows or Windows Server.'
        Write-MsgBox 'This software requires x64 (64-bit) Windows or Windows Server.'
    }
    Exit;
}
Test-Error -Err $Error
Write-Console ''

Set-OverallProgress -Status 'Admin rights...'
Write-Console '///////////////////'
Write-Console '// Admin rights //'
Write-Console '/////////////////'
[bool] $IsElevated = Test-AdminRights
Test-Error -Err $Error
Write-Console ('IsElevated: ' + $IsElevated.ToString())
if ($IsElevated -eq $false)
{
    Write-MsgBox 'Administrator rights is required. Try running setup again with Administrator rights.'
    Exit;
}

Write-Console ''
Write-Console '/////////////////'
Write-Console '// Copy Xperf //'
Write-Console '///////////////'
Write-Console ''
$xSourcePath = $InvocationFolderPath + '\xperf.exe'
$xDestination = ($env:Windir + '\System32')
Write-Console ('xSourcePath: ' + $xSourcePath)
Write-Console ('xDestination: ' + $xDestination)
Copy-Item -Path $xSourcePath -Destination $xDestination -Force -ErrorAction SilentlyContinue
$xSourcePath = $InvocationFolderPath + '\perfctrl.dll'
$xDestination = ($env:Windir + '\System32')
Write-Console ('xSourcePath: ' + $xSourcePath)
Write-Console ('xDestination: ' + $xDestination)
Copy-Item -Path $xSourcePath -Destination $xDestination -Force -ErrorAction SilentlyContinue
$xPath = $xDestination + '\xperf.exe'
$IsConfirmed = (Test-Path $xPath)
Write-Console ('xPerfConfirmed: ' + $IsConfirmed.ToString())
$xPath = $xDestination + '\perfctrl.dll'
$IsConfirmed = (Test-Path $xPath)
Write-Console ('PerfCtrlConfirmed: ' + $IsConfirmed.ToString())

Set-OverallProgress -Status 'Test Windows Performance Toolkit...'
Write-Console ''
Write-Console '////////////////////////////////////////'
Write-Console '// Windows Performance Toolkit (WPT) //'
Write-Console '//////////////////////////////////////'

[string] $SearchPath = $env:Windir + '\System32\wpr.exe'
[bool] $IsWprFound = Test-Path -Path $SearchPath
if ($IsWprFound -eq $false)
{
    [string] $SearchPath = (${Env:ProgramFiles(x86)} + '\Windows Kits')
    [bool] $IsWprFound = Test-IsExecutableFileFound -FileName 'wpr.exe' -StartingFolderPath $SearchPath
    if ($IsWprFound -eq $false)
    {
        Write-Console ('!! ERROR !!')
        Write-Console ('Unable to find WPR.exe. This tool requires the Windows Performance Toolkit (WPT). Please install the Windows Performance Toolkit which is part of the Windows ADK or part of the Windows SDK. Only the Windows Performance Tookit (WPT) is needed from those kits. Then run this setup again.')
        Write-Console ('!! Quitting !!')
        Exit;
    }
}
Write-Console ('IsWprFound: ' + $IsWprFound.ToString())

[string] $SearchPath = $env:Windir + '\System32\xperf.exe'
[bool] $IsXPerfFound = Test-Path -Path $SearchPath
if ($IsXPerfFound -eq $false)
{
    [string] $SearchPath = (${Env:ProgramFiles(x86)} + '\Windows Kits')
    [bool] $IsXPerfFound = Test-IsExecutableFileFound -FileName 'xperf.exe' -StartingFolderPath $SearchPath
    if ($IsXPerfFound -eq $false)
    {
        Write-Console ('!! ERROR !!')
        Write-Console ('Unable to find xPerf.exe. This tool requires the Windows Performance Toolkit (WPT). Please install the Windows Performance Toolkit which is part of the Windows ADK or part of the Windows SDK. Only the Windows Performance Tookit (WPT) is needed from those kits. Then run this setup again.')
        Write-Console ('!! Quitting !!')
        Exit;
    }
}
Test-Error -Err $Error
Write-Console ('IsXPerfFound: ' + $IsXPerfFound.ToString())

[string] $SearchPath = $env:Windir + '\System32\perfctrl.dll'
[bool] $IsPerfCtrlFound = Test-Path -Path $SearchPath
if ($IsPerfCtrlFound -eq $false)
{
    [string] $SearchPath = (${Env:ProgramFiles(x86)} + '\Windows Kits')
    [bool] $IsXPerfFound = Test-IsExecutableFileFound -FileName 'perfctrl.dll' -StartingFolderPath $SearchPath
    if ($IsPerfCtrlFound -eq $false)
    {
        Write-Console ('!! ERROR !!')
        Write-Console ('Unable to find PerfCtrl.dll. This tool requires the Windows Performance Toolkit (WPT). Please install the Windows Performance Toolkit which is part of the Windows ADK or part of the Windows SDK. Only the Windows Performance Tookit (WPT) is needed from those kits. Then run this setup again.')
        Write-Console ('!! Quitting !!')
        Exit;
    }
}
Test-Error -Err $Error
Write-Console ('IsPerfCtrlFound: ' + $IsPerfCtrlFound.ToString())

Set-OverallProgress -Status 'Delete scheduled tasks...'
Write-Console '/////////////////////////////'
Write-Console '// Delete scheduled tasks //'
Write-Console '////////////////////////////'
Write-Console ''
Write-Console 'Deleting scheduled tasks...' -bNoNewLine $true
Remove-AllScheduledTasksInToolFolder
Test-Error -Err $Error
Write-Console 'Done!' -bAddDateTime $false
Write-Console ''

Set-OverallProgress -Status 'Configuring...'
Write-Console '//////////////////////'
Write-Console '// Open Config.xml //'
Write-Console '////////////////////'
Write-Console ''
[xml] $XmlDoc = OpenConfigXml -XmlFilePath "$InvocationFolderPath\config.xml"
Test-Error -Err $Error
if (Test-Property -InputObject $XmlDoc -Name 'Configuration')
{
    [System.Xml.XmlElement] $XmlConfig = $XmlDoc.Configuration
    Write-Console ('IsConfigFileLoadedFromInvocationFolder: True')
}
Test-Error -Err $Error
if ($XmlConfig -eq $null)
{
    Write-MsgBox 'Unable to get the XML configuration. Setup has failed.'
    Exit;
}

Set-OverallProgress -Status 'Installation folder...'
Write-Console ''
Write-Console '//////////////////////////'
Write-Console '// Installation folder //'
Write-Console '////////////////////////'
Write-Console ''
Write-Console 'Getting installation folder...' -bNoNewLine $true
$InstallationDirectory = Get-XmlAttribute -XmlNode $XmlConfig -Name 'InstallationDirectory'
Test-Error -Err $Error
if ($InstallationDirectory -eq '') {$InstallationDirectory = '%ProgramFiles%\Clue'}
$InstallationDirectory = [System.Environment]::ExpandEnvironmentVariables($InstallationDirectory)
Write-Console 'Done!' -bAddDateTime $false
Write-Console ("`t" + 'Installation folder: "' + $InstallationDirectory + '"')
if (Test-Path -Path $InstallationDirectory) 
{
    Write-Console 'Removing previous installation folder...' -bNoNewLine $true
    Remove-Item -Path $InstallationDirectory -Recurse -ErrorAction SilentlyContinue
    Write-Console 'Done!' -bAddDateTime $false
}
Test-Error -Err $Error
Write-Console ('InvocationFolderPath: ' + $InvocationFolderPath)
Write-Console ('InstallationDirectory: ' + $InstallationDirectory)
Write-Console 'Copying content to installation folder...' -bNoNewLine $true
#$SourcePath = $InvocationFolderPath + '\*'
$SourcePath = $InvocationFolderPath + '\'
Copy-Item -Path $SourcePath -Destination $InstallationDirectory -Recurse -Force -ErrorAction SilentlyContinue
$Error.Clear()
Write-Console 'Done!' -bAddDateTime $false
[string] $FilePathOfConfigXml = $InstallationDirectory + '\config.xml'
if (Test-Path -Path $FilePathOfConfigXml)
{
    Write-Console ("`t" + 'Folder copy successful.')
}
else
{
    Write-Console ("`t" + 'Folder copy FAILED! See "' + $Log + '" for details.')
    Exit;
}
Write-Console ('Log: ' + $Log)
Write-Console ('Loading config.xml from installation directory') -bNoNewLine $true
[xml] $XmlDoc = OpenConfigXml -XmlFilePath $FilePathOfConfigXml
Test-Error -Err $Error
if (Test-Property -InputObject $XmlDoc -Name 'Configuration')
{
    [System.Xml.XmlElement] $XmlConfig = $XmlDoc.Configuration
}
Test-Error -Err $Error
if ($XmlConfig -eq $null)
{
    Write-MsgBox 'Unable to get the XML configuration. Setup has failed.'
    Exit;
}
Write-Console 'Done!' -bAddDateTime $false

<#
Write-Console ''
Write-Console '/////////////////////////'
Write-Console '// Copy UserInitiated //'
Write-Console '///////////////////////'
Write-Console ''
[string] $DesktopBatchFile = $(Get-Content env:PUBLIC) + '\Desktop\ClueUserInitiated.bat'
$xSourcePath = $InvocationFolderPath + '\ClueUserInitiatedDataCollector.bat'
$xDestination = ($env:PUBLIC + '\Desktop')
Write-Console ('xSourcePath: ' + $xSourcePath)
Write-Console ('xDestination: ' + $xDestination)
Copy-Item -Path $xSourcePath -Destination $xDestination -Force -ErrorAction SilentlyContinue
#>

Set-OverallProgress -Status 'Output folder...'
Write-Console ''
Write-Console '////////////////////'
Write-Console '// Output folder //'
Write-Console '//////////////////'
Write-Console ''
Write-Console 'Getting output folder...' -bNoNewLine $true
$OutputDirectory = Get-OutputDirectory -XmlConfig $XmlConfig
if ($OutputDirectory -eq '') {$OutputDirectory = 'C:\ClueOutput'}
Write-Console 'Done!' -bAddDateTime $false
Write-Console ("`t" + 'Output folder: "' + $OutputDirectory + '"')
Test-Error -Err $Error
Write-Console ("`t" + 'Creating output folder...') -bNoNewLine $true
$IsDone = New-DirectoryWithConfirm -DirectoryPath $OutputDirectory
if ($IsDone -eq $false)
{
    Write-Console ('!!!ERROR!!! Unable to create output directory ' + $OutputDirectory + '"')
    Exit;
}
Write-Console ('Done!') -bAddDateTime $false

Set-OverallProgress -Status 'Upload folder...'
Write-Console ''
Write-Console '////////////////////'
Write-Console '// Upload folder //'
Write-Console '//////////////////'
Write-Console ''
Write-Console 'Getting upload network share (optional)...' -bNoNewLine $true
$UploadNetworkShare = Get-UploadNetworkShare -XmlConfig $XmlConfig
Write-Console 'Done!' -bAddDateTime $false
Write-Console ("`t" + 'Upload network share: "' + $UploadNetworkShare + '"')
Test-Error -Err $Error

Set-OverallProgress -Status 'Email address(es)...'
Write-Console ''
Write-Console '///////////////////////'
Write-Console '// Email address(es) //'
Write-Console '/////////////////////'
Write-Console ''
Write-Console '// Get email address for report //'
Write-Console 'Getting email address(es) for the end user report (optional)...' -bNoNewLine $true
$EmailReportTo = Get-EmailForReport -XmlConfig $XmlConfig
Write-Console 'Done!' -bAddDateTime $false
Write-Console ("`t" + 'Email report to: "' + $EmailReportTo + '"')
Test-Error -Err $Error


Set-OverallProgress -Status 'Collection Level...'
Write-Console ''
Write-Console '///////////////////////'
Write-Console '// Collection Level //'
Write-Console '/////////////////////'
Write-Console ''
$CollectionLevelDefault = 1
$CollectionLevel = Get-CollectionLevel -XmlConfig $XmlConfig
Write-Console ("`t" + 'CollectionLevel: "' + $CollectionLevel + '"')
$IsNumeric = Test-Numeric -Value $CollectionLevel
Test-Error -Err $Error
If ($IsNumeric)
{
    if (($CollectionLevel -ge 0) -and ($CollectionLevel -le 3))
    {
        $IsFound = Test-Path -Path 'HKLM:\SOFTWARE\Clue'
        If ($IsFound -eq $false)
        {
            New-Item -Path 'HKLM:\SOFTWARE\Clue' -Force | Out-Null
        }
        $IsFound = Test-Path -Path 'HKLM:\SOFTWARE\Clue'
        If ($IsFound -eq $true)
        {
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Clue' -Name 'CollectionLevel' -Value $CollectionLevel -PropertyType DWORD -Force | Out-Null
        }
        $RegCollectionLevel = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Clue').CollectionLevel
        Write-Console ("`t" + 'RegCollectionLevel: "' + $RegCollectionLevel + '"')
        if ($CollectionLevel -ne $RegCollectionLevel)
        {
            Write-Console ('Failed to set HKLM:\SOFTWARE\Clue\CollectionLevel to: ' + $CollectionLevel)
        }
    }
    else
    {
        Write-Console ('CollectLevel must be a value between 0 and 3. Setting to default.')
    }
}
else
{
    Write-Console ('CollectLevel in config.xml is not numeric, setting to default.')
}

Set-OverallProgress -Status 'Save changes...'
Write-Console ''
Write-Console '///////////////////'
Write-Console '// Save changes //'
Write-Console '/////////////////'
Write-Console ''
Set-XmlAttribute -XmlNode $XmlConfig -Name 'OutputDirectory' -Value $OutputDirectory
Test-Error -Err $Error
Set-XmlAttribute -XmlNode $XmlConfig -Name 'UploadNetworkShare' -Value $UploadNetworkShare
Test-Error -Err $Error
Set-XmlAttribute -XmlNode $XmlConfig -Name 'EmailReportTo' -Value $EmailReportTo
Test-Error -Err $Error
Set-XmlAttribute -XmlNode $XmlConfig -Name 'WptFolderPath' -Value $WptFolderPath
Test-Error -Err $Error
$XmlDoc.Save($FilePathOfConfigXml)
Test-Error -Err $Error

Set-OverallProgress -Status 'PAL collector...'
Write-Console ''
Write-Console '////////////////////'
Write-Console '// PAL Collector //'
Write-Console '//////////////////'
Write-Console ''
Write-Console 'Creating PalCollector (this may take a few minutes)...' -bNoNewLine $true
& $InstallationDirectory\PalCollector\PalCollector.ps1 -OutputDirectory $OutputDirectory -Log '.\PalCollector.log'
Write-Console 'Done!' -bAddDateTime $false
Test-Error -Err $Error

Set-OverallProgress -Status 'Scheduled tasks...'
Write-Console ''
Write-Console '//////////////////////'
Write-Console '// Scheduled tasks //'
Write-Console '////////////////////'
Write-Console ''
Write-Console 'Creating scheduled tasks...' -bNoNewLine $true
foreach ($XmlNode in $XmlConfig.Rule)
{
    if (Test-XmlEnabled -XmlNode $XmlNode)
    {
        $NodeType = Get-XmlAttribute -XmlNode $XmlNode -Name 'Type'
        switch ($NodeType)
        {
            'Counter'
            {
                $Name = Get-XmlAttribute -XmlNode $XmlNode -Name 'Name'
                [string] $Arguments = '-ExecutionPolicy ByPass -File Test-CounterRule.ps1 -RuleName ' + $Name
                $IsCreated = New-Ps2ScheduledTask -ScheduledTaskFolderPath $global:ScheduledTaskFolderPath -Name $Name -Path 'powershell' -Arguments $Arguments -WorkingDirectory $InstallationDirectory -Description 'Performance counter data collector.' -Trigger '5' -StartImmediately $false
            }

            'EventLog'
            {
                $Name = Get-XmlAttribute -XmlNode $XmlNode -Name 'Name'
                $Description = Get-XmlAttribute -XmlNode $XmlNode -Name 'Description'
                $LogFile = Get-XmlAttribute -XmlNode $XmlNode -Name 'LogFile'
                $Source = Get-XmlAttribute -XmlNode $XmlNode -Name 'Source'
                $EventID = Get-XmlAttribute -XmlNode $XmlNode -Name 'EventID'
                $EventType = Get-XmlAttribute -XmlNode $XmlNode -Name 'EventType'
                [string] $Arguments = '-ExecutionPolicy ByPass -File Test-EventLogRule.ps1 -RuleName ' + $Name
                $IsCreated = New-Ps2ScheduledTask -ScheduledTaskFolderPath $global:ScheduledTaskFolderPath -Name $Name -Path 'powershell' -Arguments $Arguments -WorkingDirectory $InstallationDirectory -Description $Description -Trigger '5' -StartImmediately $false
            }

            'ScheduledTask'
            {
                [string] $Name = Get-XmlAttribute -XmlNode $XmlNode -Name 'Name'
                [string] $Description = Get-XmlAttribute -XmlNode $XmlNode -Name 'Description'
                [string] $Path = Get-XmlAttribute -XmlNode $XmlNode -Name 'Path'
                [string] $Arguments = Get-XmlAttribute -XmlNode $XmlNode -Name 'Arguments'
                [string] $Trigger = Get-XmlAttribute -XmlNode $XmlNode -Name 'Trigger'
                [string] $StartImmediately = Get-XmlAttribute -XmlNode $XmlNode -Name 'StartImmediately'
                [bool] $IsStartImmediately = [System.Convert]::ToBoolean($StartImmediately)
                $IsCreated = New-Ps2ScheduledTask -ScheduledTaskFolderPath $global:ScheduledTaskFolderPath -Name $Name -Path $Path -Arguments $Arguments -WorkingDirectory $InstallationDirectory -Description $Description -Trigger $Trigger -StartImmediately $IsStartImmediately
            }
        }
    }
    Write-Console '.' -bNoNewLine $true -bAddDateTime $false
    Test-Error -Err $Error
}
Write-Console 'Done!' -bAddDateTime $false

Set-OverallProgress -Status 'Scheduled tasks...'
Write-Console ''
Write-Console '//////////////////'
Write-Console '// WMI Tracing //'
Write-Console '/////////////////'
Write-Console ''
Write-Console 'Enabling WMI Tracing...' -bNoNewLine $true
[string] $sCmd = 'Wevtutil.exe sl Microsoft-Windows-WMI-Activity/Trace /e:true /q:true'
$oOutput = Invoke-Expression -Command $sCmd
Write-Log ($oOutput) -Log $Log
Test-Error -Err $Error -Log $Log
[string] $sCmd = 'Wevtutil.exe sl Microsoft-Windows-WMI-Activity/Operational /e:true /q:true'
$oOutput = Invoke-Expression -Command $sCmd
Write-Log ($oOutput) -Log $Log
Test-Error -Err $Error -Log $Log
Write-Console 'Done!' -bAddDateTime $false

#// Finalize setup.
Write-Progress -activity 'Overall progress: ' -status 'Progress: 100%' -Completed -id 1
Write-Console '[PopUp] Please acknowledge installation has finished...' -bNoNewLine $true
[string] $FinalMessage = ('Installation is finished! For details see ' + $Log)
Write-Console ''
Write-Console '////////////'
Write-Console '// DONE! //'
Write-Console '//////////'
Write-Console ''
Write-MsgBox $FinalMessage
Write-Console 'Done!' -bAddDateTime $false
Write-Log ('[Setup]: End')