#####################
## Task Scheduler ##
###################

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
    param([string] $Path, [string] $Log = '.\Clue.log')

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
            Write-Log ('sBuildPath: ' + $sBuildPath) -Log $Log
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
    param([string] $ScheduledTaskFolderPath, [string] $Name, [string] $Description, [string] $Path, [string] $Arguments, [string] $Trigger, [string] $WorkingDirectory, [string] $StartImmediately = 'true', [string] $Priority = 'normal', [string] $Log = '.\Clue.log')

    $TASK_TRIGGER_TIME = 1
    $TASK_TRIGGER_BOOT = 8
    $EXECUTABLE_OR_SCRIPT = 0
    $CREATE_OR_UPDATE = 6
    $TASK_LOGON_SERVICE_ACCOUNT = 5
    $TASK_LOGON_PASSWORD = 1
    $HIGH_PRIORITY_CLASS = 1
    $THREAD_PRIORITY_LOW = 8

    Write-Log ('[New-Ps2ScheduledTask]: START') -Log $Log
    Write-Log ('[New-Ps2ScheduledTask]: ' + $ScheduledTaskFolderPath + ',' + $Name + ',' + $Description + ',' + $Path + ',' + $Arguments + ',' + $Trigger + ',' + $WorkingDirectory + ',' + $StartImmediately) -Log $Log

    $oTaskSchedulerFolder = Get-Ps2ScheduledTaskFolder -Path $ScheduledTaskFolderPath -Log $Log

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
    Write-Log ('[New-Ps2ScheduledTask]: END') -Log $Log
}

Function Start-Ps2ScheduledTask
{
    param([string] $ScheduledTaskFolderPath, [string] $TaskName, [string] $Arguments, [string] $Log)

    [string] $TaskPath = $ScheduledTaskFolderPath + '\' + $TaskName
    Write-Log ('[Start-Ps2ScheduledTask: ' + $TaskPath + ']: START') -Log $Log
    Write-Log ('[Start-Ps2ScheduledTask: ' + $TaskPath + ']: Getting folder path...') -Log $Log
    $oTaskSchedulerFolder = Get-Ps2ScheduledTaskFolder -Path $ScheduledTaskFolderPath -Log $Log
    Test-Error -Err $Error -Log $Log
    Write-Log ('[Start-Ps2ScheduledTask: ' + $TaskPath + ']: Getting folder path...Done!') -Log $Log
    if ($oTaskSchedulerFolder -eq $null)
    {
        Return $false
    }
    Write-Log ('[Start-Ps2ScheduledTask: ' + $TaskPath + ']: Getting task...') -Log $Log
    $oTask = $oTaskSchedulerFolder.GetTask($TaskName)
    Write-Log ('[Start-Ps2ScheduledTask: ' + $TaskPath + ']: Getting task...Done!') -Log $Log
    Test-Error -Err $Error -Log $Log
    Write-Log ('[Start-Ps2ScheduledTask: ' + $TaskPath + ']: Running task...') -Log $Log
    $oTaskInstance = $oTask.Run($Arguments)
    Test-Error -Err $Error -Log $Log
    Write-Log ('[Start-Ps2ScheduledTask: ' + $TaskPath + ']: Running task...Done!') -Log $Log
    <#
    if ($oTaskInstance -ne $null)
    {
        if (Test-Property -InputObject $oTaskInstance -Name 'EnginePID')
        {
            if (Test-Numeric -Value $oTaskInstance.EnginePID)
            {
                Test-MyProcessExit -iPid $oTaskInstance.EnginePID
            }
        }
    }
    Test-Error -Err $Error -Log $Log
    #>
    Write-Log ('[Start-Ps2ScheduledTask: ' + $TaskPath + ']: END') -Log $Log
}

Function Remove-Ps2ScheduledTask
{
    param([string] $Folder, [string] $Task, [string] $Log = '.\Clue.log')
    $oTaskSchedulerService = Get-TaskSchedulerService
    $oTaskSchedulerFolder = $oTaskSchedulerService.GetFolder($Folder)
    $oTaskSchedulerFolder.DeleteTask($Task, 0)
}

Function Remove-Ps2ToolScheduledTaskFolder
{
    param([string] $Folder, [string] $Task, [string] $Log = '.\Clue.log')
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
    param([string] $Log = '.\Clue.log')
    $oTaskSchedulerService = Get-TaskSchedulerService
    Test-Error -Err $Error -Log $Log

    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get task folder "\Microsoft\Windows\Clue": START') -Log $Log
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

    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get task folder "\Microsoft\Windows\Clue": END') -Log $Log

    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get tasks of "\Microsoft\Windows\Clue": START') -Log $Log
    $oTasks = $oTaskSchedulerFolder.GetTasks(0)
    Test-Error -Err $Error -Log $Log
    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get tasks of "\Microsoft\Windows\Clue": END') -Log $Log

    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete tasks of "\Microsoft\Windows\Clue": START') -Log $Log
    ForEach ($oTask in $oTasks)
    {
        $oTask.Stop(0)
        Test-Error -Err $Error -Log $Log
        Start-Sleep -Seconds 2
        Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete task "\Microsoft\Windows\Clue\' + $oTask.Name + '": START') -Log $Log
        $oTaskSchedulerFolder.DeleteTask($oTask.Name, 0)
        Test-Error -Err $Error -Log $Log
        Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete task "\Microsoft\Windows\Clue\' + $oTask.Name + '": END') -Log $Log
        Write-Console '.' -bNoNewLine $true -bAddDateTime $false
    }
    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete tasks of "\Microsoft\Windows\Clue": END') -Log $Log
    
    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get task folder "\Microsoft\Windows\Clue": START') -Log $Log
    $oTaskSchedulerFolder = $oTaskSchedulerService.GetFolder('\Microsoft\Windows')
    Test-Error -Err $Error -Log $Log
    Write-Log ('[Remove-AllScheduledTasksInToolFolder] Get task folder "\Microsoft\Windows\Clue": END') -Log $Log

    if ($oTaskSchedulerFolder -is [System.__ComObject])
    {
        Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete "\Microsoft\Windows\Clue": START') -Log $Log
        $oTaskSchedulerFolder.DeleteFolder('Clue', 0)
        Test-Error -Err $Error -Log $Log
        Write-Log ('[Remove-AllScheduledTasksInToolFolder] Delete "\Microsoft\Windows\Clue": END') -Log $Log
    }
}

Function New-Ps2EventLogScheduledTask
{
    param([string] $ScheduledTaskFolderPath, [string] $Name, [string] $Description, [string] $Path, [string] $LogFile, [string] $Source, [string] $EventType, [string] $EventID,  [string] $Arguments, [string] $WorkingDirectory, [string] $Priority = 'normal', [string] $Log = '.\Clue.log')

    Write-Log ('[New-Ps2EventLogScheduledTask]: START') -Log $Log
    Write-Log ('[New-Ps2EventLogScheduledTask]: ' + $ScheduledTaskFolderPath + ',' + $Name + ',' + $Description + ',' + $Path + ',' + $LogFile + ',' + $Source + ',' + $EventID + ',' + $EventType + ',' + $Arguments + ',' + $Trigger + ',' + $WorkingDirectory + ',' + $StartImmediately) -Log $Log

    $TASK_TRIGGER_TIME = 1
    $TASK_TRIGGER_BOOT = 8
    $EXECUTABLE_OR_SCRIPT = 0
    $CREATE_OR_UPDATE = 6
    $TASK_LOGON_SERVICE_ACCOUNT = 5
    $TASK_LOGON_PASSWORD = 1
    $HIGH_PRIORITY_CLASS = 1
    $THREAD_PRIORITY_LOW = 8
    $TRIGGER_TYPE_EVENT = 0

    $oTaskSchedulerFolder = Get-Ps2ScheduledTaskFolder -Path $ScheduledTaskFolderPath -Log $Log

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
    Write-Log ('[New-Ps2EventLogScheduledTask]: END') -Log $Log
}

Function Get-WorkingDirectoryFromTask
{
    param([string] $ScheduledTaskFolderPath = '\Microsoft\Windows\Clue', [string] $TaskName = 'Invoke-Rule', [string] $Log = '.\Clue.log')
    $oTaskFolder = Get-Ps2ScheduledTaskFolder -Path $ScheduledTaskFolderPath -Log $Log
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