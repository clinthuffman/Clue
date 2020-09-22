##########
## XML ##
########

Function OpenConfigXml
{
    param([string] $XmlFilePath='.\config.xml', [string] $Log = '.\Clue.log')
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
    param($XmlNode, [string] $Log = '.\Clue.log')
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
    param([System.Xml.XmlElement] $XmlNode, [string] $Name, [string] $Log = '.\Clue.log')
    if (Test-Property -InputObject $XmlNode -Name $Name)
    {
        Return [string] $XmlNode.$Name
    }
    else
    {Return [string] ''}
}

Function Set-XmlAttribute
{
    param([System.Xml.XmlElement] $XmlNode, [string] $Name, [string] $Value, [string] $Log = '.\Clue.log')
    if (Test-Property -InputObject $XmlNode -Name $Name)
    {
        $XmlNode.$Name = $Value
    }
}

Function Get-MatchingNodeByAttribute
{
    param([System.Xml.XmlElement] $XmlConfig, [string] $NodeName, [string] $Attribute, [string] $Value, [string] $Log = '.\Clue.log')
    $XmlNode = $null
    foreach ($XmlNode in $XmlConfig.$NodeName)
    {
        [string] $XmlValue = Get-XmlAttribute -XmlNode $XmlNode -Name $Attribute
        if ($XmlValue -eq $Value)
        {
            Return $XmlNode
        }
    }
    Return $XmlNode
}

Function Test-RunLimit
{
    param([System.Xml.XmlElement] $XmlConfig, [string] $RuleName, [string] $Log = '.\Clue.log')
    $XmlNode = Get-MatchingNodeByAttribute -XmlConfig $XmlConfig -NodeName 'Rule' -Attribute 'Name' -Value $RuleName

    if ($XmlNode -ne $null)
    {
        [int] $iRan = 0
        If (Test-Property -InputObject $XmlNode -Name 'Ran') 
        {
            [Int] $iRan = $XmlNode.Ran
        }

        [int] $iRunLimit = 1
        If ((Test-Property -InputObject $XmlNode -Name 'RunLimit') -eq $True) 
        {
            [Int] $iRunLimit = $XmlNode.RunLimit
        } 
        
        If ($iRan -ge $iRunLimit)
        {
            Return $True
        }
    }
    Return $false
}

Function Update-Ran
{
    param([System.Xml.XmlElement] $XmlConfig, [string] $RuleName, [string] $Log = '.\Clue.log')
    $XmlNode = Get-MatchingNodeByAttribute -XmlConfig $XmlConfig -NodeName 'Rule' -Attribute 'Name' -Value $RuleName
    if ($XmlNode -ne $null)
    {
        [int] $iRan = 0
        If (Test-Property -InputObject $XmlNode -Name 'Ran') 
        {
            [Int] $iRan = $XmlNode.Ran
            $iRan = $iRan + 1
            $XmlNode.SetAttribute('Ran',$($iRan.ToString()))
            $XmlConfig.OwnerDocument.Save('.\config.xml')
        }
    }
}

Function Get-ActionsFromRule
{
    param([System.Xml.XmlElement] $XmlConfig, [string] $RuleName, [string] $Log = '.\Clue.log')

    foreach ($XmlNode in $XmlConfig.Rule)
    {
        if ((Test-Property -InputObject $XmlNode -Name 'Name') -and (Test-XmlEnabled -XmlNode $XmlNode))
        {
            if ($XmlNode.Name -eq $RuleName)
            {
                if (Test-Property -InputObject $XmlNode -Name 'Actions')
                {
                    Return $XmlNode.Actions
                }
            }
        }
    }
}

Function Get-IncidentFolderPath
{
    param([string] $TimeStamp, [string] $RuleName, [string] $OutputDirectory, [string] $Log = '.\Clue.log')
    [string] $FolderName = ''
    [string] $FolderName = $TimeStamp + '_' + $env:computername + '_' + $RuleName
    [string] $IncidentOutputFolder = Remove-FileSystemIllegalCharacters -Name $FolderName
    Return $OutputDirectory + '\' + $IncidentOutputFolder
}

Function Invoke-Actions
{
    param($XmlConfig, [string] $WptFolderPath, [string] $RuleName='UserInitiated', [string] $Actions='OnActionStart,OnUserInitiated,OnActionEnd', [string] $IncidentOutputFolder, [int] $CollectionLevel = 3, [string] $Log = '.\Clue.log')

    Write-Log ('[Invoke-Actions] Start') -Log $Log
    Write-Log ('[Invoke-Actions] Usable variables in action code:') -Log $Log
    Write-Log ('[Invoke-Actions] WptFolderPath: ' + $WptFolderPath) -Log $Log
    Write-Log ('[Invoke-Actions] RuleName: ' + $RuleName) -Log $Log
    Write-Log ('[Invoke-Actions] OutputDirectory: ' + $OutputDirectory) -Log $Log
    $WorkingDirectory = $pwd
    Write-Log ('[Invoke-Actions] WorkingDirectory: ' + $WorkingDirectory) -Log $Log
    Write-Log ('[Invoke-Actions] Actions: ' + $Actions) -Log $Log
    Write-Log ('[Invoke-Actions] IncidentOutputFolder: ' + $IncidentOutputFolder) -Log $Log
    $aActionNames = @($Actions.Split(','))
    [int] $iXmlCollectionLevel = 2
    ForEach ($ActionName in $aActionNames)
    {
        $XmlNodeAction = Get-MatchingNodeByAttribute -XmlConfig $XmlConfig -NodeName 'Action' -Attribute 'Name' -Value $ActionName
        if ($XmlNodeAction -ne $null)
        {
            if (Test-Property -InputObject $XmlNodeAction -Name 'CollectionLevel' -Log $Log)
            {
                $iXmlCollectionLevel = $XmlNodeAction.CollectionLevel
            }
            else
            {
                Write-Log ('[Invoke-Actions] CollectionLevel NOT FOUND on this node using default: ' + $iXmlCollectionLevel) -Log $Log
            }
            Write-Log ('[Invoke-Actions] CollectionLevel: ' + $CollectionLevel) -Log $Log
            Write-Log ('[Invoke-Actions] iXmlCollectionLevel: ' + $iXmlCollectionLevel) -Log $Log
            if ($iXmlCollectionLevel -le $CollectionLevel)
            {
                Write-Log ('[Invoke-Actions] Invoke-Expression:' + $ActionName + ':Start') -Log $Log
                Write-Log ($XmlNodeAction.get_innertext()) -Log $Log
                $oOutput = Invoke-Expression -Command ($XmlNodeAction.get_innertext())
                Write-Log ($oOutput) -Log $Log
                Test-Error -Err $Error -Log $Log
                Write-Log ('[Invoke-Actions] Invoke-Expression:' + $ActionName + ':End') -Log $Log
            }
            else
            {
                Write-Log ('[Invoke-Actions] iXmlCollectionLevel is greater than the CollectionLevel. SKIPPING THIS ACTION.') -Log $Log
            }
        }
    }
    Write-Log ('[Invoke-Actions] Remove-DataCollectionInProgress') -Log $Log    
}

Function Invoke-CounterRuleCode
{
    param($DataCollector, [string] $Log = '.\Clue.log')
    Write-Log ('[Invoke-CounterRuleCode] Start') -Log $Log
    [string] $Name = $DataCollector.Name
    [string] $CounterPath = $DataCollector.CounterPath
    [string] $Exclude = $DataCollector.Exclude
    [string] $SampleInterval = $DataCollector.SampleInterval
    [string] $MaxSamples = $DataCollector.MaxSamples
    [string] $Operator = $DataCollector.Operator
    [string] $Threshold = $DataCollector.Threshold
    [string] $OnStartActions = $DataCollector.OnStartActions
    [string] $OnEndActions = $DataCollector.OnEndActions

    Write-Log ('[Invoke-CounterRuleCode] Before code:') -Log $Log
    Write-Log ('[Invoke-CounterRuleCode] Name:' + $Name) -Log $Log
    Write-Log ('[Invoke-CounterRuleCode] CounterPath:' + $CounterPath) -Log $Log
    Write-Log ('[Invoke-CounterRuleCode] Exclude:' + $Exclude) -Log $Log
    Write-Log ('[Invoke-CounterRuleCode] SampleInterval:' + $SampleInterval) -Log $Log
    Write-Log ('[Invoke-CounterRuleCode] MaxSamples:' + $MaxSamples) -Log $Log
    Write-Log ('[Invoke-CounterRuleCode] Operator:' + $Operator) -Log $Log
    Write-Log ('[Invoke-CounterRuleCode] Threshold:' + $Threshold) -Log $Log
    Write-Log ('[Invoke-CounterRuleCode] OnStartActions:' + $OnStartActions) -Log $Log
    Write-Log ('[Invoke-CounterRuleCode] OnEndActions:' + $OnEndActions) -Log $Log

    Write-Log ('[Invoke-CounterRuleCode] Code:') -Log $Log
    Write-Log ($DataCollector.Code) -Log $Log
    Write-Log ('[Invoke-CounterRuleCode] Running Invoke-Expression...') -Log $Log
    Invoke-Expression -Command $DataCollector.Code
    Write-Log ('[Invoke-CounterRuleCode] Running Invoke-Expression...Done!') -Log $Log

    [string] $DataCollector.Name = $Name
    [string] $DataCollector.CounterPath = $CounterPath
    [string] $DataCollector.Exclude = $Exclude
    [string] $DataCollector.SampleInterval = $SampleInterval
    [string] $DataCollector.MaxSamples = $MaxSamples
    [string] $DataCollector.Operator = $Operator
    [string] $DataCollector.Threshold = $Threshold
    [string] $DataCollector.OnStartActions = $OnStartActions
    [string] $DataCollector.OnEndActions = $OnEndActions

    Write-Log ('[Invoke-CounterRuleCode] After code:') -Log $Log
    Write-Log ('[Invoke-CounterRuleCode] Name:' + $Name) -Log $Log
    Write-Log ('[Invoke-CounterRuleCode] CounterPath:' + $CounterPath) -Log $Log
    Write-Log ('[Invoke-CounterRuleCode] Exclude:' + $Exclude) -Log $Log
    Write-Log ('[Invoke-CounterRuleCode] SampleInterval:' + $SampleInterval) -Log $Log
    Write-Log ('[Invoke-CounterRuleCode] MaxSamples:' + $MaxSamples) -Log $Log
    Write-Log ('[Invoke-CounterRuleCode] Operator:' + $Operator) -Log $Log
    Write-Log ('[Invoke-CounterRuleCode] Threshold:' + $Threshold) -Log $Log
    Write-Log ('[Invoke-CounterRuleCode] OnStartActions:' + $OnStartActions) -Log $Log
    Write-Log ('[Invoke-CounterRuleCode] OnEndActions:' + $OnEndActions) -Log $Log

    Write-Log '[Invoke-CounterRuleCode] End' -Log $Log
    Return $DataCollector
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

Function Stop-Wpr
{
    param([string] $WptFolderPath, [string] $EtlFilePath = '', [string] $Log = '.\Clue.log')
    $OriginalDirectory = (PWD).Path
    Write-Log ('[Stop-Wpr] WptFolderPath: ' + $WptFolderPath) -Log $Log
    Write-Log ('[Stop-Wpr] EtlFilePath: ' + $EtlFilePath) -Log $Log
    Write-Log ('[Stop-Wpr] OriginalDirectory: ' + $OriginalDirectory) -Log $Log
    if ($EtlFilePath -eq '')
    {
        [string] $sCmd = '.\wpr.exe -stop DeleteMe.etl'
    }
    else
    {
        [string] $sCmd = '.\wpr.exe -stop "' + $EtlFilePath + '"'        
    }
    Write-Log ('[Stop-Wpr] sCmd: ' + $sCmd) -Log $Log
    Set-Location -Path $WptFolderPath
    $Output = Invoke-Expression -Command $sCmd
    Write-Log ($Output) -Log $Log
    Test-Error -Err $Error -Log $Log
    if (Test-Path -Path 'DeleteMe.etl')
    {Remove-Item -Path 'DeleteMe.etl' -Force -ErrorAction SilentlyContinue}
    Set-Location -Path $OriginalDirectory
}

Function Start-Xperf
{
    param([string] $WptFolderPath, [string] $Arguments = '-on Base+Diag+Latency+FileIO+DPC+DISPATCHER+Pool -stackwalk Profile+CSwitch+ReadyThread+ThreadCreate+PoolAlloc+PoolAllocSession+VirtualAlloc -BufferSize 1024 -MinBuffers 256 -MaxBuffers 256 -MaxFile 256 -FileMode Circular', [string] $Log = '.\Clue.log')
    $OriginalDirectory = (PWD).Path
    [string] $sCmd = 'xperf.exe ' + $Arguments
    Write-Log ('[Start-Xperf] ' + $sCmd) -Log $Log
    #Set-Location -Path $WptFolderPath
    Set-Location -Path 'C:\Program Files\Clue'
    $oOutput = Invoke-Expression -Command $sCmd
    Write-Log ($oOutput) -Log $Log
    Test-Error -Err $Error -Log $Log
    Set-Location -Path $OriginalDirectory
}

Function Stop-Xperf
{
    param([string] $WptFolderPath, [string] $EtlFilePath = '', [string] $Log = '.\Clue.log')
    $OriginalDirectory = (PWD).Path
    if ($EtlFilePath -eq '')
    {
        [string] $sCmd = 'xperf.exe -stop'
    }
    else
    {
        [string] $sCmd = 'xperf.exe -stop -d "' + $EtlFilePath + '"'        
    }
    Write-Log ('[Stop-Xperf] sCmd: ' + $sCmd) -Log $Log
    #Set-Location -Path $WptFolderPath
    Set-Location -Path 'C:\Program Files\Clue'
    Invoke-Expression -Command $sCmd
    Test-Error -Err $Error -Log $Log
    Set-Location -Path $OriginalDirectory
}

Function Reset-Runlimits
{
    param([string] $Log = '.\Clue.log')
    #// Open the config.xml file.
    $XmlDoc = OpenConfigXml
    if ($XmlDoc -ne $null)
    {
        [xml] $XmlDoc = $XmlDoc
        If ((Test-Property -InputObject $XmlDoc -Name 'Configuration') -eq $True)
        {
            $XmlConfig = $XmlDoc.Configuration
        }

        if ($XmlConfig -is [System.Xml.XmlElement])
        {
            foreach ($XmlNode in $XmlConfig.Rule)
            {
                If ((Test-Property -InputObject $XmlNode -Name 'Name') -eq $True)
                {
                    Write-Log ('[Reset-Runlimits] NodeName: ' + $XmlNode.Name) -Log $Log
                }        

                If ((Test-Property -InputObject $XmlNode -Name 'Ran') -eq $True)
                {
                    Write-Log ('[Reset-Runlimits] Setting Ran to 0') -Log $Log
                    $XmlNode.Ran = '0'
                }
            }
            Write-Log ('[Reset-Runlimits] Saving changes to config.xml') -Log $Log
            $XmlDoc.Save($XmlFilePath)
        }
    }
}