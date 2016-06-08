param()
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

Remove-Module * -Force
Import-Module .\Modules\General.psm1 -Force
Import-Module .\Modules\Xml.psm1 -Force
Import-Module .\Modules\FileSystem.psm1 -Force
Import-Module .\Modules\TaskScheduler.psm1 -Force

[string] $WorkingDirectory = (PWD).Path
[string] $Log = ($WorkingDirectory + '\IncidentFolderManagement.log')

[bool] $Force = [System.Convert]::ToBoolean($Force)
Write-Log ('[IncidentFolderManagement] Start') -Log $Log

#/////////////////
#// Functions
#////////////////

Function Test-KeywordInOutput
{
    param($Output,[string] $Keyword, [string] $Log = $Log)
    
    foreach ($sLine in $Output)
    {
        If ($sLine.Contains($Keyword))
        {
            Return $true
        }
    }
    Return $false
}

Function Reset-ExpirationDateTime
{
    #// Creates a random hour and minute expiration date time for the next day.
    [int] $iHour = Get-Random -Minimum 0 -Maximum 24
    [int] $iMinute = Get-Random -Minimum 0 -Maximum 60
    Return (Get-Date -Hour $iHour -Minute $iMinute -Second 00).AddDays(1)
}

#/////////////////
#// Main
#////////////////

$XmlDoc = OpenConfigXml -Log $Log
if ($XmlDoc -ne $null)
{
    [xml] $XmlDoc = $XmlDoc
    If ((Test-Property -InputObject $XmlDoc -Name 'Configuration' -Log $Log) -eq $True)
    {
        $XmlConfig = $XmlDoc.Configuration
    }

    if ($XmlConfig -isnot [System.Xml.XmlElement])
    {
        Write-Log ('[IncidentFolderManagement] Unable to get XmlConfig. Exiting!') -Log $Log
        Exit;
    }
}
else
{
    Write-Log ('[IncidentFolderManagement] Unable to get XmlDoc. Exiting!') -Log $Log
    Exit;    
}

#//////////////////////////
#// Get OutputDirectory //
#////////////////////////

$OutputDirectory = Get-XmlAttribute -XmlNode $XmlConfig -Name 'OutputDirectory' -Log $Log
If ($OutputDirectory -eq '')
{
    Write-Log ('[IncidentFolderManagement] Unable to get OutputDirectory. Exiting!') -Log $Log
    Exit;
}
Set-Location -Path $OutputDirectory

#///////////////////////
#// Get Upload share //
#/////////////////////
[bool] $IsUpload = $false
$UploadSharePath = Get-XmlAttribute -XmlNode $XmlConfig -Name 'UploadNetworkShare' -Log $Log
If ($UploadSharePath -ne '')
{
    If (Test-UncPath -UncPath $UploadSharePath)
    {
        [bool] $IsUpload = $true
    }
}

Start-TruncateLog -FilePath $Log -Log $Log
[datetime] $dtLastLogTruncate = (Get-Date)

Write-Log '[IncidentFolderManagement] Start inifint loop' -Log $Log
[datetime] $dtExpiration = Reset-ExpirationDateTime -Log $Log

Do
{    
    #////////////////////////////////
    #// Compress incident folders //
    #//////////////////////////////

    Write-Log ('[IncidentFolderManagement] Compression: Start') -Log $Log
    $IncidentFolders = @(Get-ChildItem *)
    foreach ($oFolder in $IncidentFolders)
    {
        Write-Log ('[IncidentFolderManagement] ' + $oFolder.FullName) -Log $Log
        If ($oFolder -is [System.IO.DirectoryInfo])
        {
            Write-Log '[IncidentFolderManagement] IsFolder: True' -Log $Log
            #// Compress the folder if data collection is finished.
            if (Test-IsIncidentFolder -FolderName $oFolder.Name -Log $Log)
            {
                [bool] $IsCollectionInProgress = Test-DataCollectionInProgress -FolderPath $oFolder.FullName -Log $Log
                if ($IsCollectionInProgress -eq $false)
                {
                    #// Delete any pre-merged ETL files. They are not necessary and are usually large.
                    [string] $PreMergedEtlFilePath = $oFolder.FullName + '\pre-merged-kernel.etl'
                    if (Test-Path -Path $PreMergedEtlFilePath)
                    {
                        Remove-Item -Path $PreMergedEtlFilePath -Force -ErrorAction SilentlyContinue
                    }
                    [string] $sZipFilePath = $OutputDirectory + '\' + $oFolder.Name + '.zip'
                    Write-Log ('[IncidentFolderManagement] Compressing "' + $oFolder.FullName + '"...') -Log $Log
                    Add-Zip -ZipFilePath $sZipFilePath -FolderPathToCompress $oFolder.FullName -DeleteSource $true -Log $Log
                    Write-Log ('[IncidentFolderManagement] Compressing "' + $oFolder.FullName + '"...Done!') -Log $Log
                }
                else
                {
                    Write-Log ('[IncidentFolderManagement] Skipping "' + $oFolder.FullName + '" due to data collection in progress.') -Log $Log
                }
            }
        }
        else
        {
            Write-Log '[IncidentFolderManagement] IsFolder: False' -Log $Log
        }
    }
    Write-Log ('[IncidentFolderManagement] Compression: End') -Log $Log

    #//////////////////////////////////////
    #// Move zip files to network share //
    #////////////////////////////////////

    if ($UploadSharePath -ne '')
    {
        [string] $sCmd = 'Robocopy.exe "' + $OutputDirectory + '" "' + $UploadSharePath + '" *.zip /MOV /IPG:300 /R:0'
        Write-Log ('[IncidentFolderManagement] sCmd: ' + $sCmd) -Log $Log
        $aOutput = Invoke-Expression -Command $sCmd
        foreach ($sLine in $aOutput)
        {
            Write-Log ('[IncidentFolderManagement]: ' + $sLine) -Log $Log
        }
    }

    #/////////////////////////////////////
    #// Delete failed incident folders //
    #///////////////////////////////////

    $IncidentFolders = @(Get-ChildItem *)
    foreach ($oFolder in $IncidentFolders)
    {
        If ($oFolder -is [System.IO.DirectoryInfo])
        {
            [bool] $IsFolderShouldBeDeleted = $false
            [bool] $IsCollectionInProgress = $false
            $oCollectionOfSubFolderItems = Get-ChildItem $oFolder.FullName

            :FileSearchLoop foreach ($oSubItem in $oCollectionOfSubFolderItems)
            {
                If ($oSubItem.Name -eq '_DATA_COLLECTION_IN_PROGRESS.txt')
                {
                    $IsCollectionInProgress = $true

                    $dtDiff = New-TimeSpan $oSubItem.LastWriteTime $(Get-Date)
                    if ($dtDiff.TotalMinutes -gt 30)
                    {
                        $IsFolderShouldBeDeleted = $true
                    }                
                    Break FileSearchLoop;
                }
            }

            if ($IsFolderShouldBeDeleted -eq $true)
            {
                $oFolder.Delete($true)
            }
        }
    }

    #//////////////////////////////////////////////////////////////////////////////
    #// Reset run limits at random time tomorrow if no incident zip files exist //
    #////////////////////////////////////////////////////////////////////////////

    $IncidentFiles = @(Get-ChildItem *.zip)
    Write-Log ('[IncidentFolderManagement] IncidentFiles.Count: ' + $IncidentFiles.Count) -Log $Log
    if ($IncidentFiles.Count -eq 0)
    {
        Write-Log ('[IncidentFolderManagement] dtExpiration: ' + $dtExpiration.ToString()) -Log $Log
        [datetime] $dtNow = (Get-Date)
        Write-Log ('[IncidentFolderManagement] $dtNow: ' + $dtNow.ToString()) -Log $Log
        if ($dtNow -gt $dtExpiration)
        {
            #// Reset run limits.
            Write-Log ('[IncidentFolderManagement] Reset run limits expiration time is hit. Reseting run limits') -Log $Log
            Reset-Runlimits -Log $Log

            #// Reset expiration date time to a random hour minute the next day.
            [datetime] $dtExpiration = Reset-ExpirationDateTime
            Write-Log ('[IncidentFolderManagement] Reset run limits new expiration: ' + $dtExpiration.ToString()) -Log $Log

            #// Delete logs to prevent them from getting too large.
            #Write-Log ('[IncidentFolderManagement] Delete logs') -Log $Log
            #Remove-Item -Path '.\Clue.log' -ErrorAction SilentlyContinue
            #Remove-Item -Path '.\Clue_IncidentFolderManagement.log' -ErrorAction SilentlyContinue
        }
        else
        {
            Write-Log ('[IncidentFolderManagement] Timer is not expired yet.') -Log $Log
        }
    }

    [int] $RandomMinutes = Get-Random -Minimum 100 -Maximum 200
    if ((New-TimeSpan -Start $dtLastLogTruncate -End (Get-Date)).TotalMinutes -gt $RandomMinutes)
    {
        Write-Log ('[Start-TruncateLog]') -Log $Log
        Start-TruncateLog -FilePath $Log -Log $Log
        [datetime] $dtLastLogTruncate = (Get-Date)
    }

    #/////////////////
    #// Update Clue //
    #///////////////

    #Write-Log ('[IncidentFolderManagement] Check for tool update: Start') -Log $Log
    #UpdateClue -WorkingDirectory $WorkingDirectory -UploadSharePath $UploadSharePath
    #Write-Log ('[IncidentFolderManagement] Check for tool update: End') -Log $Log

    #////////////
    #// Sleep //
    #//////////

    [int] $iSleepInSeconds = 300
    Write-Log ('[IncidentFolderManagement] Sleep for ' + $iSleepInSeconds + ' seconds : Start') -Log $Log
    Start-Sleep -Seconds $iSleepInSeconds
    Write-Log ('[IncidentFolderManagement] Sleep for ' + $iSleepInSeconds + ' seconds : End') -Log $Log

} until ($True -eq $False)