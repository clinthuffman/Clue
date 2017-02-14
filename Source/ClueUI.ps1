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

$Error.Clear()
Remove-Module * -Force
Import-Module .\Modules\General.psm1 -Force
Import-Module .\Modules\Xml.psm1 -Force
Import-Module .\Modules\FileSystem.psm1 -Force
Import-Module .\Modules\TaskScheduler.psm1 -Force

[string] $Log = '.\ClueUI.log'

Start-TruncateLog -FilePath $Log -Log $Log
[datetime] $dtLastLogTruncate = (Get-Date)

$error.Clear()
Write-Log ('Start Log') -Log $Log
Write-Log ('Written by Clint Huffman (clinth@microsoft.com)') -Log $Log

#[string] $env:ProgramData

[xml] $XmlDoc = Get-Content -Path 'C:\ProgramData\Clue\config.xml'
Test-Error -Err $Error -Log $Log
if (Test-Property -InputObject $XmlDoc -Name 'Configuration' -Log $Log)
{
    [System.Xml.XmlElement] $XmlConfig = $XmlDoc.Configuration
}

function wl
{
    param([string] $Line)
    if (($Line -ne $null) -and ($Line -ne ''))
    {
        Write-Log ($Line) -Log $Log
        Write-Host ($Line)
    }
}

Function Show-Config
{
    Write-Host ('------- CONFIGURATION -------')
    $XmlConfig
    Write-Host ('-----------------------------')
    Write-Host ('')
    Write-Host ('COMMANDS')
    Write-Host ('')
    Write-Host ("M`t Main Menu")
    Write-Host ('')
}

function Show-MainMenu
{
    Write-Host ('------ MAIN MENU ------')
    Write-Host ('Welcome to the Collection of Logs and the User Experience (CLUE) tool!')
    Write-Host ('-----------------------')
    Write-Host ('')
    Write-Host ('COMMANDS')
    Write-Host ('')
    Write-Host ("R`t Rules")
    Write-Host ("C`t Configuration")
    Write-Host ("Q`t Quit")
    Write-Host ('')
}

function Show-Quit
{
    Write-Host ('Quitting!!!')
    Exit;
}

function Show-Rules
{
    Write-Host ('------ RULES ------')
    $XmlConfig.Rule
    Write-Host ('-------------------')
    Write-Host ('')
    Write-Host ('COMMANDS')
    Write-Host ('')
    Write-Host ("M`t Main Menu")
    Write-Host ("C`t Configuration")
    Write-Host ("Q`t Quit")
    Write-Host ('')
}

function Process-Command
{
    param([string] $Command)
    Write-Host ('')
    switch ($Command)
    {
        'M' {Show-MainMenu}
        'C' {Show-Config}
        'Q' {Show-Quit}
        'R' {Show-Rules}
        default {Show-MainMenu;Write-Host ('!!! Unknown command !!!');Write-Host ('');}
    }
}

Show-MainMenu

Do
{
    [string] $Command = Read-Host -Prompt 'Option'
    Process-Command -Command $Command
} until ($true -eq $false)

