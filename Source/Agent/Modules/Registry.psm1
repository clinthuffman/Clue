Function Get-RegistryKey
{
    param([string] $Path, [string] $Log = '.\Clue.log')
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