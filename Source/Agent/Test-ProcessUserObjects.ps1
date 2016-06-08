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
Import-Module .\Modules\TaskScheduler.psm1 -Force
Import-Module .\Modules\Xml.psm1 -Force
Import-Module .\Modules\FileSystem.psm1 -Force

[string] $Log = '.\Test-ProcessUserObjects.log'

Write-Log ('[Test-ProcessUserObjects] Started') -Log $Log

function Run-Impersonated {
    param([scriptblock]$ScriptBlock, [string] $Log = $Log) 

    Add-Type -MemberDefinition @'
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct TokPriv1Luid {
                public int Count;
                public long Luid;
                public int Attr;
            }

        public const int SE_PRIVILEGE_ENABLED = 0x00000002;
        public const int TOKEN_QUERY = 0x00000008;
        public const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
        public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const UInt32 TOKEN_DUPLICATE = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE = 0x0004;
        public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
        public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
        public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
        public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
        public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID);

        public const string SE_TIME_ZONE_NAMETEXT = "SeTimeZonePrivilege";
        public const int ANYSIZE_ARRAY = 1;

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID {
            public UInt32 LowPart;
            public UInt32 HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES {
            public LUID Luid;
            public UInt32 Attributes;
        }

            public struct TOKEN_PRIVILEGES {
            public UInt32 PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=ANYSIZE_ARRAY)]
            public LUID_AND_ATTRIBUTES [] Privileges;
        }

        [DllImport("advapi32.dll", SetLastError=true)]
        public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetThreadToken(IntPtr PHThread, IntPtr Token);

        [DllImport("advapi32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
'@ -Name Impersonate -Namespace WinAPI

    $adjPriv = [WinAPI.Impersonate]
    [long]$luid = 0
    $tokPriv1Luid = New-Object WinAPI.Impersonate+TokPriv1Luid
    $tokPriv1Luid.Count = 1
    $tokPriv1Luid.Luid = $luid
    $tokPriv1Luid.Attr = [WinAPI.Impersonate]::SE_PRIVILEGE_ENABLED
    $adjPriv::LookupPrivilegeValue($null, 'SeDebugPrivilege', [ref]$tokPriv1Luid.Luid) | Out-Null


    [IntPtr]$hCurrentToken = [IntPtr]::Zero
    $pExplorer = @(Get-Process -Name explorer)[0]
    
    $adjPriv::OpenProcessToken($pExplorer.Handle, ([WinAPI.Impersonate]::TOKEN_IMPERSONATE -BOR 
        [WinAPI.Impersonate]::TOKEN_DUPLICATE), [ref]$hCurrentToken) | Out-Null

    [IntPtr]$hDuplicateToken = [IntPtr]::Zero
    $adjPriv::DuplicateToken($hCurrentToken, 2, [ref]$hDuplicateToken) | Out-Null

    $adjPriv::SetThreadToken([IntPtr]::Zero, $hDuplicateToken) | Out-Null

    & $ScriptBlock

    $adjPriv::SetThreadToken([IntPtr]::Zero, [IntPtr]::Zero) | Out-Null 
}

$aExceptions = @('explorer','system','taskmgr','csrss')

$code = {
    function Get-ProcessUserObjectCount {
        param([System.IntPtr] $pHandle, [string] $Log = $Log)
        [string] $MethodDefinition = '[DllImport("User32", ExactSpelling = true, CharSet = CharSet.Auto)] public static extern int GetGuiResources(IntPtr hProcess, int uiFlags);'
        if ($Kernel32 -eq $null) {
            $Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -Namespace 'Win32' -PassThru
        }
        Return $Kernel32::GetGuiResources($pHandle,1)
    }

    $aObjects = @()
    foreach ($oProcess in (Get-Process))
    {
        [string] $sName = $oProcess.Name
        if ($aExceptions.Contains($sName.ToLower()) -eq $false)
        {
            if ($oProcess.Handle -ne $null)
            {
                if ($oProcess.HandleCount -gt 100)
                {
                    [int] $UserObjectCount = Get-ProcessUserObjectCount -pHandle $oProcess.Handle
                    ('[Test-ProcessUserObjects] Name:' + $oProcess.Name + ', HandleCount:' + $oProcess.HandleCount.ToString() + ', UserObjectCount: ' + $UserObjectCount) >> '.\Clue2.log'
                    if ($UserObjectCount -gt 100)
                    {
			            $oObject = New-Object pscustomobject
			            Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'Name' -Value $([string] $oProcess.Name)
			            Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'UserObjectCount' -Value $([Int] $UserObjectCount)
                        Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'HandleCount' -Value $([Int] $oProcess.HandleCount)
                        Add-Member -InputObject $oObject -MemberType NoteProperty -Name 'Pid' -Value $([Int] $oProcess.Id)
                        $aObjects += @($oObject)
                    }
                }
            }
        }
    }

    if ($aObjects.Count -gt 0)
    {
        $TimeStamp = "$(Get-Date -format yyyyMMdd-HHmmss)"

        [xml] $xmlDoc = Get-Content -Path '.\config.xml'
        [string] $OutputDirectory = $xmlDoc.Configuration.OutputDirectory
        [string] $IncidentOutputFolder = $TimeStamp + '_' + $env:computername + '_Test-ProcessUserObjects'
        ('[Test-ProcessUserObjects] IncidentOutputFolder: ' + $IncidentOutputFolder)  >> '.\Clue2.log'
        $null = New-Item -Path $IncidentOutputFolder -ItemType Directory

        [string] $DataCollectionInProgressFilePath = $IncidentOutputFolder + '\_DATA_COLLECTION_IN_PROGRESS.txt'
        $null = New-Item -Path $DataCollectionInProgressFilePath -Type File
        foreach ($oObject in $aObjects)
        {
            ('[Test-ProcessUserObjects] Name: ' + $oObject.Name + ', Pid: ' + $oObject.Pid + ', HandleCount: ' + $oObject.HandleCount + ', UserObjects: ' + $oObject.UserObjectCount) >> '.\Clue2.log'
            [string] $sCmd = '.\sysint\procdump -ma -o -a -r ' + ($oObject.Pid) + ' ' + $IncidentOutputFolder + '\' + $TimeStamp + '-' + $oObject.Name + '-Pid' + $oObject.Pid + '-UserObjectCount' + $oObject.UserObjectCount + '.dmp -accepteula'
            $scmd >> '.\Clue2.log'
            #Invoke-MyCmd -Cmd $sCmd
        }
        Remove-Item -Path $DataCollectionInProgressFilePath -Force

        Start-Sleep -Seconds 14400 #// Wait for 4 hours before collecting again.
    }
}

Start-TruncateLog -FilePath $Log -Log $Log
[datetime] $dtLastLogTruncate = (Get-Date)

Do
{
    Run-Impersonated -ScriptBlock $code

    [int] $RandomMinutes = Get-Random -Minimum 100 -Maximum 200
    if ((New-TimeSpan -Start $dtLastLogTruncate -End (Get-Date)).TotalMinutes -gt $RandomMinutes)
    {
        Write-Log ('[Start-TruncateLog]') -Log $Log
        Start-TruncateLog -FilePath $Log -Log $Log
        [datetime] $dtLastLogTruncate = (Get-Date)
    }

    Start-Sleep -Seconds 60
} until ($true -eq $false)