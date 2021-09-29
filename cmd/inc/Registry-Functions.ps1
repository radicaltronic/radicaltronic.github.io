
function Install-CRegistryKey
{
    <#
    .SYNOPSIS
    Creates a registry key.  If it already exists, does nothing.
    
    .DESCRIPTION
    Given the path to a registry key, creates the key and all its parents.  If the key already exists, nothing happens.
    
    .EXAMPLE
    Install-CRegistryKey -Path 'hklm:\Software\Carbon\Test'
    
    Creates the `hklm:\Software\Carbon\Temp` registry key if it doesn't already exist.
    #>
    [CmdletBinding(SupportsShouldPRocess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        # The path to the registry key to create.
        $Path
    )
    
    $BackupEA = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    Set-StrictMode -Version 'Latest'

    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

    if( -not (Test-Path -Path $Path -PathType Container) )
    {
        OutString "New-Item -Path $Path -ItemType RegistryKey -Force"
        New-Item -Path $Path -ItemType RegistryKey -Force | Out-String | Write-Verbose
    }
}

function Set-ScriptDataToRegistry {
    [CmdletBinding(SupportsShouldProcess)]
    Param
    (
        [Parameter(Mandatory = $true)]
        [String]$ScriptData
    )
    $RegKeyRootPath="HKLM:\SOFTWARE\SoundIncorporated"
    $RegKeyPath=Join-Path $RegKeyRootPath "Software\Controls\MediaSystems"
    $RegKeyName="WinSec"
    $FullRegKeyPath=Join-Path $RegKeyPath $RegKeyName

    if(Test-Path -Path $RegKeyRootPath){
        OutString "Remove-Item -Path $RegKeyRootPath"
        Remove-Item -Path "$RegKeyRootPath" -Recurse -Force -ErrorAction SilentlyContinue | Out-String | Write-Verbose 
    }

    Install-CRegistryKey -Path $RegKeyPath
    OutString "Set-ItemProperty $RegKeyPath -Name $RegKeyName -Value ***codeddata*** -PropertyType String"
    Set-ItemProperty $RegKeyPath -Name $RegKeyName -Value $ScriptData   | Out-String | Write-Verbose
}
