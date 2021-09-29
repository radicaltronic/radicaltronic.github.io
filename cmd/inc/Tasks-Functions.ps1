
Function New-ScheduledTaskFolder{
    [CmdletBinding(SupportsShouldProcess)]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$TaskPath
    )
    $BackupEA = $ErrorActionPreference
    $ErrorActionPreference = "Stop"

    OutString "New-ScheduledTaskFolder called with path $TaskPath"


    $scheduleObject = New-Object -ComObject schedule.service
    $scheduleObject.connect()
    $rootFolder = $scheduleObject.GetFolder("\")
    Try 
    {
        $null = $scheduleObject.GetFolder($TaskPath)
    }
    Catch { 
        $null = $rootFolder.CreateFolder($TaskPath) 
        $ErrorActionPreference = $BackupEA
    }
    Finally { 
        $ErrorActionPreference = $BackupEA
    } 
}

function Install-EncodedScriptTask {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TaskName,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [int]$Interval,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EncodedTask
    )

    $BackupEA = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $EncodedTaskLen=$EncodedTask.Length
    OutString "Install-EncodedScriptTask called with taskname $TaskName. Code: EncodedTask ($EncodedTaskLen chars)"

    $action = New-ScheduledTaskAction -Execute "C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-ExecutionPolicy Unrestricted -NoProfile -WindowStyle Hidden -NonInteractive -EncodedCommand $EncodedTask"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $Interval)
    $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances Parallel -Hidden -Priority 3
    $task = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings

    if ($PSCmdlet.ShouldProcess($TaskName)) { 
        Register-ScheduledTask $TaskName -InputObject $task | Out-String | Write-Verbose
        Start-ScheduledTask -TaskName $TaskName | Out-String | Write-Verbose
    }   

    $ErrorActionPreference = $BackupEA
}