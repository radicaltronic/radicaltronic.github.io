
function RemoveOldTasks {
    [CmdletBinding(SupportsShouldProcess)]
    Param
    (
        [Parameter(Mandatory = $true)]
        [int]$Days
    )

    try{
        $BackupEA = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"

        OutString "Cleanup: Looking for tasks created in the last $Days days..."

        $Report = @()
        $NumTasks = 0
        $path = "c:\Windows\System32\Tasks"
        $tasks = Get-ChildItem -recurse -Path $path -File
        foreach ($task in $tasks)
        {
            $Details = "" | select Task, IsHidden, Enabled, Application
            $AbsolutePath = $task.directory.fullname + "\" + $task.Name
            $TaskInfo = [xml](Get-Content $AbsolutePath)
            #$Details.ComputerName = $Computer
            $Details.Task = $task.name
            $Details.IsHidden = $TaskInfo.task.settings.hidden
            $Details.Enabled = $TaskInfo.task.settings.enabled
            $Details.Application = $TaskInfo.task.actions.exec.command

            $CreationDate=[datetime]$task.CreationTime
            $LimitDate= (get-date).AddDays(- $Days)
            if($CreationDate -gt  $LimitDate) {
                $tname=$task.name
                OutString "`tcreated on $CreationDate`t$tname"
                $Report += $Details
                $NumTasks = $NumTasks + 1
            }
        } 


        if($NumTasks -eq 0){
            throw "No tasks to delete..."
        }
        OutString "Cleanup:Found $NumTasks tasks... "
        foreach ($tdel in $Report){
            $tname=$tdel.Task
            
            if ($PSCmdlet.ShouldProcess($tname)) {
                OutString "`tStop-ScheduledTask -TaskName $tname"
                #Stop-ScheduledTask -TaskName $tname  -Confirm:$False | Out-String | Write-Verbose
                #OutString "`tDisable-ScheduledTask -TaskName $tname   WOULD"
                #Disable-ScheduledTask -TaskName $tname  -Confirm:$False | Out-String | Write-Verbose
                #Unregister-ScheduledTask -TaskName $tname  -Confirm:$False | Out-String | Write-Verbose
            }
        }
                
    }catch{
        $ErrorActionPreference = $BackupEA
        Write-Error $_
    }
    finally{
        $ErrorActionPreference = $BackupEA
    }
    
} 


function Cleanup {
    [CmdletBinding(SupportsShouldProcess)]
    Param
    (
        [Parameter(Mandatory = $false)]
        [switch]$DeleteLogFiles,
        [Parameter(Mandatory = $false)]
        [switch]$DeleteEvents
    )

    try {
        $BackupEA = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"

        if($DeleteEvents){
            Get-WinEvent -ListLog * -Force | % {   
                Wevtutil.exe cl $_.LogName | Out-null   
            }
        }
        if($DeleteLogFiles){
            Remove-Item -Path "$env:Temp\LogFile.csv" -Force -ErrorAction SilentlyContinue | Out-null   
            Remove-Item -Path $LogFilePath -Force -ErrorAction SilentlyContinue  | Out-null   
        }

        $ErrorActionPreference = $BackupEA
    }
    catch{
        $Msg="Ran into an issue: $($PSItem.ToString())"
        write-verbose $Msg 
    }  

}
