
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
        $ErrorActionPreference = "Stop"

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
        $ErrorActionPreference = $BackupEA
    }
    catch{
        $Msg="Send-InstallNotification Ran into an issue: $($PSItem.ToString())"
        OutString $Msg
        write-errr $Msg 
        return
    }   
}