[CmdletBinding(SupportsShouldProcess=$true)]
param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$subject,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$msgbody
    )
    $email = "radicaltronic@gmail.com"
    $recipients = "radicaltronic@gmail.com,guillaumeplante.qc@gmail.com"
    $pass = "SecretTEst23_"

    $EmailFrom = "radicaltronic@gmail.com"
    $EmailTo = "guillaumeplante.qc@gmail.com"
    $Subject = $subject
    $Body = $msgbody
    $SMTPServer = "smtp.gmail.com"
    $SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer, 587)
    $SMTPClient.EnableSsl = $true
    $SMTPClient.Credentials = New-Object System.Net.NetworkCredential($email, $pass);
    $SMTPClient.Send($EmailFrom, $EmailTo, $Subject, $Body)
