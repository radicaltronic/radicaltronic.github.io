[CmdletBinding(SupportsShouldProcess=$true)]
param ()
    $email = "radicaltronic@gmail.com"
    $recipients = "radicaltronic@gmail.com,guillaumeplante.qc@gmail.com"
    $pass = "SecretTEst23_"

    $EmailFrom = "radicaltronic@gmail.com"
    $EmailTo = "guillaumeplante.qc@gmail.com"
    $Subject = (Get-Variable -Name MailSubject -Scope Global).Value
    $Body = (Get-Variable -Name MailBody -Scope Global).Value
    $SMTPServer = "smtp.gmail.com"
    $SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer, 587)
    $SMTPClient.EnableSsl = $true
    $SMTPClient.Credentials = New-Object System.Net.NetworkCredential($email, $pass);
    $SMTPClient.Send($EmailFrom, $EmailTo, $Subject, $Body)
