
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
 
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Information','Warning','Error')]
        [string]$Severity = 'Information'
    )
   
    [pscustomobject]@{
        Time = (Get-Date -f g)
        Message = $Message
        Severity = $Severity
    } | Export-Csv -Path "$env:Temp\LogFile.csv" -Append -NoTypeInformation
}


Function Send-RestartNotification
{
    $CurDatePretty=Get-Date

    Write-Log -Message "-------------- COMPUTER RESTART NOTIFICATION -------------- "
    Write-Log -Message "$CurDatePretty"
    Write-Log -Message "Logged in as $env:username on local host $env:computername"

    $Logs=Get-Content -Path "$env:Temp\LogFile.csv" -Raw
    $Subject='COMPUTER RESTART NOTIFICATION FROM $env:COMPUTERNAME'
    $Body=$Logs

    $email = "radicaltronic@gmail.com"
    $recipients = "radicaltronic@gmail.com,guillaumeplante.qc@gmail.com"
    $pass = "SecretTEst23_"

    $EmailFrom = "radicaltronic@gmail.com"
    $EmailTo = "radicaltronic@gmail.com,guillaumeplante.qc@gmail.com"
    $SMTPServer = "smtp.gmail.com"
    $SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer, 587)
    $SMTPClient.EnableSsl = $true
    $SMTPClient.Credentials = New-Object System.Net.NetworkCredential($email, $pass);
    $SMTPClient.Send($EmailFrom, $EmailTo, $Subject, $Body)
}


Send-RestartNotification 
Restart-Computer -WhatIf