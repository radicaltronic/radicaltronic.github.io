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




Function Send-Notification {
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
$Start=Get-Date
OutString "cllogs.ps1: CEARING LOGS. Started on $Start"
Cleanup -DeleteEvents

$End=Get-Date
$Diff=$End-$Start
$Min=$Diff.Minutes
$Sec=$Diff.Seconds
OutString "cllogs.ps1: CEARING LOGS. Ended on $End."

OutString "cllogs.ps1: Took a total of $Min minutes and $Sec seconds."
$EnableLogs=$false
$TempFile="$env:Temp\att.txt"
Copy-Item "$LogFilePath" "$TempFile"

OutString "Send-Notification"
Send-Notification "CLear Logs Notice for $env:COMPUTERNAME" " Took a total of $Min minutes and $Sec seconds." "$TempFile"