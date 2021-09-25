[CmdletBinding(SupportsShouldProcess=$true)]
param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$path
    )
  trap { "Decryption failed"; break }
  $raw = Get-Content $path
  $secure = ConvertTo-SecureString $raw
  $helper = New-Object system.Management.Automation.PSCredential("test", $secure)
  $plain = $helper.GetNetworkCredential().Password
  Invoke-Expression $plain
