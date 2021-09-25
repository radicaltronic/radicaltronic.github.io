[CmdletBinding(SupportsShouldProcess=$true)]
param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$path,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$destination
    )

  $script = Get-Content $path | Out-String
  $secure = ConvertTo-SecureString $script -asPlainText -force
  $export = $secure | ConvertFrom-SecureString
  Set-Content $destination $export
  "Script '$path' has been encrypted as '$destination'"

