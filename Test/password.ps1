# 
# .\password.ps1 ..\..\..\example.ubidemo.com\sso-api.json -Credential (..\..\..\example.ubidemo.com\get-credential.ps1)
#
[CmdletBinding()]
param(
    [parameter()]
    [string]
    $Authority = "https://login.example.ubidemo.com/uas",

    [parameter(Mandatory=$true,Position=0)]
    [string]
    $Path,

    [parameter(Mandatory=$true)]
    [pscredential]
    $Credential
)
begin {
    Push-Location $PSScriptRoot
    Import-Module (Split-Path $PSScriptRoot -Parent -Resolve -ErrorAction Stop) -Force -ErrorAction Stop
}
process {
    $Client = New-OAuthClientConfig -Path $Path
    $Bearer = Get-OAuthAccessToken -Client $Client -Authority $Authority -Credential $Credential
    Get-OAuthUserInfo -Authority $Authority -Bearer $Bearer | Out-Host
    Get-OAuthTokenInfo -Client $Client -Authority $Authority -Bearer $Bearer | Out-Host
}
end {
    Pop-Location
}
