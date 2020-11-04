#
# .\code-flow.ps1 ..\..\..\example.ubidemo.com\daily\public-client.json
#
[CmdletBinding()]
param(
    [parameter()]
    [string]
    $Authority = "https://login.example.ubidemo.com/uas",

    [parameter(Mandatory=$true,Position=0)]
    [string]
    $Path,

    [parameter()]
    [string]
    $Browser = "default"
)
begin {
    Push-Location $PSScriptRoot
    Import-Module (Split-Path $PSScriptRoot -Parent -Resolve -ErrorAction Stop) -Force -ErrorAction Stop
}
process {
    $Client = New-OAuthClientConfig -Path $Path
    $Code = Get-OAuthAuthorizationCode -Client $Client -Authority $Authority -Browser $Browser -ForceAuthn:$false
    $Bearer = Get-OAuthAccessToken -Client $Client -Authority $Authority -Code $Code 
    Get-OAuthUserInfo -Authority $Authority -Bearer $Bearer | Out-Host
    Get-OAuthTokenInfo -Client $Client -Authority $Authority -Bearer $Bearer | Out-Host
}
end {
    Pop-Location
}
