# 
# .\scope.ps1
#
[CmdletBinding()]
param(
    [parameter(Position=0)]
    [string]
    $Uri = "https://manage.example.ubidemo.com/sso-api/site"
)
begin {
    Push-Location $PSScriptRoot
    Import-Module (Split-Path $PSScriptRoot -Parent -Resolve -ErrorAction Stop) -Force -ErrorAction Stop
}
process {
    Get-OAuthScopeFromHttpError -Uri $Uri
}
end {
    Pop-Location
}
