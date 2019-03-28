# PowerShell OAuth 2.0 Client for Ubisecure SSO

Depends on [Ubisecure.QueryString](../../../Ubisecure.QueryString), [Ubisecure.HttpListener](../../../Ubisecure.HttpListener)

Used by [Ubisecure.SSO.Management](../../../Ubisecure.SSO.Management)

## Example

```powershell
$config = New-OAuthClientConfig -ClientId "public" -ClientSecret (ConvertTo-SecureString -String "public" -AsPlainText -Force) -RedirectUri "http://localhost/public"

$code = Get-OAuthAuthorizationCode -Client $config -Authority "https://login.example.ubidemo.com/uas" -Browser "default"

$token = Get-OAuthAccessToken -Client $config -Authority "https://login.example.ubidemo.com/uas" -Code $code

Get-OAuthUserInfo -Authority "https://login.example.ubidemo.com/uas" -Bearer $token
```
