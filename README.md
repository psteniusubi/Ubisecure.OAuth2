# PowerShell OAuth 2.0 Client for Ubisecure SSO

Depends on [Ubisecure.QueryString](../../../Ubisecure.QueryString), [Ubisecure.HttpListener](../../../Ubisecure.HttpListener)

Used by [Ubisecure.SSO.Management](../../../Ubisecure.SSO.Management)

## Install from gituhub.com

Windows

```cmd
cd /d %USERPROFILE%\Documents\WindowsPowerShell\Modules
git clone https://github.com/psteniusubi/Ubisecure.OAuth2.git
```

Linux

```bash
cd ~/.local/share/powershell/Modules
git clone https://github.com/psteniusubi/Ubisecure.OAuth2.git
```

## Example

```powershell
$client = New-OAuthClientConfig -Json @"
{
    "redirect_uris":  [
                          "http://localhost/public"
                      ],
    "grant_types":  [
                        "authorization_code"
                    ],
    "client_id":  "public",
    "client_secret":  "public"
}
"@

$code = Get-OAuthAuthorizationCode -Client $client -Authority "https://login.example.ubidemo.com/uas" -Browser "default"

$token = Get-OAuthAccessToken -Client $client -Authority "https://login.example.ubidemo.com/uas" -Code $code

Get-OAuthUserInfo -Authority "https://login.example.ubidemo.com/uas" -Bearer $token
```
