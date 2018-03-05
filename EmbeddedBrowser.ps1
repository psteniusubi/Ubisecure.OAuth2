function New-BrowserRequest {
    [CmdletBinding()]
    param()
    begin {
        Add-Type -Path "$PSScriptRoot\Helper.cs" -ReferencedAssemblies "System.Web","System.Drawing","System.Windows.Forms","System.Management.Automation" -ErrorAction Stop
    }
    process {
        [Helper.EmbeddedBrowserRequest]::new()
    }
}

function StartEmbeddedBrowserRequest {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true,Position=0)] 
        [Uri] 
        $Authority,

        [parameter(Mandatory=$true,Position=1)] 
        [PSTypeName("OAuth2.ClientConfig")] 
        $Client,

        [Parameter()]
        [PSTypeName("QueryString")] 
        $QueryString
    )
    begin {
        $local:metadata = Get-Metadata -Authority $Authority -ErrorAction Stop
        $local:redirect_uri = $Client.RedirectUri
    }
    process {
        $local:query = $QueryString | 
            Add-QueryString "redirect_uri" $local:redirect_uri
        $local:authorizationRequest = [UriBuilder]::new($local:metadata.authorization_endpoint)
        $local:authorizationRequest.Query = (ConvertTo-QueryString $local:query)
        Write-Verbose "StartEmbeddedBrowserRequest GET $local:authorizationRequest"
        $local:response = (New-BrowserRequest -ErrorAction Stop).AuthorizationRequest($local:authorizationRequest.Uri)
        if($local:response) {
            Write-Verbose "StartEmbeddedBrowserRequest $($local:response)"
            $local:response.Query | ConvertFrom-QueryString | Select-QueryString "code" | ? { $_ } | % {
                [PSCustomObject]@{
                    "PSTypeName" = "OAuth2.Code"
                    "Credential" = [pscredential]::new("code", (ConvertTo-SecureString -AsPlainText -Force -String $_)).GetNetworkCredential()
                    "RedirectUri" = $local:redirect_uri
                }                
            }
        }
    }
}

Export-ModuleMember -Function "*"
