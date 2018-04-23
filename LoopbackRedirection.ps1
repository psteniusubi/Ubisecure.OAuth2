
function GetRootUrl {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)] 
        [uri] 
        $Url
    )
    process {
        $Url | % {
            $local:t = [UriBuilder]::new($_)
            $local:t.Path = "/"
            $local:t.Query = $null
            $local:t.Uri
        }
    }
}

function SetUrlPort {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true)] 
        [uri] 
        $Url,

        [Parameter(Position=1)] 
        [int] 
        $Port
    )
    process {
        $Url | % {
            $local:t = [UriBuilder]::new($_)
            $local:t.Port = $Port
            $local:t.Uri
        }
    }
}

function StartLoopbackRedirectionRequest {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true,Position=0)] 
        [uri] 
        $Authority,

        [parameter(Mandatory=$true,Position=1)] 
        [PSTypeName("OAuth2.ClientConfig")] 
        $Client,

        [parameter()] 
        [string] 
        $Browser = "default",

        [parameter()] 
        [switch] 
        $Private,

        [parameter()] 
        [switch] 
        $RandomPort = $true,

        [Parameter()]
        [PSTypeName("QueryString")] 
        $QueryString
    )
    begin {
        if([string]::IsNullOrEmpty($Client.RedirectUri)) {
            throw "redirect_uri is not defined"
        }
        $local:metadata = Get-Metadata -Authority $Authority -ErrorAction Stop
        $local:listener = Start-HttpListener -Prefix (GetRootUrl $Client.RedirectUri) -RandomPort:$RandomPort
        $local:redirect_uri = SetUrlPort -Url $Client.RedirectUri -Port $local:listener.Prefix.Port
        $local:id = [Guid]::NewGuid()
        $local:html = @"
<body onload="window.close()">
<p>The operation was completed.</p>
<p><input type="button" onclick="window.close()" value="Close"></input></p>
</body>
"@;
    }
    process {
        $local:query = $QueryString | 
            Add-QueryString "redirect_uri" $local:redirect_uri
        $local:authorizationRequest = [UriBuilder]::new($local:metadata.authorization_endpoint)
        $local:authorizationRequest.Query = (ConvertTo-QueryString $local:query)
        Write-Verbose "StartLoopbackRedirectionRequest GET $local:authorizationRequest"
        Start-Browser -Uri "$($local:listener.Prefix)$id" -Name $Browser -Private:$Private
        $local:response = $local:listener | Read-HttpRequest | % {
            Write-Verbose "Read-HttpRequest $($_.Uri)"
            if($_.Url.LocalPath -eq "/$id") {
                $_ | Write-HttpResponse -Location $local:authorizationRequest.Uri
            } elseif($_.Url.LocalPath -eq $redirect_uri.LocalPath) {
                $_ | Write-HttpResponse -Body $local:html -Stop -PassThru
            }
        }
        if($local:response) {
            $local:response | % { $_.QueryString.Get("code") } | ? { $_ } | % {
                [PSCustomObject]@{
                    "PSTypeName" = "OAuth2.Code"
                    "Credential" = [pscredential]::new("code", (ConvertTo-SecureString -AsPlainText -Force -String $_)).GetNetworkCredential()
                    "RedirectUri" = $local:redirect_uri
                }                
            }
        }
    }
    end {
        $local:listener | Stop-HttpListener
    }
}

Export-ModuleMember -Function "*"
