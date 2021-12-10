
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

        [parameter()] 
        [switch] 
        $AnyHost = $false,

        [Parameter()]
        [System.Collections.IDictionary] 
        $QueryString
    )
    begin {
        if([string]::IsNullOrEmpty($Client.RedirectUri)) {
            throw "redirect_uri is not defined"
        }
        $local:metadata = Get-Metadata -Authority $Authority -ErrorAction Stop
        $local:listener = Start-HttpListener -Prefix (GetRootUrl $Client.RedirectUri) -RandomPort:$RandomPort -AnyHost:$AnyHost
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
        $local:code = $null
        $local:listener | Read-HttpRequest | % {
            Write-Verbose "Read-HttpRequest $($_.Uri)"
            if($_.Url.LocalPath -eq "/$id") {
                $_ | Write-HttpResponse -Location $local:authorizationRequest.Uri
            } elseif($_.Url.LocalPath -eq $redirect_uri.LocalPath) {
                $local:code = $_.QueryString.Get("code")
                $_ | Write-HttpResponse -Body $local:html -Stop 
            }
        }
        if($local:code) {
            [PSCustomObject]@{
                "PSTypeName" = "OAuth2.Code"
                "Credential" = [pscredential]::new("code", (ConvertTo-SecureString -AsPlainText -Force -String $local:code)).GetNetworkCredential()
                "RedirectUri" = $local:redirect_uri
            }                
        }
    }
    end {
        $local:listener | Stop-HttpListener
    }
}

Export-ModuleMember -Function "*"
