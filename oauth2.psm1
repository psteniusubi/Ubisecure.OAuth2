Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath "querystring/querystring.psd1") -Scope Local

function Get-ModulePath {
    [CmdletBinding(DefaultParameterSetName="Self")]
    param(
        [parameter(ValueFromPipeline=$true,Position=0,Mandatory=$true,ParameterSetName="Child")] 
        [string] 
        $ChildPath
    )
    process {
        if($PSCmdlet.ParameterSetName -eq "Self") {
            $PSScriptRoot
        } else {
            $ChildPath | % {
                Join-Path -Path $PSScriptRoot -ChildPath $_
            }
        }
    }
}

function Get-ClientConfigPath {
    [CmdletBinding(DefaultParameterSetName="Name")]
    param(
        [parameter(ValueFromPipeline=$true,ParameterSetName="Name",Position=0)] 
        [string] 
        $Name,

        [parameter(ParameterSetName="Root",Position=0)] 
        [switch] 
        $Root
    )
    begin {
        $local:r = Join-Path -Path $HOME -ChildPath ".oauth2"
        Write-Verbose "Get-ClientConfigPath -Root = $local:r"
    }
    process {
        if($Root) {
            $local:r
        } else {
            $Name | % { Join-Path -Path $local:r -ChildPath $_ }
        }
    }
}

function SelectRedirectUri {
    [CmdletBinding()]
    [OutputType([uri])]
    param(
        [parameter(Mandatory=$false,ValueFromPipeline=$true,Position=0)] 
        [uri[]] 
        $InputObject
    )
    begin {
        $local:first = $null
        $local:loopback = $null
    }
    process {
        $InputObject | % {
            if(-not ($local:first)) {
                $local:first = $_
            }
            if($_.IsLoopback) {
                if(-not ($local:loopback)) {
                    $local:loopback = $_
                }
            }
        }
    }
    end {
        if($local:loopback) {
            $local:loopback
        } elseif($local:first) {
            $local:first
        }
    }
}

function New-ClientConfig {
    [CmdletBinding(DefaultParameterSetName="Path")]
    param(
        [parameter(Mandatory=$true,ParameterSetName="Name")] 
        [string] 
        $Name,

        [parameter(Mandatory=$true,ParameterSetName="Path",ValueFromPipeline=$true)] 
        [Alias("File")]
        [string] 
        $Path,

        [parameter(Mandatory=$true,ParameterSetName="Json")] 
        [string] 
        $Json,

        [parameter(Mandatory=$true,ParameterSetName="Credential",Position=0)]
        [System.Net.NetworkCredential] 
        $Credential,

        [parameter(Mandatory=$true,ParameterSetName="ClientId",Position=0)]
        [string] 
        $ClientId,

        [parameter(Mandatory=$true,ParameterSetName="ClientId",Position=1)]
        [securestring] 
        $ClientSecret,

        [parameter(Mandatory=$true,ParameterSetName="Credential",Position=1)] 
        [parameter(Mandatory=$true,ParameterSetName="ClientId",Position=2)]
        [AllowNull()] 
        [AllowEmptyString()] 
        [string] 
        $RedirectUri
    )
    process {
        switch ($PsCmdlet.ParameterSetName) {
            "Name" {
                $Name | Get-ClientConfigPath | New-ClientConfig
            }
            "Path" {
                $Path | 
                % {
                    Write-Verbose "Get-Content $_"
                    $local:t = [string] (Get-Content -Path $_ -ErrorAction Stop | Out-String)
                    if($local:t) {
                        New-ClientConfig -Json $t
                    }
                }
            }
            "Json" {
                Write-Verbose "ConvertFrom-Json $Json"
                ConvertFrom-Json -InputObject $Json |
                % {
                    if(-not $_.client_id) { Write-Error -Message "client_id is not defined" -Category InvalidArgument; return }
                    if(-not $_.client_secret) { Write-Error -Message "client_secret is not defined" -Category InvalidArgument; return }
                    $local:t = New-ClientConfig -ClientId $_.client_id `
                        -ClientSecret (ConvertTo-SecureString -AsPlainText -Force -String $_.client_secret) `
                        -RedirectUri ($_.redirect_uris | SelectRedirectUri)
                    $local:t | Add-Member -MemberType NoteProperty -Name "Json" -Value $_ -PassThru
                }
            }
            "ClientId" {
                New-ClientConfig -Credential ([pscredential]::new($ClientId, $ClientSecret).GetNetworkCredential()) -RedirectUri $RedirectUri
            }
            "Credential" {
                [PSCustomObject]@{
                    "PSTypeName" = "OAuth2.ClientConfig";
                    "Credential" = $Credential;
                    "RedirectUri" = [string] $RedirectUri;
                }
            }
        }
    }
}

$global:metadatacache = @{}

function Get-Metadata {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)] 
        [Uri] 
        $Authority,

        [parameter(Mandatory=$false)] 
        [switch] 
        $Force,

        [parameter(Mandatory=$false)] 
        [string] 
        $Path = ".well-known/openid-configuration"
    )
    process {
        $Authority | 
        % {
            if(-not $Force -and $global:metadatacache.ContainsKey($Authority)) {
                Write-Verbose "Get-Metadata CACHE $Authority"
                return $global:metadatacache[$Authority]
            }
            $local:t = [uribuilder]::new($Authority)
            if(-not $local:t.Path.EndsWith("/")) {
                $local:t.Path += "/"
            }
            $local:t.Path += $Path
            $local:uri = $local:t.Uri
            Write-Verbose "Get-Metadata GET $local:uri"
            $local:metadata = Invoke-RestMethod -Method Get -Uri $local:uri -UseBasicParsing
            if($local:metadata) {
                $global:metadatacache[$Authority] = $local:metadata
                return $local:metadata
            } else {
                Write-Error "cannot find metadata for $Authority"
            }
        }
    }
}

function Add-Metadata {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true,Position=0)] 
        [Alias("issuer")]
        [Uri] 
        $Authority,

        [parameter(Mandatory=$true,Position=1,ParameterSetName="Value")] 
        [object] 
        $Value,

        [parameter(Mandatory=$true,ParameterSetName="Endpoint")] 
        [Alias("token_endpoint")]
        [uri] 
        $TokenEndpoint,

        [parameter(Mandatory=$false,ParameterSetName="Endpoint")] 
        [Alias("authorization_endpoint")]
        [uri] 
        $AuthorizationEndpoint,

        [parameter(Mandatory=$false,ParameterSetName="Endpoint")] 
        [Alias("userinfo_endpoint")]
        [uri] 
        $UserInfoEndpoint
    )
    process {
        switch ($PsCmdlet.ParameterSetName) {
            "Value" {
                $global:metadatacache[$Authority] = $Value
            }
            "Endpoint" {
                Add-Metadata -Authority $Authority -Value ([PSCustomObject] @{
                    "issuer" = $Authority
                    "token_endpoint" = $TokenEndpoint
                    "authorization_endpoint" = $AuthorizationEndpoint
                    "userinfo_endpoint" = $UserInfoEndpoint
                })
            }
        }
    }
}

function Get-ScopeFromHttpError {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true,ParameterSetName="Uri")] 
        [uri] 
        $Uri,

        [parameter(Mandatory=$true,ParameterSetName="Error",ValueFromPipeline=$true)] 
        [Alias("Error")] 
        [System.Net.WebException] 
        $Exception,

        [parameter(Mandatory=$true,ParameterSetName="Value",ValueFromPipeline=$true)] 
        [string] 
        $Value
    )
    begin {
        Add-Type -AssemblyName "System.Net.Http"
    }
    process {
        switch ($PsCmdlet.ParameterSetName) {
            "Uri" {
                Write-Verbose "Get-ScopeFromHttpError GET $Uri"
                try {
                    Invoke-RestMethod -Method Get -Uri $Uri -UseBasicParsing
                } catch {
                    if(-not $_.Exception.Response) { 
                        Write-Error -Message "no response from $Uri" -Category ConnectionError
                        return 
                    }
                    if($_.Exception.Response.StatusCode -ne "Unauthorized") {
                        Write-Error -Message "unexpected status $($local:r.StatusCode) from $Uri" -Category ProtocolError
                        return
                    }
                    $local:r = $_.Exception.Response.Headers.GetValues("WWW-Authenticate") | % { Get-ScopeFromHttpError -Value $_ }
                    if($local:r) { return $local:r }
                    Write-Error -Message "no WWW-Authenticate header from $Uri" -Category ProtocolError
                }
            }
            "Exception" {
                if($Exception.Status -ne "ProtocolError") { 
                    Write-Error -Message "unexpected status $($Exception.Status)" -Category ProtocolError
                    return 
                }
                $Exception | 
                % { $_.Response } |
                % { $_.GetResponseHeader("WWW-Authenticate") } |
                % { Get-ScopeFromHttpError -Value $_ }
            }
            "Value" {
                Write-Debug "Get-ScopeFromHttpError $Value"
                $Value | 
                ? { $_ -match "(^|\s)scope=`"([^`"]+)`"($|\s)" } |
                % { $Matches[2] }
            }
        }
    }
}

function Get-AuthorizationCode {
    [CmdletBinding(DefaultParameterSetName="Browser")]
    param(
        [parameter(Mandatory=$true,Position=0)] 
        [Uri] 
        $Authority,

        [parameter(Mandatory=$true,Position=1)] 
        [PSTypeName("OAuth2.ClientConfig")] 
        $Client,

        [parameter(Mandatory=$false,ParameterSetName="EmbeddedBrowser")] 
        [switch] 
        $EmbeddedBrowser,

        [parameter(Mandatory=$false,ParameterSetName="Browser")] 
        [string] 
        $Browser = "default",

        [parameter(Mandatory=$false,ParameterSetName="Browser")] 
        [switch] 
        $Private,

        [parameter(Mandatory=$false,ParameterSetName="Browser")] 
        [switch] 
        $RandomPort = $true,

        [parameter(Mandatory=$false)] 
        [string] 
        $Scope = "openid",

        [parameter(Mandatory=$false)] 
        [switch] 
        $ForceAuthn = $true,

        [parameter(Mandatory=$false)] 
        [AllowNull()] 
        [string] 
        $Username,

        [parameter(Mandatory=$false)] 
        [hashtable] 
        $Parameters
    )
    begin {
        $local:metadata = Get-Metadata -Authority $Authority -ErrorAction Stop
    }
    process {
        $local:query = New-QueryString |
            Add-QueryString "response_type" "code" |
            Add-QueryString "client_id" $Client.Credential.UserName |
            Add-QueryString "scope" $Scope
        if($ForceAuthn) {
            $local:query = $local:query |
                Add-QueryString "max_age" "0" 
                #|
                #Add-QueryString "prompt" "login"
        }
        if($Username) {
            $local:query = $local:query | Add-QueryString "login_hint" $Username
        }
        if($Parameters) {
            $local:query = $local:query | Add-QueryString -Values $Parameters
        }
        if($EmbeddedBrowser) {
            StartEmbeddedBrowserRequest -Authority $Authority -Client $Client -QueryString $local:query
        } else {
            StartLoopbackRedirectionRequest -Authority $Authority -Client $Client -Browser $Browser -Private:$Private -RandomPort:$RandomPort -QueryString $local:query
        }
    }
}

function Get-AccessToken {
    [CmdletBinding(DefaultParameterSetName="Code")]
    param(
        [parameter(Mandatory=$true,Position=0)] 
        [Uri] 
        $Authority,

        [parameter(Mandatory=$true,Position=1)] 
        [PSTypeName("OAuth2.ClientConfig")] 
        $Client,

        [parameter(Mandatory=$true,ParameterSetName="Credential")] 
        [pscredential] 
        $Credential,

        [parameter(Mandatory=$true,ParameterSetName="Code")] 
        [PSTypeName("OAuth2.Code")] 
        $Code,

        [parameter(Mandatory=$true,ParameterSetName="RefreshToken")] 
        [System.Net.NetworkCredential] 
        $RefreshToken,

        [parameter(Mandatory=$false,ParameterSetName="Credential")] 
        [parameter(Mandatory=$false,ParameterSetName="RefreshToken")] 
        [string] 
        $Scope = "openid",

        [parameter(Mandatory=$true,ParameterSetName="Body")] 
        [hashtable] 
        $Body,

        [parameter(Mandatory=$false)] 
        [switch] 
        $HttpBasic = $true,

        [parameter(Mandatory=$false)] 
        [ref] 
        $RefreshTokenOut,

        [parameter(Mandatory=$false)] 
        [ref] 
        $ResponseOut
    )
    process {
        $local:metadata = Get-Metadata -Authority $Authority -ErrorAction Stop
        $local:headers = @{"Accept"="application/json"}
        $local:tokenrequest = New-QueryString
        if($HttpBasic) {
            $local:headers += ($Client.Credential | ConvertTo-HttpBasic | ConvertTo-HttpAuthorization)
        } else {
            $local:tokenrequest = $local:tokenrequest |
                Add-QueryString "client_id" $Client.Credential.UserName |
                Add-QueryString "client_secret" $Client.Credential.Password
        }
        switch ($PsCmdlet.ParameterSetName) {
            "Credential" {
                $local:nc = $Credential.GetNetworkCredential()
                $local:tokenrequest = $local:tokenrequest | 
                    Add-QueryString "grant_type" "password" |
                    Add-QueryString "scope" $Scope |
                    Add-QueryString "username" $local:nc.UserName |
                    Add-QueryString "password" $local:nc.Password |
                    ConvertTo-QueryString
            }
            "Code" {
                $local:tokenrequest = $local:tokenrequest | 
                    Add-QueryString "grant_type" "authorization_code" |
                    Add-QueryString "redirect_uri" $Code.RedirectUri |
                    Add-QueryString "code" $Code.Credential.Password |
                    ConvertTo-QueryString
            }
            "RefreshToken" {
                $local:tokenrequest = $local:tokenrequest | 
                    Add-QueryString "grant_type" "refresh_token" |
                    Add-QueryString "scope" $Scope |
                    Add-QueryString "refresh_token" $local:RefreshToken.Password |
                    ConvertTo-QueryString
            }
            "Body" {
                $local:tokenrequest = $local:tokenrequest | 
                    Add-QueryString -Values $Body |
                    ConvertTo-QueryString
            }
        }
        $local:uri = $local:metadata.token_endpoint
        Write-Verbose "Get-AccessToken POST $local:uri $local:tokenrequest"
        $local:tokenresponse = Invoke-RestMethod -Method Post -Uri $local:uri -Headers $local:headers -Body $local:tokenrequest -ContentType "application/x-www-form-urlencoded" -UseBasicParsing
        if($local:tokenresponse) {
            Write-Debug ($local:tokenresponse | ConvertTo-Json -Depth 8)
        }
        if($ResponseOut) {
            $ResponseOut.Value = $local:tokenresponse
        }
        if($local:tokenresponse -and $local:tokenresponse.access_token) {
            if($RefreshTokenOut) {
                if($local:tokenresponse.refresh_token) {
                    $local:t = [pscredential]::new("RefreshToken", (ConvertTo-SecureString -AsPlainText -Force -String $local:tokenresponse.refresh_token)).GetNetworkCredential()
                    $RefreshTokenOut.Value = $local:t
                } else {
                    $RefreshTokenOut.Value = $null
                }
            }
            [pscredential]::new("Bearer", (ConvertTo-SecureString -AsPlainText -Force -String $local:tokenresponse.access_token)).GetNetworkCredential()
        }
    }
}

function Get-UserInfo {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true,Position=0)] 
        [Uri] 
        $Authority,

        [parameter(Mandatory=$true,Position=1)] 
        [System.Net.NetworkCredential] 
        $Bearer
    )
    process {
        $local:metadata = Get-Metadata -Authority $Authority -ErrorAction Stop
        $local:headers = @{"Accept"="application/json"}
        $local:headers += $Bearer | ConvertTo-HttpBearer | ConvertTo-HttpAuthorization
        $local:uri = $local:metadata.userinfo_endpoint
        if(-not $local:uri) {
            Write-Error "userinfo_endpoint is not defined"
            return
        }
        Write-Verbose "Get-UserInfo GET $local:uri"
        Invoke-RestMethod -Method Get -Uri $local:uri -Headers $local:headers -UseBasicParsing
    }
}

function Get-TokenInfo {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true,Position=0)] 
        [Uri] 
        $Authority,

        [parameter(Mandatory=$true,Position=1)] 
        [PSTypeName("OAuth2.ClientConfig")] 
        $Client,

        [parameter(Mandatory=$true,Position=2)] 
        [System.Net.NetworkCredential] 
        $Bearer
    )
    process {
        $local:metadata = Get-Metadata -Authority $Authority -ErrorAction Stop
        $local:headers = @{"Accept"="application/json"}
        $local:headers += $Client.Credential | ConvertTo-HttpBasic | ConvertTo-HttpAuthorization
        $local:uri = $local:metadata.introspection_endpoint
        if(-not $local:uri) {
            Write-Error "introspection_endpoint is not defined"
            return
        }
        $local:request = New-QueryString | Add-QueryString "token" $Bearer.Password | ConvertTo-QueryString
        Write-Verbose "Get-TokenInfo POST $local:uri $local:request"
        Invoke-RestMethod -Method Post -Uri $local:uri -Headers $local:headers -Body $local:request -ContentType "application/x-www-form-urlencoded" -UseBasicParsing
    }
}

function ConvertTo-HttpBasic {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true,ValueFromPipeline=$true)] 
        [System.Net.NetworkCredential] 
        $In
    )
    process {
        $In | 
        % { ($_.UserName, $_.Password -join ":") } |
        % { [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($_)) } |
        % { ("Basic", $_ -join " ") }
    }
}

function ConvertTo-HttpBearer {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true,ValueFromPipeline=$true)] 
        [System.Net.NetworkCredential] 
        $In
    )
    Process {
        $In | 
        ? { $_.UserName -eq "Bearer" } |
        % { ($_.UserName, $_.Password -join " ") }
    }
}

function ConvertTo-HttpAuthorization {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true,ValueFromPipeline=$true)] 
        [string] 
        $In
    )
    process {
        $In | 
        % { 
            @{ "Authorization" = $_; }
        }
    }
}

Export-ModuleMember -Function "*"
