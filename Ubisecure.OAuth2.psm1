﻿
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
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        $r = Join-Path -Path $HOME -ChildPath ".oauth2"
        Write-Verbose "Get-ClientConfigPath -Root = $r"
    }
    process {
        if($Root) {
            $r
        } else {
            $Name | % { Join-Path -Path $r -ChildPath $_ }
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
        $first = $null
        $loopback = $null
    }
    process {
        $InputObject | % {
            if(-not ($first)) {
                $first = $_
            }
            if($_.IsLoopback) {
                if(-not ($loopback)) {
                    $loopback = $_
                }
            }
        }
    }
    end {
        if($loopback) {
            $loopback
        } elseif($first) {
            $first
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

        [parameter(Mandatory=$false,ParameterSetName="ClientId",Position=1)]
        [AllowNull()]
        [securestring] 
        $ClientSecret,

        [parameter(Mandatory=$false,ParameterSetName="Credential",Position=1)] 
        [parameter(Mandatory=$false,ParameterSetName="ClientId",Position=2)]
        [AllowNull()] 
        [AllowEmptyString()] 
        [string] 
        $RedirectUri
    )
    begin {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    }
    process {
        switch ($PsCmdlet.ParameterSetName) {
            "Name" {
                $Name | Get-ClientConfigPath | New-ClientConfig
            }
            "Path" {
                $Path | 
                % {
                    Write-Verbose "Get-Content $_"
                    $t = [string] (Get-Content -Path $_ -ErrorAction Stop | Out-String)
                    if($t) {
                        New-ClientConfig -Json $t
                    }
                }
            }
            "Json" {
                Write-Verbose "ConvertFrom-Json $Json"
                ConvertFrom-Json -InputObject $Json |
                % {
                    if(-not $_.client_id) { Write-Error -Message "client_id is not defined" -Category InvalidArgument; return }
                    $t = New-ClientConfig -Credential ([System.Net.NetworkCredential]::new($_.client_id, $_.client_secret)) `
                        -RedirectUri ($_.redirect_uris | SelectRedirectUri)
                    $t | Add-Member -MemberType NoteProperty -Name "Json" -Value $_ -PassThru
                }
            }
            "ClientId" {
                New-ClientConfig -Credential ([System.Net.NetworkCredential]::new($ClientId, $ClientSecret)) `
                    -RedirectUri $RedirectUri
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
        $Path = ".well-known/openid-configuration",

        [parameter(Mandatory=$false,DontShow=$true)]
        [hashtable]
        $Extensions = [hashtable]::new()
    )
    begin {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        $InvokeRestMethod = [hashtable]::new($Extensions)
        $InvokeRestMethod["UseBasicParsing"] = $true
    }
    process {
        $Authority | 
        % {
            if(-not $Force -and $global:metadatacache.ContainsKey($Authority)) {
                Write-Verbose "Get-Metadata CACHE $Authority"
                return $global:metadatacache[$Authority]
            }
            $t = [uribuilder]::new($Authority)
            if(-not $t.Path.EndsWith("/")) {
                $t.Path += "/"
            }
            $t.Path += $Path
            $InvokeRestMethod["Method"] = "Get"
            $InvokeRestMethod["Uri"] = $t.Uri
            Write-Verbose "Get-Metadata GET $($InvokeRestMethod.Uri)"
            $metadata = Invoke-RestMethod @InvokeRestMethod
            if($metadata) {
                $global:metadatacache[$Authority] = $metadata
                return $metadata
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
    begin {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    }
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
        $Value,

        [parameter(Mandatory=$false,DontShow=$true)]
        [hashtable]
        $Extensions = [hashtable]::new()
    )
    begin {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        Add-Type -AssemblyName "System.Net.Http"
        $InvokeRestMethod = [hashtable]::new($Extensions)
        $InvokeRestMethod["UseBasicParsing"] = $true
    }
    process {
        switch ($PsCmdlet.ParameterSetName) {
            "Uri" {
                Write-Verbose "Get-ScopeFromHttpError GET $Uri"
                try {
                    $InvokeRestMethod["Method"] = "Get"
                    $InvokeRestMethod["Uri"] = $Uri
                    $null = Invoke-RestMethod @InvokeRestMethod
                } catch {
                    if(-not $_.Exception.Response) { 
                        Write-Error -Message "no response from $Uri" -Category ConnectionError
                        return 
                    }
                    if($_.Exception.Response.StatusCode -ne "Unauthorized") {
                        Write-Error -Message "unexpected status $($_.Exception.Response.StatusCode) from $Uri" -Category ProtocolError
                        return
                    }
                    $r = $_.Exception.Response.Headers.GetValues("WWW-Authenticate") | % { Get-ScopeFromHttpError -Value $_ }
                    if($r) { return $r }
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
                ? { $_ -match "\bscope=`"([^`"]+)`"" } |
                % { $Matches[1] }
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

        [parameter(Mandatory=$false,ParameterSetName="Browser")] 
        [switch] 
        $AnyHost = $false,

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
        $Parameters,

        [parameter(Mandatory=$false,DontShow=$true)]
        [hashtable]
        $Extensions = [hashtable]::new()
    )
    begin {
        $local:metadata = Get-Metadata -Authority $Authority -Extensions $Extensions -ErrorAction Stop
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
            StartLoopbackRedirectionRequest -Authority $Authority -Client $Client -Browser $Browser -Private:$Private -RandomPort:$RandomPort -AnyHost:$AnyHost -QueryString $local:query
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
        $ResponseOut,

        [parameter(Mandatory=$false,DontShow=$true)]
        [hashtable]
        $Extensions = [hashtable]::new()
    )
    begin {
        $InvokeRestMethod = [hashtable]::new($Extensions)
        $InvokeRestMethod["UseBasicParsing"] = $true
        $local:metadata = Get-Metadata -Authority $Authority -Extensions $Extensions -ErrorAction Stop
    }
    process {
        $local:headers = @{"Accept"="application/json"}
        $local:tokenrequest = New-QueryString
        if($HttpBasic -and -not [string]::IsNullOrWhiteSpace($Client.Credential.Password)) {
            $local:headers += ($Client.Credential | ConvertTo-HttpBasic | ConvertTo-HttpAuthorization)
        } else {
            $local:tokenrequest = $local:tokenrequest |
                Add-QueryString "client_id" $Client.Credential.UserName
            if(-not [string]::IsNullOrWhiteSpace($Client.Credential.Password)) {
                $local:tokenrequest = $local:tokenrequest |
                    Add-QueryString "client_secret" $Client.Credential.Password
            }
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
                    Add-QueryString "code" $Code.Credential.Password 
                if($null -ne $Code.Verifier) {
                    $local:tokenrequest = $local:tokenrequest | 
                        Add-QueryString "code_verifier" $Code.Verifier 
                }
                $local:tokenrequest = $local:tokenrequest | ConvertTo-QueryString
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
        $InvokeRestMethod["Method"] = "Post"
        $InvokeRestMethod["Uri"] = $local:metadata.token_endpoint
        $InvokeRestMethod["Headers"] = $local:headers
        $InvokeRestMethod["Body"] = $local:tokenrequest
        $InvokeRestMethod["ContentType"] = "application/x-www-form-urlencoded"
        Write-Verbose "Get-AccessToken POST $($InvokeRestMethod.Uri) $($InvokeRestMethod.Body)"
        $local:tokenresponse = Invoke-RestMethod @InvokeRestMethod
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
        $Bearer,

        [parameter(Mandatory=$false,DontShow=$true)]
        [hashtable]
        $Extensions = [hashtable]::new()
    )
    begin {
        $InvokeRestMethod = [hashtable]::new($Extensions)
        $InvokeRestMethod["UseBasicParsing"] = $true
        $local:metadata = Get-Metadata -Authority $Authority -Extensions $Extensions -ErrorAction Stop
    }
    process {
        $local:headers = @{"Accept"="application/json"}
        $local:headers += $Bearer | ConvertTo-HttpBearer | ConvertTo-HttpAuthorization
        $local:uri = $local:metadata.userinfo_endpoint
        if(-not $local:uri) {
            Write-Error "userinfo_endpoint is not defined"
            return
        }
        $InvokeRestMethod["Method"] = "Get"
        $InvokeRestMethod["Uri"] = $local:uri
        $InvokeRestMethod["Headers"] = $local:headers
        Write-Verbose "Get-UserInfo GET $($InvokeRestMethod.Uri)"
        Invoke-RestMethod @InvokeRestMethod
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

        [parameter(Mandatory=$false)] 
        [switch] 
        $HttpBasic = $true,

        [parameter(Mandatory=$true,Position=2)] 
        [System.Net.NetworkCredential] 
        $Bearer,

        [parameter(Mandatory=$false,DontShow=$true)]
        [hashtable]
        $Extensions = [hashtable]::new()
    )
    begin {
        $InvokeRestMethod = [hashtable]::new($Extensions)
        $InvokeRestMethod["UseBasicParsing"] = $true
        $local:metadata = Get-Metadata -Authority $Authority -Extensions $Extensions -ErrorAction Stop
    }
    process {
        $local:headers = @{"Accept"="application/json"}
        $local:request = New-QueryString
        if($HttpBasic -and -not [string]::IsNullOrWhiteSpace($Client.Credential.Password)) {
            $local:headers += $Client.Credential | ConvertTo-HttpBasic | ConvertTo-HttpAuthorization
        } else {
            $local:request = $local:request | 
                Add-QueryString "client_id" $Client.Credential.UserName
            if(-not [string]::IsNullOrWhiteSpace($Client.Credential.Password)) {
                $local:request = $local:request | 
                    Add-QueryString "client_secret" $Client.Credential.Password
            }
        }
        $local:uri = $local:metadata.introspection_endpoint
        if(-not $local:uri) {
            Write-Error "introspection_endpoint is not defined"
            return
        }
        $local:request = $local:request | Add-QueryString "token" $Bearer.Password | ConvertTo-QueryString
        $InvokeRestMethod["Method"] = "Post"
        $InvokeRestMethod["Uri"] = $local:uri
        $InvokeRestMethod["Headers"] = $local:headers
        $InvokeRestMethod["Body"] = $local:request
        $InvokeRestMethod["ContentType"] = "application/x-www-form-urlencoded"
        Write-Verbose "Get-TokenInfo POST $($InvokeRestMethod.Uri) $($InvokeRestMethod.Body)"
        Invoke-RestMethod @InvokeRestMethod
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

function ToBase64UrlSafe {
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [byte[]] 
        $Bytes
    )
    process {
        $t = [convert]::ToBase64String($Bytes)
        $t.Replace("+", "-").Replace("/", "_").Replace("=", "")
    }
}

function New-CodeChallenge {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true,Position=0)]
        [ref]
        $Verifier
    )
    begin {
        $prng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    }
    process {
        $bytes = [byte[]]::new(32)
        $null = $prng.GetNonZeroBytes($bytes)
        $Verifier.Value = ToBase64UrlSafe $bytes
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($Verifier.Value)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $bytes = $sha256.ComputeHash($bytes)
        return ToBase64UrlSafe $bytes
    }
}

Export-ModuleMember -Function "*"
