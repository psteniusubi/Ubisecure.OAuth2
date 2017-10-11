$OAuthBrowserDefinitions = @{
    "default" = { 
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]
            [uri]
            $Uri,
            [Parameter()]
            [switch]
            $Private
        )
        Write-Verbose "Start-Process $Uri"
        Start-Process -FilePath $Uri
    }
    "iexplore" = { 
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]
            [uri]
            $Uri,
            [Parameter()]
            [switch]
            $Private
        )
        if($Private) {
            $ArgumentList = @("-private",$Uri)
        } else {
            $ArgumentList = @($Uri)
        }
        Write-Verbose "Start-Process iexplore $ArgumentList"
        Start-Process -FilePath "iexplore" -ArgumentList $ArgumentList
    }
    "chrome" = { 
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]
            [uri]
            $Uri,
            [Parameter()]
            [switch]
            $Private
        )
        if($Private) {
            $ArgumentList = @("--incognito",$Uri)
        } else {
            $ArgumentList = @($Uri)
        }
        Write-Verbose "Start-Process chrome $ArgumentList"
        Start-Process -FilePath "chrome" -ArgumentList $ArgumentList
    }
    "edge" = { 
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]
            [uri]
            $Uri,
            [Parameter()]
            [switch]
            $Private
        )
        $Uri = "microsoft-edge:$Uri"
        Write-Verbose "Start-Process $Uri"
        Start-Process -FilePath $Uri
    }
}

function Start-Browser {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=$true)]
        [uri]
        $Uri,
        [Parameter(Mandatory=$false)]
        [string]
        $Name = "default",
        [Parameter()]
        [switch]
        $Private
    )
    begin {
        if(-not $OAuthBrowserDefinitions.ContainsKey($Name)) {
            throw "Start-Browser: browser $Name is not defined"
        }
    }
    process {
        $Parameters = @{
            "Uri"=$Uri
            "Private"=$Private
        }
        & $OAuthBrowserDefinitions[$Name] @Parameters
    }
}

Export-ModuleMember -Function "*" -Variable "OAuthBrowserDefinitions"
