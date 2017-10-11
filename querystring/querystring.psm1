
function New-QueryString {
[CmdletBinding()]
param()
    [PSCustomObject] @{
        "PSTypeName" = "QueryString";
        "Value" = [System.Collections.Specialized.NameValueCollection]::new();
    }
}

function Add-QueryString {
[CmdletBinding()]
param(
[parameter(Mandatory=$true,Position=0,ParameterSetName="NameValue")] [string] $Name,
[parameter(Mandatory=$true,Position=1,ParameterSetName="NameValue")] [AllowEmptyString()] [string] $Value,
[parameter(Mandatory=$true,Position=0,ParameterSetName="Hashtable")] [hashtable] $Values,
[parameter(Mandatory=$true,Position=2,ValueFromPipeline=$true)] [PSTypeName("QueryString")] $QueryString 
)
    Begin {
        $out = New-QueryString
        switch ($PsCmdlet.ParameterSetName) {
            "NameValue" {
                $out.Value.Add($Name, $Value)
            }
            "Hashtable" {
                $Values.Keys | % {
                    $key = $_
                    $Values[$key] | % {
                        #Write-Verbose "$key $_"
                        $out.Value.Add($key, $_)
                    }
                }
            }
        }        
    }
    Process {
        $out.Value.Add($QueryString.Value)
    }
    End {
        return $out
    }
}

function Select-QueryString {
[CmdletBinding()]
param(
[parameter(Mandatory=$true,Position=0)] [string[]] $Name,
[parameter(Mandatory=$true,Position=1,ValueFromPipeline=$true)] [PSTypeName("QueryString")] $QueryString = (New-QueryString)
)
    Process {
        $Name | % {
            $QueryString.Value.GetValues($_)
        }
    }
}

function ConvertTo-QueryString {
[CmdletBinding()]
param(
[parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)] [PSTypeName("QueryString")] $QueryString
)
    Begin {
        $out = New-QueryString
    }
    Process {
        $out.Value.Add($QueryString.Value)
    }
    End {
        ($out.Value.AllKeys | % {
            $key = $_
            $out.Value.GetValues($key) | % {
                @(
                    [System.Net.WebUtility]::UrlEncode($key),
                    [System.Net.WebUtility]::UrlEncode($_)
                ) -join "="
            }
        }) -join "&"
    }
}

function ConvertFrom-QueryString {
[CmdletBinding()]
param(
[parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)] [AllowEmptyString()] [string] $Value
)
    Begin {
        Add-Type -AssemblyName "System.Web" -ErrorAction Stop
        $out = New-QueryString
    }
    Process {
        $out.Value.Add([System.Web.HttpUtility]::ParseQueryString($Value))
    }
    End {
        return $out
    }
}

