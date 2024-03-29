#
# Module manifest for module "Ubisecure.OAuth2"
#

@{
RootModule = "Ubisecure.OAuth2.psm1"
ModuleVersion = "1.3.0"
GUID = "96e72ae8-79d7-4728-a0e0-6f4b28409460"
Author = "petteri.stenius@ubisecure.com"
Description = "PowerShell OAuth 2.0 Client for Ubisecure SSO"
PowerShellVersion = "5.1"
CompatiblePSEditions = "Desktop","Core"
DefaultCommandPrefix = "OAuth"
FunctionsToExport = @(
    "Add-Metadata",
    "ConvertTo-HttpAuthorization",
    "ConvertTo-HttpBasic",
    "ConvertTo-HttpBearer",
    "Get-AccessToken",
    "Get-AuthorizationCode",
    "Get-ClientConfigPath",
    "Get-Metadata",
    "Get-ModulePath",
    "Get-ScopeFromHttpError",
    "Get-TokenInfo",
    "Get-UserInfo",
    "New-BrowserRequest",
    "New-ClientConfig",
    "Start-Browser"
)
CmdletsToExport = @()
VariablesToExport = @(
    "OAuthBrowserDefinitions"
)
AliasesToExport = @()
NestedModules = @(
    "Get-CallerPreference.ps1",
    "EmbeddedBrowser.ps1",
    "LoopbackRedirection.ps1",
    "BrowserDefinitions.ps1"
)
ScriptsToProcess = @()
RequiredModules = @(
    @{"ModuleName"="Ubisecure.QueryString";"ModuleVersion"="1.3.0";"Guid"="80f2f884-f2e3-457f-b7c2-16e884ce9ba2"},
    @{"ModuleName"="Ubisecure.HttpListener";"ModuleVersion"="1.2.0";"Guid"="f94e8814-3091-4ee4-bb63-660ae73471ba"}
)
}
