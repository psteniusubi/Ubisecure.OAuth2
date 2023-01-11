Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot "Ubisecure.OAuth2.psd1") -Force -ErrorAction Stop
}

Context "New-ClientConfig(Json)" {
    It "Test1" {
        $config = New-OAuthClientConfig -Json @"
{
"client_id":"client1"
}
"@
        $config | Should -Not -BeNullOrEmpty
        $config.Credential | Should -Not -BeNullOrEmpty
        $config.Credential.UserName | Should -Be "client1"
        $config.Credential.Password | Should -BeNullOrEmpty
        $config.RedirectUri | Should -BeNullOrEmpty
        $config.Json | Should -Not -BeNullOrEmpty
    }
    It "Test2" {
        $config = New-OAuthClientConfig -Json @"
{
"client_id":"client1",
"client_secret":"secret1",
"redirect_uris":["http://localhost/"]
}
"@
        $config | Should -Not -BeNullOrEmpty
        $config.Credential | Should -Not -BeNullOrEmpty
        $config.Credential.UserName | Should -Be "client1"
        $config.Credential.Password | Should -Be "secret1"
        $config.RedirectUri | Should -Be "http://localhost/"
        $config.Json | Should -Not -BeNullOrEmpty
    }
}

Context "New-ClientConfig(ClientId)" {
    It "Test1" {
        $config = New-OAuthClientConfig -ClientId "client1"
        $config | Should -Not -BeNullOrEmpty
        $config.Credential | Should -Not -BeNullOrEmpty
        $config.Credential.UserName | Should -Be "client1"
        $config.Credential.Password | Should -BeNullOrEmpty
        $config.RedirectUri | Should -BeNullOrEmpty
        $config.Json | Should -BeNullOrEmpty
    }
    It "Test2" {
        $config = New-OAuthClientConfig -ClientId "client1" -ClientSecret (ConvertTo-SecureString -String "secret1" -AsPlainText -Force) -RedirectUri "http://localhost/"
        $config | Should -Not -BeNullOrEmpty
        $config.Credential | Should -Not -BeNullOrEmpty
        $config.Credential.UserName | Should -Be "client1"
        $config.Credential.Password | Should -Be "secret1"
        $config.RedirectUri | Should -Be "http://localhost/"
        $config.Json | Should -BeNullOrEmpty
    }
}

Context "NetworkCredential" {
    It "Test1" {
        $t = [System.Net.NetworkCredential]::new("username", "password")
        $t.UserName | Should -BeExactly "username"
        $t.Password | Should -BeExactly "password"
        $t = [System.Net.NetworkCredential]::new("username", "")
        $t.UserName | Should -BeExactly "username"
        $t.Password | Should -BeExactly ""
        $t = [System.Net.NetworkCredential]::new("username", $null)
        $t.UserName | Should -BeExactly "username"
        $t.Password | Should -BeExactly "" # surprise!
    }
}