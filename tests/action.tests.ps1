<#
.SYNOPSIS
    Pester tests for the dependabot-kev-action.
.DESCRIPTION
    Unit tests validate the CVE matching logic in isolation using mock data (no internet required).
    Integration tests validate the CISA KEV API connectivity and response schema and require
    internet access to reach the CISA KEV catalog.
#>

Describe "CVE Matching Logic" {
    Context "When comparing CVE lists" {
        It "Should find a matching CVE" {
            $CISA_KEV_CVEs = @("CVE-2021-44228", "CVE-2022-22965", "CVE-2023-1234")
            $Dependabot_CVEs = @("CVE-2021-44228", "CVE-2023-9999")

            $matches = $CISA_KEV_CVEs | Where-Object { $Dependabot_CVEs -contains $_ }

            $matches | Should -Contain "CVE-2021-44228"
            $matches.Count | Should -Be 1
        }

        It "Should find multiple matching CVEs" {
            $CISA_KEV_CVEs = @("CVE-2021-44228", "CVE-2022-22965", "CVE-2023-1234")
            $Dependabot_CVEs = @("CVE-2021-44228", "CVE-2022-22965", "CVE-2023-9999")

            $matches = $CISA_KEV_CVEs | Where-Object { $Dependabot_CVEs -contains $_ }

            $matches.Count | Should -Be 2
            $matches | Should -Contain "CVE-2021-44228"
            $matches | Should -Contain "CVE-2022-22965"
        }

        It "Should return empty when no CVEs match" {
            $CISA_KEV_CVEs = @("CVE-2021-44228", "CVE-2022-22965")
            $Dependabot_CVEs = @("CVE-2023-9999", "CVE-2023-8888")

            $matches = $CISA_KEV_CVEs | Where-Object { $Dependabot_CVEs -contains $_ }

            $matches | Should -BeNullOrEmpty
        }

        It "Should return empty when Dependabot CVE list is empty" {
            $CISA_KEV_CVEs = @("CVE-2021-44228", "CVE-2022-22965")
            $Dependabot_CVEs = @()

            $matches = $CISA_KEV_CVEs | Where-Object { $Dependabot_CVEs -contains $_ }

            $matches | Should -BeNullOrEmpty
        }

        It "Should return empty when CISA KEV CVE list is empty" {
            $CISA_KEV_CVEs = @()
            $Dependabot_CVEs = @("CVE-2021-44228")

            $matches = $CISA_KEV_CVEs | Where-Object { $Dependabot_CVEs -contains $_ }

            $matches | Should -BeNullOrEmpty
        }

        It "Should match CVE IDs case-insensitively (PowerShell -contains default behavior)" {
            $CISA_KEV_CVEs = @("CVE-2021-44228")
            $Dependabot_CVEs = @("cve-2021-44228")

            $matches = $CISA_KEV_CVEs | Where-Object { $Dependabot_CVEs -contains $_ }

            # PowerShell -contains is case-insensitive by default
            $matches | Should -Not -BeNullOrEmpty
        }
    }

    Context "When building the summary message" {
        It "Should report matching CVEs when isFail is true" {
            $OrganizationName = "test-org"
            $RepositoryName = "test-repo"
            $CVEs_Match = @("CVE-2021-44228")
            $isFail = $CVEs_Match.Count -gt 0

            $summary = "[$OrganizationName/$RepositoryName] - "
            $summary += $isFail ? "Matching CISA KEV CVEs found in Dependabot alerts:`n $($CVEs_Match -join "`n")" : "No CVEs found"

            $summary | Should -Match "Matching CISA KEV CVEs found"
            $summary | Should -Match "CVE-2021-44228"
        }

        It "Should report no matches when isFail is false" {
            $OrganizationName = "test-org"
            $RepositoryName = "test-repo"
            $CVEs_Match = @()
            $Dependabot_Alerts_CVEs = @("CVE-2023-9999")
            $CISA_KEV_CVEs = @("CVE-2021-44228")
            $isFail = $CVEs_Match.Count -gt 0

            $summary = "[$OrganizationName/$RepositoryName] - "
            $summary += $isFail ? "Matching CISA KEV CVEs found" : "No CVEs found in ($($Dependabot_Alerts_CVEs.Count)) Dependabot alerts that match CISA KEV CVEs ($($CISA_KEV_CVEs.Count))"

            $summary | Should -Match "No CVEs found"
            $summary | Should -Match "test-org/test-repo"
        }
    }
}

Describe "CISA KEV API Integration" -Tag "Integration" {
    BeforeAll {
        $script:KEV_URI = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        $script:CISA_KEV = Invoke-RestMethod -Uri $script:KEV_URI -Method Get
    }

    Context "When fetching the KEV catalog" {
        It "Should return a non-empty response" {
            $script:CISA_KEV | Should -Not -BeNullOrEmpty
        }

        It "Should contain a vulnerabilities list" {
            $script:CISA_KEV.vulnerabilities | Should -Not -BeNullOrEmpty
        }

        It "Should contain at least one vulnerability" {
            $script:CISA_KEV.vulnerabilities.Count | Should -BeGreaterThan 0
        }

        It "Should have a catalogVersion field" {
            $script:CISA_KEV.catalogVersion | Should -Not -BeNullOrEmpty
        }

        It "Should have a dateReleased field" {
            $script:CISA_KEV.dateReleased | Should -Not -BeNullOrEmpty
        }
    }

    Context "When inspecting individual vulnerability entries" {
        It "Each entry should have a cveID field" {
            $missingCveID = $script:CISA_KEV.vulnerabilities | Where-Object { $null -eq $_.cveID -or $_.cveID -eq "" }
            $missingCveID | Should -BeNullOrEmpty
        }

        It "Each cveID should match the CVE ID format" {
            $invalidFormat = $script:CISA_KEV.vulnerabilities | Where-Object { $_.cveID -notmatch "^CVE-\d{4}-\d+$" }
            $invalidFormat | Should -BeNullOrEmpty
        }

        It "Each entry should have a vendorProject field" {
            $missingVendor = $script:CISA_KEV.vulnerabilities | Where-Object { $null -eq $_.vendorProject -or $_.vendorProject -eq "" }
            $missingVendor | Should -BeNullOrEmpty
        }

        It "Each entry should have a product field" {
            $missingProduct = $script:CISA_KEV.vulnerabilities | Where-Object { $null -eq $_.product -or $_.product -eq "" }
            $missingProduct | Should -BeNullOrEmpty
        }
    }
}
