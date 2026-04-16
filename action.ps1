<#
.SYNOPSIS
Action to detect if any open Dependabot alerts are in the list of CISA KEV CVEs and fail the workflow if so.
When run on a pull request, only checks vulnerabilities introduced in the diff using the dependency review API.
.DESCRIPTION
Requirements:
- GITHUB_TOKEN env variable with repo scope or security_events scope. For public repositories, you may instead use the public_repo scope.
.EXAMPLE
# PS>gh auth token # <-- Easy to grab a local auth token to test with from here!
# PS>Write-Host "initializing local run! Ensure you provide a valid GITHUB_TOKEN otherwise you will get a 401!!! "
# $VerbosePreference = 'SilentlyContinue'
# $env:GITHUB_TOKEN = gh auth token
# $env:GITHUB_REPOSITORY = 'vulna-felickz/log4shell-vulnerable-app'
# CLEAR GLOBAL VARIABLES!
# Remove-Variable * -ErrorAction SilentlyContinue; 
# PS> action.ps1

A simple example execution of the internal pwsh script against an Owner/Repo outside of GitHub Action context

.NOTES

.LINK
https://github.com/advanced-security/dependabot-kev-action
#>

# Handle `Untrusted repository` prompt
Set-PSRepository PSGallery -InstallationPolicy Trusted

#check if GitHubActions module is installed
if (Get-Module -ListAvailable -Name GitHubActions -ErrorAction SilentlyContinue) {
    Write-ActionDebug "GitHubActions module is installed"
}
else {
    #directly to output here before module loaded to support Write-ActionInfo
    Write-Output "GitHubActions module is not installed.  Installing from Gallery..."
    Install-Module -Name GitHubActions
}

#check if PowerShellForGitHub module is installed
if (Get-Module -ListAvailable -Name PowerShellForGitHub -ErrorAction SilentlyContinue) {
    Write-ActionDebug "PowerShellForGitHub module is installed"
}
else {
    Write-ActionInfo "PowerShellForGitHub module is not installed.  Installing from Gallery..."
    Install-Module -Name PowerShellForGitHub

    #Disable Telemetry since we are accessing sensitive apis - https://github.com/microsoft/PowerShellForGitHub/blob/master/USAGE.md#telemetry
    Set-GitHubConfiguration -DisableTelemetry -SessionOnly
}

#check if GITHUB_TOKEN is set
if ($null -eq $env:GITHUB_TOKEN) {
    Set-ActionFailed -Message "GITHUB_TOKEN is not set"    
}
else {
    Write-ActionDebug "GITHUB_TOKEN is set"
}

# Allows you to specify your access token as a plain-text string ("<Your Access Token>")
# which will be securely stored on the machine for use in all future PowerShell sessions.
$secureString = ($env:GITHUB_TOKEN | ConvertTo-SecureString -AsPlainText -Force)
$cred = New-Object System.Management.Automation.PSCredential "username is ignored", $secureString
Set-GitHubAuthentication -Credential $cred
$secureString = $null # clear this out now that it's no longer needed
$cred = $null # clear this out now that it's no longer needed

#Init Owner/Repo/PR variables+
$actionRepo = Get-ActionRepo
$OrganizationName = $actionRepo.Owner
$RepositoryName = $actionRepo.Repo

#Get the list of CISA KEV from https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
$CISA_KEV = Invoke-RestMethod -Uri "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" -Method Get

#Get the list of CVEs from CISA KEV
$CISA_KEV_CVEs = $CISA_KEV.vulnerabilities | % { $_.cveID }
Write-ActionInfo "CISA KEV CVEs Count: $($CISA_KEV_CVEs.Count)"
Write-ActionDebug "CISA KEV CVEs: $CISA_KEV_CVEs"

#Detect if running on a pull request
$isPullRequest = $env:GITHUB_EVENT_NAME -eq 'pull_request' -or $env:GITHUB_EVENT_NAME -eq 'pull_request_target'

if ($isPullRequest) {
    Write-ActionInfo "Pull request detected - checking only vulnerabilities introduced in the diff"

    #Read event payload to get base/head SHAs for the dependency review comparison
    $eventPayload = Get-Content -Raw -Path $env:GITHUB_EVENT_PATH | ConvertFrom-Json
    $baseSha = $eventPayload.pull_request.base.sha
    $headSha = $eventPayload.pull_request.head.sha

    Write-ActionDebug "Base SHA: $baseSha"
    Write-ActionDebug "Head SHA: $headSha"

    #Call the dependency review API to get dependency changes between base and head
    #https://docs.github.com/en/rest/dependency-graph/dependency-review
    $depReviewUrl = "https://api.github.com/repos/$OrganizationName/$RepositoryName/dependency-graph/compare/${baseSha}...${headSha}"
    Write-ActionDebug "Dependency Review URL: $depReviewUrl"
    $depReview = Invoke-GHRestMethod -Method GET -Uri $depReviewUrl

    #Extract unique GHSA advisory IDs from vulnerabilities in added/changed dependencies
    #Exclude 'removed' dependencies since those represent vulnerabilities being fixed, not introduced
    $ghsaIds = @()
    foreach ($dep in $depReview) {
        if ($dep.change_type -ne 'removed' -and $dep.vulnerabilities) {
            foreach ($vuln in $dep.vulnerabilities) {
                if ($vuln.advisory_ghsa_id -and $ghsaIds -notcontains $vuln.advisory_ghsa_id) {
                    $ghsaIds += $vuln.advisory_ghsa_id
                }
            }
        }
    }

    Write-ActionInfo "Vulnerable GHSA advisories found in diff: $($ghsaIds.Count)"
    Write-ActionDebug "GHSA IDs: $($ghsaIds -join ', ')"

    #Look up CVE IDs from GHSA IDs using the global security advisory API
    #https://docs.github.com/en/rest/security-advisories/global-advisories#get-a-global-security-advisory
    $Dependabot_Alerts_CVEs = @()
    foreach ($ghsaId in $ghsaIds) {
        try {
            $advisory = Invoke-GHRestMethod -Method GET -Uri "https://api.github.com/advisories/$ghsaId"
            if ($advisory.cve_id) {
                $Dependabot_Alerts_CVEs += $advisory.cve_id
                Write-ActionDebug "GHSA $ghsaId -> CVE $($advisory.cve_id)"
            }
            else {
                Write-ActionDebug "GHSA $ghsaId has no associated CVE ID"
            }
        }
        catch {
            Write-ActionWarning "Failed to look up advisory ${ghsaId}: $($_.Exception.Message)"
        }
    }

    Write-ActionInfo "$OrganizationName/$RepositoryName Diff Vulnerability CVEs Count: $($Dependabot_Alerts_CVEs.Count)"
    Write-ActionDebug "$OrganizationName/$RepositoryName Diff Vulnerability CVEs: $Dependabot_Alerts_CVEs"
}
else {
    #Get the list of OPEN Dependabot alerts from github repo (paginated via -ExtendedResult)
    #https://docs.github.com/en/rest/dependabot/alerts?apiVersion=2022-11-28#list-dependabot-alerts-for-a-repository
    $perPage = 100
    $Dependabot_Alerts = Invoke-GHRestMethod -Method GET -Uri "https://api.github.com/repos/$OrganizationName/$RepositoryName/dependabot/alerts?state=open&per_page=$perPage" -ExtendedResult $true
    $Dependabot_Alerts_CVEs = $Dependabot_Alerts.result | % { $_.security_advisory.cve_id }
    #Get next page of dependabot alerts if there is one
    while ($null -ne $Dependabot_Alerts.nextLink) {
        $Dependabot_Alerts = Invoke-GHRestMethod -Method GET -Uri $Dependabot_Alerts.nextLink -ExtendedResult $true
        $Dependabot_Alerts_CVEs += $Dependabot_Alerts.result | % { $_.security_advisory.cve_id }
    }

    Write-ActionInfo "$OrganizationName/$RepositoryName Dependabot CVEs Count: $($Dependabot_Alerts_CVEs.Count)"
    Write-ActionDebug "$OrganizationName/$RepositoryName Dependabot CVEs: $Dependabot_Alerts_CVEs"
}

#Compare the two lists
$CVEs_Match = $CISA_KEV_CVEs | Where-Object { $Dependabot_Alerts_CVEs -contains $_ }
$isFail = $CVEs_Match.Count -gt 0

# summary that contains list of all CVEs that match CISA KEV
$checkContext = $isPullRequest ? "PR diff vulnerabilities" : "Dependabot alerts"
$summary = "[$OrganizationName/$RepositoryName] - "
$summary += $isFail ? "Matching CISA KEV CVEs found in ${checkContext}:`n $($CVEs_Match -join '`n')" : "No CVEs found in ($($Dependabot_Alerts_CVEs.Count)) ${checkContext} that match CISA KEV CVEs ($($CISA_KEV_CVEs.Count))" 

# Fail the action if any CVEs match CISA KEV
if ($isFail) {
    Set-ActionFailed -Message $summary
}
else {
    Write-ActionInfo $summary
    exit 0
}
