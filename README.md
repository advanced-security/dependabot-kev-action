Action to detect if any open Dependabot alert CVEs are in the list of [CISA Known Exploitable Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and fail the workflow.

When run on a pull request (`pull_request` or `pull_request_target` events), the action uses the [dependency review API](https://docs.github.com/en/rest/dependency-graph/dependency-review) to check only vulnerabilities introduced in the diff rather than all open Dependabot alerts. It resolves CVE identifiers from GHSA advisory IDs via the [global security advisory API](https://docs.github.com/en/rest/security-advisories/global-advisories#get-a-global-security-advisory).

![image](https://user-images.githubusercontent.com/1760475/208767910-dc8e1192-d41e-489c-bf71-ea4df20025bf.png)

### Push / scheduled check (all open Dependabot alerts)

```yml
name: 'Dependabot KEV Action'
on: [push]

jobs:
  dependabot-kev-action:
    name: 'CISA KEV Compliance Check'
    runs-on: ubuntu-latest
    steps:
      - name: 'KEV Policy'
        uses: advanced-security/dependabot-kev-action@v0                                          # floating major tag
        # uses: advanced-security/dependabot-kev-action@1c8496fa1d30a8520114a18d92e347d13ec63a32 # v0.1.1 (pinned)
        env:
            GITHUB_TOKEN: ${{ secrets.DEPENDABOT_KEV_GITHUB_TOKEN }}
```

### Pull request check (only new vulnerabilities in the diff)

```yml
name: 'Dependabot KEV Action'
on: [pull_request]

jobs:
  dependabot-kev-action:
    name: 'CISA KEV Compliance Check'
    runs-on: ubuntu-latest
    steps:
      - name: 'KEV Policy'
        uses: advanced-security/dependabot-kev-action@v0
        env:
            GITHUB_TOKEN: ${{ secrets.DEPENDABOT_KEV_GITHUB_TOKEN }}
```

## Required Credentials
* [GITHUB_TOKEN](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token) 
   * Classic Tokens
      *  repo scope or security_events scope. For public repositories, you may instead use the public_repo scope.
   * Fine-grained personal access token permissions
      * Read-Only - [Dependabot Alerts](https://docs.github.com/en/rest/overview/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=2022-11-28#vulnerability-alerts)

