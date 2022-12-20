name: 'Dependabot KEV Action'
on: [push]

jobs:
  dependabot-kev-action:
    runs-on: ubuntu-latest
    steps:
      - name: 'KEV Policy'
        uses: felickz/dependabot-kev-action@main
        env:
            GITHUB_TOKEN: ${{ secrets.DEPENDABOT_KEV_GITHUB_TOKEN }}