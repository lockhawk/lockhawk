#!/usr/bin/env bash
# Set GitHub repository topics so the project is discoverable on GitHub search
# and the Topics directory. GitHub allows up to 20 topics.
#
# Run once after the repo exists and you've authenticated `gh`:
#   gh auth login
#   ./scripts/set-github-topics.sh
set -euo pipefail

gh repo edit --add-topic \
security,vulnerability-scanner,sca,software-composition-analysis,dependency-scanning,supply-chain-security,devsecops,appsec,osv,cve,cvss,sarif,npm,yarn,pnpm,typescript,cli,security-tools,vulnerability-management,dashboard

echo "Topics set. View them at the top of your repository page."
