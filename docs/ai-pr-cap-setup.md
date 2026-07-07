# AI PR cap — setup

This repo caps **AI-authored PRs at 5 pending** (open + ready-for-review) while
leaving human contributions unlimited, and requires every AI commit to be
attributed to the project's human contributors. Design rationale is in
[`docs/superpowers/specs/2026-07-06-ai-pr-cap-design.md`](superpowers/specs/2026-07-06-ai-pr-cap-design.md).

Two workflows implement it:

- [`.github/workflows/ai-pr-cap.yml`](../.github/workflows/ai-pr-cap.yml) — parks
  the 6th+ ready AI PR as a draft and auto-promotes queued drafts when a slot frees.
- [`.github/workflows/ai-pr-attribution.yml`](../.github/workflows/ai-pr-attribution.yml)
  — a required check that AI commits credit Beniah + Faith and never Claude.

The workflows are inert until the one-time setup below is done.

## 1. Create the `lockhawk-ai` GitHub App

The AI must open PRs under its **own** identity so the cap can count them by
author (a spoof-proof signal). A human-opened PR is never counted or touched.

1. **Settings → Developer settings → GitHub Apps → New GitHub App.**
   - **Name:** `lockhawk-ai` (the bot login becomes `lockhawk-ai[bot]`; if you
     pick a different name, update `APP_LOGIN` in both workflows).
   - **Homepage URL:** the repo URL is fine.
   - **Webhook:** uncheck **Active** (not needed).
   - **Repository permissions:**
     - **Contents:** Read and write (push branches).
     - **Pull requests:** Read and write (open PRs, toggle draft, label, comment).
     - **Metadata:** Read-only (mandatory default).
   - Where can this App be installed: **Only on this account.**
2. **Create**, then **Install App** on the `lockhawk` repo (or the whole org).
3. On the App's page: note the **App ID**, and **Generate a private key**
   (downloads a `.pem`).

## 2. Store the App credentials as secrets

Repo **Settings → Secrets and variables → Actions → New repository secret**:

- `LOCKHAWK_AI_APP_ID` — the numeric App ID.
- `LOCKHAWK_AI_APP_PRIVATE_KEY` — the full contents of the downloaded `.pem`
  (including the `-----BEGIN…` / `-----END…` lines).

The `ai-pr-cap` workflow mints an installation token from these to toggle draft
state reliably.

## 3. Point the AI at the App identity

Whatever runs the AI (e.g. Claude Code) must, for this repo:

- **Open PRs as the App** — authenticate `gh` / the API with the App's
  installation token so the PR author is `lockhawk-ai[bot]`. (Minting a token:
  `actions/create-github-app-token` in CI, or the `gh` App-auth flow locally.)
- **Attribute commits to the humans** — every commit authored by
  `Beniah Onyebueke <ifeanyionyebueke.ben@gmail.com>` with a
  `Co-Authored-By: Faith Chinonye <faithchinonye53@gmail.com>` trailer, and **no**
  Claude/Anthropic attribution. The attribution check enforces this.

> Note: if the AI opens PRs under a human's `gh` token instead, the PRs count as
> that human's and the cap won't apply — the separate App identity is what makes
> "humans unlimited, AI capped" real.

## 4. (Optional) Pre-create the queue label

The `ai-pr-cap` workflow creates the `ai-queued` label on first use, but you can
create it up front: **Issues → Labels → New label** → name `ai-queued`,
color `#fbca04`.

## 5. Require the attribution check on `main`

**Settings → Branches → Branch protection rules → `main` → Require status checks
to pass before merging**, and add **`attribution`** (the job in the AI PR
attribution workflow). It passes trivially for human PRs, so it won't block them.

Do **not** mark `ai-pr-cap` as a required check — it manages queue state, it isn't
a pass/fail gate.

## How it behaves once live

| Event                                                        | Result                                              |
| ------------------------------------------------------------ | --------------------------------------------------- |
| AI opens a PR while < 5 AI PRs are ready                     | Stays ready — normal review                         |
| AI opens a PR while 5 AI PRs are ready                       | Converted to draft, labelled `ai-queued`, commented |
| An AI PR is merged or closed                                 | Oldest `ai-queued` draft is promoted to ready       |
| AI marks a queued draft ready while 5 are ready              | Re-parked as a draft                                |
| A human opens any number of PRs                              | Never counted, never modified                       |
| AI commit not attributed to Beniah+Faith (or credits Claude) | Attribution check fails, blocking merge             |

## Verifying it works

There's no local test for GitHub's event system; verify against a real repo:

1. With the App installed, open 6 PRs as the App → the 6th becomes a draft
   labelled `ai-queued`; 5 stay ready.
2. Merge one ready PR → the oldest queued draft is promoted; still 5 ready.
3. Open a PR as yourself while the AI is at 5 → untouched.
4. Open an App PR whose commits credit Claude or the wrong author → the
   `attribution` check fails.

## Tuning

- **Change the limit:** edit `LIMIT` in `ai-pr-cap.yml`.
- **Rename the App:** update `APP_LOGIN` in both workflows to `<new-name>[bot]`.
- **Races:** if two AI PRs are opened in the same instant, a transient 6th ready
  PR is possible until the next event corrects it. If that ever matters, add a
  low-frequency scheduled reconciler that re-runs the same top-up/park logic.
