# Design: Cap AI-authored PRs at 5 pending (GitHub)

**Date:** 2026-07-06
**Status:** Approved design — pending spec review before implementation planning.

## Context

We want both humans and AI to contribute to `lockhawk/lockhawk` at high volume,
but AI contributions must not flood the human review queue. The goal is a
governance control on GitHub: **AI may keep at most 5 PRs awaiting review at any
time; humans are unlimited.** AI PRs must be attributed to the project's real
contributors (never to Claude), consistent with the standing commit-attribution
rule.

## Goals

- Enforce **≤ 5 "pending" (ready-for-review) PRs** authored by the AI identity.
- Keep **humans unlimited** and never touch human PRs.
- Discard nothing — excess AI PRs are **parked**, not closed, and resurface
  automatically when a slot frees.
- Every AI PR is **attributed to Beniah / Faith Chinonye** at the commit level,
  never to Claude.

## Non-goals

- No cap or gating on human PRs.
- No cap on AI *draft* PRs (only ready-for-review PRs count).
- Not a merge-queue or CI-gating system; this is purely a review-queue bound.

## Definitions

- **AI identity:** a GitHub App `lockhawk-ai`. Every AI PR is *opened by* this
  App and appears with GitHub PR author `lockhawk-ai[bot]`.
- **AI PR:** an open PR whose **GitHub PR author is the `lockhawk-ai` App.** This
  is the only signal the cap uses — it is set at authentication time and cannot
  be spoofed by PR content.
- **Pending / counted PR:** an AI PR that is **open AND not a draft.** Draft AI
  PRs are unlimited and do not count.
- **Slot:** one of the 5 pending positions.

## Identity & attribution (two independent layers)

1. **PR author (enforcement layer):** the `lockhawk-ai` App opens the PR. The cap
   counts PRs by this author. Humans open PRs under their own accounts and are
   never counted or modified.
2. **Commit authorship (attribution layer):** the commits *inside* each AI PR are
   attributed to the humans, never Claude:
   - `Author: Beniah Onyebueke <ifeanyionyebueke.ben@gmail.com>`
   - `Co-Authored-By: Faith Chinonye <faithchinonye53@gmail.com>` on every commit
   - **No** `Co-Authored-By: Claude` / Anthropic trailer anywhere.

   These layers are independent: history and `git blame` credit the two humans;
   the App identity is used only for counting and does not appear in commit
   history.

## Enforcement design

A single **event-driven GitHub Actions workflow** (mechanism A) reacts to the
App's PR lifecycle. It uses the built-in `GITHUB_TOKEN` with
`permissions: { pull-requests: write, contents: read }`. Actions taken by
`GITHUB_TOKEN` do not retrigger workflows, so promotion is loop-safe.

**Triggers:** `pull_request` with types `[opened, reopened, ready_for_review, closed]`.

**Guard:** every job first checks the PR author is the `lockhawk-ai` App; if not,
it exits immediately (humans untouched).

### On open / reopened / ready_for_review

1. Count the App's *other* pending PRs (open, not draft).
2. If that count is already ≥ 5, this PR would be the 6th → **park it**:
   - convert to draft (GraphQL `convertPullRequestToDraft`),
   - add label `ai-queued`,
   - comment: "AI review-queue is full (5/5). This PR is queued as a draft and
     will be promoted automatically when a slot frees."
3. Otherwise leave it as a normal ready PR.

### On closed (merged or closed) — free a slot

1. **Top up to 5** (idempotent): while the App has < 5 pending PRs and at least
   one `ai-queued` draft exists, take the **oldest** `ai-queued` draft (by
   `createdAt`), mark it ready-for-review (GraphQL `markPullRequestReadyForReview`),
   and remove the `ai-queued` label.

Top-up-to-5 (rather than promote-exactly-one) self-heals if an event is ever
missed or two PRs close near-simultaneously.

## Attribution guardrail

A required status check on AI PRs (author = App) that inspects **every commit** in
the PR and enforces the standing attribution rule (the `no-claude-coauthor`
convention). It **fails** (blocking merge, with an explanatory message) if any
commit:

- is not authored by `Beniah Onyebueke <ifeanyionyebueke.ben@gmail.com>`; or
- lacks a `Co-Authored-By: Faith Chinonye <faithchinonye53@gmail.com>` trailer; or
- carries any Claude / Anthropic attribution.

> **Interpretation to confirm at review:** this follows the standing rule
> (*author* = Beniah, *co-author* = Faith on every commit). Your phrasing "either
> Beniah or Chinonye" could instead mean the author may be *either* human. If you
> want that, the check would accept author ∈ {Beniah, Faith} with the other as
> co-author. Flag it and I'll adjust.

This makes the attribution rule real rather than trusting the AI to self-apply
it. It runs only on App-authored PRs; human PRs are exempt.

## Edge cases & races

- **AI manually marks a queued draft ready** while 5 are active → the
  `ready_for_review` handler re-parks it as a draft.
- **Concurrent opens** (two PRs at once): each run re-counts, so the worst case is
  a transient 6th ready PR that the next event corrects. If this ever proves
  noticeable, add a low-frequency cron reconciler (mechanism C) as a safety net —
  deferred (YAGNI) until observed.
- **Closed without merge** also frees a slot (the `closed` event covers merged and
  closed).
- **A queued draft is closed** → no promotion needed (it was not pending).

## To verify during implementation planning

These are assumptions to confirm, not established facts:

1. `GITHUB_TOKEN` with `pull-requests: write` can toggle draft state via the
   GraphQL `convertPullRequestToDraft` / `markPullRequestReadyForReview`
   mutations. (Historically draft conversion sometimes required a PAT.) If not,
   the workflow runs with a PAT or the App's own installation token instead.
2. The exact author-filter syntax for the App in `gh` / GraphQL search
   (`author:app/lockhawk-ai` vs `lockhawk-ai[bot]`).
3. That PRs opened by the `lockhawk-ai` App reliably trigger `pull_request`
   workflows (App-authored events are not suppressed the way `GITHUB_TOKEN`-
   authored events are).

## Testing strategy

No unit test can exercise GitHub's event system, so verify end-to-end on a scratch
branch/fork with `gh`, observing real state:

1. Open 6 App PRs → the 6th becomes a draft labelled `ai-queued`; 5 remain ready.
2. Merge one ready PR → the oldest `ai-queued` draft is promoted to ready and the
   label removed; still exactly 5 ready.
3. Close (no merge) one ready PR → same promotion behaviour.
4. Open a human PR while AI is at 5 → untouched, not counted, not capped.
5. Open an App PR whose commits credit Claude / wrong author → the attribution
   guardrail check fails and blocks merge.

## Out of scope (YAGNI)

- Cron reconciler (add only if races prove real).
- Any limit or gating on human contributions.
- Notifications beyond the queued-PR comment.
- Per-author sub-quotas (e.g., separate caps for Beniah- vs Faith-attributed PRs).
