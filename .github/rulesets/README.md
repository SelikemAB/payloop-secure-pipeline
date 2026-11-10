# Branch protection ruleset (Option A)

`protect-main.json` is the repository ruleset that protects the default branch.
It is committed here as source-controlled configuration.

## What it enforces
- A pull request is required before merging to the default branch (no direct pushes).
- Force-pushes and branch deletion on the default branch are blocked.
- The `gate` status check must pass, and the branch must be up to date, before merging.
- Required approving reviews: 0. This is a single-maintainer repository, and GitHub
  does not allow approving your own pull request, so a non-zero count would make the
  branch unmergeable. The protection that applies is the required PR flow, plus a mandatory passing `gate` check.
- The repository-admin role is the only bypass actor (break-glass).

## Why it is not already active
Repository rulesets and branch protection are not available for **private** repositories
on the GitHub Free plan (the API returns HTTP 403: "Upgrade to GitHub Pro or make this
repository public"). This file records the exact policy so it applies the moment the
repository is on GitHub Pro or is made public.

## How to apply
Once the plan allows it (Pro, or the repo is public):

```bash
gh api --method POST repos/SelikemAB/payloop-secure-pipeline/rulesets --input .github/rulesets/protect-main.json
```

Verify:

```bash
gh api repos/SelikemAB/payloop-secure-pipeline/rulesets -q '.[] | select(.name=="protect-main") | {id,enforcement}'
```
