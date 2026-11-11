# Branch protection: make the gate mandatory

A gate that can be bypassed is a suggestion. Apply this to `main` after the first green run so the check names exist.

## Plan limitation (read first)
Branch protection and repository rulesets are **not available on private repositories on the GitHub Free plan**: both the
`branches/*/protection` and the `rulesets` APIs return `HTTP 403: Upgrade to GitHub Pro or make this repository public`.
On Free, this applies the moment the repo is on **GitHub Pro** or is made **public**. The ready-to-apply ruleset is committed
at [`.github/rulesets/protect-main.json`](../.github/rulesets/protect-main.json); apply it with one command once the plan allows:

```bash
gh api --method POST repos/<you>/payloop-secure-pipeline/rulesets --input .github/rulesets/protect-main.json
```

## Solo maintainer (default): require the gate and a PR, no self-approval deadlock
On a one-person repo, **do not require approving reviews**: GitHub will not let you approve your own pull request, so a non-zero
count makes `main` unmergeable. Require the passing `gate` check and a PR, and block force-pushes and deletion. This is what
`protect-main.json` encodes (0 approvals, repo-admin break-glass bypass). The classic-API equivalent:

```bash
OWNER=<you>; REPO=payloop-secure-pipeline
gh api -X PUT "repos/$OWNER/$REPO/branches/main/protection" --input - <<'JSON'
{
  "required_status_checks": {"strict": true, "contexts": ["gate"]},
  "enforce_admins": false,
  "required_pull_request_reviews": {"required_approving_review_count": 0},
  "restrictions": null
}
JSON
```

## With a second reviewer: require review too
Once another maintainer can review, add review enforcement (`"required_approving_review_count": 1`,
`"require_code_owner_reviews": true`, `"enforce_admins": true`) and add `"rules"` to the required contexts.

Also enable in repository settings where the plan allows: require signed commits (optional), disallow force-pushes and branch deletion,
enable secret scanning and push protection (these need GitHub Advanced Security on private repos), enable Dependabot alerts and updates.
`gate` is the required check for code; `rules` covers detection changes (its workflow only triggers on detection paths, so make it
required only if you accept that GitHub shows it as "pending" on other PRs, or run it unconditionally).

## Demonstrate it in an interview (3 minutes)
1. Branch `demo/bad-hash`. In `app/src/PasswordHasher.php` replace the body of `hash()` with `return md5($password);`. Push and open a PR.
2. The `sast` job succeeds (it only produces evidence); the `gate` job fails and its summary lists `weak-password-hash` as HIGH with the file and line.
3. Fix it, or add a waiver to `policy/gate-policy.yml` with owner, reason and a near expiry, and show the PR turns green and the waiver appears under "Waived".
4. Advance the clock in your head: after the expiry date the same waiver fails the build. That is the point.
