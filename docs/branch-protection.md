# Branch protection: make the gate mandatory

A gate that can be bypassed is a suggestion. Apply this to `main` after the first green run so the check names exist.

```bash
OWNER=<you>; REPO=payloop-secure-pipeline
gh api -X PUT "repos/$OWNER/$REPO/branches/main/protection" --input - <<'JSON'
{
  "required_status_checks": {"strict": true, "contexts": ["gate", "rules"]},
  "enforce_admins": true,
  "required_pull_request_reviews": {"required_approving_review_count": 1, "require_code_owner_reviews": true},
  "restrictions": null
}
JSON
```

Also enable in repository settings: require signed commits (optional), disallow force-pushes and branch deletion, enable secret scanning and
push protection, enable Dependabot alerts and updates. `gate` is the required check for code; `rules` covers detection changes
(its workflow only triggers on detection paths, so make it required only if you accept that GitHub shows it as "pending" on other PRs,
or run it unconditionally).

## Demonstrate it in an interview (3 minutes)
1. Branch `demo/bad-hash`. In `app/src/PasswordHasher.php` replace the body of `hash()` with `return md5($password);`. Push and open a PR.
2. The `sast` job succeeds (it only produces evidence); the `gate` job fails and its summary lists `weak-password-hash` as HIGH with the file and line.
3. Fix it, or add a waiver to `policy/gate-policy.yml` with owner, reason and a near expiry, and show the PR turns green and the waiver appears under "Waived".
4. Advance the clock in your head: after the expiry date the same waiver fails the build. That is the point.
