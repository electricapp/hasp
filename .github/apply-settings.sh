#!/usr/bin/env bash
# Reconcile GitHub-side settings for electricapp/hasp to match
# .github/settings.json (the single source of truth).
#
# Idempotent: apply, then re-fetch and assert actual == desired.
# Exits non-zero if any drift remains after apply.
#
#   ./.github/apply-settings.sh
#
# Requires: gh (authenticated, admin), jq.

set -euo pipefail

REPO="electricapp/hasp"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETTINGS="$HERE/settings.json"

command -v gh >/dev/null || { echo "missing: gh"; exit 1; }
command -v jq >/dev/null || { echo "missing: jq"; exit 1; }

cat <<EOF
About to apply admin-scope settings to $REPO:
  - branch protection on main (required CI checks, no force pushes, no deletions)
  - deployment environments (wait timer + reviewer + tag policies)
  - merge policy (squash-only, auto-delete branches)
  - security features (vulnerability alerts, secret scanning, dependabot)

Source of truth: $SETTINGS
EOF
read -r -p 'Type "yes" to proceed: ' confirm
[[ "$confirm" = "yes" ]] || { echo "aborted."; exit 1; }

echo "Applying settings from $SETTINGS ..."

resolve_user_id() { gh api "users/$1" --jq '.id'; }

# -------- branch protection: main --------
contexts=$(jq -c '.branch_protection.main.required_status_checks_contexts' "$SETTINGS")
strict=$(jq -r '.branch_protection.main.required_status_checks_strict' "$SETTINGS")
enforce=$(jq -r '.branch_protection.main.enforce_admins' "$SETTINGS")
linear=$(jq -r '.branch_protection.main.required_linear_history' "$SETTINGS")
force=$(jq -r '.branch_protection.main.allow_force_pushes' "$SETTINGS")
del=$(jq -r '.branch_protection.main.allow_deletions' "$SETTINGS")
convres=$(jq -r '.branch_protection.main.required_conversation_resolution' "$SETTINGS")

gh api -X PUT "repos/$REPO/branches/main/protection" --input - <<JSON >/dev/null
{
  "required_status_checks": { "strict": $strict, "contexts": $contexts },
  "enforce_admins": $enforce,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "required_linear_history": $linear,
  "allow_force_pushes": $force,
  "allow_deletions": $del,
  "required_conversation_resolution": $convres,
  "lock_branch": false,
  "allow_fork_syncing": true
}
JSON
echo "  main: branch protection applied"

# -------- environments --------
jq -c '.environments[]' "$SETTINGS" | while read -r env_json; do
  name=$(jq -r '.name' <<<"$env_json")
  wait_timer=$(jq -r '.wait_timer' <<<"$env_json")

  reviewers_json="[]"
  for login in $(jq -r '.reviewer_logins[]' <<<"$env_json"); do
    id=$(resolve_user_id "$login")
    reviewers_json=$(jq -c ". + [{\"type\":\"User\",\"id\":$id}]" <<<"$reviewers_json")
  done

  gh api -X PUT "repos/$REPO/environments/$name" --input - <<JSON >/dev/null
{
  "wait_timer": $wait_timer,
  "prevent_self_review": false,
  "reviewers": $reviewers_json,
  "deployment_branch_policy": { "protected_branches": false, "custom_branch_policies": true }
}
JSON

  # Tag policies: clear existing, re-add from fixture.
  for id in $(gh api "repos/$REPO/environments/$name/deployment-branch-policies" --jq '.branch_policies[].id'); do
    gh api -X DELETE "repos/$REPO/environments/$name/deployment-branch-policies/$id" >/dev/null
  done
  for pattern in $(jq -r '.tag_patterns[]' <<<"$env_json"); do
    gh api -X POST "repos/$REPO/environments/$name/deployment-branch-policies" \
      -f name="$pattern" -f type=tag >/dev/null
  done
  echo "  env $name: reviewer + ${wait_timer}m wait + tags applied"
done

# -------- repo flags --------
repo_payload=$(jq -c '.repo' "$SETTINGS")
gh api -X PATCH "repos/$REPO" --input - <<<"$repo_payload" >/dev/null
echo "  repo: merge policy applied"

# -------- security --------
gh api -X PUT "repos/$REPO/vulnerability-alerts" >/dev/null
gh api -X PUT "repos/$REPO/automated-security-fixes" >/dev/null
sec=$(jq -c '{ security_and_analysis: .security_and_analysis | to_entries | map({key, value: {status: .value}}) | from_entries }' "$SETTINGS")
gh api -X PATCH "repos/$REPO" --input - <<<"$sec" >/dev/null
echo "  security: vuln alerts + dependabot + secret scanning applied"

# =================================================================
# ASSERT: re-fetch actual state, compare against fixture. Fail on drift.
# =================================================================
echo
echo "Asserting final state matches $SETTINGS ..."
errors=0
check() {
  local label="$1" actual="$2" expected="$3"
  if [[ "$actual" != "$expected" ]]; then
    printf "  DRIFT [%s]\n    expected: %s\n    actual:   %s\n" "$label" "$expected" "$actual"
    errors=$((errors+1))
  fi
}

bp=$(gh api "repos/$REPO/branches/main/protection")
check "bp.contexts"       "$(jq -c '.required_status_checks.contexts | sort' <<<"$bp")" \
                           "$(jq -c '.branch_protection.main.required_status_checks_contexts | sort' "$SETTINGS")"
check "bp.strict"         "$(jq -r '.required_status_checks.strict' <<<"$bp")" \
                           "$(jq -r '.branch_protection.main.required_status_checks_strict' "$SETTINGS")"
check "bp.enforce_admins" "$(jq -r '.enforce_admins.enabled' <<<"$bp")" \
                           "$(jq -r '.branch_protection.main.enforce_admins' "$SETTINGS")"
check "bp.linear"         "$(jq -r '.required_linear_history.enabled' <<<"$bp")" \
                           "$(jq -r '.branch_protection.main.required_linear_history' "$SETTINGS")"
check "bp.force"          "$(jq -r '.allow_force_pushes.enabled' <<<"$bp")" \
                           "$(jq -r '.branch_protection.main.allow_force_pushes' "$SETTINGS")"
check "bp.del"            "$(jq -r '.allow_deletions.enabled' <<<"$bp")" \
                           "$(jq -r '.branch_protection.main.allow_deletions' "$SETTINGS")"
check "bp.convres"        "$(jq -r '.required_conversation_resolution.enabled' <<<"$bp")" \
                           "$(jq -r '.branch_protection.main.required_conversation_resolution' "$SETTINGS")"

jq -c '.environments[]' "$SETTINGS" | while read -r env_json; do
  name=$(jq -r '.name' <<<"$env_json")
  actual_env=$(gh api "repos/$REPO/environments/$name")
  actual_wait=$(jq -r '.protection_rules[] | select(.type=="wait_timer") | .wait_timer' <<<"$actual_env")
  actual_reviewers=$(jq -c '[.protection_rules[] | select(.type=="required_reviewers") | .reviewers[].reviewer.login] | sort' <<<"$actual_env")
  actual_tags=$(gh api "repos/$REPO/environments/$name/deployment-branch-policies" --jq '[.branch_policies[] | select(.type=="tag") | .name] | sort')

  check "env.$name.wait"      "$actual_wait"      "$(jq -r '.wait_timer' <<<"$env_json")"
  check "env.$name.reviewers" "$actual_reviewers" "$(jq -c '.reviewer_logins | sort' <<<"$env_json")"
  check "env.$name.tags"      "$actual_tags"      "$(jq -c '.tag_patterns | sort' <<<"$env_json")"
done

repo_actual=$(gh api "repos/$REPO")
for key in allow_squash_merge allow_merge_commit allow_rebase_merge delete_branch_on_merge allow_auto_merge; do
  check "repo.$key" "$(jq -r ".$key" <<<"$repo_actual")" "$(jq -r ".repo.$key" "$SETTINGS")"
done
for key in secret_scanning secret_scanning_push_protection secret_scanning_non_provider_patterns secret_scanning_validity_checks; do
  check "sec.$key" "$(jq -r ".security_and_analysis.$key.status" <<<"$repo_actual")" \
                   "$(jq -r ".security_and_analysis.$key" "$SETTINGS")"
done

if [[ $errors -gt 0 ]]; then
  echo
  echo "FAIL: $errors drift(s) detected."
  exit 1
fi
echo "OK: actual state matches fixture."
