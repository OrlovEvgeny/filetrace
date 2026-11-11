#!/bin/sh
# usage: github-setup.sh [--yes] [--keys <directory>]
# Applies the repository settings the release process relies on; RELEASING.md
# lists them. Safe to run again. With --keys, also stores the signing keys that
# keys.sh made in <directory> as secrets of the release environment, and gives
# the release workflow a deploy key for the Homebrew tap.
# Needs gh, signed in as an administrator of the repository.
set -eu

assume_yes=0
keys=
while [ $# -gt 0 ]; do
    case $1 in
    --yes) assume_yes=1 ;;
    --keys)
        [ $# -ge 2 ] || {
            echo "github-setup.sh: --keys needs a directory" >&2
            exit 2
        }
        keys=$2
        shift
        ;;
    *)
        echo "usage: github-setup.sh [--yes] [--keys <directory>]" >&2
        exit 2
        ;;
    esac
    shift
done

repo=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
owner=${repo%/*}
tap=$owner/homebrew-filetrace

echo "This changes the settings of $repo${keys:+, stores its release secrets and adds a deploy key to $tap}."
if [ "$assume_yes" -eq 0 ]; then
    printf 'Continue? [y/N] '
    read -r answer
    case $answer in
    y | Y | yes) ;;
    *) exit 1 ;;
    esac
fi

say()
{
    printf '%s\n' "- $*"
}

# ruleset <name>: creates the ruleset read from stdin, or replaces the one of that name.
ruleset()
{
    id=$(gh api "repos/$repo/rulesets" --jq ".[] | select(.name == \"$1\") | .id")
    if [ -n "$id" ]; then
        gh api --silent -X PUT "repos/$repo/rulesets/$id" --input -
    else
        gh api --silent -X POST "repos/$repo/rulesets" --input -
    fi
    say "rules: $1"
}

gh api --silent -X PATCH "repos/$repo" \
    -F allow_merge_commit=false -F allow_squash_merge=false -F allow_rebase_merge=true \
    -F delete_branch_on_merge=true
say 'pull requests are rebased; merged branches are deleted'

gh api --silent -X PUT "repos/$repo/actions/permissions/workflow" \
    -f default_workflow_permissions=read -F can_approve_pull_request_reviews=true
say 'workflows may open pull requests'

if gh api --silent "repos/$repo/pages" 2>/dev/null; then
    gh api --silent -X PUT "repos/$repo/pages" -f build_type=workflow
else
    gh api --silent -X POST "repos/$repo/pages" -f build_type=workflow
fi
say 'GitHub Pages is deployed by Actions'

gh api --silent -X PUT "repos/$repo/immutable-releases"
say 'published releases are immutable'

gh api --silent -X PUT "repos/$repo/private-vulnerability-reporting"
say 'vulnerabilities can be reported privately'

gh api --silent -X PUT "repos/$repo/environments/release" --input - <<JSON
{
  "reviewers": [{ "type": "User", "id": $(gh api user --jq .id) }],
  "prevent_self_review": false
}
JSON
say 'the release environment waits for your approval'

# The maintainer pushes to these branches directly, so what is protected is
# their history. A release checks its commit itself before publishing.
ruleset 'Branches' <<'JSON'
{
  "name": "Branches",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": { "include": ["~DEFAULT_BRANCH", "refs/heads/[0-9][0-9].*"], "exclude": [] }
  },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" }
  ]
}
JSON

ruleset 'Release tags' <<'JSON'
{
  "name": "Release tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "update" }
  ]
}
JSON

[ -n "$keys" ] || exit 0

for file in gpg.key filetrace.rsa; do
    [ -f "$keys/$file" ] || {
        echo "github-setup.sh: $keys/$file is missing; run tools/release/keys.sh $keys" >&2
        exit 1
    }
done
gh secret set FILETRACE_GPG_KEY --env release <"$keys/gpg.key"
gh secret set FILETRACE_APK_KEY --env release <"$keys/filetrace.rsa"
say 'the signing keys are stored'

if [ ! -f "$keys/tap_key" ]; then
    ssh-keygen -q -t ed25519 -N '' -C 'filetrace release' -f "$keys/tap_key"
fi
if ! gh repo deploy-key list --repo "$tap" | grep -q 'filetrace release'; then
    gh repo deploy-key add "$keys/tap_key.pub" --repo "$tap" --allow-write \
        --title 'filetrace release' >/dev/null
fi
gh secret set HOMEBREW_TAP_KEY --env release <"$keys/tap_key"
say "the release workflow can push to $tap"

# The workflow checks the tap out, which an empty repository does not allow.
if ! gh api --silent "repos/$tap/commits?per_page=1" 2>/dev/null; then
    gh api --silent -X PUT "repos/$tap/contents/README.md" \
        -f message='docs: describe the tap' \
        -f content="$(printf '# Homebrew tap\n\n    brew install %s/filetrace/filetrace\n' "$owner" | base64)"
    say "$tap has its first commit"
fi
