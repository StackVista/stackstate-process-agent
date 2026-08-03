#!/usr/bin/env bash
#
# Open (or refresh) a pull request whose commit is signed by GitHub.
#
# Why this exists rather than an off-the-shelf action: master requires signed
# commits, and StackVista's Actions allowlist does not include the usual
# create-pull-request action. The GraphQL createCommitOnBranch mutation is the
# only way to have GitHub sign a commit made on behalf of a token, so the
# branch, the commit and the PR are all created through the API here.
#
# Everything is driven by environment variables so no caller input is
# interpolated into this script:
#
#   GH_TOKEN       GitHub App installation token (contents:write, pull-requests:write)
#   GH_REPO        owner/name
#   BASE_BRANCH    branch the PR merges into
#   HEAD_BRANCH    working branch to create
#   COMMIT_MESSAGE headline of the commit
#   PR_TITLE       pull request title
#   PR_BODY        pull request body
#
# Reads the working tree for changes relative to HEAD; exits 0 without doing
# anything if there are none.

set -euo pipefail

for var in GH_TOKEN GH_REPO BASE_BRANCH HEAD_BRANCH COMMIT_MESSAGE PR_TITLE PR_BODY; do
  if [ -z "${!var:-}" ]; then
    echo "::error::open-signed-pr: missing required environment variable: ${var}" >&2
    exit 1
  fi
done

BASE_SHA=$(git rev-parse HEAD)

# Files the updater touched, split into content changes and removals. The
# lowercase 'd' filter means "everything except deletions".
mapfile -t changed_files < <(git diff --name-only --diff-filter=d)
mapfile -t deleted_files < <(git diff --name-only --diff-filter=D)

if [ ${#changed_files[@]} -eq 0 ] && [ ${#deleted_files[@]} -eq 0 ]; then
  echo "No changes in the working tree; nothing to open."
  exit 0
fi

echo "Changed: ${changed_files[*]:-none}"
echo "Deleted: ${deleted_files[*]:-none}"

additions='[]'
if [ ${#changed_files[@]} -gt 0 ]; then
  additions=$(
    for f in "${changed_files[@]}"; do
      jq -n --arg path "$f" --arg contents "$(base64 -w0 "$f")" \
        '{path: $path, contents: $contents}'
    done | jq -s '.'
  )
fi

deletions='[]'
if [ ${#deleted_files[@]} -gt 0 ]; then
  deletions=$(printf '%s\n' "${deleted_files[@]}" | jq -R '{path: .}' | jq -s '.')
fi

# Point the working branch at the commit we built from. Creating the commit
# with expectedHeadOid equal to this SHA then fails loudly if anything else
# moved the branch in between.
if gh api "repos/${GH_REPO}/git/ref/heads/${HEAD_BRANCH}" >/dev/null 2>&1; then
  echo "Branch ${HEAD_BRANCH} exists; resetting it to ${BASE_SHA}."
  gh api --method PATCH "repos/${GH_REPO}/git/refs/heads/${HEAD_BRANCH}" \
    -F sha="${BASE_SHA}" -F force=true >/dev/null
else
  echo "Creating branch ${HEAD_BRANCH} at ${BASE_SHA}."
  gh api --method POST "repos/${GH_REPO}/git/refs" \
    -f ref="refs/heads/${HEAD_BRANCH}" -F sha="${BASE_SHA}" >/dev/null
fi

payload=$(mktemp)
trap 'rm -f "${payload}"' EXIT

jq -n \
  --arg repo "${GH_REPO}" \
  --arg branch "${HEAD_BRANCH}" \
  --arg message "${COMMIT_MESSAGE}" \
  --arg oid "${BASE_SHA}" \
  --argjson additions "${additions}" \
  --argjson deletions "${deletions}" \
  '{
     query: "mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid url } } }",
     variables: {
       input: {
         branch: {
           repositoryNameWithOwner: $repo,
           branchName: $branch
         },
         message: { headline: $message },
         expectedHeadOid: $oid,
         fileChanges: {
           additions: $additions,
           deletions: $deletions
         }
       }
     }
   }' > "${payload}"

echo "Creating signed commit on ${HEAD_BRANCH}."
commit_url=$(gh api graphql --input "${payload}" --jq '.data.createCommitOnBranch.commit.url')
echo "Commit: ${commit_url}"

existing=$(gh pr list --repo "${GH_REPO}" --head "${HEAD_BRANCH}" --state open --json url --jq '.[0].url // empty')
if [ -n "${existing}" ]; then
  echo "Pull request already open, refreshed in place: ${existing}"
  gh pr edit "${existing}" --repo "${GH_REPO}" --title "${PR_TITLE}" --body "${PR_BODY}" >/dev/null
  echo "pr_url=${existing}" >> "${GITHUB_OUTPUT:-/dev/null}"
  exit 0
fi

pr_url=$(gh pr create --repo "${GH_REPO}" \
  --base "${BASE_BRANCH}" \
  --head "${HEAD_BRANCH}" \
  --title "${PR_TITLE}" \
  --body "${PR_BODY}")
echo "Pull request: ${pr_url}"
echo "pr_url=${pr_url}" >> "${GITHUB_OUTPUT:-/dev/null}"
