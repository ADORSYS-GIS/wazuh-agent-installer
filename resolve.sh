#!/bin/bash
THREADS=(
"PRRT_kwDOSx70ac6n_yQg"
"PRRT_kwDOSx70ac6n_yQj"
"PRRT_kwDOSx70ac6n_yQn"
"PRRT_kwDOSx70ac6n_yQv"
"PRRT_kwDOSx70ac6n_yQy"
"PRRT_kwDOSx70ac6n_yQ2"
"PRRT_kwDOSx70ac6n_yQ8"
"PRRT_kwDOSx70ac6n_yRD"
"PRRT_kwDOSx70ac6n_yRG"
"PRRT_kwDOSx70ac6n_yRK"
"PRRT_kwDOSx70ac6n_yRQ"
"PRRT_kwDOSx70ac6n_yRZ"
"PRRT_kwDOSx70ac6n_yRg"
)

for id in "${THREADS[@]}"; do
  gh api graphql -f query='mutation($id: ID!) { resolveReviewThread(input: {threadId: $id}) { thread { isResolved } } }' -F id="$id" >/dev/null 2>&1
done
echo "Resolved threads!"
