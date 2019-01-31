#!/bin/bash
# Take built zip bundle and upload to S3
set -euo pipefail

run() {
    echo >&2 "+ $*"
    "$@"
}

# Print expected CircleCI input environment variables
cat <<EOM
CircleCI env variables:
LG_AWS_ACCESS_KEY_ID: $LG_AWS_ACCESS_KEY_ID
LG_AWS_SECRET_ACCESS_KEY: <length ${#LG_AWS_SECRET_ACCESS_KEY}>
LG_DEPLOY_S3_BUCKET: $LG_DEPLOY_S3_BUCKET
LG_DEPLOY_S3_PREFIX: ${LG_DEPLOY_S3_PREFIX-}
EOM

# fill in default prefix
if [ -z "${LG_DEPLOY_S3_PREFIX-}" ]; then
    repo_name="$(run cat "$(dirname "$0")/repo-name.txt")"
    LG_DEPLOY_S3_PREFIX="${LG_DEPLOY_S3_PREFIX-circleci/$repo_name/}"
fi

# Put AWS API key in expected variable
AWS_ACCESS_KEY_ID="$LG_AWS_ACCESS_KEY_ID"
AWS_SECRET_ACCESS_KEY="$LG_AWS_SECRET_ACCESS_KEY"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

built_zip="build/function.zip"

set -x
sha256sum "$built_zip"

git_rev="$(git rev-parse HEAD)"
aws s3 cp "$built_zip" "s3://$LG_DEPLOY_S3_BUCKET/${LG_DEPLOY_S3_PREFIX%%/}/$git_rev.zip"

set +x

echo "Uploaded $git_rev.zip successfully"

# To deploy uploaded bundle:
# in separate script: aws lambda update-function-code --function-name helloWorld -bucket MyBucket --s3-key circleci/repo-name/$git_rev.zip
