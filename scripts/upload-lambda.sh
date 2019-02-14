#!/bin/bash
# Take built zip bundle and upload to S3 in each of the AWS accounts listed by
# environment variables.
set -euo pipefail

run() {
    echo >&2 "+ $*"
    "$@"
}

# Dereference a variable name.
#
# For example: if you want the contents of `$foo_sandbox`, then you can run:
#   foo_sandbox=somevalue
#   env=sandbox
#   deref "foo_$env"
#
deref() {
    echo "${!1}"
}

deploy_to_env() {
    local env
    env="$1"

    echo
    echo "===== Deploying to ${env} ====="

    AWS_ACCESS_KEY_ID="$(deref "LG_${env}_AWS_ACCESS_KEY_ID")"
    AWS_SECRET_ACCESS_KEY="$(deref "LG_${env}_AWS_SECRET_ACCESS_KEY")"
    LG_DEPLOY_S3_BUCKET="$(deref "LG_${env}_DEPLOY_S3_BUCKET")"

    cat <<EOM
CircleCI variables for AWS account env "$env":
    LG_${env}_AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID
    LG_${env}_AWS_SECRET_ACCESS_KEY: <length ${#AWS_SECRET_ACCESS_KEY}>
    LG_${env}_DEPLOY_S3_BUCKET: $LG_DEPLOY_S3_BUCKET
EOM

    # aws cli needs these
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

    run aws s3 cp "$built_zip" "s3://$LG_DEPLOY_S3_BUCKET/${LG_DEPLOY_S3_PREFIX%%/}/$git_rev.zip"

    echo "Uploaded $git_rev.zip successfully."
    echo "Deploy to $env is complete!"

    # To deploy uploaded bundle:
    # in separate script: aws lambda update-function-code --function-name helloWorld -bucket MyBucket --s3-key circleci/repo-name/$git_rev.zip
    # Typically we use `cloudlib lambda deploy <function-name> <environment>`
}

# Print expected CircleCI input environment variables
cat <<EOM
CircleCI env variables:
    LG_AWS_ACCOUNTS: '$LG_AWS_ACCOUNTS'
    LG_DEPLOY_S3_PREFIX: ${LG_DEPLOY_S3_PREFIX-}
EOM

# fill in default prefix
if [ -z "${LG_DEPLOY_S3_PREFIX-}" ]; then
    repo_name="$(run cat "$(dirname "$0")/repo-name.txt")"
    LG_DEPLOY_S3_PREFIX="${LG_DEPLOY_S3_PREFIX-circleci/$repo_name/}"
fi

built_zip="build/function.zip"

run sha256sum "$built_zip"

git_rev="$(run git rev-parse HEAD)"

for env in $LG_AWS_ACCOUNTS; do
    deploy_to_env "$env"
done
