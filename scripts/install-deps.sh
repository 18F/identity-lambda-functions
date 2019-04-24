#!/bin/sh
set -eux
cd "$(dirname "$0")/.."

bundle install --deployment --without=development --jobs=4 --retry=3 --path vendor/bundle

# show resulting bundler config values
bundle config
