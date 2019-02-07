#!/bin/sh
set -eux
cd "$(dirname "$0")/.."
bundle install --jobs=4 --retry=3 --path vendor/bundle
