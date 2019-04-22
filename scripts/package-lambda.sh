#!/bin/bash
set -euxo pipefail

# Record current git revision so code can read it out of the .zip bundle
git rev-parse HEAD > REVISION.txt

pwd
ls -la

zip -r build/function.zip . --exclude 'build/*' --exclude '.git/*'
