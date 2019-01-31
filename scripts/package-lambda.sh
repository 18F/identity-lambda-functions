#!/bin/bash
set -euxo pipefail

pwd
ls -la

zip -r build/function.zip . --exclude 'build/*' --exclude '.git/*'
