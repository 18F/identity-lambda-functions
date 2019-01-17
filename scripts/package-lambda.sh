#!/bin/bash
set -eux

echo "Hello from $0"

pwd
ls -la
tree || echo 'no tree'

zip -r build/function.zip main.rb vendor .ruby-version Gemfile Gemfile.lock
