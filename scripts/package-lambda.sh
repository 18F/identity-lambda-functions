#!/bin/bash
set -eux

echo "Hello from $0"

pwd
ls -la
tree || echo 'no tree'

zip -r config.json config.json.default main.rb identity-audit.rb lib vendor .ruby-version Gemfile Gemfile.lock
