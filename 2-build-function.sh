#!/bin/bash
set -eo pipefail
rm -rf node_modules
npm install --omit=dev
zip -r function.zip index.mjs node_modules .env