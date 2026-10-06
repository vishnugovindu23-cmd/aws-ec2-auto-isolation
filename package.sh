#!/usr/bin/env bash
# Builds build/lambda.zip for Terraform. boto3 ships with the Lambda runtime, so only our code is packaged.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build
rm -f build/lambda.zip
zip -rq build/lambda.zip isolation -x '*__pycache__*'
echo "Built build/lambda.zip"
