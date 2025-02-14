#!/bin/bash
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
set -e

SCRIPT_DIR=$(dirname $(realpath "$0"))
IMAGE_DB_DIR="$SCRIPT_DIR/../kernel-image-db"
KPWN_DB_DIR="$SCRIPT_DIR/../kpwn_db"

if [ "$1" == "--rebuild" ]; then
    echo -n > db_releases.txt
else
    gcloud storage cp gs://kernel-research/pwnkit/db/kernelctf.kpwn db.kpwn; echo
    "$KPWN_DB_DIR/kpwn_db.py" -i db.kpwn --list-targets | grep kernelctf | sed "s/kernelctf\///" > db_releases.txt
fi

# gcloud storage ls gs://kernelctf-build/releases | sed "s/.*releases\/\(.*\)\//\1/" > build_releases.txt

# missing_releases = kernelctf_releases without db_releases and skipped_releases
curl -s https://raw.githubusercontent.com/google/security-research/master/kernelctf/server/releases.yaml | grep -Eoh "^[^: ]*"  > kernelctf_releases.txt
cat kernelctf_releases.txt | grep -v -f db_releases.txt | grep -v -f <(cat skipped_releases.txt | sed 's/\s*#.*//') > missing_releases.txt || true
if [[ ! -s "missing_releases.txt" ]]; then echo "Nothing is missing from the database, exiting..."; exit 0; fi

echo "The following releases missing from the DB, adding them now:"
cat missing_releases.txt | sed 's/$/, /' | tr -d '\n'
echo
