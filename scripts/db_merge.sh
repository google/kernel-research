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
set -ex

SCRIPT_DIR=$(dirname $(realpath "$0"))
IMAGE_DB_DIR="$SCRIPT_DIR/../kernel-image-db"
KPWN_DB_DIR="$SCRIPT_DIR/../kpwn_db"

mkdir -p db
rm -rf db/*

if [ "$1" == "--rebuild" ]; then
    echo -n > db_releases.txt
else
    gcloud storage cp gs://kernel-research/pwnkit/db/kernelctf.kpwn db/_original.kpwn; echo
    "$KPWN_DB_DIR/kpwn_db.py" -i db/_original.kpwn --list-targets | grep kernelctf | sed "s/kernelctf\///" > db_releases.txt
fi

gcloud storage ls gs://kernel-research/pwnkit/db/kernelctf/*.kpwn > gcs_releases.txt
cat gcs_releases.txt | grep -v -f db_releases.txt > missing_db_releases.txt || true

if [[ ! -s "missing_db_releases.txt" ]]; then echo "Nothing is missing from DB, exiting..."; exit 0; fi

echo "The following files were not merged into the DB yet: "
cat missing_db_releases.txt
echo

cat missing_db_releases.txt | gsutil -m cp -I ./db

"$KPWN_DB_DIR/kpwn_db.py" -i "db/*.kpwn" -o kernelctf.kpwn
"$KPWN_DB_DIR/kpwn_db.py" -i kernelctf.kpwn -o kernelctf.json

echo "Uploading new db"
for EXT in kpwn json; do
    gcloud storage cp -Z -a publicRead kernelctf.$EXT gs://kernel-research/pwnkit/db/kernelctf.$EXT
done
