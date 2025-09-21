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
IMAGE_DB_DIR="$SCRIPT_DIR/../../image_db"
KXDB_DIR="$SCRIPT_DIR/../../kxdb_tool"

./db_get_missing_releases.sh

while IFS= read -r RELEASE <&3; do
    if [ "$1" == "--auto-cleanup" ]; then
        rm -rf "$IMAGE_DB_DIR/releases"
        find "$IMAGE_DB_DIR"
    fi

    echo "Downloading release $RELEASE"
    "$IMAGE_DB_DIR/download_release.sh" kernelctf $RELEASE dbgsym,vmlinuz >/dev/null || continue

    echo "Processing release $RELEASE"
    "$IMAGE_DB_DIR/download_release.sh" kernelctf $RELEASE process --only-db || continue

    echo "Collecting runtime data..."
    "$IMAGE_DB_DIR/collect_runtime_data.sh" || continue

    echo "Adding $RELEASE to the database"
    "$KXDB_DIR/kxdb_tool.py" -i db.kxdb -o db.kxdb --image-db-path "$IMAGE_DB_DIR"

    echo "Uploading new db"
    gcloud storage cp -Z -a publicRead db.kxdb gs://kernelxdk/db/kernelctf.kxdb
done 3< missing_db_releases.txt
