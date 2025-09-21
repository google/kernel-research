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
set -eo pipefail

SCRIPT_DIR=$(dirname $(realpath "$0"))
IMAGE_DB_DIR="$SCRIPT_DIR/../../image_db"
KXDB_DIR="$SCRIPT_DIR/../../kxdb_tool"
DISTRO="$1"
RELEASE="$2"

echo "Downloading release $RELEASE"
"$IMAGE_DB_DIR/download_release.sh" "$DISTRO" "$RELEASE" dbgsym,vmlinuz >/dev/null

echo "Processing release $RELEASE"
"$IMAGE_DB_DIR/download_release.sh" "$DISTRO" "$RELEASE" process --only-db

echo "Collecting runtime data..."
"$IMAGE_DB_DIR/collect_runtime_data.sh"

echo "Creating db for release $DISTRO $RELEASE"
"$KXDB_DIR/kxdb_tool.py" -o db.kxdb --image-db-path "$IMAGE_DB_DIR" --release-filter-add "$DISTRO/$RELEASE"
"$KXDB_DIR/kxdb_tool.py" -i db.kxdb -o db.json --indent 4

if [[ "$3" == "--upload" ]]; then
    echo "Uploading dbs"
    for EXT in kxdb json; do
        gcloud storage cp -Z -a publicRead db.$EXT gs://kernelxdk/db/$DISTRO/$RELEASE.$EXT
    done

    echo "Uploading missing image_db information"
    gcloud storage rsync "$IMAGE_DB_DIR/releases/$DISTRO/$RELEASE" "gs://kernel-research/image_db/releases/$DISTRO/$RELEASE" -a publicRead -x "^(?!(btf|btf.json|rop_actions.json|slabinfo.txt|stack_pivots.json|structs.json|symbols.txt|version.txt)$).*"
fi
