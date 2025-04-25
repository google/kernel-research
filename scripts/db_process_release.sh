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
IMAGE_DB_DIR="$SCRIPT_DIR/../kernel-image-db"
KPWN_DB_DIR="$SCRIPT_DIR/../kpwn_db"
DISTRO="$1"
RELEASE="$2"

echo "Downloading release $RELEASE"
"$IMAGE_DB_DIR/download_release.sh" "$DISTRO" "$RELEASE" dbgsym >/dev/null

echo "Processing release $RELEASE"
"$IMAGE_DB_DIR/download_release.sh" "$DISTRO" "$RELEASE" process --only-db

echo "Collecting runtime data..."
"$IMAGE_DB_DIR/collect_runtime_data.sh"

echo "Creating db for release $DISTRO $RELEASE"
"$KPWN_DB_DIR/kpwn_db.py" -o db.kpwn --kernel-image-db-path "$IMAGE_DB_DIR" --release-filter-add "$DISTRO/$RELEASE"
"$KPWN_DB_DIR/kpwn_db.py" -i db.kpwn -o db.json --indent 4

if [[ "$3" == "--upload" ]]; then
    echo "Uploading dbs"
    for EXT in kpwn json; do
        gcloud storage cp -Z -a publicRead db.$EXT gs://kernel-research/pwnkit/db/$DISTRO/$RELEASE.$EXT
    done

    echo "Uploading missing kernel-image-db information"
    gcloud storage rsync "$IMAGE_DB_DIR/releases/$DISTRO/$RELEASE" "gs://kernel-research/kernel-image-db/releases/$DISTRO/$RELEASE" -a publicRead -x "^(?!(btf|btf.json|rop_actions.json|slabinfo.txt|stack_pivots.json|structs.json|symbols.txt|version.txt)$).*"
fi