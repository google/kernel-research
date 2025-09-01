# Copyright 2025 Google LLC
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

if [ ! -f kernelctf.kxdb ]; then
    gcloud storage cp gs://kernelxdk/db/kernelctf.kxdb kernelctf.kxdb
fi

FILES_TO_DOWNLOAD=$($KXDB_DIR/kxdb_tool.py -i kernelctf.kxdb --partial-list-files 2>/dev/null || true)
if [ -z "$FILES_TO_DOWNLOAD" ]; then echo "Nothing to download, exiting..."; exit 0; fi

REGEX_FILE_LIST=$(echo "$FILES_TO_DOWNLOAD"|tr ' ' '|')
EXCLUDE_REGEX="^(?!.*/($REGEX_FILE_LIST)$).*"
echo "Files to download: $FILES_TO_DOWNLOAD (regex: $EXCLUDE_REGEX)"

gcloud storage rsync --recursive "gs://kernel-research/image_db/releases/" "$IMAGE_DB_DIR/releases/" -x "$EXCLUDE_REGEX"
"$KXDB_DIR/kxdb_tool.py" -i kernelctf.kxdb --image-db-path $IMAGE_DB_DIR --partial-sync --output-file kernelctf_new.kxdb
"$KXDB_DIR/kxdb_tool.py" -i kernelctf_new.kxdb -o kernelctf_new.json

echo "Uploading new db"
for EXT in kxdb json; do
    gcloud storage cp -Z -a publicRead kernelctf_new.$EXT gs://kernelxdk/db/kernelctf.$EXT
done
