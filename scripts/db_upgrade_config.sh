set -eo pipefail

SCRIPT_DIR=$(dirname $(realpath "$0"))
IMAGE_DB_DIR="$SCRIPT_DIR/../kernel-image-db"
KXDB_DIR="$SCRIPT_DIR/../kxdb_tool"

if [ ! -f kernelctf.kxdb ]; then
    gcloud storage cp gs://kernel-research/pwnkit/db/kernelctf.kxdb kernelctf.kxdb
fi

FILES_TO_DOWNLOAD=$($KXDB_DIR/kxdb_tool.py -i kernelctf.kxdb --partial-list-files 2>/dev/null || true)
if [ -z "$FILES_TO_DOWNLOAD" ]; then echo "Nothing to download, exiting..."; exit 0; fi

REGEX_FILE_LIST=$(echo "$FILES_TO_DOWNLOAD"|tr ' ' '|')
EXCLUDE_REGEX="^(?!.*/($REGEX_FILE_LIST)$).*"
echo "Files to download: $FILES_TO_DOWNLOAD (regex: $EXCLUDE_REGEX)"

gcloud storage rsync --recursive "gs://kernel-research/kernel-image-db/releases/" "$IMAGE_DB_DIR/releases/" -x "$EXCLUDE_REGEX"
"$KXDB_DIR/kxdb_tool.py" -i kernelctf.kxdb --kernel-image-db-path $IMAGE_DB_DIR --partial-sync --output-file kernelctf_new.kxdb
"$KXDB_DIR/kxdb_tool.py" -i kernelctf_new.kxdb -o kernelctf_new.json

echo "Uploading new db"
for EXT in kxdb json; do
    gcloud storage cp -Z -a publicRead kernelctf_new.$EXT gs://kernel-research/pwnkit/db/kernelctf.$EXT
done
