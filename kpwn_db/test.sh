SCRIPT_DIR=$(dirname $(realpath "$0"))
cd "$SCRIPT_DIR"
python3 -m unittest
