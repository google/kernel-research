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

DISTRO="$1"
RELEASE_NAME="$2"
CUSTOM_MODULES="$3"

SCRIPT_DIR=$(dirname $(realpath "$0"))
cd $SCRIPT_DIR

RELEASE_DIR="$SCRIPT_DIR/../kernel-image-db/releases/$DISTRO/$RELEASE_NAME"
CUSTOM_MODULES_DIR="$RELEASE_DIR/custom_modules"
CUSTOM_MODULES_BUILD_DIR="$RELEASE_DIR/.custom_modules_build"

usage() {
    echo "Usage: $0 (kernelctf|ubuntu) <release-name> <helloworld|xdk_device>";
    exit 1;
}

if [[ $# -lt 3 ]]; then usage; fi
if [ -z "$CUSTOM_MODULES" ]; then exit; fi

../kernel-image-db/download_release.sh "$DISTRO" "$RELEASE_NAME" headers
VERSION_FN="$RELEASE_DIR/version.txt"
if [ ! -f "$VERSION_FN" ]; then
    ./run.sh --only-command-output $DISTRO $RELEASE_NAME -- cat /proc/version > $VERSION_FN
fi

mkdir -p $CUSTOM_MODULES_DIR
rm $CUSTOM_MODULES_DIR/*.ko
mkdir -p "$CUSTOM_MODULES_BUILD_DIR"

for MODULE_NAME in ${CUSTOM_MODULES//,/ }; do
    HDR_DIR="$RELEASE_DIR/linux-headers-for-module/"
    MODULE_DIR="$SCRIPT_DIR/../third_party/kernel-modules/$MODULE_NAME"
    BUILD_DIR="$CUSTOM_MODULES_BUILD_DIR/$MODULE_NAME"

    cp -a "$MODULE_DIR/." "$BUILD_DIR/"

    if [[ "$DISTRO" = "kernelctf" ]] && [ ! -f "$HDR_DIR/.modules_prepared" ]; then
        make -C $HDR_DIR olddefconfig
        make -C $HDR_DIR prepare

        # "LOCALVERSION=" is needed because otherwise if the repo is not clean, it will add a + into
        #   the version (e.g. 6.1.81 -> 6.1.81+) which makes the module incompatible
        LOCALVERSION=""
        if grep '[+]' $VERSION_FN; then LOCALVERSION="+"; fi
        make LOCALVERSION=$LOCALVERSION -C $HDR_DIR modules_prepare && touch "$HDR_DIR/.modules_prepared"
    fi

    KBUILD_MODPOST_WARN=1 make -C $HDR_DIR M=$BUILD_DIR modules || exit 1
    cp "$BUILD_DIR/$MODULE_NAME.ko" $CUSTOM_MODULES_DIR/
    #make -C $HDR_DIR M=$MODULE_DIR clean
done
tar --directory=$CUSTOM_MODULES_DIR --owner=root --group=root -cf $CUSTOM_MODULES_DIR.tar . > /dev/null
