DISTRO="$1"
RELEASE_NAME="$2"
CUSTOM_MODULES="$3"

SCRIPT_DIR=$(dirname $(realpath "$0"))
cd $SCRIPT_DIR

RELEASE_DIR="$SCRIPT_DIR/../kernel-image-db/releases/$DISTRO/$RELEASE_NAME"

usage() {
    echo "Usage: $0 (kernelctf|ubuntu) <release-name> <helloworld|kpwn>";
    exit 1;
}

if [[ $# -lt 3 ]]; then usage; fi

../kernel-image-db/download_release.sh "$DISTRO" "$RELEASE_NAME" headers

rm -rf rootfs/custom_modules/*
for MODULE_NAME in ${CUSTOM_MODULES//,/ }; do
    HDR_DIR="$RELEASE_DIR/linux-headers-for-module/"

    if [[ "$DISTRO" = "kernelctf" ]] && [ ! -f "$HDR_DIR/.modules_prepared" ]; then
        make -C $HDR_DIR olddefconfig
        make -C $HDR_DIR prepare

        # "LOCALVERSION=" is needed because otherwise if the repo is not clean, it will add a + into
        #   the version (e.g. 6.1.81 -> 6.1.81+) which makes the module incompatible
        LOCALVERSION=""
        if grep '[+]' $RELEASE_DIR/version.txt; then LOCALVERSION="+"; fi
        make LOCALVERSION=$LOCALVERSION -C $HDR_DIR modules_prepare && touch "$HDR_DIR/.modules_prepared"
    fi

    KBUILD_MODPOST_WARN=1 make -C $HDR_DIR M=$SCRIPT_DIR/custom-modules/$MODULE_NAME modules || exit 1
    mv custom-modules/$MODULE_NAME/$MODULE_NAME.ko rootfs/custom_modules/
    make -C $HDR_DIR M=$SCRIPT_DIR/custom-modules/$MODULE_NAME clean
done