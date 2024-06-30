#!/bin/bash
SCRIPT_DIR=$(dirname $(realpath "$0"))
UBUNTU_BASE_URL="https://mirrors.edge.kernel.org/ubuntu/pool/main/l"
KERNELCTF_BASE_URL="https://storage.googleapis.com/kernelctf-build/releases"

ARGS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --) # stop processing special arguments after "--"
        shift
        while [[ $# -gt 0 ]]; do ARGS+=("$1"); shift; done
        break
        ;;
    -*|--*) echo "Unknown option $1"; usage;;
    *) ARGS+=("$1"); shift;;
  esac
done
set -- "${ARGS[@]}"

usage() {
    echo "Usage: $0 (kernelctf|ubuntu) (list|<release-name>) (vmlinuz|dbgsym|headers|modules|all)";
    exit 1;
}

release_format() {
    declare -A groups

    while IFS= read -r line; do
        [[ "$line" =~ ^(.*)-([^-]*)$ ]]
        prefix=${BASH_REMATCH[1]}
        if [[ -v "groups[$prefix]" ]]; then groups[$prefix]+=", "; fi
        groups[$prefix]+="$line"
    done

    keys=( $( echo ${!groups[@]} | tr ' ' $'\n' | sort -V ) )
    # Output the grouped strings
    for prefix in "${keys[@]}"; do
        echo " - $prefix: ${groups[$prefix]}"
        echo
    done
}

list_ubuntu_releases() {
    printf "Supported Ubuntu releases:\n\n"
    curl -s "$UBUNTU_BASE_URL/linux-signed/" | sed -n 's/.*linux-image-[0-9][^>]*-generic_\([^>]*\)_amd64.deb.*/\1/p' | \
        sort -V | sed -z '$ s/\n$//' | release_format
}

list_kernelctf_releases() {
    printf "Supported kernelCTF releases:\n\n"
    curl -s https://raw.githubusercontent.com/google/security-research/master/kernelctf/server/releases.yaml | \
        grep -Eoh "^[^: ]*" | sort -V | sed -z '$ s/\n$//' | release_format
}

download_file() {
    URL="$1"
    DST_FN="$2"

    if [ ! -f "$DST_FN" ]; then
        echo "Downloading '$DST_FN' from $URL"
        if ! curl -f "$URL" -o "$DST_FN"; then
            echo "Failed to download '$DST_FN' from $URL"
            exit 1
        fi
        return 1
    fi
    return 0
}

download_ddeb_and_extract() {
    URL="$1"
    DEB_FN="$2"
    DST_DIR="$3"
    FILE_SRC_FN="$4"
    FILE_DST_FN="$5"

    if [ -f $DEB_FN ]; then mv $DEB_FN "debs/$DEB_FN"; fi

    if [ -f "$FILE_DST_FN" ]; then return; fi

    mkdir -p debs
    download_file "$URL" "debs/$DEB_FN"

    if [ ! -d "$DST_DIR" ]; then
        echo "Extracting 'debs/$DEB_FN' into '$DST_DIR'..."
        dpkg-deb -x "debs/$DEB_FN" "$DST_DIR"
    fi

    if [ ! -z "$FILE_SRC_FN" ]; then
        mv "$DST_DIR/$FILE_SRC_FN" "$FILE_DST_FN"
        rm -rf "$DST_DIR"
    fi
}

# this one won't create zero-length files
save() {
    local FILE="$1"
    if [ -f "$FILE" ]; then rm "$FILE"; fi
    while IFS= read -r LINE; do echo "$LINE" >> "$FILE"; done
}

process_vmlinux() {
    if [ ! -f "btf" ];                then pahole --btf_encode_detached btf vmlinux; fi
    if [ ! -f "btf.json" ];           then bpftool btf dump -j file btf | save btf.json; fi
    if [ ! -f "btf_formatted.json" ]; then jq . btf.json | save btf_formatted.json; fi
    if [ ! -f "pahole.txt" ];         then pahole vmlinux | save pahole.txt; fi
    if [ ! -f "symbols.txt" ];        then nm vmlinux | save symbols.txt; fi
    if [ ! -f ".config" ];            then $SCRIPT_DIR/extract-ikconfig vmlinux | save .config; fi
    if [ ! -f "rop_gadgets.txt" ];    then ROPgadget --binary vmlinux | save rop_gadgets.txt; fi
}

DISTRO="$1"
RELEASE_NAME="$2"
DOWNLOAD_TYPE="$3"

if [ -z "$DOWNLOAD_TYPE" ]; then DOWNLOAD_TYPE="all"; fi
if [ "$DOWNLOAD_TYPE" = "all" ]; then DOWNLOAD_TYPE="vmlinuz,dbgsym,headers,modules"; fi
if [[ ! "$DISTRO" =~ ^(kernelctf|ubuntu)$ ]]; then usage; fi

if [[ -z "$RELEASE_NAME" || "$RELEASE_NAME" == "list" ]]; then
    $"list_${DISTRO}_releases"
    exit 0
fi

RELEASE_DIR="$SCRIPT_DIR/releases/$DISTRO/$RELEASE_NAME"
mkdir -p $RELEASE_DIR
pushd $RELEASE_DIR >/dev/null

case $DISTRO in
  kernelctf)
    if [[ "$DOWNLOAD_TYPE" =~ "vmlinuz" ]]; then
        download_file "$KERNELCTF_BASE_URL/$RELEASE_NAME/bzImage" "vmlinuz"
    fi

    if [[ "$DOWNLOAD_TYPE" =~ "dbgsym" && ! -f "vmlinux" ]]; then
        download_file "$KERNELCTF_BASE_URL/$RELEASE_NAME/vmlinux.gz" vmlinux.gz
        echo "Extracing vmlinux.gz..."
        gzip -d vmlinux.gz
    fi
    ;;
  ubuntu)
    if ! [[ "$RELEASE_NAME" =~ ^(.*?)[.](.*)$ ]]; then
        echo "Invalid release name."
        list_ubuntu_releases
        exit 1
    fi
    RELEASE_SHORT=${BASH_REMATCH[1]}

    IMAGE_URL="$UBUNTU_BASE_URL/linux-signed/linux-image-$RELEASE_SHORT-generic_${RELEASE_NAME}_amd64.deb"
    HEADERS_URL="$UBUNTU_BASE_URL/linux/linux-headers-${RELEASE_SHORT}_${RELEASE_NAME}_all.deb"
    GENHEADERS_URL="$UBUNTU_BASE_URL/linux/linux-headers-${RELEASE_SHORT}-generic_${RELEASE_NAME}_amd64.deb"
    MODULES_URL="$UBUNTU_BASE_URL/linux/linux-modules-${RELEASE_SHORT}-generic_${RELEASE_NAME}_amd64.deb"
    DBGSYM_URL="http://ddebs.ubuntu.com/pool/main/l/linux/linux-image-unsigned-${RELEASE_SHORT}-generic-dbgsym_${RELEASE_NAME}_amd64.ddeb"

    if [[ "$DOWNLOAD_TYPE" =~ "vmlinuz" ]]; then
        download_ddeb_and_extract $IMAGE_URL linux-image.deb linux-image boot/vmlinuz-$RELEASE_SHORT-generic vmlinuz
    fi

    if [[ "$DOWNLOAD_TYPE" =~ "headers" ]]; then
        download_ddeb_and_extract $HEADERS_URL linux-headers.deb linux-headers
        download_ddeb_and_extract $GENHEADERS_URL linux-headers-generic.deb linux-headers
    fi

    if [[ "$DOWNLOAD_TYPE" =~ "modules" ]]; then
        download_ddeb_and_extract $MODULES_URL linux-modules.deb linux-modules
        cp linux-modules/boot/config-$RELEASE_SHORT-generic .config
        cp linux-modules/boot/System.map-$RELEASE_SHORT-generic System.map
    fi

    if [[ "$DOWNLOAD_TYPE" =~ "dbgsym" ]]; then
        download_ddeb_and_extract $DBGSYM_URL dbgsym.ddeb dbgsym "usr/lib/debug/boot/vmlinux-$RELEASE_SHORT-generic" vmlinux
    fi
    ;;
  *)
    usage ;;
esac

if [ -f "vmlinux" ]; then
    process_vmlinux
fi

popd >/dev/null