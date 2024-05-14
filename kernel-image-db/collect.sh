#!/bin/bash
set -e

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
DB_DIR="$SCRIPT_DIR/database"

process_vmlinux() {
    if [ ! -f "btf" ];                then pahole --btf_encode_detached btf vmlinux; fi
    if [ ! -f "btf.json" ];           then bpftool btf dump -j file btf > btf.json; fi
    if [ ! -f "btf_formatted.json" ]; then jq . btf.json > btf_formatted.json; fi
    if [ ! -f "pahole.txt" ];         then pahole vmlinux > pahole.txt; fi
    if [ ! -f "symbols.txt" ];        then nm vmlinux > symbols.txt; fi
    if [ ! -f ".config" ];            then $SCRIPT_DIR/extract-ikconfig vmlinux > .config; fi
}

yq -r '.kernelctf|keys[]' releases.yaml | while read -r RELEASE; do
    echo "====================================================="
    echo "Processing kernelCTF release: $RELEASE"
    echo "====================================================="
    RELEASE_DIR="$DB_DIR/kernelctf/$RELEASE"
    mkdir -p $RELEASE_DIR
    cd $RELEASE_DIR

    set -x
    if [ ! -f "vmlinux" ]; then
        wget https://storage.googleapis.com/kernelctf-build/releases/$RELEASE/vmlinux.gz -O vmlinux.gz
        gzip -d vmlinux.gz
    fi

    process_vmlinux
    set +x
done

yq -r '.ubuntu|keys[]' releases.yaml | while read -r RELEASE_FULL; do
    [[ "$RELEASE_FULL" =~ ^(.*?)[.](.*)$ ]]
    RELEASE=${BASH_REMATCH[1]}

    echo "====================================="
    echo "Processing Ubuntu release: $RELEASE"
    echo "====================================="
    RELEASE_DIR="$DB_DIR/ubuntu/$RELEASE"
    mkdir -p $RELEASE_DIR
    cd $RELEASE_DIR

    set -x
    if [ ! -f "dbgsym.ddeb" ]; then
        wget https://ddebs.ubuntu.com/pool/main/l/linux/linux-image-unsigned-$RELEASE-generic-dbgsym_${RELEASE_FULL}_amd64.ddeb -O dbgsym.ddeb
    fi

    if [ ! -f "vmlinux" ]; then
        mkdir -p dbgsym 2>/dev/null || true
        ar -x dbgsym.ddeb --output dbgsym
        tar -C dbgsym -xvf dbgsym/data.tar.xz ./usr/lib/debug/boot/vmlinux-$RELEASE-generic --occurrence
        mv dbgsym/usr/lib/debug/boot/vmlinux-$RELEASE-generic vmlinux
        rm -rf dbgsym
    fi

    process_vmlinux
    set +x
done