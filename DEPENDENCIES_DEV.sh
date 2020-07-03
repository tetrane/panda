#!/bin/bash

# panda
STRETCH_DEPENDENCIES="$STRETCH_DEPENDENCIES
chrpath
libc++-dev
libcapstone-dev
libdwarf-dev
libelf-dev
libfdt-dev
libglib2.0-dev
libpixman-1-dev
libprotobuf-c0-dev
libprotoc-dev
pkg-config
protobuf-c-compiler
protobuf-compiler
python-pycparser
qemu-utils
zlib1g-dev
"

function echo_error() {
    echo -ne '\033[0;31m'
    echo $@
    echo -ne '\033[0m'
}

function run() {
    $@ >/tmp/reven_dependencies.log 2>&1
    exit_code=$?
    if [ "$exit_code" != "0" ]; then
        echo "======================= BEGIN APT LOG ======================="
        cat /tmp/reven_dependencies.log
        echo "=======================  END APT LOG  ======================="
        echo_error -e "\nThere was a problem installing dependencies. Please check-out the logs above."
        exit $exit_code
    fi
}

if [ -z "${MAIN_SCRIPT+x}" ]; then
    echo "Updating package list"
    run apt update
    echo "Installing dependencies. This may take a while."
    DEBIAN_VERSION=$(lsb_release -sc)
    if [ "$DEBIAN_VERSION" = "stretch" ]; then
        run apt install -y $STRETCH_DEPENDENCIES
        run apt install -t stretch-backports -y $STRETCH_BACKPORTS_DEPENDENCIES
    elif [ "$DEBIAN_VERSION" = "buster" ]; then
        run apt install -y $BUSTER_DEPENDENCIES
    fi
    export MAIN_SCRIPT=1
fi


