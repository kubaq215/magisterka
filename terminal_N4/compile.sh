#!/bin/bash

SCRIPT_DIR="$(dirname "$(realpath "$0")")"

cd $SCRIPT_DIR
rm build/ -rf
rm install/ -rf

meson build --prefix=`pwd`/install
ninja -C build
cd build/
ninja install
