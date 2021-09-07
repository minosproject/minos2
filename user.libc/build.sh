#!/bin/sh

INSTALL_DIR=$1

if [ -z "$STRING" ]; then
	INSTALL_DIR=$(dirname $(pwd))/out
fi

echo "Libc install dir ${INSTALL_DIR}"

./configure CROSS_COMPILE=aarch64-linux-gnu- --disable-shared --target=aarch64 \
	--prefix=${INSTALL_DIR} --with-malloc=mallocng
