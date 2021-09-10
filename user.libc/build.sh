#!/bin/sh

INSTALL_DIR=$1
LIBC_TAGET_ARCH=$2
LIBC_CROSS_COMPILE=$3

if [ -z "$INSTALL_DIR" ]; then
	INSTALL_DIR=$(dirname $(pwd))/out
fi

if [ -z "$LIBC_TAGET_ARCH" ]; then
	LIBC_TAGET_ARCH="$(uname -m)"
fi

echo "LIBC INSTALL-DIR:${INSTALL_DIR} ARCH:${LIBC_TAGET_ARCH} CROSS:${LIBC_CROSS_COMPILE}"

./configure CROSS_COMPILE=${LIBC_CROSS_COMPILE} --disable-shared --target=${LIBC_TAGET_ARCH} \
	--prefix=${INSTALL_DIR} --with-malloc=mallocng
