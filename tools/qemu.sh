#!/bin/bash

qemu-system-aarch64 -nographic -machine virt -bios u-boot.bin -cpu cortex-a57 -smp 4 -m 2G \
    -drive if=none,file=sd.img,format=raw,id=hd0 \
    -device virtio-blk-device,drive=hd0
