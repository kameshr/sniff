#!/bin/bash
mkdir /mnt/ramdisk
mkfs.ext3 /dev/ram0
/usr/sbin/rdev -r /dev/ram0 64000
mount /dev/ram0 /mnt/ramdisk
# sniff_dump 10000 /mnt/ramdisk/file.dump
