DESCRIPTION = "Memory watchpoint kernel module"
LICENSE = "CLOSED"

FILESEXTRAPATHS:prepend := "${THISDIR}:"

SRC_URI = "file://Makefile \
           file://memory-watchpoint-mod.c"

S = "${WORKDIR}"

inherit module

EXTRA_OEMAKE = "KERNEL_SRC=${STAGING_KERNEL_DIR}"