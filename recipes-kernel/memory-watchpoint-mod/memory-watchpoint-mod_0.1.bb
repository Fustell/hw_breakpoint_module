# memory-watchpoint-mod.bb

DESCRIPTION = "Memory watchpoint kernel module"
LICENSE = "CLOSED"

FILESEXTRAPATHS:prepend := "${THISDIR}:"

SRC_URI = "file://Makefile \
           file://memory-watchpoint-mod.c"

S = "${WORKDIR}"

inherit module

DEPENDS += "virtual/kernel"
do_compile[depends] += "virtual/kernel:do_shared_workdir"
