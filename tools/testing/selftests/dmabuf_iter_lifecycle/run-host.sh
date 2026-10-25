#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Host-stub lifecycle coverage, not a kernel concurrency or verifier test.
set -eu
src=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
kernel=$(CDPATH= cd -- "$src/../../../.." && pwd)
: "${TEST_OUTPUT:?set TEST_OUTPUT outside the source tree}"
: "${HOSTCC:=cc}"
mkdir -p "$TEST_OUTPUT"
"$HOSTCC" -std=gnu11 -g -fsanitize=address,undefined -I"$src/include" \
 -DITER_SOURCE="\"$kernel/kernel/bpf/dmabuf_iter.c\"" "$src/test.c" -o "$TEST_OUTPUT/test"
"$TEST_OUTPUT/test"
