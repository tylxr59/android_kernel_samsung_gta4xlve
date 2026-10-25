#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Keep every generated fixture in caller-supplied output, outside the source.
set -eu
src=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${RESOLVE_BTFIDS:?set RESOLVE_BTFIDS to the built host resolver}"
: "${TEST_OUTPUT:?set TEST_OUTPUT to a disposable output directory}"
: "${PAHOLE:=pahole}"
: "${LLVM_OBJCOPY:=llvm-objcopy}"
: "${HOSTCC:=cc}"
export LLVM_OBJCOPY
mkdir -p "$TEST_OUTPUT"
cd "$TEST_OUTPUT"
"$HOSTCC" -O0 -g -fno-eliminate-unused-debug-types "$src/a.c" "$src/b.c" "$src/c.c" -o fixture
cp fixture missing-btf
flags=''
for flag in skip_encoding_btf_enum64 skip_encoding_btf_decl_tag skip_encoding_btf_type_tag; do
 if "$PAHOLE" --help | grep -q -- "--$flag"; then flags="$flags --$flag"; fi
done
"$PAHOLE" $flags -J fixture
"$RESOLVE_BTFIDS" fixture
"$LLVM_OBJCOPY" --dump-section .BTF_ids=ids.bin fixture
python3 - <<'PY'
import struct
from pathlib import Path
count, *ids = struct.unpack('<3I', Path('ids.bin').read_bytes())
assert count == 2 and len(set(ids)) == 2 and all(ids) and ids == sorted(ids), (count, ids)
print('PASS: distinct layouts with duplicate type names and a late unique type resolve')
PY
if "$RESOLVE_BTFIDS" missing-btf > missing-btf.txt 2>&1; then
 echo 'FAIL: resolver accepted missing BTF' >&2
 exit 1
fi
echo 'PASS: missing BTF rejected'
