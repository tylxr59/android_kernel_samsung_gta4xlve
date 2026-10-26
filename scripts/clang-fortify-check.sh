#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# GCC uses the original wrappers. Clang needs object-size propagation and the
# global __builtin_constant_p fix available in Clang 13 (also in 12.0.1).
# Deliberately require 13 here instead of relying on a downstream 12.x backport.
if "$@" -Werror -x c -c -o /dev/null - <<'SRC'
#if !defined(__clang__) || __clang_major__ < 13
#error Clang 13 or newer required
#endif
#if !__has_attribute(pass_object_size) || !__has_attribute(overloadable)
#error Missing Clang FORTIFY attributes
#endif
extern __attribute__((always_inline,gnu_inline,overloadable)) inline
unsigned long check(const void *const __attribute__((pass_object_size(0))) p)
{
 return __builtin_object_size(p,0);
}
SRC
then echo y; else echo n; fi
