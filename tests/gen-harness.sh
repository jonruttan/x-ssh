#!/bin/sh
# # x-ssh -- SSH on x-lang, after Dropbear
#
# ## tests/gen-harness.sh -- shim onto the lang kit's harness generator
#
# @description Writes tests/lib/harness.gen.x with the platform's generator:
#   the dialect lang.xon declares, booted as `x -l ssh` boots it, then the
#   bundle's own tests/harness.x.
# @author [Jon Ruttan](jonruttan@gmail.com)
# @copyright 2026 Jon Ruttan
# @license MIT No Attribution (MIT-0)
#
# Usage: gen-harness.sh X_ROOT BUNDLE
#
# The platform ships the generator; a bundle does not vendor it.  X_LANG_KIT
# overrides where the kit is, as it does for tests/spec-gate.sh.
set -e

X_ROOT="$1"
BUNDLE="$2"

KIT="${X_LANG_KIT:-$X_ROOT/tools/lang-kit}"
[ -f "$KIT/gen-harness.sh" ] || {
	echo "x-ssh: no harness generator at $KIT -- set X_LANG_KIT, or point X at an x-lang checkout" >&2
	exit 2
}

BUNDLE="$BUNDLE" X="${X:-x}" sh "$KIT/gen-harness.sh"
