#!/bin/sh
# # x-ssh -- SSH on x-lang, after Dropbear
#
# ## tests/spec-runner.sh -- the bundle's runner
#
# @description Sources the platform's spec runner; vendors nothing.
# @author [Jon Ruttan](jonruttan@gmail.com)
# @copyright 2026 Jon Ruttan
# @license MIT No Attribution (MIT-0)
#
# No path reaches into an x-lang source tree; everything comes from x itself:
# --share-dir says which tree x reads from (repo root in a checkout, share/x
# when installed) and --engine-path says where the engine is.
#
# Set X to point at a particular x; otherwise the one on PATH is used.
set -e

BUNDLE="$(cd "$(dirname "$0")/.." && pwd)"
X="${X:-x}"

command -v "$X" >/dev/null 2>&1 || {
	echo "x-ssh: no x on PATH.  Set X=/path/to/x.sh and retry." >&2
	exit 1
}

X_ROOT="$("$X" --share-dir)"
X_BIN="${X_BIN:-$("$X" --engine-path)}"

# The platform runner locates its harness relative to the engine binary, which
# sits beside tests/ only in a checkout; a sourced script cannot portably find
# its own path, so the caller sets this.
SPEC_RUNNER_DIR="$X_ROOT/tests"
export SPEC_RUNNER_DIR

# The harness is GENERATED, never committed: it embeds two absolute paths
# that are facts of this machine, not of the bundle.
sh "$BUNDLE/tests/gen-harness.sh" "$X_ROOT" "$BUNDLE"

LANG_LIB="$BUNDLE/tests/lib/harness.gen.x"
# SPEC_PATH is env-overridable so a single spec file can be run in isolation.
SPEC_PATH="${SPEC_PATH:-$BUNDLE/tests/specs}"

# The suite boots from a state image of the harness when the platform can write
# one. tools/dev/image-build.sh images a child that loaded the harness, keyed on
# what it depends on (the harness, the platform's lib/, its engine, and ssh/), so
# an edit to any of them rewrites the image and a current one is reused.
#
# The image writer is a checkout tool: an installed tree has none, and a library
# holding words no image can carry is refused; either way the suite boots from
# source and says so. The `Ansi repl-own` probe checks for a specific platform
# fix (x-lang#655) rather than a version. IMG=0 runs the same suite from source,
# one file per process, for when the image is the suspect.
if [ "${IMG:-1}" = 0 ]; then
	SPEC_BATCH="${SPEC_BATCH:-1}"; export SPEC_BATCH
else
	_builder="$X_ROOT/tools/dev/image-build.sh"
	_probe="${TMPDIR:-/tmp}/x-imgprobe.$$.x"
	printf '(Ansi repl-own)\n' > "$_probe"
	_keeps_printer=0
	"$X" -f "$_probe" >/dev/null 2>&1 && _keeps_printer=1
	rm -f "$_probe"
	if [ ! -f "$_builder" ]; then
		echo "x-ssh: no image writer at $_builder (not a checkout) -- the suite boots from source" >&2
	elif [ "$_keeps_printer" = 0 ]; then
		echo "x-ssh: the platform moves a REPL printer it does not own (x-lang#655) -- the suite boots from source" >&2
	elif X_BIN="$X_BIN" sh "$_builder" "$LANG_LIB" "$BUNDLE/tests/lib/.images" "$BUNDLE/ssh"; then
		X_IMG_DIR="$BUNDLE/tests/lib/.images"; export X_IMG_DIR
	else
		echo "x-ssh: no state image -- the suite boots from source" >&2
	fi
fi

# No collect at the snippet seam (x-lang#568/#572): the per-seam heap collect
# exhausted the allocation ceiling on x-ash's and x-python's suites; this
# bundle sets the same knob.
export SPEC_SEAM_COLLECT=0

# One spec file per process, and with it the platform's own 300M-object
# ceiling rather than a raised one.  Nothing collects between snippets, so a
# batch's allocation is the sum of its files.
# x-cc, x-infocom, x-r5rs and x-r7rs set the same knob.
export SPEC_BATCH="${SPEC_BATCH:-1}"

. "$X_ROOT/tests/spec-runner.sh"
