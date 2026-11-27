#!/bin/sh
# # x-ssh -- SSH on x-lang
#
# ## tests/linux/run.sh -- the Linux leg
#
# @description Runs tests/linux/password.sh as root in a Linux container.
# @author [Jon Ruttan](jonruttan@gmail.com)
# @copyright 2026 Jon Ruttan
# @license MIT No Attribution (MIT-0)
#
# The image is built from tests/linux/Containerfile at the x-lang release
# bundle.xon declares, once a release and Containerfile.  The bundle is
# mounted, not copied, so an edit runs at once.  ENGINE names the
# container engine, podman by default.
set -e

BUNDLE="$(cd "$(dirname "$0")/../.." && pwd)"
ENGINE="${ENGINE:-podman}"
REF="${X_LANG_REF:-$(sed -n 's/^(requires-release "\(.*\)")$/\1/p' "$BUNDLE/bundle.xon")}"
[ -n "$REF" ] || { echo "x-ssh: bundle.xon declares no release" >&2; exit 2; }
TAG="x-ssh-linux:$(printf %s "$REF" | tr / -)-$(cksum < "$BUNDLE/tests/linux/Containerfile" | cut -d " " -f 1)"

"$ENGINE" image inspect "$TAG" >/dev/null 2>&1 ||
	"$ENGINE" build --build-arg X_LANG_REF="$REF" -t "$TAG" "$BUNDLE/tests/linux"

exec "$ENGINE" run --rm -v "$BUNDLE:/x-ssh:ro" "$TAG" sh tests/linux/password.sh
