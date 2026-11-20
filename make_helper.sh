#!/bin/sh -eu

# This script is not present in the tarball because it requires both a git
# working copy and build_common.sh (which is not in the tarball either).

usage_and_exit()
{
	SCRIPTNAME=`basename "$0"`
	echo "Usage: $SCRIPTNAME whitespacecheck" >&2
	echo "   or: $SCRIPTNAME releasetar <tag> <release files>" >&2
	exit 64 # EX_USAGE
}

[ $# -ge 1 ] || usage_and_exit
TARGET="$1"
shift
MAKE_HELPER_DIR_PREFIX="tcpdump_build_${TARGET}"
SOURCE_DIR=`dirname "$0"`
. "$SOURCE_DIR"/build_common.sh

case "$TARGET" in
whitespacecheck)
	# Require no other arguments.
	[ $# -eq 0 ] || usage_and_exit
	init_make_helper_dir "$MAKE_HELPER_DIR_PREFIX"
	git -C "$SOURCE_DIR" ls-files >"$MAKE_HELPER_DIR/ls-files.txt"
	# grep output is meant to expand.
	# shellcheck disable=SC2046
	make_whitespacecheck "$SOURCE_DIR" `grep -v '^tests/' "$MAKE_HELPER_DIR/ls-files.txt"`
	;;
releasetar)
	# Require the tag and at least one file to package.
	[ $# -ge 2 ] || usage_and_exit
	TAG=${1:?}
	shift
	init_make_helper_dir "$MAKE_HELPER_DIR_PREFIX"
	make_releasetar "$SOURCE_DIR" "$TAG" "$MAKE_HELPER_DIR" releasetar.txt "$@"
	;;
*)
	usage_and_exit
	;;
esac

remove_make_helper_dir
