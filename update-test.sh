#!/bin/sh

# Update the tests given as positional parameters

TZ=GMT0; export TZ

for TEST in "$@"; do
    PREFIX=tests
    MATCH=0
    while read name input output options
    do
        [ _$name = _ ] && continue        # ignore empty lines
        [ _${name#\#} != _$name ] && continue    # ignore comment lines
        [ $name != "$TEST" ] && continue    # not the requested test
        [ _$output = _ ] && continue    # ignore incomplete lines
        MATCH=1
        ./tcpdump -# -n -r "$PREFIX/$input" $options >"$PREFIX/$output"
    done < $PREFIX/TESTLIST
    [ $MATCH = 0 ] && echo "test $TEST not found" >&2
done
