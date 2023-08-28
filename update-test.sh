#!/bin/sh

# Update the tests given as positional parameters

TZ=GMT0; export TZ

for TEST in "$@"; do
    PREFIX=tests
    MATCH=0
    while read -r name input output raw_options
    do
        [ -z "$name" ] && continue        # ignore empty lines
        [ "${name#\#}" != "$name" ] && continue    # ignore comment lines
        [ "$name" != "$TEST" ] && continue    # not the requested test
        [ -z "$output" ] && continue    # ignore incomplete lines
        MATCH=1
	options=$(echo "$raw_options" | sed "s/\(^\|\s\+\)-V\b//")
	if [ "$options" = "$raw_options" ]
        then
                inputswitch=-r
        else
                inputswitch=-V
	fi

        # Word splitting is intentional for $options.
        # shellcheck disable=SC2086
        ./tcpdump -# -n $inputswitch "$PREFIX/$input" $options >"$PREFIX/$output"
    done < $PREFIX/TESTLIST
    [ $MATCH = 0 ] && echo "test $TEST not found" >&2
done
