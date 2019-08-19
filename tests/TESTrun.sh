#!/bin/sh

#
# Force UTC, so time stamps are printed in a standard time zone, and
# tests don't have to be run in the time zone in which the output
# file was generated.
#
TZ=GMT0; export TZ

#
# Get the tests directory from $0.
#
testsdir=`dirname "$0"`

#
# Convert it to an absolute path, so it works even after we do a cd.
#
testsdir=`cd ${testsdir}; pwd`

echo Running tests from ${testsdir}

passedfile=$(pwd)/tests/.passed
failedfile=$(pwd)/tests/.failed
failureoutput=$(pwd)/tests/failure-outputs.txt
mkdir -p tests/NEW
mkdir -p tests/DIFF
cat /dev/null > ${failureoutput}

runComplexTests()
{
  for i in ${testsdir}/*.sh
  do
    case $i in
        ${testsdir}/TEST*.sh) continue;;
        ${testsdir}/\*.sh) continue;;
    esac
    echo Running $i
    (cd tests && sh $i ${srcdir})
  done
  passed=`cat ${passedfile}`
  failed=`cat ${failedfile}`
}

runSimpleTests()
{
  only=$1
  cat ${testsdir}/TESTLIST | while read name input output options
  do
    case $name in
      \#*) continue;;
      '') continue;;
    esac
    rm -f core
    [ "$only" != "" -a "$name" != "$only" ] && continue
    # I hate shells with their stupid, useless subshells.
    passed=`cat ${passedfile}`
    failed=`cat ${failedfile}`
    (cd tests  # run TESTonce in tests directory
    if ${testsdir}/TESTonce $name ${testsdir}/$input ${testsdir}/$output "$options"
    then
      passed=`expr $passed + 1`
      echo $passed >${passedfile}
    else
      failed=`expr $failed + 1`
      echo $failed >${failedfile}
    fi)
    [ "$only" != "" -a "$name" = "$only" ] && break
  done
  # I hate shells with their stupid, useless subshells.
  passed=`cat ${passedfile}`
  failed=`cat ${failedfile}`
}

passed=0
failed=0
echo $passed >${passedfile}
echo $failed >${failedfile}
if [ $# -eq 0 ]
then
  runComplexTests
  runSimpleTests
elif [ $# -eq 1 ]
then
  runSimpleTests $1
else
  echo "Usage: $0 [test_name]"
  exit 30
fi

# exit with number of failing tests.
echo '------------------------------------------------'
printf "%4u tests failed\n" $failed
printf "%4u tests passed\n" $passed
echo
cat ${failureoutput}
echo
echo
exit $failed
