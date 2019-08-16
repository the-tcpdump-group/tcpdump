#!/bin/sh

TZ=GMT0; export TZ
srcdir=${SRCDIR-..}

echo RUNNING from ${srcdir}

# make it absolute
srcdir=$(cd $srcdir && pwd)

# this should be run from the compiled build directory,
# with srcdir= set to wherever the source code is.
# not from the tests directory.
echo RUNNING from ${srcdir}

mkdir -p tests/NEW
mkdir -p tests/DIFF
cat /dev/null > failure-outputs.txt

runComplexTests()
{
  for i in ${srcdir}/tests/*.sh
  do
    case $i in
        ${srcdir}/tests/TEST*.sh) continue;;
        ${srcdir}/tests/\*.sh) continue;;
    esac
    echo Running $i
    (cd tests && sh $i ${srcdir})
  done
  passed=`cat .passed`
  failed=`cat .failed`
}

runSimpleTests()
{
  only=$1
  cat ${srcdir}/tests/TESTLIST | while read name input output options
  do
    case $name in
      \#*) continue;;
      '') continue;;
    esac
    rm -f core
    [ "$only" != "" -a "$name" != "$only" ] && continue
    export SRCDIR=${srcdir}
    (cd tests  # run TESTonce in tests directory
    if ${srcdir}/tests/TESTonce $name ${srcdir}/tests/$input ${srcdir}/tests/$output "$options"
    then
      passed=`expr $passed + 1`
      echo $passed >.passed
    else
      failed=`expr $failed + 1`
      echo $failed >.failed
    fi)
    [ "$only" != "" -a "$name" = "$only" ] && break
  done
  # I hate shells with their stupid, useless subshells.
  passed=`cat .passed`
  failed=`cat .failed`
}

passed=0
failed=0
echo $passed >.passed
echo $failed >.failed
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
cat failure-outputs.txt
echo
echo
exit $failed
