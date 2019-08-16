#!/bin/sh

srcdir=${SRCDIR-..}

echo RUNNING from ${srcdir}

mkdir -p NEW
mkdir -p DIFF
cat /dev/null > failure-outputs.txt

runComplexTests()
{
  for i in ${srcdir}/*.sh
  do
    case $i in ${srcdir}/TEST*.sh) continue;; esac
    sh ./$i ${srcdir}
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
    if ${srcdir}/tests/TESTonce $name ${srcdir}/tests/$input ${srcdir}/tests/$output "$options"
    then
      passed=`expr $passed + 1`
      echo $passed >.passed
    else
      failed=`expr $failed + 1`
      echo $failed >.failed
    fi
    if [ -d COREFILES ]; then
        if [ -f core ]; then mv core COREFILES/$name.core; fi
    fi
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
