#!/bin/sh

mkdir -p NEW
mkdir -p DIFF
cat /dev/null > failure-outputs.txt

runComplexTests()
{
  for i in *.sh
  do
    case $i in TEST*.sh) continue;; esac
    sh ./$i
  done
  passed=`cat .passed`
  failed=`cat .failed`
}

runSimpleTests()
{
  only=$1
  cat TESTLIST | while read name input output options
  do
    case $name in
      \#*) continue;;
      '') continue;;
    esac
    rm -f core
    [ "$only" != "" -a "$name" != "$only" ] && continue
    if ./TESTonce $name $input $output "$options"
    then
      passed=`expr $passed + 1`
      echo $passed >.passed
    else
      failed=`expr $failed + 1`
      echo $failed >.failed
    fi
    [ "$only" != "" -a "$name" = "$only" ] && break
  done
  # I hate shells with their stupid, useless subshells.
  passed=`cat .passed`
  failed=`cat .failed`
}

runOutfileTests() {
    passed=`cat .passed`
    failed=`cat .failed`
    only=$1
    cat TESTOUTLIST | while read name input output outfile options
    do
        case $name in
            \#*) continue;;
            '') continue;;
        esac
        rm -f core
        [ "$only" != "" -a "$name" != "only" ] && continue
        if ./TESToutfile $name $input $output $outfile "$options"
        then
            passed=`expr $passed + 1`
            echo $passed > .passed
        else
            failed=`expr $failed + 1`
            echo $failed > .failed
        fi
        [ "$only" != "" -a "$name" = "$only" ] && break
    done
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
  runOutfileTests
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
