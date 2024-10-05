#!/bin/bash
# 이 파일은 퍼징 과정 중에 실행되어야함. SoN도 확인.
# INPUT: 거리값이 계산된 csv 파일, SoN --trace-turbo & --always-opt  
# OUTPUT: 이번 시도의 distance 값 총합 계산 + '정규화'까지 거친 값

if [ $# -lt 2 ]; then
  echo "Usage: $0 <target-directory> <temporary-directory> <target_func> [fuzzer-name]"
  echo "npm install -g js-callgraph"
  echo ""
  exit 1
fi


TARGETS=$(readlink -e $1)
TMPDIR=$(readlink -e $2)
TARGET_FUNC=$(readlink -e $3)
AFLGO="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../" && pwd )"
fuzzer=""


SCRIPT=$0
ARGS=$@

#SANITY CHECKS
if [ -z "$TARGETS" ]; then echo "Couldn't find targets folder ($1)."; exit 1; fi
if [ -z "$TMPDIR" ]; then echo "Couldn't find temporary directory ($3)."; exit 1; fi


if [ -z $(which python) ] && [ -z $(which python3) ]; then echo "Please install Python"; exit 1; fi
#if python -c "import pydotplus"; then echo "Install python package: pydotplus (sudo pip install pydotplus)"; exit 1; fi
#if python -c "import pydotplus; import networkx"; then echo "Install python package: networkx (sudo pip install networkx)"; exit 1; fi

FAIL=0
STEP=1

RESUME=$(if [ -f $TMPDIR/state ]; then cat $TMPDIR/state; else echo 0; fi)

function next_step {
  echo $STEP > $TMPDIR/state
  if [ $FAIL -ne 0 ]; then
    tail -n30 $TMPDIR/step${STEP}.log
    echo "-- Problem in Step $STEP of generating $OUT!"
    echo "-- You can resume by executing:"
    echo "$ $SCRIPT $ARGS $TMPDIR"
    exit 1
  fi
  STEP=$((STEP + 1))
}


#-------------------------------------------------------------------------------
# Construct control flow graph and call graph
    """
    - Description: 
    - Input: 
    - Output: 
    """
#-------------------------------------------------------------------------------
if [ $RESUME -le $STEP ]; then

  cd $TMPDIR/dot-files # 생성된 그래프 파일들이 저장


  if npx js-callgraph exists; then
    echo "($STEP) Constructing CG for $TARGETS.."
    prefix="$TMPDIR/dot-files/$(basename $TARGETS)" #그래프 파일이 저장될 경로를 설정
    js-callgraph --cg $TARGETS >/dev/null 2> $TMPDIR/step${STEP}.txt
    while !  cg2dot.py $TMPDIR/step${STEP}.txt  ; do # 첫번째 인자는 input, 두번째는 output 이름
      echo -e "\e[93;1m[!]\e[0m Could not generate turbo graph. Repeating.."

  done

  #Remove repeated lines and rename
  awk '!a[$0]++' $(basename $binary).callgraph.dot > callgraph.$(basename $binary).dot
  rm $(basename $binary).callgraph.dot
done

fi
next_step

#-------------------------------------------------------------------------------
# Generate config file keeping distance information for code instrumentation
#-------------------------------------------------------------------------------
if [ $RESUME -le $STEP ]; then
  echo "($STEP) Computing distance for call graph .."

  # distance 계산하기
  $AFLGO/distance/distance_calculator/distance.py -d $TMPDIR/dot-files/callgraph.dot -t $TMPDIR/Ftargets.txt -n $TMPDIR/Fnames.txt -o $TMPDIR/distance.callgraph.txt > $TMPDIR/step${STEP}.log 2>&1 || FAIL=1

  if [ $(cat $TMPDIR/distance.callgraph.txt | wc -l) -eq 0 ]; then
    FAIL=1
    next_step
  fi

  # CG 중에 Target까지 도달하는지 여부 확인 
  if TARGET_FUNC in callgraph.dot:


    # 도달시 CFG 그리기 
    ./node/out/Release/node --trace-turbo-graph $TARGETS >/dev/null 2> $TMPDIR/step${STEP}.log

    # CG에 있는 함수들 대상으로 그래프 뽑기 +  dot으로 만들기

    # CFG 계산 
    printf "($STEP) Computing distance for control-flow graphs "
    for f in $(ls -1d $TMPDIR/dot-files/cfg.*.dot); do


    # Compute distance
    printf "\nComputing distance for $f..\n"
    $AFLGO/distance/distance_calculator/distance.py -d $f -t $TMPDIR/BBtargets.txt -n $TMPDIR/BBnames.txt -s $TMPDIR/BBcalls.txt -c $TMPDIR/distance.callgraph.txt -o ${f}.distances.txt >> $TMPDIR/step${STEP}.log 2>&1 #|| FAIL=1
    if [ $? -ne 0 ]; then
      echo -e "\e[93;1m[!]\e[0m Could not calculate distance for $f."
    fi
    
    # CG + CFG
  
  else:
    

  done
  echo ""

  cat $TMPDIR/dot-files/*.distances.txt > $TMPDIR/distance.cfg.txt

fi
next_step

echo ""
echo "----------[DONE]----------"
echo ""
echo "Now, you may wish to compile your sources with "
echo "CC=\"$AFLGO/instrument/aflgo-clang\""
echo "CXX=\"$AFLGO/instrument/aflgo-clang++\""
echo "CFLAGS=\"\$CFLAGS -distance=$(readlink -e $TMPDIR/distance.cfg.txt)\""
echo "CXXFLAGS=\"\$CXXFLAGS -distance=$(readlink -e $TMPDIR/distance.cfg.txt)\""
echo ""
echo "--------------------------"
