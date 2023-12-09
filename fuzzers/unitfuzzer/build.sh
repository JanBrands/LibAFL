#!/bin/bash

# Variables
FUZZER_NAME=${FUZZER_NAME:-"unitfuzzer"}
PROFILE=${PROFILE:-"release"}
TARGET=${TARGET:-"x86_64-unknown-linux-gnu"}
LLVM_PATH=${LLVM_PATH:-"/usr/lib/llvm"}
ENV_SETUP=${ENV_SETUP:-"./env_setup"}

# Commands
CLEAN="clean"
FUZZER="fuzzer"
HARNESS="harness"

if [[ $1 == $CLEAN ]]; then
    echo "Cleaning up.";
    rm -f ./${FUZZER_NAME} ./harness_*;
    cargo clean;
elif [[ $1 == $FUZZER ]]; then
    echo "Building fuzzer executable for target $TARGET.";
    cargo build --profile ${PROFILE} --target ${TARGET};
    source ${ENV_SETUP};
    $CXX $CXXFLAGS -O3 -flto -nostdlib++ -o ${FUZZER_NAME} src/fuzzer.cc target/${TARGET}/${PROFILE}/lib${FUZZER_NAME}.a -L${LLVM_PATH}/lib -ldl -lpthread -lrt -lm -lc++;
elif [[ $1 == $HARNESS ]]; then
    echo "Building harness for target $TARGET.";
    source ${ENV_SETUP};
    $CC $CFLAGS -O3 -fPIC -shared -o harness_simple.so harness/harness_simple.c;
else
    echo "Usage: ./build.sh <clean|fuzzer|harness>";
    exit 1;
fi

exit;