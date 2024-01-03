#!/bin/bash

# Variables
FUZZER_NAME=${FUZZER_NAME:-"unitfuzzer"}
PROFILE=${PROFILE:-"dev"}
PROFILE_PATH="debug"
TARGET=${TARGET:-"x86_64-unknown-linux-gnu"}
LLVM_PATH=${LLVM_PATH:-"/usr/lib/llvm"}
ENV_SETUP=${ENV_SETUP:-""}

if [[ ! $PROFILE == "dev" ]]; then
    PROFILE_PATH=$PROFILE;
fi
CARGO_TARGET_DIR=target/${TARGET}/${PROFILE_PATH}

# Commands
CLEAN="clean"
FUZZER="fuzzer"
HARNESS="harness"

if [[ $1 == $CLEAN ]]; then
    echo "Cleaning up.";
    rm -f ./${FUZZER_NAME} ./harness*.so;
    cargo clean;
elif [[ $1 == $FUZZER ]]; then
    echo "Building fuzzer executable for target ${TARGET}.";
    cargo build --profile ${PROFILE} --target ${TARGET};
    if [[ ! -z $ENV_SETUP ]]; then
        source ${ENV_SETUP};
    fi
    #$CXX $CXXFLAGS -O3 -o ${FUZZER_NAME} src/fuzzer.cc experimental/mock.cc ${CARGO_TARGET_DIR}/lib${FUZZER_NAME}.a -lpthread -lm -lrt -ldl -lc;
    $CXX $CXXFLAGS -O3 -o ${FUZZER_NAME} src/fuzzer.cc ${CARGO_TARGET_DIR}/lib${FUZZER_NAME}.a -lpthread -lm -lrt -ldl -lc;
elif [[ $1 == $HARNESS ]]; then
    echo "Building harness for target $TARGET.";
    if [[ ! -z $ENV_SETUP ]]; then
        source ${ENV_SETUP};
    fi
    $CC $CFLAGS -O3 -fPIC -shared -o harness_simple.so harness/harness_simple.cc;
else
    echo "Usage: ./build.sh <clean|fuzzer|harness>";
    exit 1;
fi

exit;