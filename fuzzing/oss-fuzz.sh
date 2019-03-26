#!/bin/bash

set -ex

export CC=${CC:-clang}
export CXX=${CXX:-clang++}
export WORK=${WORK:-$(pwd)}
export OUT=${OUT:-$(pwd)/out}

build=$WORK/build
rm -rf $build
mkdir -p $build

fuzzflag="oss-fuzz=true"
if [ -z "$FUZZING_ENGINE" ]; then
    fuzzflag="llvm-fuzz=true"
fi

meson $build \
      -D$fuzzflag \
      -Db_lundef=false \
      -Ddefault_library=static \
      -Dstatic=true \
      -Dbuildtype=debugoptimized

ninja -C $build

zip -jqr $OUT/fuzz-input_seed_corpus.zip "$(dirname "$0")/IN"

find $build -type f -executable -name "fuzz-*" -exec mv {} $OUT \;
find $build -type f -name "*.options" -exec mv {} $OUT \;
