#!/bin/bash

set -ex

export CC=${CC:-clang}
export CXX=${CXX:-clang++}
export WORK=${WORK:-$(pwd)}
export OUT=${OUT:-$(pwd)/out}

build=$WORK/build
rm -rf $build
mkdir -p $build
mkdir -p $OUT

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

zip -jqr $OUT/fuzz-ip-header_seed_corpus.zip "$(dirname "$0")/IN_ip-header"
zip -jqr $OUT/fuzz-udp_seed_corpus.zip "$(dirname "$0")/IN_udp"
zip -jqr $OUT/fuzz-udp_h_seed_corpus.zip "$(dirname "$0")/IN_udp-h"
zip -jqr $OUT/fuzz-tftp_seed_corpus.zip "$(dirname "$0")/IN_tftp"
zip -jqr $OUT/fuzz-dhcp_seed_corpus.zip "$(dirname "$0")/IN_dhcp"
zip -jqr $OUT/fuzz-icmp_seed_corpus.zip "$(dirname "$0")/IN_icmp"
zip -jqr $OUT/fuzz-tcp_seed_corpus.zip "$(dirname "$0")/IN_tcp"

find $build -type f -executable -name "fuzz-*" -exec mv {} $OUT \;
find $build -type f -name "*.options" -exec mv {} $OUT \;
