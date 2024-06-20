#!/bin/bash

rm -rvf -f build
mkdir -p build
cd build
cmake ../..
make -j4
