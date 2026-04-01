#!/bin/bash
set -euo pipefail

#mvn compile
mkdir -p target/benchmarks

BENCHES=(
    "InstructionBenchmark"
)

for bench in ${BENCHES[@]} ; do
    mvn exec:java -Dexec.mainClass=OmniSphinx.benchmarks."$bench"
done
