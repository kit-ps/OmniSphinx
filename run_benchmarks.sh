#!/bin/bash
set -euo pipefail

mvn compile
mkdir -p target/benchmarks

BENCHES=(
    "InstructionBenchmark"
    "MultiSphinxPackageCreationBenchmark"
    "MultiSphinxPackageProcessingBenchmark"
    "PolySphinxPackageCreationBenchmark"
)

for bench in ${BENCHES[@]} ; do
    mvn exec:java -Dexec.mainClass=OmniSphinx.benchmarks."$bench"
done
