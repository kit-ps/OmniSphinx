#!/bin/bash
set -euo pipefail

mkdir -p target/benchmarks

BENCHES=(
    "InstructionBenchmark"
    "MultiSphinxPackageCreationBenchmark"
    "MultiSphinxPackageProcessingBenchmark"
    "PolySphinxPackageCreationBenchmark"
    "PolySphinxPackageProcessingBenchmark"
    "SphinxPackageCreationBenchmark"
    "SphinxPackageProcessingBenchmark"
)

for bench in ${BENCHES[@]} ; do
    mvn compile exec:java -Dexec.mainClass=OmniSphinx.benchmarks."$bench"
done
