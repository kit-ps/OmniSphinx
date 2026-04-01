#!/bin/bash
set -euo pipefail

echo "Starting benchmark run for OmniSphinx"
BENCHES=(
    "InstructionBenchmark"
    "MultiSphinxPackageCreationBenchmark"
    "MultiSphinxPackageProcessingBenchmark"
    "PolySphinxPackageCreationBenchmark"
    "PolySphinxPackageProcessingBenchmark"
    "SphinxPackageCreationBenchmark"
    "SphinxPackageProcessingBenchmark"
)

taskset -c 0 mvn test -Dtest="$(IFS=, ; echo "${BENCHES[*]}")"
