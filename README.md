# OmniSphinx Paper

This repository contains the materials used in the OmniSphinx evaluation, including:

* The Java implementation of OmniSphinx, in the directory ``main/java/OmniSphinx``

* The mix programs of different mix formats (Sphinx, MultiSphinx, PolySphinx, AE-Sphinx) in the directory ``main/java/OmniSphinx/MixFormats``

* The implementation of Information Flow Security to analyze mix programs, in the directory ``main/java/OmniSphinx/ifs``

* Benchmarks of this implementation, in the directory ``main/java/OmniSphinx/benchmarks``

* The Jupyter notebook for the size/bandwidth overhead evaluation in ``size_evaluation.ipynb``

To rerun benchmark, execute:

```
mvn test -Dtest="SphinxPackageProcessingBenchmark"
```
