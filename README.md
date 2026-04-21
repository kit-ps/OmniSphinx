# OmniSphinx Paper 💊

This repository contains the materials used in the OmniSphinx evaluation, including:

* The Java implementation of OmniSphinx, in the directory ``main/java/OmniSphinx``

* The mix programs of different mix formats (Sphinx, MultiSphinx, PolySphinx, AE-Sphinx) in the directory ``main/java/OmniSphinx/MixFormats``

* The implementation of Information Flow Security to analyze mix programs, in the directory ``main/java/OmniSphinx/ifs``

* Benchmarks of this implementation, in the directory ``main/java/OmniSphinx/benchmarks``

* The Jupyter notebook for the size/bandwidth overhead evaluation in ``size_evaluation.ipynb``

This repository was forked from the Sphinx implementation at https://github.com/rsoultanaev/java-sphinx

## Requirements

We have tested this software on the following system:

* Ubuntu 24.04.4 LTS
* Java 25.0.2
* Apache Maven 3.9.14

The [maven Docker image](https://hub.docker.com/_/maven) provides a working environment.

## Running the benchmarks

You can use the `run_benchmarks.sh` script to run all benchmarks. The output
files will be saved in `target/benchmarks`.

The script `instruction-table.py` can be used to produce Table 4 in the paper.

The script `processing-table.py` can be used to produce Table 3 in the paper.
It requires the Sphinx benchmarks to be available (by default in
`../java-sphinx/target/benchmarks`).

## Extended version

The extended version of the paper (including the security proofs) can be found
in `Extended Version.pdf`.

## License

This code is based on `java-sphinx` by Robert Soultanaev:

```
MIT License

Copyright (c) 2018 Robert Soultanaev

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
