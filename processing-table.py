import json
from pathlib import Path

SPHINX_PATH = Path("../java-sphinx")
OMNI_PATH = Path(".")


def read_bench(base_path, bench_group, bench_name):
    fname = base_path / "target" / "benchmarks" / f"{bench_group}.json"
    with open(fname) as fobj:
        data = json.load(fobj)

    for bench in data:
        if bench["benchmark"].endswith(f".{bench_name}"):
            avg_s = bench["primaryMetric"]["score"]
            err_s = bench["primaryMetric"]["scoreError"]
            return (avg_s, err_s)

    return None


def fmt(tpl, unit):
    avg, err = tpl
    factor = 1
    unit_str = "\\s"
    if unit == "ms":
        factor = 1000
        unit_str = "\\ms"
    elif unit == "us":
        factor = 1000 * 1000
        unit_str = "\\us"
    return f"\\(\\qty{{{avg * factor:.2f}}}{{{unit_str}}}\\pm\\qty{{{err * factor:.2f}}}{{{unit_str}}}\\)"



sphinx_create = fmt(read_bench(SPHINX_PATH, "sphinx-native", "create"), "ms")
sphinx_interm = fmt(read_bench(SPHINX_PATH, "sphinx-native", "processRelay"), "us")
sphinx_exit = fmt(read_bench(SPHINX_PATH, "sphinx-native", "processExit"), "us")
omni_create = fmt(read_bench(OMNI_PATH, "sphinx-creation", "sphinxCreation"), "ms")
omni_interm = fmt(read_bench(OMNI_PATH, "sphinx-processing", "relay"), "us")
omni_exit = fmt(read_bench(OMNI_PATH, "sphinx-processing", "exit"), "us")

print(f"""
\\begin{{tabularx}}{{0.95\\textwidth}}{{lXXX}}\\toprule
    Format        & Packet Creation & \\multicolumn{{2}}{{c}}{{Mix Processing}}\\\\
                  &                 & Intermediate Node & Exit Node\\\\\\midrule
    Native Sphinx & {sphinx_create} & {sphinx_interm}   & {sphinx_exit}\\\\
    \\prot{{}}    & {omni_create}   & {omni_interm}     & {omni_exit}\\\\\\bottomrule
\\end{{tabularx}}
""")
