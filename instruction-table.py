import json
with open("target/benchmarks/instructions.json") as input_file:
    benches = json.load(input_file)

wanteds = [
    "Stop",
    "StoreBytes2",
    "Hash",
    "Mac",
    "Verify",
    "Exponent",
    "Pad",
    "PrgGenerate",
    "Xor",
    "Decrypt",
    "Encrypt",
    "Concat",
    "ConcatWithByte",
    "Copy",
    "Add",
    "Forward",
    "LoadBytes2",
    "For",
]

print("\\rotatebox{90}{Avg}", end=" ")

for wanted in wanteds:
    bench = None
    for b in benches:
        if b["benchmark"] == f"OmniSphinx.benchmarks.InstructionBenchmark.op{wanted}":
            bench = b
            break

    if bench is None:
        print("& \\rotatebox{90}{---}", end=" ")
    else:
        avg_us = round(bench["primaryMetric"]["score"] * 1000 * 1000, 2)
        err_us = round(bench["primaryMetric"]["scoreError"] * 1000 * 1000, 2)
        print(f"& \\rotatebox{{90}}{{\\(\\qty{{{avg_us:.2f}}}{{\\us}}\\pm\\qty{{{err_us:.2f}}}{{\\us}}\\)}}", end=" ")

print("\\\\\\bottomrule")
