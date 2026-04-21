import json
with open("target/benchmarks/instructions.json") as input_file:
    benches = json.load(input_file)


def get_benchmark(op):
    for b in benches:
        if b["benchmark"] == f"OmniSphinx.benchmarks.InstructionBenchmark.op{wanted}":
            return b
    return None


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


print(r"""
\begin{tabularx}{0.95\textwidth}{XXXXXXXXXXXXXXXXXXX}\toprule
    & \rlap{\rotatebox{60}{\instr{Stop}}}
    & \rlap{\rotatebox{60}{\instr{CutBytes}}}
    & \rlap{\rotatebox{60}{\instr{Hash}}}
    & \rlap{\rotatebox{60}{\instr{MAC}}}
    & \rlap{\rotatebox{60}{\instr{Verify}}}
    & \rlap{\rotatebox{60}{\instr{Exponent}}}
    & \rlap{\rotatebox{60}{\instr{Pad}}}
    & \rlap{\rotatebox{60}{\instr{Prg}}}
    & \rlap{\rotatebox{60}{\instr{XOR}}}
    & \rlap{\rotatebox{60}{\instr{Decrypt}}}
    & \rlap{\rotatebox{60}{\instr{Encrypt}}}
    & \rlap{\rotatebox{60}{\instr{Concat}}}
    & \rlap{\rotatebox{60}{\instr{ConcatBytes}}}
    & \rlap{\rotatebox{60}{\instr{Copy}}}
    & \rlap{\rotatebox{60}{\instr{Add}}}
    & \rlap{\rotatebox{60}{\instr{Forward}}}
    & \rlap{\rotatebox{60}{\instr{Load}}}
    & \rlap{\rotatebox{60}{\instr{ForLoop}}}
    \\\midrule
""")


print(r"    \rotatebox{90}{\textbf{\quad Average time}}")


for wanted in wanteds:
    bench = get_benchmark(wanted)

    if bench is None:
        print("    & \\rotatebox{90}{---}")
    else:
        avg_us = round(bench["primaryMetric"]["score"] * 1000 * 1000, 2)
        err_us = round(bench["primaryMetric"]["scoreError"] * 1000 * 1000, 2)
        pz = ""
        if avg_us < 10:
            pz = "\\pz{}\\pz{}"
        elif avg_us < 100:
            pz = "\\pz{}"
        print(f"    & \\rotatebox{{90}}{{\\({pz}\\qty{{{avg_us:.2f}}}{{\\us}}\\pm\\qty{{{err_us:.2f}}}{{\\us}}\\)}}")

print("    \\\\\\bottomrule")
print("\\end{tabularx}")
