#!/usr/bin/env python3
import argparse
import sys
from modules import static, disasm, strings, entropy, report

def main():
    parser = argparse.ArgumentParser(description="Binary Analysis Toolkit")
    parser.add_argument("binary", help="Path to binary file")
    parser.add_argument("--disasm", action="store_true", help="Disassemble .text section")
    parser.add_argument("--strings", action="store_true", help="Extract strings")
    parser.add_argument("--entropy", action="store_true", help="Section entropy analysis")
    parser.add_argument("--all", action="store_true", help="Run all modules")
    parser.add_argument("--report", choices=["json", "markdown"], help="Export report")
    args = parser.parse_args()

    print(f"\n[*] Analyzing: {args.binary}\n{'='*50}")

    info = static.analyze(args.binary)
    if not info:
        sys.exit(1)

    results = {"static": info}

    if args.disasm or args.all:
        results["disassembly"] = disasm.analyze(args.binary, info["type"])

    if args.strings or args.all:
        results["strings"] = strings.analyze(args.binary)

    if args.entropy or args.all:
        results["entropy"] = entropy.analyze(args.binary, info["type"])

    if args.report:
        report.export(results, args.binary, args.report)
    else:
        report.print_summary(results)

if __name__ == "__main__":
    main()
