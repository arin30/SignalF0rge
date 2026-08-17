import argparse
from pathlib import Path
from .parser import load_jsonl
from .rules import load_rules
from .engine import analyze
from .report import write_json, write_html
from .sigma import load_sigma_rule, sigma_summary


def main():
    parser = argparse.ArgumentParser(prog="signalf0rge")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="Analyze normalized JSONL security events")
    a.add_argument("input")
    a.add_argument("--rules", default="rules.yml")
    a.add_argument("--out", default="output")

    s = sub.add_parser("sigma", help="Inspect Sigma detection metadata")
    s.add_argument("rule")

    args = parser.parse_args()
    if args.command == "sigma":
        print(sigma_summary(load_sigma_rule(args.rule)))
        return

    events = load_jsonl(args.input)
    rules = load_rules(args.rules)
    findings = analyze(events, rules)
    out = Path(args.out)
    print(f"Analyzed {len(events)} events")
    print(f"Generated {len(findings)} findings")
    print(f"JSON: {write_json(findings, out)}")
    print(f"HTML: {write_html(findings, out)}")


if __name__ == "__main__":
    main()
