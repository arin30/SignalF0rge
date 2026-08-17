import argparse
from pathlib import Path
from .parser import load_jsonl
from .telemetry import load_events
from .rules import load_rules
from .engine import analyze
from .report import write_json, write_html
from .sigma import load_sigma_rule, sigma_summary
from .intel import load_stix_bundle, enrich_events, write_intel_matches


def main():
    parser = argparse.ArgumentParser(prog="signalf0rge")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="Analyze security telemetry")
    a.add_argument("input")
    a.add_argument("--format", choices=["normalized", "windows"], default="normalized")
    a.add_argument("--rules", default="rules.yml")
    a.add_argument("--out", default="output")

    s = sub.add_parser("sigma", help="Inspect Sigma detection metadata")
    s.add_argument("rule")

    i = sub.add_parser("intel", help="Enrich events using STIX 2.x indicators")
    i.add_argument("input", help="Normalized JSONL event file")
    i.add_argument("--stix", required=True, help="Path to a STIX bundle")
    i.add_argument("--out", default="output/intel_matches.json")

    args = parser.parse_args()

    if args.command == "sigma":
        print(sigma_summary(load_sigma_rule(args.rule)))
        return

    if args.command == "intel":
        events = load_jsonl(args.input)
        indicators = load_stix_bundle(args.stix)
        matches = enrich_events(events, indicators)
        path = write_intel_matches(matches, args.out)
        print(f"Loaded {len(indicators)} STIX indicators")
        print(f"Matched {len(matches)} event observables")
        print(f"Threat intelligence results: {path}")
        return

    events = load_events(args.input, args.format)
    rules = load_rules(args.rules)
    findings = analyze(events, rules)
    out = Path(args.out)
    print(f"Analyzed {len(events)} events")
    print(f"Generated {len(findings)} findings")
    print(f"JSON: {write_json(findings, out)}")
    print(f"HTML: {write_html(findings, out)}")


if __name__ == "__main__":
    main()
