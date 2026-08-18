import argparse
from pathlib import Path
from .parser import load_jsonl
from .telemetry import load_events
from .rules import load_rules
from .engine import analyze
from .report import write_json, write_html
from .sigma import load_sigma_rule, sigma_summary
from .intel import load_stix_bundle, enrich_events, write_intel_matches
from .evaluate import load_ground_truth, evaluate_findings, write_evaluation


def main():
    parser = argparse.ArgumentParser(prog="signalf0rge")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="Analyze security telemetry")
    a.add_argument("input")
    a.add_argument("--format", choices=["normalized", "windows"], default="normalized")
    a.add_argument("--rules", default="rules.yml")
    a.add_argument("--out", default="output")

    e = sub.add_parser("evaluate", help="Evaluate detections against labeled telemetry")
    e.add_argument("input")
    e.add_argument("--labels", required=True)
    e.add_argument("--format", choices=["normalized", "windows"], default="normalized")
    e.add_argument("--rules", default="rules.yml")
    e.add_argument("--out", default="output/evaluation.json")

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

    if args.command == "evaluate":
        expected = load_ground_truth(args.labels)
        metrics = evaluate_findings(findings, expected)
        path = write_evaluation(metrics, args.out)
        print(f"Analyzed {len(events)} events")
        print(f"Generated {len(findings)} findings")
        print(f"Expected cases: {metrics['expected_cases']}")
        print(f"True positives: {metrics['true_positives']}")
        print(f"False positives: {metrics['false_positives']}")
        print(f"False negatives: {metrics['false_negatives']}")
        print(f"Precision: {metrics['precision']:.3f}")
        print(f"Recall: {metrics['recall']:.3f}")
        print(f"F1: {metrics['f1']:.3f}")
        print(f"Evaluation: {path}")
        return

    out = Path(args.out)
    print(f"Analyzed {len(events)} events")
    print(f"Generated {len(findings)} findings")
    print(f"JSON: {write_json(findings, out)}")
    print(f"HTML: {write_html(findings, out)}")


if __name__ == "__main__":
    main()
