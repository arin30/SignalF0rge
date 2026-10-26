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
from .agent import investigate
from .agent_runner import run_investigation, run_llm_investigation
from .incident_narrative import generate_narrative
from .case_memory import append_case_history, load_case_history
import json
import os


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

    inv = sub.add_parser("investigate", help="Build investigation cases from security telemetry")
    inv.add_argument("input")
    inv.add_argument("--format", choices=["normalized", "windows"], default="normalized")
    inv.add_argument("--rules", default="rules.yml")
    inv.add_argument("--out", default="output/investigations.json")
    inv.add_argument("--agent", action="store_true", help="Run read-only investigation tools for each case")\n    inv.add_argument("--llm", action="store_true", help="Let an LLM choose investigation tool calls")\n    inv.add_argument("--model", default="gpt-5-mini", help="OpenAI-compatible model name")
    inv.add_argument("--narrative", action="store_true", help="Generate evidence-cited LLM incident narratives")
    inv.add_argument("--case-history", help="JSON file for bounded prior investigation metadata")

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

    if args.command == "investigate":
        cases = investigate(findings)
        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = [case.to_dict() for case in cases]
        reports = []
        if args.narrative and args.agent:
            raise SystemExit("--narrative cannot be combined with --agent")
        if args.llm or args.narrative:
            api_key = os.environ.get("OPENAI_API_KEY")
            if not api_key:
                raise SystemExit("OPENAI_API_KEY is required with --llm")
            history = load_case_history(args.case_history) if args.case_history else []
            if args.narrative:
                payload = [generate_narrative(case, findings, api_key, args.model).to_dict() for case in cases]
            else:
                reports = [
                    run_llm_investigation(case, events, findings, api_key, args.model, case_history=history)
                    for case in cases
                ]
                payload = [report.to_dict() for report in reports]
        elif args.agent:
            reports = [run_investigation(case, events, findings) for case in cases]
            payload = [report.to_dict() for report in reports]
        if args.case_history and reports:
            for report in reports:
                append_case_history(args.case_history, report)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Analyzed {len(events)} events")
        print(f"Generated {len(findings)} findings")
        print(f"Built {len(cases)} investigation cases")
        if args.narrative:
            print("Generated evidence-cited LLM incident narratives")
        elif args.llm:
            print("Ran bounded LLM-planned investigation tools")
        elif args.agent:
            print("Ran evidence-grounded investigation tools")
        if args.case_history and reports:
            print(f"Case history: {args.case_history}")
        print(f"Investigations: {path}")
        return

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
