import argparse
import getpass
import json
from pathlib import Path
import sys

from .network import ScanError
from .reports import clean_text, render, summarize
from .scanner import demo_report, scan
from .ai import AIError, add_ai_sample, explain, load_report, preview


def positive_timeout(value):
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Timeout must be a number between 1 and 30 seconds.") from exc
    if not 1 <= number <= 30:
        raise argparse.ArgumentTypeError("Timeout must be between 1 and 30 seconds.")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(prog="verifact", description="Verifact: inspect a public link and review website configuration evidence.")
    commands = parser.add_subparsers(dest="command", required=True)
    web = commands.add_parser("serve", help="Open the local website checker with a URL input and AI settings")
    web.add_argument("--port", type=int, default=8765, help="Local port (default: 8765)")
    web.add_argument("--open", action="store_true", help="Open the app in your default browser")
    for name, help_text in [("scan", "Assess one public website link"), ("demo", "Generate a synthetic report without network access")]:
        command = commands.add_parser(name, help=help_text)
        if name == "scan":
            command.add_argument("domain", nargs="?", help="Public domain or full HTTP(S) link; path and query are preserved")
            command.add_argument("--target-stdin", action="store_true", help="Read the URL from stdin, keeping it out of the process command line")
            command.add_argument("--expected-domain", help="Optional domain you expected this link to reach, e.g. example.com")
            command.add_argument("--community", action="store_true", help="Download the free community domain feed and match hostnames locally; no submitted URL is sent to its provider")
            command.add_argument("--security-contact", action="store_true", help="Fetch the public security.txt disclosure contact file as an unscored owner check")
            command.add_argument("--rdap", action="store_true", help="Include an optional public registration lookup")
            command.add_argument("--rdap-domain", help="Explicit registered parent domain for a subdomain target; enables RDAP")
            command.add_argument("--timeout", type=positive_timeout, default=8.0, help="Per-request socket/body time budget (default: 8 seconds)")
        else:
            command.add_argument("--ai-sample", action="store_true", help="Add a hand-authored illustrative AI section; no model is called")
        command.add_argument("--format", choices=["text", "json", "html"], default="text")
        command.add_argument("--output", type=Path, help="Write the report to this file")
    for name, help_text in [("explain", "Add optional AI explanations to a saved JSON report"),
                            ("render", "Render a saved JSON report without an API call")]:
        command = commands.add_parser(name, help=help_text)
        command.add_argument("report", type=Path)
        command.add_argument("--format", choices=["text", "json", "html"], default="text")
        command.add_argument("--output", type=Path)
        if name == "explain":
            command.add_argument("--provider", choices=["openai", "ollama"], default="ollama", help="Default: local Ollama (no paid fallback)")
            command.add_argument("--model", help="Override the provider's default model")
            command.add_argument("--preview", action="store_true", help="Print selected AI input and schema; no network or key required")
            command.add_argument("--prompt-key", action="store_true", help="Read an OpenAI key with hidden input; never saved")
            command.add_argument("--max-output-tokens", type=int, default=1800, choices=range(256, 4097), metavar="256..4096")
            command.add_argument("--ai-timeout", type=ai_timeout, default=90.0, metavar="1..300")
    aggregate = commands.add_parser("summarize", help="Compare check counts across saved JSON reports; no network requests")
    aggregate.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            if not 1024 <= args.port <= 65535:
                raise ValueError("Choose a port between 1024 and 65535.")
            from .server import serve
            return serve(args.port, args.open)
        if args.command == "summarize":
            reports = [json.loads(path.read_text(encoding="utf-8")) for path in args.files]
            if any(report.get("schema_version") != 1 for report in reports):
                raise ValueError("Expected Verifact JSON reports with schema_version 1.")
            if any(report.get("demo") for report in reports):
                raise ValueError("Synthetic demo reports cannot be included in live-study summaries.")
            print(summarize(reports), end="")
            return 0
        if args.command in {"explain", "render"}:
            if args.output and (args.output.resolve() == args.report.resolve()
                                or (args.output.exists() and args.output.samefile(args.report))):
                raise AIError("Choose a different output path so the source report stays intact.")
            report = load_report(args.report)
            if args.command == "explain":
                if args.prompt_key and args.provider != "openai":
                    raise AIError("--prompt-key is only available with --provider openai.")
                if args.preview:
                    content = json.dumps(preview(report, args.provider, args.model, args.max_output_tokens), indent=2, ensure_ascii=False) + "\n"
                else:
                    key = None
                    if args.prompt_key:
                        if not sys.stdin.isatty():
                            raise AIError("--prompt-key needs an interactive terminal. Use OPENAI_API_KEY for automation.")
                        key = getpass.getpass("OpenAI API key (hidden): ")
                    print(f"Generating explanations with {args.provider}; one request, no retries…", file=sys.stderr)
                    report = explain(report, args.provider, args.model, args.max_output_tokens, args.ai_timeout, api_key=key)
                    content = render(report, args.format)
            else:
                content = render(report, args.format)
        elif args.command == "demo":
            report = demo_report()
            if args.ai_sample:
                report = add_ai_sample(report)
            content = render(report, args.format)
        else:
            if bool(args.domain) == bool(args.target_stdin):
                raise ValueError("Supply one website link or use --target-stdin, but not both.")
            target = sys.stdin.read(2049) if args.target_stdin else args.domain
            # Do not echo URL paths or query strings into terminal logs.
            print("Observing the public link…", file=sys.stderr)
            scan_options = {"expected_domain": args.expected_domain}
            if args.community:
                scan_options["community_check"] = True
            if args.security_contact:
                scan_options["security_contact"] = True
            report = scan(target, args.rdap or bool(args.rdap_domain), args.rdap_domain, args.timeout,
                          **scan_options)
            content = render(report, args.format)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(content, encoding="utf-8")
            print(f"Report saved: {clean_text(args.output.resolve())}", file=sys.stderr)
        else:
            print(content, end="")
        # Findings never change exit codes. A totally unavailable scan does.
        return 1 if args.command == "scan" and not report["response"] else 0
    except (ScanError, OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"verifact: {clean_text(exc)}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nScan interrupted.", file=sys.stderr)
        return 130


def ai_timeout(value):
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("AI timeout must be between 1 and 300 seconds.") from exc
    if not 1 <= number <= 300:
        raise argparse.ArgumentTypeError("AI timeout must be between 1 and 300 seconds.")
    return number
