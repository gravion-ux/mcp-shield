"""Command-line interface for mcp-shield.

Subcommands:
  audit   Static-audit an MCP config and/or tool definitions.
  pin     Record a baseline of tool/server fingerprints (rug-pull defence).
  check   Diff current files against a pinned baseline.

Exit codes:
  0  no findings at or above the --fail-on severity
  1  findings at or above the --fail-on severity (CI should fail)
  2  usage / input error
"""

import argparse
import sys

from . import __version__
from .baseline import build_baseline, diff_baseline, load_baseline, write_baseline
from .checks import audit_config, audit_tools
from .loader import LoadError, load_config, load_tools
from .models import SEVERITIES, meets_threshold
from .report import build_report, render_json, render_markdown


def _load_inputs(args):
    servers, tools = {}, []
    targets = []
    if getattr(args, "config", None):
        servers = load_config(args.config)
        targets.append(args.config)
    if getattr(args, "tools", None):
        tools = load_tools(args.tools)
        targets.append(args.tools)
    return servers, tools, ", ".join(targets) if targets else "<none>"


def _emit(report, fmt, output):
    text = render_json(report) if fmt == "json" else render_markdown(report)
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("mcp-shield: wrote %s report to %s (risk score %d/100, %s)"
              % (fmt, output, report["risk_score"], report["grade"]))
    else:
        sys.stdout.write(text)


def _exit_code(findings, fail_on):
    return 1 if any(meets_threshold(f, fail_on) for f in findings) else 0


def cmd_audit(args):
    servers, tools, target = _load_inputs(args)
    if not servers and not tools:
        raise LoadError("nothing to audit: pass --config and/or --tools")
    findings = audit_config(servers) + audit_tools(tools)
    report = build_report(target, findings, mode="audit")
    _emit(report, args.format, args.output)
    return _exit_code(findings, args.fail_on)


def cmd_pin(args):
    servers, tools, _target = _load_inputs(args)
    if not servers and not tools:
        raise LoadError("nothing to pin: pass --config and/or --tools")
    baseline = build_baseline(tools, servers)
    write_baseline(args.baseline, baseline)
    print("mcp-shield: pinned %d tool(s) and %d server(s) to %s"
          % (len(baseline["tools"]), len(baseline["servers"]), args.baseline))
    return 0


def cmd_check(args):
    servers, tools, target = _load_inputs(args)
    baseline = load_baseline(args.baseline)
    findings = diff_baseline(baseline, tools, servers)
    report = build_report(target, findings, mode="check")
    _emit(report, args.format, args.output)
    return _exit_code(findings, args.fail_on)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="mcp-shield",
        description="Defensive security auditor for MCP server configurations "
                    "and tool definitions.",
    )
    parser.add_argument("--version", action="version",
                        version="mcp-shield %s" % __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_inputs(p):
        p.add_argument("--config", help="Path to an MCP config JSON file "
                                        "(mcpServers format).")
        p.add_argument("--tools", help="Path to a tool-definitions JSON file.")

    def add_report_opts(p, default_fail_on):
        p.add_argument("--format", choices=("markdown", "json"),
                       default="markdown", help="Report format (default: markdown).")
        p.add_argument("--output", help="Write the report to this file instead "
                                        "of stdout.")
        p.add_argument("--fail-on", choices=SEVERITIES, default=default_fail_on,
                       help="Exit 1 if any finding is at or above this severity "
                            "(default: %(default)s).")

    p_audit = sub.add_parser("audit", help="Audit a config / tool definitions.")
    add_inputs(p_audit)
    add_report_opts(p_audit, "high")
    p_audit.set_defaults(func=cmd_audit)

    p_pin = sub.add_parser("pin", help="Pin a baseline of current definitions.")
    add_inputs(p_pin)
    p_pin.add_argument("--baseline", required=True,
                       help="Where to write the baseline JSON file.")
    p_pin.set_defaults(func=cmd_pin)

    p_check = sub.add_parser("check", help="Diff current definitions against a baseline.")
    add_inputs(p_check)
    p_check.add_argument("--baseline", required=True,
                         help="Baseline JSON file created by 'pin'.")
    add_report_opts(p_check, "low")
    p_check.set_defaults(func=cmd_check)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except LoadError as exc:
        print("mcp-shield: error: %s" % exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print("mcp-shield: error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
