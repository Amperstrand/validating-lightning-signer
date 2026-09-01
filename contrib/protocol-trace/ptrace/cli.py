"""ptrace CLI — merge / render / perfetto / view.

    python3 contrib/protocol-trace/ptrace/cli.py merge <trace-dir> [--out DIR]
        [--vls-src PATH] [--cln-src PATH] [--command STR] [--run-id ID]
    python3 contrib/protocol-trace/ptrace/cli.py render <trace.jsonl>
    python3 contrib/protocol-trace/ptrace/cli.py perfetto <trace.jsonl> [out.json]
    python3 contrib/protocol-trace/ptrace/cli.py view <dir> [port]
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# runnable both as a module (`python3 -m ptrace.cli`) and as a plain
# script (`python3 contrib/protocol-trace/ptrace/cli.py`) — absolute
# imports + a path shim for the script form.
_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


def _cmd_merge(args) -> int:
    from ptrace.merge import assemble

    out = assemble(
        args.trace_dir,
        args.out,
        vls_src=args.vls_src,
        cln_src=args.cln_src,
        command=args.command,
        run_id=args.run_id,
    )
    print("run dir: %s" % out)
    with open(os.path.join(out, "results.json")) as fh:
        results = json.load(fh)
    print("scenarios: %s" % json.dumps(results.get("scenarios")))
    print("failed invariants: %d" % len(results.get("failed_invariants", [])))
    print("viewer: python3 contrib/trace-viewer/serve.py %s 8799" % out)
    return 0


def _cmd_render(args) -> int:
    from ptrace.llm import render
    from ptrace.schema import read_events

    events, dropped = read_events(args.trace)
    sys.stdout.write(render(events))
    if dropped:
        sys.stderr.write("(%d dropped lines)\n" % dropped)
    return 0


def _cmd_perfetto(args) -> int:
    from ptrace.perfetto import export_chrome_trace, validate_chrome_trace
    from ptrace.schema import read_events

    events, _ = read_events(args.trace)
    doc = export_chrome_trace(events)
    problems = validate_chrome_trace(doc)
    if problems:
        sys.stderr.write("perfetto validation FAILED:\n  " + "\n  ".join(problems[:10]) + "\n")
        return 1
    with open(args.out, "w") as fh:
        json.dump(doc, fh)
    print("wrote %s (%d events, validation clean)" % (args.out, len(doc["traceEvents"])))
    return 0


def _cmd_view(args) -> int:
    serve = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "trace-viewer", "serve.py",
    )
    os.execv(sys.executable, [sys.executable, serve, args.dir, str(args.port)])


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="ptrace", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("merge", help="assemble a trace dir into a run directory")
    m.add_argument("trace_dir")
    m.add_argument("--out", default=None)
    m.add_argument("--vls-src", default=None, help="VLS checkout for the manifest version")
    m.add_argument("--cln-src", default=None, help="CLN checkout for the manifest version")
    m.add_argument("--command", default=None, help="exact repro command for the manifest")
    m.add_argument("--run-id", default=None)
    m.set_defaults(fn=_cmd_merge)

    r = sub.add_parser("render", help="render trace.jsonl to the LLM text form")
    r.add_argument("trace")
    r.set_defaults(fn=_cmd_render)

    pf = sub.add_parser("perfetto", help="export Chrome Trace JSON (validated)")
    pf.add_argument("trace")
    pf.add_argument("out", nargs="?", default="perfetto.json")
    pf.set_defaults(fn=_cmd_perfetto)

    v = sub.add_parser("view", help="serve the trace viewer on a run dir")
    v.add_argument("dir")
    v.add_argument("port", nargs="?", type=int, default=8799)
    v.set_defaults(fn=_cmd_view)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
