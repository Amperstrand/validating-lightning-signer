#!/usr/bin/env python3
"""Tiny static server for the splice trace viewer.

Serves the viewer directory plus a traces directory so traces can be
loaded via ?trace=<name>.jsonl without browser file-access issues.

Usage:
    python3 contrib/trace-viewer/serve.py [TRACES_DIR] [PORT]

Defaults: TRACES_DIR=target/splice-traces, PORT=8799 — then open
    http://localhost:8799/?trace=<scenario>.jsonl
"""
import http.server
import os
import sys
import urllib.parse
from pathlib import Path

VIEWER_DIR = Path(__file__).resolve().parent


class Handler(http.server.SimpleHTTPRequestHandler):
    traces_dir = Path("target/splice-traces")

    def translate_path(self, path):
        parsed = urllib.parse.urlparse(path).path
        if parsed.startswith("/trace/"):
            name = os.path.basename(urllib.parse.unquote(parsed[len("/trace/"):]))
            return str(self.traces_dir / name)
        return super().translate_path(path)

    def list_traces(self):
        if not self.traces_dir.is_dir():
            return []
        return sorted(p.name for p in self.traces_dir.glob("*.jsonl"))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/traces.json":
            body = ("\n".join(self.list_traces())).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/":
            listing = "".join(
                f'<li><a href="?trace={urllib.parse.quote(n)}">{n}</a></li>' for n in self.list_traces()
            )
            body = (
                "<html><head><meta charset='utf-8'><title>splice traces</title></head>"
                "<body style='font-family:monospace;background:#10151c;color:#dbe4f0'>"
                "<h2>available traces</h2><ul>" + (listing or "<li>(none)</li>") +
                "</ul><p><a href='/index.html'>open viewer</a></p></body></html>"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


def main(argv):
    traces = Path(argv[1]).resolve() if len(argv) > 1 else (Path.cwd() / "target/splice-traces").resolve()
    port = int(argv[2]) if len(argv) > 2 else 8799
    Handler.traces_dir = traces
    os.chdir(VIEWER_DIR)
    print(f"serving viewer at http://localhost:{port}/ — traces from {traces}")
    http.server.HTTPServer(("", port), Handler).serve_forever()


if __name__ == "__main__":
    main(sys.argv)
