"""In-process MCP server that exposes the IDA tools to the `claude` CLI.

Why this exists
---------------
The API-key path calls tools itself (see claude_client.run_agent_turn). The CLI
path can't: `claude` runs its own agent loop in a separate process, so it has no
way to reach into IDA. MCP is that bridge. We stand up a tiny Model Context
Protocol server on localhost inside the IDA process, hand its URL + bearer token
to `claude` via `--mcp-config`, and the CLI's agent loop calls our IDA tools over
HTTP -- billed against the user's Claude subscription instead of API credits.

Transport is MCP "Streamable HTTP": a single POST endpoint speaking JSON-RPC 2.0.
Responses are returned as SSE when the client asks for it (Accept:
text/event-stream) and as plain JSON otherwise; both are allowed by the spec.

This module deliberately knows nothing about IDA. It takes two callables:

    tool_defs()            -> list of Anthropic-style tool dicts
                              ({"name", "description", "input_schema"})
    exec_tool(name, input) -> (result_str, is_error_bool)

`exec_tool` is invoked on an HTTP worker thread, so the caller is responsible
for marshalling into IDA's main thread (chat_widget does this with
idaapi.execute_sync).
"""
import json
import secrets
import threading

try:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
except ImportError:  # Python 3.6
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from socketserver import ThreadingMixIn

    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True


SERVER_NAME = "ida"
SERVER_VERSION = "1.0.0"
ENDPOINT = "/mcp"

# Protocol revisions we know how to speak. We echo back whatever the client
# asked for when we support it, else the newest one we know.
SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
DEFAULT_PROTOCOL = SUPPORTED_PROTOCOLS[0]

# JSON-RPC error codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class McpServerError(RuntimeError):
    pass


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ida-claude-mcp/" + SERVER_VERSION

    # ---------- plumbing ----------

    def log_message(self, fmt, *args):
        # BaseHTTPRequestHandler logs to stderr; in IDA that spams the Output
        # window on every tool call. Route through the owner's logger instead.
        owner = getattr(self.server, "owner", None)
        if owner is not None and owner.debug:
            print("[Claude MCP] " + (fmt % args))

    def _authorized(self):
        expected = "Bearer " + self.server.owner.token
        got = self.headers.get("Authorization", "") or ""
        return secrets.compare_digest(got, expected)

    def _send(self, code, body=b"", ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _send_rpc(self, payload):
        """Return a JSON-RPC payload, as SSE if the client asked for it."""
        raw = json.dumps(payload).encode("utf-8")
        accept = (self.headers.get("Accept") or "").lower()
        if "text/event-stream" in accept:
            body = b"event: message\ndata: " + raw + b"\n\n"
            self._send(200, body, "text/event-stream")
        else:
            self._send(200, raw, "application/json")

    @staticmethod
    def _error(req_id, code, message):
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        }

    # ---------- HTTP verbs ----------

    def do_GET(self):
        # The spec lets a server refuse the server->client SSE channel; we have
        # no server-initiated messages to send.
        self._send(405, b"", "text/plain")

    def do_DELETE(self):
        # Session teardown. We keep no per-session state, so just ack.
        self._send(200, b"", "text/plain")

    def do_POST(self):
        if self.path.split("?")[0].rstrip("/") not in (ENDPOINT, ENDPOINT + "/",
                                                       ""):
            self._send(404, b'{"error":"not found"}')
            return
        if not self._authorized():
            self._send(401, b'{"error":"unauthorized"}')
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length else b""

        try:
            msg = json.loads(raw.decode("utf-8"))
        except Exception as e:
            self._send_rpc(self._error(None, PARSE_ERROR,
                                       "invalid JSON: %s" % e))
            return

        # A batch is a list; handle each element and drop notification replies.
        if isinstance(msg, list):
            replies = [r for r in (self._dispatch(m) for m in msg)
                       if r is not None]
            if not replies:
                self._send(202, b"", "text/plain")
            else:
                self._send_rpc(replies)
            return

        reply = self._dispatch(msg)
        if reply is None:
            # Notification: 202 with no body, per the Streamable HTTP spec.
            self._send(202, b"", "text/plain")
        else:
            self._send_rpc(reply)

    # ---------- JSON-RPC dispatch ----------

    def _dispatch(self, msg):
        """Return a JSON-RPC reply dict, or None for notifications."""
        if not isinstance(msg, dict):
            return self._error(None, INVALID_REQUEST, "not an object")
        req_id = msg.get("id")
        method = msg.get("method") or ""
        params = msg.get("params") or {}
        is_notification = "id" not in msg

        try:
            if method == "initialize":
                result = self._on_initialize(params)
            elif method == "tools/list":
                result = self._on_tools_list(params)
            elif method == "tools/call":
                result = self._on_tools_call(params)
            elif method == "ping":
                result = {}
            elif method in ("resources/list", "prompts/list"):
                # Advertised as absent in `initialize`, but some clients probe
                # anyway; an empty list is friendlier than METHOD_NOT_FOUND.
                key = "resources" if method.startswith("resources") else "prompts"
                result = {key: []}
            elif method.startswith("notifications/"):
                return None
            else:
                if is_notification:
                    return None
                return self._error(req_id, METHOD_NOT_FOUND,
                                   "unknown method: %s" % method)
        except _RpcError as e:
            if is_notification:
                return None
            return self._error(req_id, e.code, e.message)
        except Exception as e:
            if is_notification:
                return None
            return self._error(req_id, INTERNAL_ERROR, "%s: %s"
                               % (type(e).__name__, e))

        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def _on_initialize(self, params):
        asked = params.get("protocolVersion")
        version = asked if asked in SUPPORTED_PROTOCOLS else DEFAULT_PROTOCOL
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": self.server.owner.instructions,
        }

    def _on_tools_list(self, _params):
        tools = []
        for t in self.server.owner.tool_defs():
            schema = t.get("input_schema") or {"type": "object",
                                               "properties": {}}
            tools.append({
                "name": t.get("name", ""),
                "description": t.get("description", ""),
                "inputSchema": schema,
            })
        return {"tools": tools}

    def _on_tools_call(self, params):
        name = params.get("name")
        if not name:
            raise _RpcError(INVALID_PARAMS, "missing tool name")
        args = params.get("arguments")
        if args is None:
            args = {}
        if not isinstance(args, dict):
            raise _RpcError(INVALID_PARAMS, "arguments must be an object")

        owner = self.server.owner
        known = {t.get("name") for t in owner.tool_defs()}
        if name not in known:
            # Answer as a tool-level error rather than a protocol error: the
            # model can read it and pick a real tool, whereas a JSON-RPC error
            # surfaces to the client as a transport failure.
            return {
                "content": [{"type": "text", "text":
                             "Unknown tool: %s. Call tools/list for the "
                             "available IDA tools." % name}],
                "isError": True,
            }
        try:
            result, is_error = owner.exec_tool(name, args)
        except Exception as e:
            result, is_error = ("tool raised: %s: %s" % (type(e).__name__, e),
                                True)
        if not isinstance(result, str):
            result = str(result)
        return {
            "content": [{"type": "text", "text": result}],
            "isError": bool(is_error),
        }


class _RpcError(Exception):
    def __init__(self, code, message):
        Exception.__init__(self, message)
        self.code = code
        self.message = message


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    # Don't sit on the port if IDA reopens the panel quickly after a close.
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        """Keep connection teardown out of IDA's Output window.

        Cancelling a turn kills the `claude` process mid-request, so the
        in-flight tool call finishes against a closed socket. The default
        handler prints a full traceback to stderr for every one of those,
        which in IDA reads like a crash.
        """
        owner = getattr(self, "owner", None)
        if owner is not None and owner.debug:
            ThreadingHTTPServer.handle_error(self, request, client_address)


class IdaMcpServer:
    """Owns the HTTP server thread and the bearer token.

    Start it once per chat panel and keep it running; `claude` connects fresh
    on every invocation, so a long-lived server avoids a port dance per turn.
    """

    def __init__(self, tool_defs, exec_tool, host="127.0.0.1",
                 port=0, instructions="", debug=False):
        self.tool_defs = tool_defs
        self.exec_tool = exec_tool
        self.host = host
        self._requested_port = port
        self.instructions = instructions or _DEFAULT_INSTRUCTIONS
        self.debug = debug
        self.token = secrets.token_urlsafe(24)
        self._httpd = None
        self._thread = None

    # ---------- lifecycle ----------

    def start(self):
        if self._httpd is not None:
            return self.url
        try:
            httpd = _Server((self.host, self._requested_port), _Handler)
        except OSError as e:
            raise McpServerError(
                "could not bind MCP server on %s:%s (%s)"
                % (self.host, self._requested_port, e)
            )
        httpd.owner = self
        self._httpd = httpd
        self._thread = threading.Thread(
            target=httpd.serve_forever, kwargs={"poll_interval": 0.2},
            name="ida-claude-mcp", daemon=True,
        )
        self._thread.start()
        return self.url

    def stop(self):
        if self._httpd is None:
            return
        try:
            self._httpd.shutdown()
        except Exception:
            pass
        try:
            self._httpd.server_close()
        except Exception:
            pass
        self._httpd = None
        self._thread = None

    def running(self):
        return self._httpd is not None

    # ---------- accessors ----------

    @property
    def port(self):
        if self._httpd is None:
            return None
        return self._httpd.server_address[1]

    @property
    def url(self):
        if self._httpd is None:
            return None
        return "http://%s:%d%s" % (self.host, self.port, ENDPOINT)

    def mcp_config(self):
        """The object `claude --mcp-config` expects."""
        return {
            "mcpServers": {
                SERVER_NAME: {
                    "type": "http",
                    "url": self.url,
                    "headers": {"Authorization": "Bearer " + self.token},
                }
            }
        }

    def mcp_config_json(self):
        return json.dumps(self.mcp_config())


_DEFAULT_INSTRUCTIONS = (
    "These tools operate on the IDA Pro database the user currently has open. "
    "Addresses are hex strings or ints; names are IDA symbol names. Prefer "
    "reading (read_function, get_xrefs_to, list_strings) before editing "
    "(rename, add_comment, set_function_prototype)."
)


# --- standalone smoke test ----------------------------------------------------
# Run `python mcp_server.py` outside IDA to serve two fake tools; useful for
# checking the handshake against a real MCP client without loading IDA.
if __name__ == "__main__":
    import time

    def _defs():
        return [
            {
                "name": "ping",
                "description": "Return pong. Test tool.",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "echo",
                "description": "Echo the given text back.",
                "input_schema": {
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                },
            },
        ]

    def _exec(name, params):
        if name == "ping":
            return ("pong", False)
        if name == "echo":
            return (str(params.get("text", "")), False)
        return ("unknown tool: %s" % name, True)

    srv = IdaMcpServer(_defs, _exec, debug=True)
    srv.start()
    print(srv.url)
    print(srv.mcp_config_json())
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.stop()
