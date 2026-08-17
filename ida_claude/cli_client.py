"""Driver for the `claude` CLI, wired to our in-process MCP server.

Uses the user's existing terminal login (`claude /login`) instead of an API
key, so usage bills against their Claude subscription rather than API credits.

Unlike the old text-only shell-out, this runs a full agent turn: we hand
`claude` an `--mcp-config` pointing at the MCP server that chat_widget stands
up inside IDA (see mcp_server.py), so the CLI's own agent loop can call the
same IDA tools the API path uses. Output is parsed from
`--output-format stream-json`, which gives us token-level text deltas, tool
calls, tool results, and usage -- the same event stream the UI already renders
for the API path.

Events emitted through `on_event(kind, payload)`:
    'step'          {'n': int, 'max': int}
    'text_delta'    {'text': str, 'step': int}
    'thinking_delta'{'text': str}
    'tool_use'      {'id': str, 'name': str, 'input': dict}
    'tool_result'   {'name': str, 'result': str, 'is_error': bool}
    'usage'         {'input_tokens': int, ...}
    'notice'        {'text': str}
"""
import json
import os
import queue
import shutil
import subprocess
import threading
import time
import uuid


# On Windows, shelling out to a .cmd wrapper flashes a console window unless
# we explicitly suppress it. CREATE_NO_WINDOW hides it entirely.
_NO_WINDOW_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0) \
    if os.name == "nt" else 0

# MCP tools are namespaced by the CLI as mcp__<server>__<tool>. We strip the
# prefix for display and for matching against ida_tools.WRITE_TOOLS.
MCP_SERVER = "ida"
MCP_PREFIX = "mcp__%s__" % MCP_SERVER

SYSTEM_PROMPT_APPEND = (
    "You are embedded in a Claude Code panel inside IDA Pro. The user is "
    "reverse-engineering the binary currently open in IDA.\n\n"
    "The `%s*` MCP tools are your interface to that database: they list "
    "functions, strings, imports, exports, segments and xrefs; fetch "
    "disassembly and Hex-Rays decompilation; search bytes and immediates; "
    "inspect stack frames and structs; and (when the user has enabled edits) "
    "rename, comment, retype, patch and jump. Use them proactively -- when "
    "asked about a function, read it; when asked who calls something, check "
    "xrefs; when you understand a routine, rename and comment it.\n\n"
    "Keep responses short and concrete. Quote addresses and identifiers "
    "verbatim so the user can jump to them in IDA. If an edit tool reports "
    "that edits are disabled, tell the user to tick 'Allow edits' in the "
    "chat window's gear menu."
) % MCP_PREFIX


class CliError(RuntimeError):
    pass


class CliCancelled(RuntimeError):
    pass


def strip_tool_prefix(name):
    """'mcp__ida__read_function' -> 'read_function'."""
    if name.startswith(MCP_PREFIX):
        return name[len(MCP_PREFIX):]
    return name


class ClaudeCliClient:
    def __init__(self):
        self._path = None
        self._version = None
        # Resumable CLI conversation id. Persisted across turns so the CLI
        # keeps its own context (and prompt cache) instead of re-reading a
        # flattened transcript every time.
        self.session_id = None

    # ---------- discovery ----------

    @property
    def cli_path(self):
        if self._path is None:
            self._path = (
                shutil.which("claude")
                or shutil.which("claude.cmd")
                or shutil.which("claude.exe")
            )
        return self._path

    def available(self):
        return self.cli_path is not None

    def version(self):
        """Cached `claude --version`.

        Callers may hit this from the UI thread (the diagnostics menu item),
        so it must not pay for a subprocess more than once per session.
        """
        if self._version is not None:
            return self._version or None
        if not self.available():
            return None
        try:
            out = subprocess.run(
                [self.cli_path, "--version"], capture_output=True, text=True,
                timeout=15, shell=False, creationflags=_NO_WINDOW_FLAGS,
            )
        except Exception:
            self._version = ""   # remember the failure; don't retry per click
            return None
        self._version = (out.stdout or "").strip()
        return self._version or None

    def reset_session(self):
        self.session_id = None

    # ---------- command construction ----------

    def _build_args(self, model, mcp_config_json, resume, allow_builtin_tools,
                    effort, extra_system_prompt):
        args = [
            self.cli_path,
            "-p",
            "--output-format", "stream-json",
            "--include-partial-messages",
            "--verbose",                 # required by -p + stream-json
        ]
        if model:
            args += ["--model", model]
        if effort:
            args += ["--effort", effort]

        if mcp_config_json:
            args += [
                "--mcp-config", mcp_config_json,
                # Ignore the user's own configured MCP servers: this turn is
                # about the IDA database, and unrelated servers would only
                # add tools (and latency) the panel can't render.
                "--strict-mcp-config",
                # Pre-approve every tool from our server. Without this the CLI
                # would try to prompt for permission and, being non-
                # interactive, auto-deny.
                "--allowedTools", "mcp__%s" % MCP_SERVER,
            ]
        if not allow_builtin_tools:
            # Match the API path's surface: IDA tools only, no Bash/Read/Write
            # against the analyst's filesystem.
            args += ["--tools", ""]

        system = SYSTEM_PROMPT_APPEND
        if extra_system_prompt:
            system += "\n\n" + extra_system_prompt
        args += ["--append-system-prompt", system]

        if resume:
            args += ["--resume", resume]
        else:
            # Generate the id ourselves so we can resume even if the run dies
            # before emitting its init event.
            args += ["--session-id", self.session_id]
        return args

    # ---------- the turn ----------

    def run_agent_turn(self, model, prompt, on_event=None, is_cancelled=None,
                       mcp_config_json=None, cwd=None, effort=None,
                       allow_builtin_tools=False, extra_system_prompt=None,
                       timeout=1800, resume=True):
        """Run one user turn through the CLI. Returns the final assistant text.

        `prompt` is the full user message (context blocks included). When a
        session already exists and `resume` is true, only this message is sent
        -- the CLI still has the earlier turns.
        """
        if not self.available():
            raise CliError(
                "`claude` CLI not found on PATH. Install Claude Code and run "
                "`claude` once to log in, then restart IDA."
            )
        on_event = on_event or (lambda kind, payload: None)
        is_cancelled = is_cancelled or (lambda: False)

        if resume and self.session_id:
            resume_id = self.session_id
        else:
            # No session to continue (or the caller asked for a clean one):
            # mint the id ourselves so we can resume next turn even if this
            # run dies before emitting its init event.
            resume_id = None
            self.session_id = str(uuid.uuid4())

        args = self._build_args(model, mcp_config_json, resume_id,
                                allow_builtin_tools, effort,
                                extra_system_prompt)
        try:
            proc = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd or None,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                shell=False,
                creationflags=_NO_WINDOW_FLAGS,
            )
        except FileNotFoundError:
            raise CliError("`claude` CLI not found.")
        except OSError as e:
            raise CliError("could not start `claude`: %s" % e)

        reader = _StreamReader(proc)
        try:
            proc.stdin.write(prompt)
            proc.stdin.close()
        except Exception as e:
            reader.stop()
            _kill(proc)
            raise CliError("failed to send the prompt to `claude`: %s" % e)

        parser = _StreamParser(on_event)
        deadline = time.time() + float(timeout)
        cancelled = False

        try:
            while True:
                if is_cancelled():
                    cancelled = True
                    break
                if time.time() > deadline:
                    _kill(proc)
                    raise CliError("`claude` timed out after %ds" % timeout)
                try:
                    line = reader.lines.get(timeout=0.2)
                except queue.Empty:
                    if proc.poll() is not None and reader.done():
                        break
                    continue
                if line is _SENTINEL:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    parser.feed(json.loads(line))
                except ValueError:
                    # Non-JSON chatter on stdout (e.g. an update notice).
                    continue
        finally:
            if cancelled:
                _kill(proc)
            reader.stop()

        if cancelled:
            raise CliCancelled("cancelled")

        rc = proc.wait()
        stderr = reader.stderr_text().strip()

        if parser.session_id:
            self.session_id = parser.session_id
        elif resume_id is None and rc not in (0, None):
            # A brand-new session that died before its init event probably
            # never got created; don't try to resume a ghost next turn.
            self.session_id = None

        if parser.error_message:
            raise CliError(parser.error_message)
        if rc not in (0, None):
            detail = stderr or parser.text.strip() or "(no output)"
            if resume_id and _looks_like_bad_session(detail):
                # The stored session is gone (cleared cache, different cwd).
                # Start a fresh one and let the caller retry with full history.
                self.session_id = None
                raise CliError(
                    "the previous CLI session could not be resumed; it has "
                    "been reset -- send the message again."
                )
            raise CliError("`claude` exited %d: %s" % (rc, detail[:2000]))

        text = parser.final_text()
        if not text:
            if stderr:
                raise CliError("`claude` produced no output: %s" % stderr[:500])
            text = "(empty response)"
        return text

    # ---------- back-compat ----------

    def send(self, model, history, timeout=300):
        """Text-only single-shot, kept for callers that just want a reply.

        Flattens the tail of `history` into one prompt; no tools, no MCP.
        """
        parts = []
        for m in history[-8:]:
            content = m.get("content")
            if not isinstance(content, str):
                continue
            tag = "User" if m.get("role") == "user" else "Assistant"
            parts.append("%s:\n%s\n" % (tag, content))
        prompt = "\n".join(parts).strip() or "(no input)"
        return self.run_agent_turn(
            model, prompt, timeout=timeout, resume=False,
            mcp_config_json=None,
        )


# ---------- helpers ----------

_SENTINEL = object()


def _kill(proc):
    try:
        proc.terminate()
    except Exception:
        return
    try:
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _looks_like_bad_session(text):
    low = (text or "").lower()
    return ("session" in low
            and ("not found" in low or "no conversation" in low
                 or "could not" in low or "invalid" in low))


class _StreamReader:
    """Pumps stdout lines into a queue and drains stderr, so the main loop can
    stay responsive to cancellation instead of blocking on readline()."""

    def __init__(self, proc):
        self.proc = proc
        self.lines = queue.Queue()
        self._err = []
        self._stopped = False
        self._out_done = threading.Event()
        self._t_out = threading.Thread(target=self._pump_stdout, daemon=True)
        self._t_err = threading.Thread(target=self._pump_stderr, daemon=True)
        self._t_out.start()
        self._t_err.start()

    def _pump_stdout(self):
        try:
            for line in self.proc.stdout:
                if self._stopped:
                    break
                self.lines.put(line)
        except Exception:
            pass
        finally:
            self._out_done.set()
            self.lines.put(_SENTINEL)

    def _pump_stderr(self):
        try:
            for line in self.proc.stderr:
                if self._stopped:
                    break
                self._err.append(line)
                if len(self._err) > 400:
                    del self._err[:200]
        except Exception:
            pass

    def done(self):
        return self._out_done.is_set()

    def stderr_text(self):
        return "".join(self._err)

    def stop(self):
        self._stopped = True
        for stream in (self.proc.stdout, self.proc.stderr):
            try:
                stream.close()
            except Exception:
                pass


class _StreamParser:
    """Turns the CLI's stream-json events into our on_event() vocabulary."""

    def __init__(self, on_event):
        self.on_event = on_event
        self.session_id = None
        self.text = ""              # text we streamed as deltas
        self.result_text = None     # authoritative final text from `result`
        self.error_message = None
        self._step = 0
        self._tool_names = {}       # tool_use_id -> display name
        self._streamed_msgs = set()  # message ids we emitted deltas for
        self._cur_msg_id = None

    # -- event fan-in ------------------------------------------------------

    def feed(self, evt):
        kind = evt.get("type")
        if kind == "stream_event":
            self._on_stream_event(evt.get("event") or {})
        elif kind == "assistant":
            self._on_assistant(evt)
        elif kind == "user":
            self._on_user(evt)
        elif kind == "system":
            self._on_system(evt)
        elif kind == "result":
            self._on_result(evt)
        elif kind == "rate_limit_event":
            self._on_rate_limit(evt)
        if not self.session_id and evt.get("session_id"):
            self.session_id = evt["session_id"]

    # -- individual handlers ----------------------------------------------

    def _on_stream_event(self, e):
        t = e.get("type")
        if t == "message_start":
            msg = e.get("message") or {}
            self._cur_msg_id = msg.get("id")
            self._step += 1
            self.on_event("step", {"n": self._step, "max": 0})
        elif t == "content_block_delta":
            delta = e.get("delta") or {}
            dt = delta.get("type")
            if dt == "text_delta":
                txt = delta.get("text") or ""
                if txt:
                    self.text += txt
                    if self._cur_msg_id:
                        self._streamed_msgs.add(self._cur_msg_id)
                    self.on_event("text_delta",
                                  {"text": txt, "step": self._step})
            elif dt == "thinking_delta":
                txt = delta.get("thinking") or ""
                if txt:
                    self.on_event("thinking_delta", {"text": txt})

    def _on_assistant(self, evt):
        msg = evt.get("message") or {}
        msg_id = msg.get("id")
        content = msg.get("content") or []
        blocks = content if isinstance(content, list) else []

        # If partial-message streaming didn't reach us (older CLI, or the
        # flag was rejected), fall back to emitting the whole block at once
        # so the panel still shows the answer.
        if msg_id and msg_id not in self._streamed_msgs:
            whole = "".join(b.get("text", "") for b in blocks
                            if isinstance(b, dict) and b.get("type") == "text")
            if whole:
                self._streamed_msgs.add(msg_id)
                self.text += whole
                self.on_event("text_delta",
                              {"text": whole, "step": self._step})

        for b in blocks:
            if not isinstance(b, dict) or b.get("type") != "tool_use":
                continue
            name = strip_tool_prefix(b.get("name") or "")
            self._tool_names[b.get("id")] = name
            self.on_event("tool_use", {
                "id": b.get("id"),
                "name": name,
                "input": b.get("input") or {},
            })

        # Per-message usage is deliberately ignored: the final `result` event
        # reports totals for the whole turn, and adding both double-counts.

    def _on_user(self, evt):
        msg = evt.get("message") or {}
        content = msg.get("content")
        if not isinstance(content, list):
            return
        for b in content:
            if not isinstance(b, dict) or b.get("type") != "tool_result":
                continue
            tid = b.get("tool_use_id")
            self.on_event("tool_result", {
                "name": self._tool_names.get(tid, "tool"),
                "result": _flatten_result(b.get("content")),
                "is_error": bool(b.get("is_error")),
            })

    def _on_system(self, evt):
        if evt.get("subtype") != "init":
            return
        self.session_id = evt.get("session_id") or self.session_id
        broken = [s.get("name") for s in (evt.get("mcp_servers") or [])
                  if s.get("status") not in ("connected", "connecting")]
        if broken:
            self.on_event("notice", {
                "text": "MCP server(s) failed to connect: %s. IDA tools are "
                        "unavailable for this turn." % ", ".join(
                            n or "?" for n in broken)
            })
        elif not (evt.get("mcp_servers") or []):
            self.on_event("notice", {
                "text": "No MCP server attached; the CLI has no IDA tools "
                        "this turn."
            })

    def _on_result(self, evt):
        self.session_id = evt.get("session_id") or self.session_id
        usage = evt.get("usage") or {}
        if usage:
            self.on_event("usage", _usage_fields(usage))
        denials = evt.get("permission_denials") or []
        if denials:
            names = sorted({strip_tool_prefix(d.get("tool_name") or "?")
                            for d in denials if isinstance(d, dict)})
            self.on_event("notice", {
                "text": "The CLI denied %d tool call(s): %s"
                        % (len(denials), ", ".join(names))
            })
        if evt.get("is_error") or evt.get("subtype") not in (None, "success"):
            self.error_message = (
                evt.get("result")
                or evt.get("error")
                or "`claude` reported: %s" % evt.get("subtype")
            )
            return
        res = evt.get("result")
        if isinstance(res, str) and res.strip():
            self.result_text = res

    def _on_rate_limit(self, evt):
        info = evt.get("rate_limit_info") or {}
        if info.get("status") in (None, "allowed"):
            return
        resets = info.get("resetsAt")
        when = ""
        if isinstance(resets, (int, float)):
            when = " (resets %s)" % time.strftime(
                "%H:%M", time.localtime(resets))
        self.on_event("notice", {
            "text": "Claude subscription limit %s%s."
                    % (info.get("status"), when)
        })

    # -- output ------------------------------------------------------------

    def final_text(self):
        if self.result_text:
            return self.result_text.strip()
        return self.text.strip()


def _usage_fields(u):
    out = {}
    for k in ("input_tokens", "output_tokens", "cache_read_input_tokens",
              "cache_creation_input_tokens"):
        v = u.get(k)
        if isinstance(v, int):
            out[k] = v
    return out


def _flatten_result(content):
    """tool_result content is a string or a list of content blocks."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, dict):
                if b.get("type") == "text":
                    parts.append(b.get("text") or "")
                else:
                    parts.append("(%s)" % b.get("type"))
            else:
                parts.append(str(b))
        return "\n".join(p for p in parts if p)
    if content is None:
        return ""
    return str(content)
