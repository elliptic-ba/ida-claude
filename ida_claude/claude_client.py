"""Minimal Anthropic Messages API client using only Python stdlib.

Supports:
  * plain text chat
  * the tool-use protocol, driven via run_agent_turn()
  * SSE streaming (text appears incrementally in the UI)
  * prompt caching (system prompt, tool defs, most recent user turn)
  * usage reporting (input/output/cache-hit/cache-create tokens) surfaced
    per API call via an on_usage callback so the UI can show a running total
"""
import copy
import email.utils
import json
import os
import threading
import time
import urllib.error
import urllib.request


SYSTEM_PROMPT = (
    "You are an expert reverse engineer embedded inside IDA Pro. The user is "
    "analyzing a binary and will ask questions or give you tasks.\n\n"
    "You have a set of tools that let you read the database (list functions, "
    "strings, imports, exports, segments, xrefs, callers/callees; fetch "
    "disassembly and Hex-Rays decompilation; search bytes or immediates; "
    "read raw bytes; inspect stack frames and structs) and modify it (rename "
    "functions/labels, rename/retype Hex-Rays locals, comment, set prototypes, "
    "set return types, create structs, make/undefine data, format operands as "
    "enums, patch bytes, apply FLIRT signatures, load type libraries, jump). "
    "Use them proactively - when the user asks about a function, read it; "
    "when they ask who calls something, check xrefs/callers; when you "
    "understand a routine, feel free to rename and comment it.\n\n"
    "Keep responses short and concrete. Quote addresses and identifiers "
    "verbatim so the user can jump to them in IDA. If the user's question is "
    "about the current function and it's already attached below, answer "
    "directly without calling tools unnecessarily. If an edit tool returns "
    "that edits are disabled, tell the user they can enable 'Allow edits' in "
    "the chat window."
)


class ClaudeError(RuntimeError):
    pass


class CancelledError(RuntimeError):
    pass


# --- prompt-cache helpers ---

def _clone_tools_with_cache(tools):
    """Return a copy of the tool list with cache_control on the LAST tool
    definition. This caches the (usually large) tool block so subsequent
    requests in the same session only pay for changed messages."""
    if not tools:
        return tools
    out = [dict(t) for t in tools]
    out[-1] = dict(out[-1])
    out[-1]["cache_control"] = {"type": "ephemeral"}
    return out


def _strip_thinking(history):
    """Drop thinking blocks from assistant turns.

    Needed when the picker switches mid-conversation to a model that doesn't
    do adaptive thinking (Haiku 4.5 here): the transcript still carries
    thinking blocks produced by, say, Opus 5. An assistant turn that held
    nothing but thinking would become empty, which the API rejects, so it
    keeps a placeholder instead.
    """
    out = []
    for msg in history:
        content = msg.get("content")
        if msg.get("role") != "assistant" or not isinstance(content, list):
            out.append(msg)
            continue
        kept = [b for b in content
                if not (isinstance(b, dict)
                        and b.get("type") in ("thinking", "redacted_thinking"))]
        if len(kept) == len(content):
            out.append(msg)
            continue
        if not kept:
            kept = [{"type": "text", "text": "(reasoning omitted)"}]
        msg = dict(msg)
        msg["content"] = kept
        out.append(msg)
    return out


def _messages_with_cache(history):
    """Return a deep copy of history with cache_control on the final content
    block of the most recent message. Caches the conversation up through that
    turn so follow-up requests read the bulk of the prompt from cache."""
    msgs = copy.deepcopy(history)
    if not msgs:
        return msgs
    last = msgs[-1]
    content = last.get("content")
    if isinstance(content, str):
        # Promote to block form so we can attach cache_control.
        last["content"] = [{
            "type": "text",
            "text": content,
            "cache_control": {"type": "ephemeral"},
        }]
    elif isinstance(content, list) and content:
        # Mark the last block. Copy so we don't mutate the caller's dict.
        last["content"] = list(content)
        last["content"][-1] = dict(last["content"][-1])
        last["content"][-1]["cache_control"] = {"type": "ephemeral"}
    return msgs


def _system_blocks():
    return [{
        "type": "text",
        "text": SYSTEM_PROMPT,
        "cache_control": {"type": "ephemeral"},
    }]


# --- per-model request shaping ---

# Models predating the 4.6 generation reject `thinking: {"type": "adaptive"}`
# and `output_config.effort`, so we only send those to models that take them.
# (Haiku 4.5 is the one in our picker that doesn't.)
_NO_ADAPTIVE_PREFIXES = (
    "claude-haiku",
    "claude-3",
    "claude-2",
    "claude-sonnet-4-0",
    "claude-sonnet-4-5",
    "claude-opus-4-0",
    "claude-opus-4-1",
    "claude-opus-4-5",
)


def _takes_adaptive_thinking(model):
    model = (model or "").lower()
    return not any(model.startswith(p) for p in _NO_ADAPTIVE_PREFIXES)


def model_supports_effort(model):
    """Public gate, used by the CLI path too (`--effort` has the same
    per-model support as `output_config.effort`)."""
    return _takes_adaptive_thinking(model)


def _prepare_messages(history, model):
    """History as the wire wants it for `model` (cache markers, no stray
    thinking blocks on models that can't take them)."""
    if not _takes_adaptive_thinking(model):
        history = _strip_thinking(history)
    return _messages_with_cache(history)


def _apply_model_options(payload, model, effort=None):
    """Add thinking/effort to a request when the model supports them.

    Thinking is left on (adaptive) deliberately: on Opus 5 it is the default,
    and turning it off there has known failure modes -- the model can emit a
    tool call as plain text, which in an agent loop looks like a turn that
    silently did nothing. `display: summarized` gives us reasoning summaries
    to show while the model works instead of a long silent pause.
    """
    if not _takes_adaptive_thinking(model):
        return payload
    payload["thinking"] = {"type": "adaptive", "display": "summarized"}
    if effort:
        payload["output_config"] = {"effort": effort}
    return payload


class ClaudeClient:
    # Default input-tokens-per-minute budget. Anthropic's free-tier / default
    # org limit for most Claude models is 30k input tokens/min; staying a bit
    # below the cap avoids false 429s caused by estimation jitter.
    DEFAULT_TPM_LIMIT = 30000
    TPM_SAFETY = 0.90   # only use 90% of the nominal limit client-side

    def __init__(self, api_key=None, tpm_limit=None):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.endpoint = "https://api.anthropic.com/v1/messages"
        # The 30k default is the free/default-tier ceiling. Paid tiers are far
        # higher, and with 51 tool definitions in every request the client-side
        # throttle is the binding constraint long before the server's is --
        # hence the env override.
        if tpm_limit is None:
            try:
                tpm_limit = int(os.environ.get("IDA_CLAUDE_TPM_LIMIT") or 0)
            except ValueError:
                tpm_limit = 0
        self.tpm_limit = int(tpm_limit or self.DEFAULT_TPM_LIMIT)
        # Sliding 60s window of (timestamp, estimated_tokens) reservations.
        self._tpm_window = []
        self._tpm_lock = threading.Lock()

    # ---------- client-side rate limiting ----------

    @staticmethod
    def _estimate_tokens(payload):
        """Rough upper bound: ~1 token per 4 chars of serialized JSON.
        Used only for client-side throttling; the server's own accounting
        is authoritative."""
        try:
            s = json.dumps(payload, ensure_ascii=False)
        except Exception:
            return 1000
        return max(1, len(s) // 4)

    def _tpm_reserve(self, estimated_tokens, is_cancelled=None,
                     on_wait=None):
        """Block until `estimated_tokens` fits in the last-60s budget, then
        record the reservation. Polls `is_cancelled` (if given) so users can
        abort a long wait. `on_wait(seconds, used, limit)` is called once when
        we start waiting so the UI can explain the pause."""
        budget = int(self.tpm_limit * self.TPM_SAFETY)
        # A single request larger than the whole minute can never fit; cap the
        # reservation at the budget so it still goes out (server may 429, and
        # we'll back off via retry-after).
        est = min(estimated_tokens, budget)
        notified = False
        while True:
            if is_cancelled and is_cancelled():
                raise CancelledError("cancelled")
            with self._tpm_lock:
                now = time.time()
                self._tpm_window = [(t, n) for (t, n) in self._tpm_window
                                    if now - t < 60.0]
                used = sum(n for (_, n) in self._tpm_window)
                if used + est <= budget:
                    self._tpm_window.append((now, est))
                    return
                oldest = self._tpm_window[0][0]
                wait_total = 60.0 - (now - oldest) + 0.1
            if on_wait and not notified:
                try:
                    on_wait(wait_total, used, budget)
                except Exception:
                    pass
                notified = True
            time.sleep(max(0.25, min(wait_total, 5.0)))

    def _record_actual_usage(self, usage):
        """Correct the sliding window using real token counts from the
        response's `usage` field. We replace the most recent reservation
        (which was an estimate) with the authoritative number."""
        if not usage:
            return
        actual = int(usage.get("input_tokens") or 0) \
            + int(usage.get("cache_creation_input_tokens") or 0) \
            + int(usage.get("cache_read_input_tokens") or 0)
        if actual <= 0:
            return
        with self._tpm_lock:
            if self._tpm_window:
                ts, _ = self._tpm_window[-1]
                self._tpm_window[-1] = (ts, actual)

    # ---------- low-level HTTP ----------

    @staticmethod
    def _parse_retry_after(headers):
        """Return seconds to wait based on 429 response headers, or None."""
        if not headers:
            return None
        ra = headers.get("retry-after")
        if ra:
            try:
                return max(0.0, float(ra))
            except Exception:
                try:
                    dt = email.utils.parsedate_to_datetime(ra)
                    return max(0.0, (dt.timestamp() - time.time()))
                except Exception:
                    pass
        reset = headers.get("anthropic-ratelimit-input-tokens-reset")
        if reset:
            try:
                dt = email.utils.parsedate_to_datetime(reset)
                return max(0.0, dt.timestamp() - time.time())
            except Exception:
                pass
        return None

    def _request(self, payload, stream=False, timeout=180,
                 is_cancelled=None, max_retries=3, on_wait=None):
        if not self.api_key:
            raise ClaudeError(
                "No Anthropic API key set. Click 'API Key...' in the chat "
                "window, or set ANTHROPIC_API_KEY before launching IDA."
            )
        body = dict(payload)
        if stream:
            body["stream"] = True
        data = json.dumps(body).encode("utf-8")
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        if stream:
            headers["accept"] = "text/event-stream"

        # Client-side throttle based on payload size.
        est = self._estimate_tokens(payload)
        self._tpm_reserve(est, is_cancelled=is_cancelled, on_wait=on_wait)

        attempt = 0
        while True:
            req = urllib.request.Request(
                self.endpoint, data=data, headers=headers, method="POST")
            try:
                return urllib.request.urlopen(req, timeout=timeout)
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < max_retries:
                    wait = self._parse_retry_after(e.headers)
                    # Fall back to exponential backoff if no header was given.
                    if wait is None or wait <= 0:
                        wait = min(30.0, 2.0 * (2 ** attempt))
                    wait = max(1.0, min(wait, 65.0))
                    if on_wait:
                        try:
                            on_wait(wait, -1, self.tpm_limit)
                        except Exception:
                            pass
                    # Poll cancellation while sleeping.
                    deadline = time.time() + wait
                    while time.time() < deadline:
                        if is_cancelled and is_cancelled():
                            raise CancelledError("cancelled")
                        time.sleep(min(0.5, max(0.05, deadline - time.time())))
                    attempt += 1
                    continue
                err = e.read().decode("utf-8", errors="replace")
                raise ClaudeError(
                    "HTTP %d from Anthropic API: %s" % (e.code, err))
            except urllib.error.URLError as e:
                raise ClaudeError("Network error calling Anthropic API: %s" % e)

    def _post(self, payload, timeout=180, is_cancelled=None, on_wait=None):
        resp = self._request(payload, stream=False, timeout=timeout,
                             is_cancelled=is_cancelled, on_wait=on_wait)
        with resp:
            body = resp.read().decode("utf-8")
        result = json.loads(body)
        self._record_actual_usage(result.get("usage") or {})
        return result

    # ---------- SSE streaming ----------

    def _stream(self, payload, on_text_delta, is_cancelled, timeout=300,
                on_wait=None, on_thinking_delta=None):
        """Open a streaming response, parse SSE, and return
        (content_blocks, stop_reason, usage_dict).

        content_blocks mirrors the non-streamed response shape: a list of
        {'type': 'text', 'text': ...} and/or {'type': 'tool_use', 'id': ...,
        'name': ..., 'input': {...}} dicts.

        on_text_delta(str) is called for each text fragment so the UI can
        render the assistant turn as it's produced. is_cancelled() is polled
        between events; if true, the stream is closed and CancelledError
        is raised.
        """
        resp = self._request(payload, stream=True, timeout=timeout,
                             is_cancelled=is_cancelled, on_wait=on_wait)
        blocks = {}             # index -> block dict being built
        tool_json_buf = {}      # index -> partial JSON string for tool_use.input
        stop_reason = ""
        usage = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
        }

        event_name = ""
        data_lines = []
        try:
            for raw in resp:
                if is_cancelled():
                    raise CancelledError("cancelled")
                try:
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                except Exception:
                    line = ""
                if line.startswith("event: "):
                    event_name = line[7:].strip()
                    continue
                if line.startswith("data: "):
                    data_lines.append(line[6:])
                    continue
                if line == "":
                    if not data_lines:
                        event_name = ""
                        continue
                    raw_data = "\n".join(data_lines)
                    data_lines = []
                    try:
                        evt = json.loads(raw_data)
                    except Exception:
                        event_name = ""
                        continue
                    t = evt.get("type") or event_name
                    event_name = ""

                    if t == "message_start":
                        u = (evt.get("message") or {}).get("usage") or {}
                        for k in usage:
                            if k in u:
                                usage[k] = u.get(k) or 0
                    elif t == "content_block_start":
                        idx = evt.get("index", 0)
                        cb = dict(evt.get("content_block") or {})
                        if cb.get("type") == "text":
                            cb.setdefault("text", "")
                        elif cb.get("type") == "tool_use":
                            cb.setdefault("input", {})
                            tool_json_buf[idx] = ""
                        elif cb.get("type") == "thinking":
                            # Rebuilt verbatim (text + signature) because the
                            # API rejects modified thinking blocks when they
                            # are replayed on the next request.
                            cb.setdefault("thinking", "")
                            cb.setdefault("signature", "")
                        blocks[idx] = cb
                    elif t == "content_block_delta":
                        idx = evt.get("index", 0)
                        delta = evt.get("delta") or {}
                        cb = blocks.get(idx)
                        if cb is None:
                            continue
                        if delta.get("type") == "text_delta":
                            txt = delta.get("text", "")
                            cb["text"] = cb.get("text", "") + txt
                            if txt:
                                try:
                                    on_text_delta(txt)
                                except Exception:
                                    pass
                        elif delta.get("type") == "input_json_delta":
                            tool_json_buf[idx] = tool_json_buf.get(idx, "") \
                                + delta.get("partial_json", "")
                        elif delta.get("type") == "thinking_delta":
                            txt = delta.get("thinking", "")
                            cb["thinking"] = cb.get("thinking", "") + txt
                            if txt and on_thinking_delta:
                                try:
                                    on_thinking_delta(txt)
                                except Exception:
                                    pass
                        elif delta.get("type") == "signature_delta":
                            cb["signature"] = cb.get("signature", "") \
                                + delta.get("signature", "")
                    elif t == "content_block_stop":
                        idx = evt.get("index", 0)
                        cb = blocks.get(idx)
                        if cb is not None and cb.get("type") == "tool_use":
                            raw_json = tool_json_buf.get(idx, "")
                            if raw_json:
                                try:
                                    cb["input"] = json.loads(raw_json)
                                except Exception:
                                    cb["input"] = {"_raw": raw_json}
                            else:
                                cb["input"] = cb.get("input") or {}
                    elif t == "message_delta":
                        d = evt.get("delta") or {}
                        if "stop_reason" in d and d["stop_reason"]:
                            stop_reason = d["stop_reason"]
                        u = evt.get("usage") or {}
                        for k in ("output_tokens",
                                  "cache_read_input_tokens",
                                  "cache_creation_input_tokens",
                                  "input_tokens"):
                            if k in u and u[k] is not None:
                                usage[k] = u[k]
                    elif t == "message_stop":
                        pass
                    elif t == "error":
                        err = evt.get("error", {})
                        raise ClaudeError(
                            "stream error: %s" % err.get("message", err))
                    # ignore unknown event types
                else:
                    # line inside an event body we don't recognize; skip
                    continue
        finally:
            try:
                resp.close()
            except Exception:
                pass

        ordered = [blocks[i] for i in sorted(blocks.keys())]
        self._record_actual_usage(usage)
        return ordered, stop_reason, usage

    # ---------- plain chat (no tools) ----------

    def send(self, model, history, max_tokens=16000, on_usage=None,
             on_text_delta=None, is_cancelled=None, stream=True,
             on_wait=None, effort=None, on_thinking_delta=None):
        if is_cancelled is None:
            is_cancelled = lambda: False  # noqa: E731
        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "system": _system_blocks(),
            "messages": _prepare_messages(history, model),
        }
        _apply_model_options(payload, model, effort)
        if stream:
            blocks, _sr, usage = self._stream(
                payload, on_text_delta or (lambda t: None), is_cancelled,
                on_wait=on_wait, on_thinking_delta=on_thinking_delta)
            if on_usage:
                try:
                    on_usage(usage)
                except Exception:
                    pass
            chunks = [b.get("text", "") for b in blocks
                      if b.get("type") == "text"]
            return "\n".join(chunks).strip() or "(empty response)"
        result = self._post(payload, is_cancelled=is_cancelled,
                            on_wait=on_wait)
        if on_usage:
            try:
                on_usage(result.get("usage") or {})
            except Exception:
                pass
        chunks = [c.get("text", "") for c in result.get("content", [])
                  if c.get("type") == "text"]
        return ("\n".join(chunks).strip() or "(empty response)")

    # ---------- agent loop with tools ----------

    def run_agent_turn(self, model, history, tools, exec_tool, on_event,
                       is_cancelled, max_tokens=16000, max_steps=50,
                       on_usage=None, stream=True, on_wait=None, effort=None):
        """Drive a single 'user turn' through as many tool calls as Claude needs.

        Arguments:
          history      -- list of message dicts; this function appends to it in place.
          tools        -- list of tool definitions for the API.
          exec_tool    -- callable(name, input_dict) -> (result_str, is_error_bool).
                          Will be invoked from whatever thread run_agent_turn is
                          running on; the caller is responsible for marshaling.
          on_event     -- callable(kind, payload). Kinds:
                            'text_delta' payload={text}
                            'tool_use'   payload={name, input, id}
                            'tool_result' payload={name, result, is_error}
                            'step'        payload={n}
                          Safe to emit across threads (caller wraps with Qt signal).
          is_cancelled -- callable() -> bool; checked between API calls.
          max_steps    -- hard cap on tool-use rounds within this turn.
          on_usage     -- callable(usage_dict) invoked after each API response
                          so the UI can accumulate token counts.

        Returns the concatenated final assistant text for the turn.
        """
        cached_tools = _clone_tools_with_cache(tools)
        for step in range(max_steps):
            if is_cancelled():
                raise CancelledError("cancelled")
            on_event("step", {"n": step + 1, "max": max_steps})

            payload = {
                "model": model,
                "max_tokens": max_tokens,
                "system": _system_blocks(),
                "tools": cached_tools,
                "messages": _prepare_messages(history, model),
            }
            _apply_model_options(payload, model, effort)

            if stream:
                def _emit_text(txt, _step=step):
                    on_event("text_delta", {"text": txt, "step": _step})

                def _emit_thinking(txt):
                    on_event("thinking_delta", {"text": txt})
                content, stop_reason, usage = self._stream(
                    payload, _emit_text, is_cancelled, on_wait=on_wait,
                    on_thinking_delta=_emit_thinking)
                if on_usage:
                    try:
                        on_usage(usage)
                    except Exception:
                        pass
            else:
                resp = self._post(payload, is_cancelled=is_cancelled,
                                  on_wait=on_wait)
                content = resp.get("content", []) or []
                stop_reason = resp.get("stop_reason", "")
                if on_usage:
                    try:
                        on_usage(resp.get("usage") or {})
                    except Exception:
                        pass

            history.append({"role": "assistant", "content": content})
            tool_uses = [b for b in content if b.get("type") == "tool_use"]

            if stop_reason == "refusal":
                # Newer models can decline server-side (HTTP 200, empty or
                # partial content). Say so plainly instead of surfacing an
                # empty turn.
                return (
                    "(The model declined this request -- its safety "
                    "classifiers rejected it. Rephrasing, or switching to "
                    "another model in the picker, usually works.)"
                )

            if stop_reason != "tool_use" or not tool_uses:
                texts = [b.get("text", "") for b in content
                         if b.get("type") == "text"]
                return "\n".join(t for t in texts if t).strip() or "(no text)"

            tool_results = []
            for tu in tool_uses:
                if is_cancelled():
                    raise CancelledError("cancelled")
                on_event("tool_use", {
                    "id": tu.get("id"),
                    "name": tu.get("name", ""),
                    "input": tu.get("input", {}),
                })
                result, is_error = exec_tool(
                    tu.get("name", ""), tu.get("input", {}) or {})
                on_event("tool_result", {
                    "name": tu.get("name", ""),
                    "result": result,
                    "is_error": is_error,
                })
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tu.get("id"),
                    "content": result if isinstance(result, str) else str(result),
                    "is_error": bool(is_error),
                })
            history.append({"role": "user", "content": tool_results})

        return (
            "(stopped: reached the max tool-call budget of %d for this turn. "
            "Raise 'Max tool calls' in the gear menu, or ask me to continue "
            "and I'll pick up where I left off.)" % max_steps
        )
