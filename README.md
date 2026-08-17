# Claude Code for IDA Pro

An IDA Pro plugin that embeds Claude as a dockable chat panel. Ask questions
about the current function or run an agent loop that drives the database
(list / read / rename / comment / jump) — either through the Anthropic API
with a key, or through the logged-in `claude` CLI on your Claude
subscription. Both paths get the same IDA tools.

![Claude Code UI](Capture1.png)

## Features

- **Dockable chat panel** pinned to IDA's right dock area (next to
  Functions / Imports), Ctrl+Shift+K to open.
- **Claude-style UI** — rounded dark input card with toolbar, coral send
  button, and a sliders menu.
- **Terminal-style transcript** — the conversation renders the way Claude
  Code does in a terminal: monospace throughout, `>` for your prompt, a
  coral `●` per assistant turn and tool call, and results hanging off a
  `└` branch. Tool activity is shown by default (untick *Show tool
  activity* for prose only).
- **Two auth modes, both with full tool use**
  - *API key* — calls the Anthropic Messages API directly and runs the
    agent loop in-process. Billed as API usage.
  - *Claude CLI (subscription)* — drives the logged-in `claude` binary
    (same account as Claude Code in the terminal), no key required. The
    plugin starts a local **MCP server** inside IDA and hands it to the CLI,
    so the CLI's own agent loop calls the same IDA tools. Usage counts
    against your Claude plan rather than API credits.
- **MCP bridge** — a localhost-only, bearer-token-authenticated MCP server
  (`127.0.0.1`, random port, token regenerated per panel) exposing all 51
  IDA tools. It is passed to the CLI with `--strict-mcp-config`, and the
  CLI's built-in file/shell tools are disabled, so a CLI turn can touch the
  IDB and nothing else. Tool calls are additionally refused unless a turn is
  actually in flight, so a `claude` process that outlives a cancel can't
  keep editing the database.
- **IDA tools Claude can call** (both modes):
  - *read / navigate:* `read_function`, `list_functions`, `list_strings`,
    `list_imports`, `list_exports`, `list_globals`, `get_xrefs_to`,
    `get_xrefs_from`, `xrefs_to_field`, `read_bytes`, `get_int`,
    `get_string`, `get_global_value`, `read_struct`,
    `get_current_address`, `get_function_info`, `jump_to`,
    `int_convert`.
  - *edit:* `rename`, `add_comment`, `set_function_comment`,
    `set_function_prototype`, `patch_asm`, `declare_type`, `define_func`,
    `define_code`, `declare_stack`, `delete_stack`.
- **Selection-aware context** — if you highlight lines in the disasm or
  pseudocode view, Claude's reply focuses on that slice; otherwise the
  full current function is attached as before.
- **Auto-refresh after edits** — renames, retypes, comments and patches
  invalidate the Hex-Rays cache and repaint open disasm + pseudocode
  views, so you see changes without pressing F5.
- **Quick actions** — one-click prompts for explaining a function, renaming
  + commenting, vulnerability review, caller tracing, binary summary, or
  crypto hunting.
- **Allow edits** toggle — write tools are rejected unless the user opts
  in, so an agent run can't silently mutate the idb.
- **Dry run** — write tools return `(dry-run) would ...` instead of
  mutating the database, so you can preview an agent's plan.
- **Rate-limit aware** — a client-side sliding window caps input tokens
  per minute (30k default), and 429 responses are retried automatically
  using the server's `retry-after` header; the UI shows why it's paused
  instead of silently hanging.
- **Resilient history** — the conversation is sanitized on startup and
  after every turn, so cancelled tool calls never leave orphan `tool_use`
  blocks that would 400 the next request.
- **Streaming with live reasoning** — text streams token-by-token in both
  modes; while the model is thinking, a summary of its reasoning ticks along
  in the status line instead of a silent pause.
- **Model picker** — Opus 5 (default), Sonnet 5, Haiku 4.5, Opus 4.8,
  Fable 5. The same id is used for the API (`model`) and the CLI
  (`--model`).
- **Effort control** — `low` / `medium` / `high` / `xhigh` / `max` in the
  settings menu, mapped to `output_config.effort` (API) and `--effort`
  (CLI). Lower is cheaper and faster; higher digs deeper on hard binaries.
  Skipped automatically for models that don't support it (Haiku 4.5).

## Requirements

- IDA Pro 7.4+ with the bundled Python 3 and PyQt5 (standard IDA builds).
- Hex-Rays decompiler (optional; used only if "Include decomp" is checked).
- One of:
  - An Anthropic API key, or
  - Claude Code (`claude`) on PATH and logged in. Tool use over MCP needs a
    reasonably recent build — `claude --version` ≥ 2.0 — since it relies on
    `--mcp-config`, `--strict-mcp-config` and `--output-format stream-json`.

No third-party Python packages are needed — the client uses only the stdlib.

## Installation

1. Locate your IDA plugins directory.
   - Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
   - macOS: `~/.idapro/plugins/`
   - Linux: `~/.idapro/plugins/`
2. Copy **both** of these into that folder:
   - `ida_claude.py`
   - the `ida_claude/` package directory
3. Copy `claude.png` and `chatclaude.png` next to `ida_claude.py` for the menu icon.
4. Restart IDA. You should see `[Claude] plugin loaded. Hotkey: Ctrl-Shift-K`
   in the output window.

### Authentication

Pick one:

**API key**
- Set `ANTHROPIC_API_KEY` in your environment before launching IDA, **or**
- Open the panel and click **Set API key...** to paste it for the session
  (kept in memory only, not written to disk).

**Claude CLI (uses your logged-in account / subscription)**
- Install Claude Code: <https://docs.claude.com/claude-code>
- Run `claude` in a terminal once and complete the browser sign-in.
- Verify `claude --version` works from a plain shell.
- In the panel, set **Auth** to **Claude CLI (subscription)**.

The panel auto-selects CLI mode if the binary is on PATH and no API key is
set. Tool use works in either mode; the difference is what gets billed.

Note that IDA must be able to see the same PATH your terminal does — if you
installed Claude Code after IDA was started, restart IDA. **CLI / MCP
diagnostics** in the settings menu prints the binary, version, session id
and MCP endpoint the panel resolved.

## Usage

1. Open a binary in IDA.
2. Press **Ctrl+Shift+K** (or *View → Open subviews → Claude Code*, or
   *Windows → Claude Code*).
3. Put the cursor in a function you want to ask about. With **Auto-attach**
   on (default), the function is included with every message.
4. Type a question or pick a **quick action**. Ctrl+Enter to send.

### Panel controls

The input card's toolbar keeps only the essentials; everything else lives
behind the **sliders icon**  to the left of the attach button.

| Toolbar (always visible) | What it does                                         |
|--------------------------|------------------------------------------------------|
| `+` Attach func          | Attach a specific function by name to next message.  |
|  Settings slider             | Open the settings menu (all toggles below).          |
| Quick actions            | One-click prompts (explain, rename, bug review, ...).|
| Model                    | Which Claude model to use.                           |
| `✕` Cancel               | Cancel the in-flight turn (only shown while busy).   |
| `↑` Send                 | Submit (Ctrl+Enter).                                 |

| Settings menu        | What it does                                         |
|--------------------------|------------------------------------------------------|
| Auth → API key / CLI     | Choose between Anthropic API and the `claude` CLI.   |
| Set API key...           | Paste a key for this IDA session.                    |
| Effort                   | low / medium / high / xhigh / max per turn.          |
| Use tools                | Let Claude call IDA tools in an agent loop (both modes).|
| Allow edits              | Permit write tools (rename, comment, patch, ...).    |
| Include decomp           | Attach Hex-Rays pseudocode along with disassembly.   |
| Auto-attach context      | Attach current function / selection to each message. |
| Dry run                  | Write tools report `(dry-run) would ...` only.       |
| Show tool activity       | Render each `● tool(args)` / `└ result` inline (on by default).|
| Max tool calls           | Hard cap on agent loop steps per turn (API mode).    |
| CLI / MCP diagnostics    | Print CLI path, version, session id, MCP endpoint.   |
| Undo last batch          | Revert the edits made by the most recent turn.       |
| Clear conversation       | Wipe history and start over (also drops the CLI session).|

### Tips

- **CLI mode bills your subscription, not API credits** — the practical
  reason to use it. Tool use is the same; only the transport differs.
- **Max tool calls applies to API mode only.** In CLI mode the `claude`
  binary owns the loop and stops when it's done.
- **Leave "Allow edits" off** during exploratory chats and flip it on when
  you explicitly want Claude to rename / comment.
- **Highlight a range** in the disasm or pseudocode view before asking a
  question to scope the answer to that slice. No highlight = full function.
- **Tool chatter is shown by default**, terminal-style. Untick *Show tool
  activity* in the settings menu if you'd rather read only the prose; the
  status line still counts the calls.
- Quoting an address like `0x401200` in Claude's reply is clickable via
  IDA's jump history — or ask Claude to `jump_to` it directly.

## Project layout

```
ida-pro-claude/
  ida_claude.py            # IDA plugin entry (PLUGIN_ENTRY, menu, dock)
  ida_claude/
    __init__.py
    chat_widget.py         # ClaudeChatForm: the Qt panel
    claude_client.py       # stdlib-only Anthropic Messages API client
    cli_client.py          # drives the `claude` CLI, parses its stream-json
    mcp_server.py          # localhost MCP server exposing ida_tools to the CLI
    ida_context.py         # pulls function context (disasm + decomp) from IDA
    ida_tools.py           # @tool-decorated IDA operations exposed to Claude
  claude.png               # menu icon
  chatclaude.png           # chat icon
```

## Troubleshooting

- **"No API key detected"** — set `ANTHROPIC_API_KEY` or click *API Key...*,
  or switch **Auth** to Claude CLI.
- **"`claude` CLI not found on PATH"** — install Claude Code and make sure
  its install dir is on PATH before launching IDA; run `claude` once to log
  in.
- **"MCP server(s) failed to connect"** in CLI mode — the `claude` process
  couldn't reach the panel's localhost endpoint. Check the endpoint with
  *CLI / MCP diagnostics*, and make sure a local firewall or proxy env var
  (`HTTP_PROXY`/`ALL_PROXY` without a `127.0.0.1` exclusion in `NO_PROXY`)
  isn't intercepting loopback traffic.
- **"the previous CLI session could not be resumed"** — the stored session
  was cleared or the IDB moved. The panel resets it; just send again.
- **CLI turn says a tool was denied** — the CLI only pre-approves the MCP
  tools; anything else (its own Bash/Read/Write) is refused by design.
- **Panel disappears when clicking another tab** — it shouldn't; the plugin
  attaches to IDA's outer main window's right dock area rather than the
  central stacked widget. If it does, reopen via Ctrl+Shift+K.
- **Edits rejected** — enable **Allow edits** in the gear menu.
- **"Waiting Xs..." system lines** — the plugin is throttling to stay
  under the 30k input-tokens/min org limit, or the server returned a 429
  and we're honoring its `retry-after`. It resumes automatically. On a paid
  tier that default is far too low (every request carries 51 tool
  definitions) — raise it with `IDA_CLAUDE_TPM_LIMIT=200000` in the
  environment before launching IDA. API mode only.
- **Pseudocode didn't update after an edit** — should auto-refresh now.
  If a view is stale, press F5 to force a re-decompile.
- **If you dont see plugins directory in APPDATA create it and add the code**
