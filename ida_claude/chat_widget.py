"""Docked PyQt chat window for the IDA Pro Claude plugin.

UI is modeled after the 21st.dev Claude-style AI input component: a rounded
dark card (#30302E) with the textarea on top and a toolbar row inside the
card -- `+` (attach) and the settings gear on the left, the model picker and
coral send arrow on the right. All other controls (auth, toggles, tool-call
budget, undo, clear) live behind the gear menu (option B).
"""
import html
import json
import os
import re
import threading

import idaapi

try:
    import ida_netnode
except Exception:
    ida_netnode = None


# Per-IDB chat persistence lives in a named netnode. The "$ " prefix is the
# IDA convention for plugin-private netnodes.
_NETNODE_NAME = "$ claude_ida_chat"
_NETNODE_TAG_HISTORY = "H"
_NETNODE_TAG_USAGE = "U"


def _nn_save(tag, data):
    if ida_netnode is None:
        return
    try:
        n = ida_netnode.netnode(_NETNODE_NAME, 0, True)
        payload = data if isinstance(data, bytes) else str(data).encode("utf-8")
        try:
            n.delblob(0, tag)
        except Exception:
            pass
        n.setblob(payload, 0, tag)
    except Exception:
        pass


def _nn_load(tag):
    if ida_netnode is None:
        return None
    try:
        n = ida_netnode.netnode(_NETNODE_NAME, 0, False)
        if n == idaapi.BADADDR:
            return None
        data = n.getblob(0, tag)
        if not data:
            return None
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace")
        return str(data)
    except Exception:
        return None


def _nn_delete():
    if ida_netnode is None:
        return
    try:
        n = ida_netnode.netnode(_NETNODE_NAME, 0, False)
        if n == idaapi.BADADDR:
            return
        try:
            n.delblob(0, _NETNODE_TAG_HISTORY)
            n.delblob(0, _NETNODE_TAG_USAGE)
        except Exception:
            pass
        try:
            n.kill()
        except Exception:
            pass
    except Exception:
        pass


def _load_history_from_netnode():
    raw = _nn_load(_NETNODE_TAG_HISTORY)
    if not raw:
        return []
    try:
        hist = json.loads(raw)
    except Exception:
        return []
    if not isinstance(hist, list):
        return []
    return hist


def _save_history_to_netnode(history):
    try:
        _nn_save(_NETNODE_TAG_HISTORY, json.dumps(history))
    except Exception:
        pass


def _load_usage_from_netnode():
    raw = _nn_load(_NETNODE_TAG_USAGE)
    totals = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 0,
        "tool_calls": 0,
    }
    if not raw:
        return totals
    try:
        saved = json.loads(raw)
        for k in totals:
            if k in saved and isinstance(saved[k], int):
                totals[k] = saved[k]
    except Exception:
        pass
    return totals


def _save_usage_to_netnode(totals):
    try:
        _nn_save(_NETNODE_TAG_USAGE, json.dumps(totals))
    except Exception:
        pass


# Icon path is still used for the dock-tab icon.
_ICON_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "claude.png",
)


def _find_asset(filename):
    """Locate a bundled asset. When IDA loads the plugin from
    %APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\ the user may have dropped only
    `ida_claude.py` + the package and forgotten an accompanying PNG, so we
    try several sensible locations before giving up."""
    here = os.path.dirname(os.path.abspath(__file__))           # ida_claude/
    parent = os.path.dirname(here)                              # plugins/
    candidates = [
        os.path.join(parent, filename),   # sibling of ida_claude.py
        os.path.join(here, filename),     # inside the package
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None


# Larger starburst logo shown next to the welcome banner.
_CHAT_LOGO_PATH = _find_asset("chatclaude.png")


from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtCore import pyqtSignal

# IDA 9.0+ ships PySide6; older IDA ships PyQt5. QShortcut / QAction /
# QActionGroup moved from QtWidgets (Qt5) to QtGui (Qt6).
QShortcut    = getattr(QtGui, "QShortcut",    None) or QtWidgets.QShortcut
QAction      = getattr(QtGui, "QAction",      None) or QtWidgets.QAction
QActionGroup = getattr(QtGui, "QActionGroup", None) or QtWidgets.QActionGroup


class _FlushSubmenuStyle(QtWidgets.QProxyStyle):
    """Force submenus to sit just outside their parent menu.

    Qt's native style returns a positive value for PM_SubMenuOverlap so the
    child menu slides a few pixels *over* the parent on open -- the stacked-
    panel look. Even 0 still leaves the submenu's 1px left border painting
    on top of the parent's 1px right border (same column), which reads as a
    faint double-line clip. Returning -1 shifts the submenu one pixel past
    the parent so the two borders sit in adjacent columns and look like a
    single shared edge.
    """
    def pixelMetric(self, metric, option=None, widget=None):
        if metric == QtWidgets.QStyle.PM_SubMenuOverlap:
            return 5
        return super(_FlushSubmenuStyle, self).pixelMetric(
            metric, option, widget)


from ida_claude.claude_client import (
    ClaudeClient, ClaudeError, CancelledError, model_supports_effort,
)
from ida_claude.cli_client import ClaudeCliClient, CliError, CliCancelled
from ida_claude.mcp_server import IdaMcpServer, McpServerError
from ida_claude.ida_context import (
    get_current_function_context,
    get_function_context_by_name,
    get_selection_context,
)
from ida_claude import ida_tools


# --- view refresh after write-tool edits -------------------------------------

# Keys commonly used by write tools to point at an EA. We parse these out of
# the params so we can invalidate the right function's decompilation cache.
_EA_PARAM_KEYS = (
    "address", "ea", "target", "func_ea", "start", "start_address",
    "start_ea", "begin", "addr",
)


def _coerce_ea(v):
    if v is None:
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        try:
            if s.lower().startswith("0x"):
                return int(s, 16)
            return int(s, 0)
        except Exception:
            try:
                import idc
                ea = idc.get_name_ea_simple(s)
                if ea != idaapi.BADADDR:
                    return ea
            except Exception:
                pass
    return None


def _refresh_ida_views_after_edit(params):
    """Mark any function referenced by `params` (or at the cursor) as dirty
    in the Hex-Rays cache, then request a refresh of disasm + pseudocode
    views so the user sees the edit without hitting F5."""
    try:
        import ida_hexrays
    except Exception:
        ida_hexrays = None
    try:
        import ida_kernwin
    except Exception:
        ida_kernwin = None

    eas = set()
    if isinstance(params, dict):
        for k in _EA_PARAM_KEYS:
            if k in params:
                ea = _coerce_ea(params[k])
                if ea is not None and ea != idaapi.BADADDR:
                    eas.add(ea)
    # Always include the cursor EA as a fallback -- most edits are about the
    # function the user is looking at.
    try:
        import idc
        cur = idc.get_screen_ea()
        if cur != idaapi.BADADDR:
            eas.add(cur)
    except Exception:
        pass

    if ida_hexrays is not None:
        for ea in eas:
            try:
                f = idaapi.get_func(ea)
                if f is not None:
                    ida_hexrays.mark_cfunc_dirty(f.start_ea)
            except Exception:
                pass

    if ida_kernwin is not None:
        try:
            mask = getattr(ida_kernwin, "IWID_DISASMS", 0) \
                | getattr(ida_kernwin, "IWID_PSEUDOCODE", 0)
            if mask:
                ida_kernwin.request_refresh(mask)
            else:
                ida_kernwin.refresh_idaview_anyway()
        except Exception:
            try:
                ida_kernwin.refresh_idaview_anyway()
            except Exception:
                pass


# (display label, model id). Labels go in the combo; ids go out on the wire.
# The same id works for both paths: the Anthropic API takes it as `model`, the
# CLI takes it as `--model`. Ids are the undated aliases -- do not append date
# suffixes, they are complete as written.
MODELS = [
    ("Opus 5",    "claude-opus-5"),
    ("Sonnet 5",  "claude-sonnet-5"),
    ("Haiku 4.5", "claude-haiku-4-5"),
    ("Opus 4.8",  "claude-opus-4-8"),
    ("Fable 5",   "claude-fable-5"),
]

# output_config.effort / --effort. Controls how much the model thinks and how
# much work it does per turn; "high" is the API default.
EFFORTS = ["low", "medium", "high", "xhigh", "max"]
DEFAULT_EFFORT = "high"

QUICK_ACTIONS = [
    ("(quick actions...)", None),
    ("Explain current function",
     "Explain what the current function does. Walk through loops and branches. "
     "Highlight any API calls or suspicious behavior."),
    ("Rename & comment current function",
     "Look at the current function. If you can identify its purpose, rename it "
     "and its key locals to meaningful names, and add a short function comment "
     "summarizing what it does. Report the changes you made."),
    ("Find bugs / vulnerability review",
     "Review the current function for memory-safety, integer, format-string, "
     "authentication, or logic bugs. For each finding, cite the address."),
    ("Trace callers",
     "List the callers of the current function (using get_xrefs_to), then "
     "briefly describe each caller's role."),
    ("Summarize this binary",
     "Give me a high-level summary of this binary: what it appears to do, "
     "notable imports, and which functions look most interesting. Use "
     "list_imports, list_strings, and list_functions as needed."),
    ("Identify crypto / encoding routines",
     "Scan the binary for crypto or encoding routines. Use list_imports and "
     "list_functions to find candidates, then read the promising ones. "
     "Report what algorithms you suspect and where."),
]


# ---------- palette: matches the 21st.dev reference ----------
_PAGE_BG    = "#262624"
_CARD_BG    = "#30302E"
_BORDER     = "#3a3835"
_TEXT       = "#eaeae8"
_TEXT_DIM   = "#a8a49c"
_TEXT_MUTED = "#8b857c"
_ACCENT     = "#cc785c"   # Claude coral (replaces the reference's amber-600)
_ACCENT_HOV = "#d68870"


# ---------- transcript: Claude Code terminal look ----------
# The panel used to render as a chat log (bold "you" lines, arrows, italics).
# This section reproduces the CLI's transcript instead: a coral dot per
# assistant/tool turn, results hanging off a box-drawing branch, and
# everything monospaced and dim except the text that matters.
_T_TEXT   = "#d7d4cd"   # body copy
_T_BRIGHT = "#faf9f5"   # bold, headings, tool names
_T_DIM    = "#8a857c"   # tool arguments, results
_T_FAINT  = "#6b6660"   # prompt markers, system notices
_T_ERR    = "#e0785f"
_T_CODEBG = "#1c1b19"

# Markers. Deliberately the widely-available box-drawing / geometric glyphs
# rather than the CLI's rarer ⏺ / ⎿ -- the same shape, but present in the
# monospace fonts IDA ships with on Windows and Linux, so no tofu.
_M_DOT    = "●"    # ● turn marker
_M_BRANCH = "└"    # └ result branch
_M_PROMPT = "&gt;"      # > user input

# Qt's rich text engine understands a subset of CSS 2.1: colors, font
# weight/style/size, margins and backgrounds work; layout properties mostly
# don't. Everything below stays inside that subset.
_DOC_CSS = (
    "pre  { background:%(codebg)s; padding:6px; white-space:pre-wrap;"
    "       color:%(text)s; margin-top:4px; margin-bottom:4px;"
    "       margin-left:14px; }"
    "code { color:#e8c48a; }"
    "a    { color:%(accent)s; }"
    # Headings read as bold text in a terminal, not as a colored banner.
    "h1   { color:%(bright)s; font-size:11pt; font-weight:bold;"
    "       margin-top:8px; margin-bottom:1px; }"
    "h2   { color:%(bright)s; font-size:10.5pt; font-weight:bold;"
    "       margin-top:8px; margin-bottom:1px; }"
    "h3   { color:%(text)s; font-size:10pt; font-weight:bold;"
    "       margin-top:6px; margin-bottom:1px; }"
    "b, strong { color:%(bright)s; }"
    "blockquote { color:%(dim)s; margin-left:14px; }"
    "li   { color:%(text)s; }"
    "table.mdtable { margin: 4px 0; }"
    "table.mdtable th { background:#2a2826; color:%(bright)s;"
    "                   padding:3px 8px; text-align:left; }"
    "table.mdtable td { padding:3px 8px; color:%(text)s; }"
    # --- transcript rows -------------------------------------------------
    ".user    { color:%(text)s; margin-top:6px; }"
    ".prompt  { color:%(faint)s; }"
    ".msg     { color:%(text)s; }"
    ".dot     { color:%(accent)s; font-weight:bold; }"
    ".tname   { color:%(bright)s; }"
    ".targs   { color:%(dim)s; }"
    ".branch  { color:%(faint)s; margin-left:6px; }"
    ".bres    { color:%(dim)s; }"
    ".sys     { color:%(faint)s; }"
    ".err     { color:%(err)s; }"
    # --- C highlighting inside <pre> -------------------------------------
    ".ckw     { color:#c586c0; }"
    ".cty     { color:#4ec9b0; }"
    ".cstr    { color:#ce9178; }"
    ".ccmt    { color:#6a9955; font-style:italic; }"
    ".cpre    { color:#9b9b9b; }"
    ".cnum    { color:#e8c48a; }"
    ".cfn     { color:#dcdcaa; }"
    # --- inline emphasis from _render_inline ------------------------------
    ".fn      { color:%(bright)s; }"
    ".num     { color:#e8c48a; }"
    ".addr    { color:#81c8f0; }"
) % {
    "text": _T_TEXT, "bright": _T_BRIGHT, "dim": _T_DIM, "faint": _T_FAINT,
    "err": _T_ERR, "accent": _ACCENT, "codebg": _T_CODEBG,
}


def _mono_font(point_size):
    """The platform's fixed-pitch UI font, so the transcript reads like a
    terminal on Windows (Consolas), macOS (Menlo) and Linux (DejaVu Sans
    Mono) without hardcoding a family that may not exist."""
    try:
        f = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont)
        if f.family():
            f.setPointSize(point_size)
            return f
    except Exception:
        pass
    f = QtGui.QFont("Consolas", point_size)
    f.setStyleHint(QtGui.QFont.Monospace)
    return f


# ---------- transcript row builders ----------
# Module-level and pure so the exact markup the panel renders can be
# unit-tested (and previewed in a browser) without a running IDA.

def _html_user(text):
    """`> what does sub_401000 do` -- the CLI's echo of your prompt."""
    return ('<div class="user"><span class="prompt">%s</span> %s</div>'
            % (_M_PROMPT, _md_to_html(text)))


def _html_assistant(body_html):
    """A coral dot, then the reply. Body is already-rendered markdown."""
    return ('<div class="msg"><span class="dot">%s</span> %s</div>'
            % (_M_DOT, body_html))


def _fmt_tool_args(params):
    """Render tool arguments the way the CLI heads a tool call: the bare
    value when there's one argument, `k=v` pairs when there are several."""
    if not isinstance(params, dict) or not params:
        return ""
    def val(v):
        if isinstance(v, str):
            return v
        return _short_repr(v, 40)
    if len(params) == 1:
        only = val(list(params.values())[0])
        return only if len(only) <= 60 else only[:57] + "..."
    parts = ["%s=%s" % (k, val(v)) for k, v in params.items()]
    joined = ", ".join(parts)
    return joined if len(joined) <= 70 else joined[:67] + "..."


def _html_tool_call(name, params):
    return ('<div class="msg"><span class="dot">%s</span> '
            '<span class="tname">%s</span>'
            '<span class="targs">(%s)</span></div>'
            % (_M_DOT, html.escape(name),
               html.escape(_fmt_tool_args(params))))


def _html_tool_result(result, is_error, max_chars=160):
    """The `└ ...` line hanging off the call above it."""
    lines = (result or "").strip().splitlines()
    preview = lines[0] if lines else ""
    if len(preview) > max_chars:
        preview = preview[:max_chars - 3] + "..."
    if len(lines) > 1:
        preview += "  (+%d lines)" % (len(lines) - 1)
    cls = "err" if is_error else "bres"
    if is_error and not preview:
        preview = "failed"
    return ('<div class="branch">%s <span class="%s">%s</span></div>'
            % (_M_BRANCH, cls, html.escape(preview)))


# ---------- thread bridge ----------

class _Bridge(QtCore.QObject):
    event    = pyqtSignal(str, object)   # (kind, payload)
    finished = pyqtSignal(str, bool)     # (final_text_or_err, is_error)


# ---------- main form ----------

class ClaudeChatForm(QtWidgets.QWidget):
    """Claude chat UI as a plain QWidget.

    We inherit directly from QWidget (instead of idaapi.PluginForm) because
    PluginForm.Show drops the widget into IDA's central QStackedWidget --
    i.e. as a sibling tab of IDA View-A / Hex View-1 / Local Types /
    Imports / Exports -- which makes the panel disappear when the user
    switches central tabs. The plugin loader wraps this widget in a
    QDockWidget that it adds directly to IDA's outer QMainWindow, putting
    Claude at the same layout level as Functions on the left so it stays
    visible regardless of central-tab switches.
    """

    def __init__(self):
        super(ClaudeChatForm, self).__init__()
        self.client = ClaudeClient()
        self.cli_client = ClaudeCliClient()
        self.history = _load_history_from_netnode()
        self._turn_history_base = None
        self._busy = False
        self._cancel = threading.Event()
        self.bridge = _Bridge()
        self.bridge.event.connect(self._on_event)
        self.bridge.finished.connect(self._on_finished)
        self._pending_attachments = []
        self._usage_totals = _load_usage_from_netnode()
        self._turn_tool_calls = 0
        # Tail of the current turn's reasoning summary, shown in the status
        # line while the model thinks (see _refresh_status).
        self._thinking_tail = ""
        # Streaming buffer + anchor: text_delta events append into the
        # conversation pane live; the anchor tracks where the current
        # assistant block started so we can re-render in-place. A separate
        # `_stream_queue` holds chars the server has delivered but we
        # haven't painted yet, so we can drip them into the view at a
        # steady rate instead of rendering whole bulk chunks at once.
        self._stream_buf = ""
        self._stream_queue = ""
        self._stream_anchor = None
        self._stream_active = False
        self._stream_timer = QtCore.QTimer(self)
        # ~33 Hz tick with a 1-char-per-tick baseline (see _drain_stream_queue)
        # gives a readable ~33 chars/sec reveal. Adaptive catch-up prevents
        # long replies from lagging seconds behind the network.
        self._stream_timer.setInterval(30)
        self._stream_timer.timeout.connect(self._drain_stream_queue)
        # Undo ledger: list of "batches" each holding the reversible edits
        # produced by a single agent turn.
        self._undo_batches = []
        # 0 = API key (Anthropic direct), 1 = Claude CLI (subscription).
        self._auth_mode = 0
        # MCP server exposing ida_tools to the CLI. Started lazily on the
        # first CLI turn and left running for the life of the panel.
        self._mcp = None
        self._effort = DEFAULT_EFFORT
        # Gate for MCP tool execution. The server outlives any single turn (the
        # CLI reconnects per invocation), so without this a `claude` process
        # that survived a cancel -- or any other local process holding the
        # token -- could still drive edits into the database. Set only while a
        # CLI turn is genuinely in flight.
        self._cli_turn_active = threading.Event()
        self._build_ui()
        self._sanitize_history_tail()
        self._replay_history()
        self._apply_window_icon()
        self._refresh_status()
        self._update_send_enabled()

    def _apply_window_icon(self):
        """Stamp claude.png on this widget so the dock's title/tab shows it."""
        if not os.path.isfile(_ICON_PATH):
            return
        icon = QtGui.QIcon(_ICON_PATH)
        if icon.isNull():
            return
        try:
            self.setWindowIcon(icon)
        except Exception:
            pass

    # ---------- UI construction ----------
    def _build_ui(self):
        self.setMinimumSize(320, 260)
        # Paint the plugin background to match the reference page (#262624)
        # via palette so we don't cascade into children stylesheets.
        pal = self.palette()
        pal.setColor(QtGui.QPalette.Window, QtGui.QColor(_PAGE_BG))
        pal.setColor(QtGui.QPalette.WindowText, QtGui.QColor(_TEXT))
        self.setPalette(pal)
        self.setAutoFillBackground(True)

        root = QtWidgets.QVBoxLayout()
        root.setContentsMargins(10, 10, 10, 6)
        root.setSpacing(8)

        # --- conversation pane ---
        self.conversation = QtWidgets.QTextBrowser()
        self.conversation.setObjectName("claudeConversation")
        self.conversation.setOpenExternalLinks(True)
        self.conversation.setFont(_mono_font(10))
        self.conversation.setStyleSheet(
            "QTextBrowser#claudeConversation {"
            "  background-color: #262624;"
            "  color: #eaeae8;"
            "  border: none;"
            "  padding: 6px;"
            "  selection-background-color: #3d3a36;"
            "  selection-color: #faf9f5;"
            "}"
            # Slim, theme-matched scrollbar. Arrows removed; rounded thumb.
            "QTextBrowser#claudeConversation QScrollBar:vertical {"
            "  background: #262624; width: 10px;"
            "  margin: 2px 2px 2px 0; border: none;"
            "}"
            "QTextBrowser#claudeConversation QScrollBar::handle:vertical {"
            "  background: #3a3835; min-height: 28px; border-radius: 4px;"
            "}"
            "QTextBrowser#claudeConversation QScrollBar::handle:vertical:hover {"
            "  background: #4a4845;"
            "}"
            "QTextBrowser#claudeConversation QScrollBar::add-line:vertical,"
            "QTextBrowser#claudeConversation QScrollBar::sub-line:vertical {"
            "  height: 0; background: transparent; border: none;"
            "}"
            "QTextBrowser#claudeConversation QScrollBar::add-page:vertical,"
            "QTextBrowser#claudeConversation QScrollBar::sub-page:vertical {"
            "  background: transparent;"
            "}"
            "QTextBrowser#claudeConversation QScrollBar:horizontal {"
            "  background: #262624; height: 10px;"
            "  margin: 0 2px 2px 2px; border: none;"
            "}"
            "QTextBrowser#claudeConversation QScrollBar::handle:horizontal {"
            "  background: #3a3835; min-width: 28px; border-radius: 4px;"
            "}"
            "QTextBrowser#claudeConversation QScrollBar::handle:horizontal:hover {"
            "  background: #4a4845;"
            "}"
            "QTextBrowser#claudeConversation QScrollBar::add-line:horizontal,"
            "QTextBrowser#claudeConversation QScrollBar::sub-line:horizontal {"
            "  width: 0; background: transparent; border: none;"
            "}"
            "QTextBrowser#claudeConversation QScrollBar::add-page:horizontal,"
            "QTextBrowser#claudeConversation QScrollBar::sub-page:horizontal {"
            "  background: transparent;"
            "}"
        )
        self.conversation.document().setDefaultStyleSheet(_DOC_CSS)

        # --- Claude-style input card ---
        # Rounded #30302E frame; textarea on top, toolbar row inside at bottom.
        card = QtWidgets.QFrame()
        card.setObjectName("claudeInputCard")
        card.setStyleSheet(
            "QFrame#claudeInputCard {"
            "  background-color: %s;"
            "  border: 1px solid %s;"
            "  border-radius: 12px;"
            "}" % (_CARD_BG, _BORDER)
        )
        card_layout = QtWidgets.QVBoxLayout(card)
        card_layout.setContentsMargins(2, 2, 2, 2)
        card_layout.setSpacing(0)

        self.input_box = QtWidgets.QPlainTextEdit()
        self.input_box.setPlaceholderText("How can I help you today?")
        self.input_box.setFrameStyle(QtWidgets.QFrame.NoFrame)
        self.input_box.setStyleSheet(
            "QPlainTextEdit {"
            "  background: transparent;"
            "  color: %s;"
            "  border: none;"
            "  padding: 8px 12px;"
            "  font-size: 11pt;"
            "  selection-background-color: #3d3a36;"
            "  selection-color: #faf9f5;"
            "}"
            "QPlainTextEdit:focus { outline: none; border: none; }"
            % _TEXT
        )
        self.input_box.setMinimumHeight(44)
        self.input_box.textChanged.connect(self._update_send_enabled)
        card_layout.addWidget(self.input_box)

        # --- toolbar row inside card ---
        tb = QtWidgets.QHBoxLayout()
        tb.setContentsMargins(8, 0, 8, 6)
        tb.setSpacing(4)

        self.btn_attach = self._mk_icon_button(
            "+", "Attach a function to the next message"
        )
        self.btn_attach.clicked.connect(self._on_attach_func)
        tb.addWidget(self.btn_attach)

        # Settings -- sliders icon, opens a popup menu (option B).
        self.btn_settings = QtWidgets.QToolButton()
        self.btn_settings.setIcon(self._make_sliders_icon(_TEXT_DIM))
        self.btn_settings.setIconSize(QtCore.QSize(18, 18))
        self.btn_settings.setToolTip("Settings")
        self.btn_settings.setFixedSize(30, 30)
        self.btn_settings.setCursor(QtCore.Qt.PointingHandCursor)
        self.btn_settings.setPopupMode(QtWidgets.QToolButton.InstantPopup)
        self.btn_settings.setStyleSheet(
            "QToolButton {"
            "  background: transparent;"
            "  border: none; border-radius: 6px;"
            "}"
            "QToolButton:hover { background: #3a3835; }"
            "QToolButton::menu-indicator { image: none; width: 0; }"
        )
        self._settings_menu = self._build_settings_menu()
        self.btn_settings.setMenu(self._settings_menu)
        tb.addWidget(self.btn_settings)

        # Quick-actions pill (optional convenience, stays visible on toolbar).
        self.quick_combo = QtWidgets.QComboBox()
        for label, _ in QUICK_ACTIONS:
            self.quick_combo.addItem(label)
        self.quick_combo.currentIndexChanged.connect(self._on_quick_action)
        self.quick_combo.setStyleSheet(self._combo_stylesheet())
        tb.addWidget(self.quick_combo)

        tb.addStretch(1)

        # Right side: model picker + cancel (while busy) + coral send.
        self.model_combo = QtWidgets.QComboBox()
        for label, model_id in MODELS:
            self.model_combo.addItem(label, model_id)
        self.model_combo.setSizeAdjustPolicy(
            QtWidgets.QComboBox.AdjustToContents
        )
        # Pin the visible width so the shorter pretty labels (e.g. "Opus 4.7")
        # don't collapse the combo and shift the send button against it.
        # 25 chars matches the previous longest id "claude-haiku-4-5-20251001".
        self.model_combo.setMinimumContentsLength(25)
        self.model_combo.setStyleSheet(self._combo_stylesheet())
        tb.addWidget(self.model_combo)

        self.btn_cancel = QtWidgets.QPushButton("\u2715")  # ✕
        self.btn_cancel.setFixedSize(30, 30)
        self.btn_cancel.setToolTip("Cancel")
        self.btn_cancel.setCursor(QtCore.Qt.PointingHandCursor)
        self.btn_cancel.setVisible(False)
        self.btn_cancel.setStyleSheet(
            "QPushButton {"
            "  background: #cf3232; color: #faf9f5;"
            "  border: none; border-radius: 8px;"
            "  font-size: 13px; font-weight: 600;"
            "}"
            "QPushButton:hover { background: #e04545; color: #ffffff; }"
            "QPushButton:pressed { background: #a82828; }"
        )
        self.btn_cancel.clicked.connect(self._on_cancel)
        tb.addWidget(self.btn_cancel)

        self.btn_send = QtWidgets.QPushButton()
        self.btn_send.setIcon(self._make_up_arrow_icon("#1f1e1c"))
        self.btn_send.setIconSize(QtCore.QSize(16, 16))
        self.btn_send.setFixedSize(30, 30)
        self.btn_send.setToolTip("Send (Ctrl+Enter)")
        self.btn_send.setCursor(QtCore.Qt.PointingHandCursor)
        self.btn_send.setDefault(True)
        self.btn_send.setStyleSheet(
            "QPushButton {"
            "  background: %s;"
            "  border: none; border-radius: 8px;"
            "}"
            "QPushButton:hover { background: %s; }"
            "QPushButton:disabled { background: #3a3835; }"
            % (_ACCENT, _ACCENT_HOV)
        )
        self.btn_send.clicked.connect(self._on_send_clicked)
        tb.addWidget(self.btn_send)

        card_layout.addLayout(tb)

        # --- empty-state welcome page (logo + heading) -----------------
        # QTextBrowser's HTML subset won't load file:// or data: URLs
        # through <img>, so the welcome is a real QWidget shown instead of
        # the conversation browser while the chat is empty.
        self._welcome_page = QtWidgets.QWidget()
        # Match the QTextBrowser's expanding policy so switching stack pages
        # doesn't shift the splitter when the first message arrives.
        self._welcome_page.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding
        )
        self._welcome_page.setAutoFillBackground(True)
        wpal = self._welcome_page.palette()
        wpal.setColor(QtGui.QPalette.Window, QtGui.QColor(_PAGE_BG))
        self._welcome_page.setPalette(wpal)
        wl = QtWidgets.QHBoxLayout(self._welcome_page)
        wl.setContentsMargins(16, 16, 16, 16)
        wl.setSpacing(14)
        wl.addStretch(1)
        if _CHAT_LOGO_PATH and os.path.isfile(_CHAT_LOGO_PATH):
            logo_lbl = QtWidgets.QLabel()
            pm = QtGui.QPixmap(_CHAT_LOGO_PATH)
            if not pm.isNull():
                pm = pm.scaled(
                    56, 56,
                    QtCore.Qt.KeepAspectRatio,
                    QtCore.Qt.SmoothTransformation,
                )
                logo_lbl.setPixmap(pm)
                logo_lbl.setStyleSheet("background: transparent;")
                wl.addWidget(logo_lbl, 0, QtCore.Qt.AlignVCenter)
        welcome_text = QtWidgets.QLabel("What are we reversing today?")
        welcome_text.setFont(_mono_font(15))
        welcome_text.setStyleSheet(
            "color:#C2C0B6; background: transparent;"
        )
        wl.addWidget(welcome_text, 0, QtCore.Qt.AlignVCenter)
        wl.addStretch(1)

        self._convo_stack = QtWidgets.QStackedWidget()
        self._convo_stack.addWidget(self._welcome_page)   # index 0
        self._convo_stack.addWidget(self.conversation)    # index 1

        # --- assemble: conversation/welcome on top, card below, splittable -
        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        splitter.setHandleWidth(6)
        splitter.setStyleSheet(
            "QSplitter { background: %s; }"
            "QSplitter::handle { background: %s; border: none; }"
            "QSplitter::handle:hover { background: %s; }"
            % (_PAGE_BG, _PAGE_BG, _BORDER)
        )
        splitter.addWidget(self._convo_stack)
        splitter.addWidget(card)
        splitter.setStretchFactor(0, 6)
        splitter.setStretchFactor(1, 1)
        splitter.setChildrenCollapsible(False)
        splitter.setSizes([500, 110])
        root.addWidget(splitter, 1)

        # --- status line: tokens + tool-call totals ---
        self.status_label = QtWidgets.QLabel("")
        self.status_label.setFont(_mono_font(8))
        self.status_label.setStyleSheet(
            "color:%s; padding:2px 4px; background: transparent;" % _T_FAINT
        )
        self.status_label.setTextInteractionFlags(
            QtCore.Qt.TextSelectableByMouse
        )
        root.addWidget(self.status_label)

        self.setLayout(root)

        QShortcut(
            QtGui.QKeySequence("Ctrl+Return"), self.input_box,
            activated=self._on_send_clicked,
        )

        # Auto-prefer CLI if available and no API key is set.
        if self.cli_client.available() and not self.client.api_key:
            self.act_auth_cli.setChecked(True)
            self._on_auth_changed(1)
        else:
            self.act_auth_api.setChecked(True)
            self._on_auth_changed(0)

        if self._auth_mode == 0 and not self.client.api_key:
            self._append_sys(
                "No API key detected. Open <b>\u2699</b> &rarr; "
                "<b>Set API key...</b>, set <code>ANTHROPIC_API_KEY</code>, "
                "or switch auth to <b>Claude CLI</b>."
            )

    def _make_up_arrow_icon(self, color_hex, size=16):
        """Paint a perfectly centered upward arrow as a QIcon so the send
        button's glyph isn't offset by font metrics."""
        pm = QtGui.QPixmap(size, size)
        pm.fill(QtCore.Qt.transparent)
        p = QtGui.QPainter(pm)
        try:
            p.setRenderHint(QtGui.QPainter.Antialiasing, True)
            col = QtGui.QColor(color_hex)
            pen = QtGui.QPen(col)
            pen.setWidthF(2.0)
            pen.setCapStyle(QtCore.Qt.RoundCap)
            pen.setJoinStyle(QtCore.Qt.RoundJoin)
            p.setPen(pen)
            p.setBrush(QtCore.Qt.NoBrush)
            cx = size / 2.0
            top_y = size * 0.22
            bot_y = size * 0.78
            # Vertical shaft.
            p.drawLine(QtCore.QPointF(cx, bot_y), QtCore.QPointF(cx, top_y))
            # Arrow head.
            head = size * 0.28
            p.drawLine(QtCore.QPointF(cx, top_y),
                       QtCore.QPointF(cx - head, top_y + head))
            p.drawLine(QtCore.QPointF(cx, top_y),
                       QtCore.QPointF(cx + head, top_y + head))
        finally:
            p.end()
        return QtGui.QIcon(pm)

    def _make_sliders_icon(self, color_hex, size=18):
        """Paint a horizontal-sliders icon (two tracks with knobs) as a QIcon."""
        pm = QtGui.QPixmap(size, size)
        pm.fill(QtCore.Qt.transparent)
        p = QtGui.QPainter(pm)
        try:
            p.setRenderHint(QtGui.QPainter.Antialiasing, True)
            col = QtGui.QColor(color_hex)
            pen = QtGui.QPen(col)
            pen.setWidthF(1.6)
            pen.setCapStyle(QtCore.Qt.RoundCap)
            p.setPen(pen)
            p.setBrush(QtCore.Qt.NoBrush)
            # Two horizontal tracks.
            y1 = size * 0.32
            y2 = size * 0.68
            x0, x1 = size * 0.12, size * 0.88
            p.drawLine(QtCore.QPointF(x0, y1), QtCore.QPointF(x1, y1))
            p.drawLine(QtCore.QPointF(x0, y2), QtCore.QPointF(x1, y2))
            # Knobs: filled dot on each track at different positions.
            p.setBrush(col)
            p.setPen(QtCore.Qt.NoPen)
            r = size * 0.13
            # Top knob toward the right, bottom knob toward the left.
            p.drawEllipse(QtCore.QPointF(size * 0.68, y1), r, r)
            p.drawEllipse(QtCore.QPointF(size * 0.32, y2), r, r)
        finally:
            p.end()
        return QtGui.QIcon(pm)

    def _mk_icon_button(self, glyph, tooltip):
        """Small transparent icon button for the card toolbar."""
        b = QtWidgets.QToolButton()
        b.setText(glyph)
        b.setToolTip(tooltip)
        b.setFixedSize(30, 30)
        b.setCursor(QtCore.Qt.PointingHandCursor)
        b.setStyleSheet(
            "QToolButton {"
            "  background: transparent; color: %s;"
            "  border: none; border-radius: 6px;"
            "  font-size: 17px; font-weight: bold;"
            "}"
            "QToolButton:hover { background: #3a3835; color: %s; }"
            "QToolButton:disabled { color: #5a5855; }"
            % (_TEXT_DIM, _TEXT)
        )
        return b

    def _combo_stylesheet(self):
        """Flat, pill-shaped combo box matching the reference's ghost buttons."""
        return (
            "QComboBox {"
            "  background: transparent; color: %s;"
            "  border: none; padding: 4px 8px; border-radius: 6px;"
            "  font-size: 10pt;"
            "}"
            "QComboBox:hover { background: #3a3835; color: %s; }"
            "QComboBox::drop-down { border: none; width: 14px; }"
            "QComboBox::down-arrow { image: none; width: 0; height: 0; }"
            "QComboBox QAbstractItemView {"
            "  background: #2a2826; color: %s;"
            "  border: 1px solid #3a3835;"
            "  selection-background-color: #3a3835;"
            "  selection-color: #faf9f5;"
            "  padding: 4px;"
            "}"
            % (_TEXT_DIM, _TEXT, _TEXT)
        )

    def _build_settings_menu(self):
        """Gear menu holding auth, toggles, budget, undo, and clear."""
        menu_style = (
            "QMenu {"
            "  background-color: #2a2826; border: 1px solid #3a3835;"
            "  color: #eaeae8; padding: 4px;"
            "}"
            "QMenu::item {"
            "  padding: 6px 24px 6px 28px; border-radius: 4px;"
            "}"
            "QMenu::item:selected { background-color: #3a3835; }"
            "QMenu::item:disabled { color: #6a6866; }"
            "QMenu::separator {"
            "  height: 1px; background: #3a3835; margin: 4px 6px;"
            "}"
        )
        # The proxy style kills PM_SubMenuOverlap so the auth submenu lands
        # flush against the parent menu instead of sliding over it. Keep a
        # reference on the widget so the style instance outlives the menu.
        self._flush_submenu_style = _FlushSubmenuStyle()

        menu = QtWidgets.QMenu(self)
        menu.setStyleSheet(menu_style)
        menu.setStyle(self._flush_submenu_style)

        # Auth -- exclusive radio group in a submenu. The submenu is a
        # separate QMenu instance, so Qt does not cascade the parent's
        # stylesheet into it -- without setting it explicitly it renders
        # with the native light chrome and appears to sit on top of the
        # dark settings menu instead of flush against it.
        auth_menu = menu.addMenu("Auth")
        auth_menu.setStyleSheet(menu_style)
        auth_menu.setStyle(self._flush_submenu_style)
        grp = QActionGroup(auth_menu)
        grp.setExclusive(True)
        self.act_auth_api = QAction("API key (Anthropic)", auth_menu)
        self.act_auth_api.setCheckable(True)
        self.act_auth_api.triggered.connect(
            lambda _checked=False: self._on_auth_changed(0)
        )
        self.act_auth_cli = QAction("Claude CLI (subscription)", auth_menu)
        self.act_auth_cli.setCheckable(True)
        self.act_auth_cli.setToolTip(
            "Run turns through the logged-in `claude` CLI, billed against "
            "your Claude subscription. IDA tools are exposed to it over a "
            "local MCP server, so tool use works the same as API mode."
        )
        self.act_auth_cli.triggered.connect(
            lambda _checked=False: self._on_auth_changed(1)
        )
        grp.addAction(self.act_auth_api)
        grp.addAction(self.act_auth_cli)
        auth_menu.addAction(self.act_auth_api)
        auth_menu.addAction(self.act_auth_cli)

        act_key = menu.addAction("Set API key...")
        act_key.triggered.connect(self._prompt_api_key)

        # Effort -- maps to output_config.effort (API) / --effort (CLI).
        effort_menu = menu.addMenu("Effort")
        effort_menu.setStyleSheet(menu_style)
        effort_menu.setStyle(self._flush_submenu_style)
        effort_grp = QActionGroup(effort_menu)
        effort_grp.setExclusive(True)
        for level in EFFORTS:
            act = QAction(level, effort_menu)
            act.setCheckable(True)
            act.setChecked(level == DEFAULT_EFFORT)
            act.triggered.connect(
                lambda _checked=False, lv=level: self._on_effort_changed(lv)
            )
            effort_grp.addAction(act)
            effort_menu.addAction(act)
        # A QMenu's own tooltip never renders; the tooltip the user sees
        # belongs to the action that opens it.
        effort_menu.menuAction().setToolTip(
            "How hard the model works per turn. 'low'/'medium' are cheaper "
            "and faster; 'xhigh'/'max' dig deeper on hard binaries."
        )

        menu.addSeparator()

        self.chk_tools = QAction("Use tools", menu)
        self.chk_tools.setCheckable(True)
        self.chk_tools.setChecked(True)
        self.chk_tools.setToolTip(
            "Let Claude call IDA tools (read, rename, comment, jump, etc.) "
            "in an agent loop. In CLI mode the tools are served over a local "
            "MCP server; unchecking sends a plain text-only turn."
        )
        menu.addAction(self.chk_tools)

        self.chk_edits = QAction("Allow edits", menu)
        self.chk_edits.setCheckable(True)
        self.chk_edits.setChecked(False)
        self.chk_edits.setToolTip(
            "When unchecked, tools that modify the database are rejected."
        )
        menu.addAction(self.chk_edits)

        self.chk_decomp = QAction("Include decomp", menu)
        self.chk_decomp.setCheckable(True)
        self.chk_decomp.setChecked(True)
        menu.addAction(self.chk_decomp)

        self.chk_auto = QAction("Auto-attach context", menu)
        self.chk_auto.setCheckable(True)
        self.chk_auto.setChecked(True)
        self.chk_auto.setToolTip(
            "Attach the highlighted selection (if any) or the current "
            "function to each message."
        )
        menu.addAction(self.chk_auto)

        self.chk_dryrun = QAction("Dry run", menu)
        self.chk_dryrun.setCheckable(True)
        self.chk_dryrun.setChecked(False)
        self.chk_dryrun.setToolTip(
            "Write tools return '(dry-run) would ...' instead of mutating "
            "the database."
        )
        menu.addAction(self.chk_dryrun)

        self.chk_show_tools = QAction("Show tool activity", menu)
        self.chk_show_tools.setCheckable(True)
        self.chk_show_tools.setChecked(True)
        self.chk_show_tools.setToolTip(
            "Show each tool call and its result inline, the way the terminal "
            "does. Untick for prose only -- you'll still get a count in the "
            "status line."
        )
        menu.addAction(self.chk_show_tools)

        menu.addSeparator()

        # Max tool calls as a spinbox embedded via QWidgetAction.
        budget_widget = QtWidgets.QWidget()
        bl = QtWidgets.QHBoxLayout(budget_widget)
        bl.setContentsMargins(12, 4, 12, 4)
        bl.setSpacing(8)
        budget_label = QtWidgets.QLabel("Max tool calls")
        budget_label.setStyleSheet("color:%s; background: transparent;" % _TEXT)
        bl.addWidget(budget_label)
        self.spin_budget = QtWidgets.QSpinBox()
        self.spin_budget.setRange(1, 512)
        self.spin_budget.setValue(50)
        self.spin_budget.setStyleSheet(
            "QSpinBox {"
            "  background:#1f1e1c; color:%s; border:1px solid #3a3835;"
            "  padding:2px 4px; border-radius:4px; min-width: 60px;"
            "}" % _TEXT
        )
        bl.addWidget(self.spin_budget)
        bl.addStretch(1)
        budget_action = QtWidgets.QWidgetAction(menu)
        budget_action.setDefaultWidget(budget_widget)
        menu.addAction(budget_action)

        menu.addSeparator()

        self.act_diag = menu.addAction("CLI / MCP diagnostics")
        self.act_diag.setToolTip(
            "Print the detected `claude` binary, its version, and the local "
            "MCP endpoint serving the IDA tools."
        )
        self.act_diag.triggered.connect(self._on_diagnostics)

        self.act_undo = menu.addAction("Undo last edits")
        self.act_undo.setToolTip(
            "Revert rename/comment/prototype/lvar/struct edits from the most "
            "recent agent turn that produced edits."
        )
        self.act_undo.setEnabled(False)
        self.act_undo.triggered.connect(self._on_undo)

        self.act_clear = menu.addAction("Clear conversation")
        self.act_clear.triggered.connect(self._on_clear)

        return menu

    def _update_send_enabled(self):
        """Send is enabled iff there is trimmed input and we're not busy."""
        has_text = bool(self.input_box.toPlainText().strip())
        self.btn_send.setEnabled(has_text and not self._busy)

    # ---------- history replay ----------
    def _replay_history(self):
        if not self.history:
            self._show_welcome()
            return
        self.conversation.clear()
        for msg in self.history:
            role = msg.get("role")
            content = msg.get("content")
            if role == "user":
                if isinstance(content, str):
                    q = content.split("\n\nUser question: ", 1)[-1]
                    self._append_user(q)
            elif role == "assistant":
                if isinstance(content, str):
                    self._append_claude(content)
                elif isinstance(content, list):
                    for b in content:
                        if b.get("type") == "text" and b.get("text"):
                            self._append_claude(b["text"])

    def _show_welcome(self):
        """Switch the stack to the welcome page (logo + heading)."""
        self._convo_stack.setCurrentWidget(self._welcome_page)

    # ---------- append helpers ----------
    def _append_raw(self, block):
        # Any content ends the empty state; swap the stack to the browser.
        if self._convo_stack.currentWidget() is not self.conversation:
            self._convo_stack.setCurrentWidget(self.conversation)
        self.conversation.append(block)
        sb = self.conversation.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _append_user(self, text):
        self._append_raw(_html_user(text))

    def _append_claude(self, text):
        self._append_raw(_html_assistant(_md_to_html(text)))

    def _append_sys(self, text):
        self._append_raw('<div class="sys">' + text + '</div>')

    def _append_err(self, text):
        self._append_raw('<div class="err">' + html.escape(text) + '</div>')

    def _append_tool_call(self, name, params):
        self._append_raw(_html_tool_call(name, params))

    def _append_tool_result(self, name, result, is_error):
        # The name is already on the call line directly above, so the result
        # row only carries the outcome -- same as the CLI.
        self._append_raw(_html_tool_result(result, is_error))

    # ---------- button handlers ----------
    def _prompt_api_key(self):
        key, ok = QtWidgets.QInputDialog.getText(
            self, "Anthropic API Key",
            "Paste your Anthropic API key (kept in memory for this IDA "
            "session only):",
            QtWidgets.QLineEdit.Password,
        )
        if ok and key.strip():
            self.client.api_key = key.strip()
            self._append_sys("API key set for this session.")

    def _on_clear(self):
        self.history = []
        self._pending_attachments = []
        self._undo_batches = []
        # Drop the CLI-side conversation too, or the next CLI turn would
        # resume a session that still remembers everything we just cleared.
        self.cli_client.reset_session()
        self.act_undo.setEnabled(False)
        self._usage_totals = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
            "tool_calls": 0,
        }
        self._discard_stream_block()
        self.conversation.clear()
        _nn_delete()
        self._show_welcome()
        self._refresh_status()

    def _on_attach_func(self):
        name, ok = QtWidgets.QInputDialog.getText(
            self, "Attach function", "Function name:",
        )
        if not ok or not name.strip():
            return
        ctx = get_function_context_by_name(
            name.strip(), include_decomp=self.chk_decomp.isChecked()
        )
        if ctx is None:
            self._append_err("No function named %r found." % name.strip())
            return
        self._pending_attachments.append(ctx)
        self._append_sys(
            "Attached <b>%s</b> to next message." % html.escape(name.strip())
        )

    def _on_quick_action(self, idx):
        if idx <= 0:
            return
        _, prompt = QUICK_ACTIONS[idx]
        self.quick_combo.setCurrentIndex(0)
        if not prompt:
            return
        self.input_box.setPlainText(prompt)
        self.input_box.setFocus()

    def _on_cancel(self):
        if self._busy:
            self._cancel.set()
            self._append_sys("Cancellation requested...")

    def _on_effort_changed(self, level):
        self._effort = level
        self._append_sys("Effort set to <b>%s</b>." % html.escape(level))

    def _on_auth_changed(self, idx):
        """0 = API key, 1 = Claude CLI (subscription, tools over MCP)."""
        self._auth_mode = int(idx)
        cli_mode = (self._auth_mode == 1)
        # Both paths support tools now, so neither toggle is mode-specific.
        self.chk_tools.setEnabled(True)
        self.chk_edits.setEnabled(True)
        if not cli_mode:
            return
        if not self.cli_client.available():
            self._append_sys(
                "<b>claude</b> CLI not found on PATH. Install Claude Code "
                "and run <code>claude</code> once to log in, then restart IDA."
            )
            return
        self._append_sys(
            "CLI mode: turns run through the logged-in <code>claude</code> "
            "binary and bill against your Claude subscription. IDA tools are "
            "served to it over a local MCP server."
        )

    # ---------- MCP server ----------
    def _ensure_mcp(self):
        """Start (once) the localhost MCP server that fronts ida_tools.

        Returns the server, or raises McpServerError. The CLI connects to it
        fresh on every turn, so it has to outlive individual turns.
        """
        if self._mcp is not None and self._mcp.running():
            return self._mcp
        # Tools run through the same callable the API path uses, so "Allow
        # edits", dry-run and the post-write view refresh all apply
        # identically no matter which side drove the call.
        self._mcp = IdaMcpServer(
            tool_defs=ida_tools.get_tool_defs,
            exec_tool=self._exec_tool_for_mcp,
        )
        self._mcp.start()
        return self._mcp

    def _exec_tool_for_mcp(self, name, params):
        """MCP entry point: refuse anything outside a live CLI turn."""
        if not self._cli_turn_active.is_set():
            return (
                "Rejected: no Claude Code turn is currently active in the IDA "
                "panel. This tool is only callable while the user has a turn "
                "in flight.",
                True,
            )
        return self._exec_tool_on_main_thread(name, params)

    def _stop_mcp(self):
        if self._mcp is not None:
            self._mcp.stop()
            self._mcp = None

    def _cli_workspace(self):
        """Working directory for the CLI process.

        Pinning it to the IDB's directory keeps `--resume` sessions stable
        across turns (the CLI keys session storage on cwd) and gives the
        agent a sensible place to look if the user enables file tools.
        """
        try:
            import idc
            path = idc.get_idb_path() or ""
            folder = os.path.dirname(path)
            if folder and os.path.isdir(folder):
                return folder
        except Exception:
            pass
        return os.path.expanduser("~")

    def _on_diagnostics(self):
        lines = []
        path = self.cli_client.cli_path
        if path:
            lines.append("claude CLI: <code>%s</code>" % html.escape(path))
            ver = self.cli_client.version()
            if ver:
                lines.append("version: %s" % html.escape(ver))
        else:
            lines.append("claude CLI: <b>not found on PATH</b>")
        lines.append("CLI session: %s"
                     % html.escape(self.cli_client.session_id or "(none yet)"))
        lines.append("workspace: <code>%s</code>"
                     % html.escape(self._cli_workspace()))
        if self._mcp is not None and self._mcp.running():
            lines.append("MCP endpoint: <code>%s</code> (%d tools)"
                         % (html.escape(self._mcp.url),
                            len(ida_tools.get_tool_defs())))
        else:
            lines.append("MCP endpoint: not started (starts on the first "
                         "CLI turn)")
        lines.append("API key: %s"
                     % ("set" if self.client.api_key else "not set"))
        self._append_sys("<br>".join(lines))

    def closeEvent(self, event):
        self._stop_mcp()
        try:
            super(ClaudeChatForm, self).closeEvent(event)
        except Exception:
            pass

    def _on_send_clicked(self):
        if self._busy:
            return
        question = self.input_box.toPlainText().strip()
        if not question:
            return
        self.input_box.clear()

        # Build context on the UI thread (IDA APIs are main-thread only).
        # If the user has a highlighted range in the disasm or pseudocode
        # view, focus the context on that selection; otherwise fall back to
        # the full surrounding function.
        ctx_parts = []
        if self.chk_auto.isChecked():
            try:
                sel = get_selection_context(
                    include_decomp=self.chk_decomp.isChecked()
                )
                if sel:
                    ctx_parts.append("=== Highlighted selection ===\n" + sel)
                else:
                    ctx = get_current_function_context(
                        include_decomp=self.chk_decomp.isChecked()
                    )
                    if ctx:
                        ctx_parts.append("=== Current function ===\n" + ctx)
            except Exception as e:
                self._append_err("Failed to read IDA context: %s" % e)
        for extra in self._pending_attachments:
            ctx_parts.append("=== Attached function ===\n" + extra)
        self._pending_attachments = []

        user_message = question
        if ctx_parts:
            user_message = ("\n\n".join(ctx_parts)
                            + "\n\nUser question: " + question)

        # Remember where history was before this turn so we can roll back
        # cleanly on cancel/error. Multi-step tool-use turns can leave
        # orphaned `tool_use` blocks if we only pop the last message; always
        # truncate to this snapshot instead.
        self._turn_history_base = len(self.history)
        self.history.append({"role": "user", "content": user_message})
        self._append_user(question)

        # Pre-consume pop_undo_batch() so any edits queued by prior plugin
        # activity don't get attributed to this turn.
        try:
            ida_tools.pop_undo_batch()
        except Exception:
            pass
        try:
            ida_tools.set_dry_run(self.chk_dryrun.isChecked())
        except Exception:
            pass

        self._busy = True
        self._cancel.clear()
        self._turn_tool_calls = 0
        # Swap send for cancel in-place so the toolbar width doesn't change
        # (showing both would widen the card and nudge the dock out).
        self.btn_send.setVisible(False)
        self.btn_cancel.setVisible(True)
        self._start_stream_block()

        model = self.model_combo.currentData() or self.model_combo.currentText()
        use_tools = self.chk_tools.isChecked()
        auth_mode = self._auth_mode
        max_steps = int(self.spin_budget.value())
        # Older models (Haiku 4.5 here) reject the effort parameter outright,
        # so only send it where it exists.
        effort = self._effort if model_supports_effort(model) else None

        # CLI mode: bring up the MCP bridge before the worker starts so a
        # bind failure surfaces as a plain error instead of a dead turn.
        mcp_config = None
        cli_cwd = None
        cli_prompt = user_message
        if auth_mode == 1:
            cli_cwd = self._cli_workspace()
            if use_tools:
                try:
                    mcp_config = self._ensure_mcp().mcp_config_json()
                except McpServerError as e:
                    # Route the failure through the normal finish path so
                    # history rollback, dry-run reset and button state are all
                    # handled in one place.
                    self.bridge.finished.emit(
                        "Could not start the MCP server: %s" % e, True)
                    return
            # A fresh CLI session doesn't know about turns that happened in
            # API mode (or before a restart), so seed it with the transcript
            # once; later turns resume server-side and send only the message.
            if not self.cli_client.session_id and self._turn_history_base:
                cli_prompt = _flatten_history_prefix(
                    self.history[:self._turn_history_base]) + user_message

        def on_usage(u):
            self.bridge.event.emit("usage", u)

        def on_wait(seconds, used, limit):
            self.bridge.event.emit("throttle", {
                "seconds": float(seconds),
                "used": int(used),
                "limit": int(limit),
            })

        # Open the MCP gate only for the duration of this turn.
        if auth_mode == 1 and mcp_config:
            self._cli_turn_active.set()

        def worker():
            try:
                if auth_mode == 1:
                    # The CLI owns its own agent loop and its own conversation
                    # state; our history is kept only for the transcript and
                    # for a later switch back to API mode.
                    reply = self.cli_client.run_agent_turn(
                        model=model,
                        prompt=cli_prompt,
                        on_event=lambda k, p: self.bridge.event.emit(k, p),
                        is_cancelled=self._cancel.is_set,
                        mcp_config_json=mcp_config,
                        cwd=cli_cwd,
                        effort=effort,
                    )
                    self.history.append(
                        {"role": "assistant", "content": reply}
                    )
                elif use_tools:
                    reply = self.client.run_agent_turn(
                        model=model,
                        history=self.history,
                        tools=ida_tools.get_tool_defs(),
                        exec_tool=self._exec_tool_on_main_thread,
                        on_event=lambda k, p: self.bridge.event.emit(k, p),
                        is_cancelled=self._cancel.is_set,
                        max_steps=max_steps,
                        on_usage=on_usage,
                        on_wait=on_wait,
                        effort=effort,
                    )
                else:
                    reply = self.client.send(
                        model, self.history,
                        on_usage=on_usage,
                        on_text_delta=lambda t: self.bridge.event.emit(
                            "text_delta", {"text": t, "step": 0}),
                        is_cancelled=self._cancel.is_set,
                        on_wait=on_wait,
                        effort=effort,
                    )
                    self.history.append(
                        {"role": "assistant", "content": reply}
                    )
                self.bridge.finished.emit(reply, False)
            except (CancelledError, CliCancelled):
                self.bridge.finished.emit("cancelled", True)
            except (ClaudeError, CliError) as e:
                self.bridge.finished.emit(str(e), True)
            except Exception as e:
                self.bridge.finished.emit("unexpected error: %s" % e, True)

        threading.Thread(target=worker, daemon=True).start()

    # ---------- tool dispatch ----------
    def _exec_tool_on_main_thread(self, name, params):
        box = {"result": ("no result", True)}
        is_write = name in ida_tools.WRITE_TOOLS

        def run():
            # The "Allow edits" read happens here, not in the caller: this
            # runs on IDA's main thread, and Qt widgets must not be touched
            # from the API worker or an MCP request thread.
            if is_write and not self.chk_edits.isChecked():
                box["result"] = (
                    "Edit tool '%s' is disabled: the user has 'Allow edits' "
                    "unchecked. Tell the user to enable it if they want this "
                    "edit." % name,
                    True,
                )
                return 1
            try:
                box["result"] = ida_tools.dispatch(name, params)
            except Exception as e:
                box["result"] = ("dispatch raised: %s" % e, True)
            # If a write tool succeeded, refresh disasm + pseudocode so the
            # user sees renames/retypes/comments without hitting F5.
            if is_write:
                _, is_err = box["result"]
                if not is_err:
                    try:
                        _refresh_ida_views_after_edit(params)
                    except Exception:
                        pass
            return 1

        idaapi.execute_sync(run, idaapi.MFF_WRITE)
        return box["result"]

    # ---------- UI-thread event handlers ----------
    def _on_event(self, kind, payload):
        if kind == "tool_use":
            self._turn_tool_calls += 1
            if self.chk_show_tools.isChecked():
                self._commit_stream_block()
                self._append_tool_call(
                    payload.get("name", "?"), payload.get("input", {})
                )
        elif kind == "tool_result":
            if self.chk_show_tools.isChecked():
                self._append_tool_result(
                    payload.get("name", "?"),
                    payload.get("result", ""),
                    bool(payload.get("is_error")),
                )
            # Errors always surface, even with traces hidden, so the user
            # isn't left wondering why Claude gave up.
            elif bool(payload.get("is_error")):
                self._append_err(
                    "tool %s failed: %s" % (
                        payload.get("name", "?"),
                        payload.get("result", "") or "(no detail)",
                    )
                )
        elif kind == "step":
            self._commit_stream_block()
            self._start_stream_block()
        elif kind == "text_delta":
            self._thinking_tail = ""
            self._append_stream_delta(payload.get("text", ""))
        elif kind == "thinking_delta":
            # Reasoning summaries land in the status line rather than the
            # transcript: they'd otherwise bury the answer, but without them
            # a thinking model looks frozen before its first token.
            tail = (getattr(self, "_thinking_tail", "")
                    + (payload.get("text") or ""))
            self._thinking_tail = tail[-160:]
            self._refresh_status()
        elif kind == "notice":
            self._append_sys(html.escape(payload.get("text", "")))
        elif kind == "usage":
            self._accumulate_usage(payload or {})
        elif kind == "throttle":
            secs = (payload or {}).get("seconds", 0.0)
            used = (payload or {}).get("used", -1)
            limit = (payload or {}).get("limit", 0)
            if used < 0:
                msg = "Rate-limited by server. Waiting %.1fs..." % secs
            else:
                msg = ("Throttling to stay under %d input-tokens/min "
                       "(used ~%d). Waiting %.1fs..."
                       % (limit, used, secs))
            self._append_sys(msg)
        elif kind == "_undo_done":
            results = (payload or {}).get("results") or []
            ok = sum(1 for _, k, _ in results if k)
            bad = len(results) - ok
            msg = "Reverted %d edit(s)" % ok
            if bad:
                msg += " (%d failed)" % bad
            self._append_sys(msg)

    def _sanitize_history_tail(self):
        """Ensure history never ends with an assistant message that contains
        unresolved `tool_use` blocks. Anthropic rejects such histories with
        a 400, and they only occur when a prior turn was cancelled/crashed
        between the assistant reply and the tool_result user turn."""
        hist = self.history
        while hist:
            last = hist[-1]
            if last.get("role") != "assistant":
                break
            content = last.get("content")
            if not isinstance(content, list):
                break
            tool_use_ids = {b.get("id") for b in content
                            if isinstance(b, dict)
                            and b.get("type") == "tool_use"}
            if not tool_use_ids:
                break
            # Check whether a following user message actually resolves them.
            # If we're at the tail, by definition nothing follows, so drop.
            hist.pop()

    def _on_finished(self, text, is_error):
        self._busy = False
        self._thinking_tail = ""
        # Close the MCP gate: any tool call arriving after this point belongs
        # to a process we no longer own.
        self._cli_turn_active.clear()
        self.btn_cancel.setVisible(False)
        self.btn_send.setVisible(True)
        self._update_send_enabled()
        try:
            batch = ida_tools.pop_undo_batch()
        except Exception:
            batch = []
        try:
            ida_tools.set_dry_run(False)
        except Exception:
            pass

        self._usage_totals["tool_calls"] = self._usage_totals.get(
            "tool_calls", 0) + self._turn_tool_calls

        if is_error:
            self._discard_stream_block()
            # Roll back to the snapshot taken before the user message was
            # appended. This drops the user turn AND any orphaned assistant
            # `tool_use` blocks from a partially completed agent loop, which
            # would otherwise cause a 400 ("tool_use ids were found without
            # tool_result blocks") on the next request.
            base = getattr(self, "_turn_history_base", None)
            if base is not None and 0 <= base <= len(self.history):
                del self.history[base:]
            else:
                while self.history and self.history[-1].get("role") != "user":
                    self.history.pop()
                if self.history and self.history[-1].get("role") == "user":
                    self.history.pop()
            self._append_err(text)
        else:
            if self._stream_active:
                self._commit_stream_block(final_text=text)
            else:
                self._append_claude(text)
            if batch:
                self._undo_batches.append(batch)
                self.act_undo.setEnabled(True)
            # Extra safety: if a successful turn somehow ended with an
            # unpaired tool_use (shouldn't happen, but guard against
            # stream/cancel races), strip it rather than poisoning future
            # requests.
            self._sanitize_history_tail()
        self._turn_history_base = None
        _save_history_to_netnode(self.history)
        _save_usage_to_netnode(self._usage_totals)
        self._refresh_status()

    # ---------- streaming helpers ----------
    def _start_stream_block(self):
        cursor = self.conversation.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        self._stream_anchor = cursor.position()
        self._stream_buf = ""
        self._stream_queue = ""
        self._stream_active = True
        self._stream_timer.stop()

    def _append_stream_delta(self, text):
        """Queue server-delivered text for the drip-feed timer. The server
        can batch several tokens into one event, which otherwise lands on
        screen as a single chunk; dripping it out smooths the reveal."""
        if not text or not self._stream_active:
            return
        self._stream_queue += text
        if not self._stream_timer.isActive():
            self._stream_timer.start()

    def _drain_stream_queue(self):
        """Timer tick: release a small slice of the backlog into the view.
        Adaptive so a large backlog drains faster than a trickle -- the
        reveal stays smooth without falling seconds behind the network."""
        if not self._stream_active or not self._stream_queue:
            self._stream_timer.stop()
            return
        backlog = len(self._stream_queue)
        # Baseline: one character per tick (~33 chars/sec at 30ms). If the
        # backlog grows past ~60 chars we start releasing 2-3 per tick so a
        # long answer eventually catches up; cap at 4 so even a huge dump
        # still reads as a reveal rather than a paste.
        n = min(4, max(1, backlog // 60))
        chunk = self._stream_queue[:n]
        self._stream_queue = self._stream_queue[n:]
        self._stream_buf += chunk
        self._rerender_stream_block(_md_to_html(self._stream_buf))
        if not self._stream_queue:
            self._stream_timer.stop()

    def _flush_stream_queue(self):
        """Drop the queue straight into the buffer without waiting for the
        timer. Used when we're about to commit/discard and can't afford to
        leave unpainted text behind."""
        if self._stream_queue:
            self._stream_buf += self._stream_queue
            self._stream_queue = ""
        self._stream_timer.stop()

    def _rerender_stream_block(self, html_body):
        if self._stream_anchor is None:
            return
        doc = self.conversation.document()
        cursor = QtGui.QTextCursor(doc)
        cursor.setPosition(self._stream_anchor)
        cursor.movePosition(
            QtGui.QTextCursor.End, QtGui.QTextCursor.KeepAnchor)
        cursor.removeSelectedText()
        cursor.insertHtml(_html_assistant(html_body))
        sb = self.conversation.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _commit_stream_block(self, final_text=None):
        if not self._stream_active:
            return
        self._flush_stream_queue()
        body = final_text if final_text is not None else self._stream_buf
        if body.strip():
            self._rerender_stream_block(_md_to_html(body))
            self._append_raw("")
        else:
            self._discard_stream_block()
            return
        self._stream_active = False
        self._stream_anchor = None
        self._stream_buf = ""

    def _discard_stream_block(self):
        self._stream_timer.stop()
        self._stream_queue = ""
        if self._stream_anchor is None:
            self._stream_active = False
            self._stream_buf = ""
            return
        doc = self.conversation.document()
        cursor = QtGui.QTextCursor(doc)
        cursor.setPosition(self._stream_anchor)
        cursor.movePosition(
            QtGui.QTextCursor.End, QtGui.QTextCursor.KeepAnchor)
        cursor.removeSelectedText()
        self._stream_active = False
        self._stream_anchor = None
        self._stream_buf = ""

    # ---------- usage + status ----------
    def _accumulate_usage(self, u):
        for k in ("input_tokens", "output_tokens",
                  "cache_read_input_tokens",
                  "cache_creation_input_tokens"):
            v = u.get(k)
            if isinstance(v, int) and v > 0:
                self._usage_totals[k] = self._usage_totals.get(k, 0) + v
        self._refresh_status()

    def _refresh_status(self):
        t = self._usage_totals
        line = (
            "tokens: in=%s out=%s  cache: read=%s created=%s  "
            "tool calls: %s" % (
                _fmt_int(t.get("input_tokens", 0)),
                _fmt_int(t.get("output_tokens", 0)),
                _fmt_int(t.get("cache_read_input_tokens", 0)),
                _fmt_int(t.get("cache_creation_input_tokens", 0)),
                _fmt_int(t.get("tool_calls", 0)),
            )
        )
        tail = getattr(self, "_thinking_tail", "")
        if self._busy and tail:
            line = "thinking: " + " ".join(tail.split())[-90:] + "   |   " + line
        self.status_label.setText(line)

    # ---------- undo ----------
    def _on_undo(self):
        if not self._undo_batches:
            return
        batch = self._undo_batches.pop()

        def run():
            try:
                results = ida_tools.revert_entries(batch)
            except Exception as e:
                results = [("revert_entries failed", False, str(e))]
            self.bridge.event.emit("_undo_done", {"results": results})
            return 1

        idaapi.execute_sync(run, idaapi.MFF_WRITE)
        if not self._undo_batches:
            self.act_undo.setEnabled(False)


# ---------- formatting helpers ----------

def _flatten_history_prefix(history, max_turns=8, max_chars=12000):
    """Render prior turns as plain text for a brand-new CLI session.

    Only used once per CLI conversation: afterwards the CLI resumes its own
    session and we send just the new message. Tool-use blocks are skipped --
    the CLI can re-run any tool it needs.
    """
    parts = []
    for m in history[-max_turns:]:
        content = m.get("content")
        if isinstance(content, list):
            content = "\n".join(
                b.get("text", "") for b in content
                if isinstance(b, dict) and b.get("type") == "text"
            )
        if not isinstance(content, str) or not content.strip():
            continue
        tag = "User" if m.get("role") == "user" else "Assistant"
        parts.append("%s: %s" % (tag, content.strip()))
    if not parts:
        return ""
    body = "\n\n".join(parts)
    if len(body) > max_chars:
        body = "...\n" + body[-max_chars:]
    return ("=== Earlier conversation in this IDA session ===\n"
            + body + "\n=== End of earlier conversation ===\n\n")


def _fmt_int(n):
    """Compact int formatter: 12345 -> '12.3K', 1234567 -> '1.23M'."""
    try:
        n = int(n)
    except Exception:
        return str(n)
    if n < 1000:
        return str(n)
    if n < 1_000_000:
        return "%.1fK" % (n / 1000.0)
    return "%.2fM" % (n / 1_000_000.0)


def _short_repr(obj, limit=120):
    try:
        s = repr(obj)
    except Exception:
        s = str(obj)
    if len(s) > limit:
        s = s[:limit - 3] + "..."
    return s


def _md_to_html(text):
    """Lightweight Markdown -> HTML for Claude's replies.

    Splits out fenced code blocks (```) first so their contents aren't touched
    by the line/inline transforms, then the prose sections get headers
    (# / ## / ###), bullet/numbered lists, blockquotes, bold (**), and
    inline `code`.
    """
    parts = text.split("```")
    out = []
    for i, part in enumerate(parts):
        if i % 2 == 0:
            out.append(_render_prose(part))
        else:
            # First line of the fence is a language tag if present.
            if "\n" in part:
                first, body = part.split("\n", 1)
                lang = first.strip().lower()
            else:
                lang = ""
                body = part
            # This plugin lives inside IDA Pro, so unmarked code blocks are
            # essentially always C / pseudo-C. Highlight them too.
            if lang in ("", "c", "cpp", "c++", "cc", "h", "hpp", "objc"):
                rendered = _highlight_c_code(body)
            else:
                rendered = html.escape(body)
            out.append("<pre>" + rendered + "</pre>")
    return "".join(out)


_C_KEYWORDS = frozenset((
    "if", "else", "for", "while", "do", "switch", "case", "default",
    "break", "continue", "return", "goto", "sizeof",
    "struct", "union", "enum", "typedef",
    "static", "extern", "const", "volatile", "register", "auto",
    "inline", "restrict",
    "_Alignas", "_Alignof", "_Atomic", "_Generic", "_Noreturn",
    "_Static_assert", "_Thread_local",
    # C++ / ObjC tokens that frequently appear in decomp output.
    "new", "delete", "this", "nullptr", "class", "public", "private",
    "protected", "virtual", "namespace", "template", "typename",
    "operator", "using", "try", "catch", "throw",
    # Common #define-ish pseudo-keywords.
    "NULL", "TRUE", "FALSE", "true", "false",
    "__stdcall", "__cdecl", "__fastcall", "__thiscall", "__declspec",
    "__try", "__except", "__finally", "__asm",
))

_C_TYPES = frozenset((
    "void", "char", "short", "int", "long", "float", "double",
    "signed", "unsigned", "bool", "_Bool", "_Complex", "_Imaginary",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "size_t", "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t",
    "wchar_t", "time_t", "off_t",
    "__int8", "__int16", "__int32", "__int64",
    "_BYTE", "_WORD", "_DWORD", "_QWORD", "_OWORD",
    "BYTE", "WORD", "DWORD", "QWORD", "BOOL", "BOOLEAN",
    "CHAR", "WCHAR", "TCHAR", "UCHAR", "SHORT", "USHORT",
    "INT", "UINT", "LONG", "ULONG", "LONGLONG", "ULONGLONG",
    "LPVOID", "LPCVOID", "LPSTR", "LPCSTR", "LPWSTR", "LPCWSTR",
    "LPBYTE", "LPDWORD", "PVOID", "PBYTE", "PDWORD",
    "HANDLE", "HMODULE", "HWND", "HRESULT", "NTSTATUS", "HINSTANCE",
    "FARPROC", "PROC", "DWORD_PTR", "ULONG_PTR", "SIZE_T",
))

# Single combined token pattern. Order of alternatives matters -- earlier
# branches win, so comment/preproc/string are tried before identifier/number.
_C_LEXER = re.compile(
    r'(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)'
    r'|(?P<preproc>^[ \t]*#[^\n]*)'
    r'|(?P<string>"(?:\\.|[^"\\\n])*"?)'
    r"|(?P<char>'(?:\\.|[^'\\\n])*'?)"
    r'|(?P<number>\b(?:0[xX][0-9a-fA-F]+|[0-9]+(?:\.[0-9]+)?)(?:[uUlLfF]+)?\b)'
    r'|(?P<ident>[A-Za-z_][A-Za-z0-9_]*)',
    re.MULTILINE,
)


def _highlight_c_code(code):
    """Tokenize a C / pseudo-C blob into span-wrapped HTML. Purely lexical --
    safe on partial / malformed snippets (including the unclosed-string case
    that Claude's streaming output can produce mid-response)."""
    out = []
    last = 0
    for m in _C_LEXER.finditer(code):
        if m.start() > last:
            out.append(html.escape(code[last:m.start()]))
        kind = m.lastgroup
        escaped = html.escape(m.group())
        if kind == "ident":
            word = m.group()
            if word in _C_KEYWORDS:
                out.append('<span class="ckw">' + escaped + '</span>')
            elif word in _C_TYPES:
                out.append('<span class="cty">' + escaped + '</span>')
            else:
                # Identifier followed by `(` -> function-call styling.
                tail = code[m.end():m.end() + 1]
                if tail == "(":
                    out.append('<span class="cfn">' + escaped + '</span>')
                else:
                    out.append(escaped)
        elif kind == "comment":
            out.append('<span class="ccmt">' + escaped + '</span>')
        elif kind == "preproc":
            out.append('<span class="cpre">' + escaped + '</span>')
        elif kind == "string" or kind == "char":
            out.append('<span class="cstr">' + escaped + '</span>')
        elif kind == "number":
            out.append('<span class="cnum">' + escaped + '</span>')
        else:
            out.append(escaped)
        last = m.end()
    if last < len(code):
        out.append(html.escape(code[last:]))
    return "".join(out)


def _render_prose(text):
    html_lines = []
    in_list = None  # 'ul', 'ol', or None
    # Track whether the previous emitted block was a heading so we can
    # swallow a single following blank line -- otherwise the heading's own
    # bottom margin + a <br> stacks up into an ugly gap.
    after_heading = False

    def close_list():
        nonlocal in_list
        if in_list:
            html_lines.append("</" + in_list + ">")
            in_list = None

    lines = text.split("\n")
    i = 0
    while i < len(lines):
        raw = lines[i]
        line = raw.rstrip()
        stripped = line.lstrip()

        # --- horizontal rules ---------------------------------------------
        # Claude often emits `---`, `***`, or `___` as paragraph separators.
        # They render as literal dashes in a text browser and just add
        # visual noise, so we drop them.
        if _is_hr_line(stripped):
            close_list()
            after_heading = False
            i += 1
            continue

        # --- markdown tables ----------------------------------------------
        # A table starts with a `|`-row followed by a separator row made of
        # `|`, `-`, `:`, and whitespace. Everything after until a non-pipe
        # line is a body row.
        if stripped.startswith("|") and i + 1 < len(lines):
            sep = lines[i + 1].strip()
            if _is_table_separator(sep):
                close_list()
                header = _split_table_row(stripped)
                i += 2  # skip header + separator
                body = []
                while i < len(lines):
                    r = lines[i].strip()
                    if not r.startswith("|"):
                        break
                    body.append(_split_table_row(r))
                    i += 1
                html_lines.append(_render_md_table(header, body))
                after_heading = False
                continue

        # --- blank line ---------------------------------------------------
        # Blank lines must NOT close an open list -- Claude often separates
        # list items with blank lines, and closing+reopening <ol> restarts
        # numbering at 1 for every item. Also swallow ALL blank lines right
        # after a heading so the heading's own bottom margin alone controls
        # the gap to the following body.
        if not stripped:
            if in_list or after_heading:
                # Keep swallowing: leave after_heading True so subsequent
                # blanks also get eaten, until a content line resets it.
                pass
            else:
                html_lines.append("<br>")
            i += 1
            continue

        list_kind = None
        item_body = None
        if stripped.startswith("- ") or stripped.startswith("* "):
            list_kind = "ul"
            item_body = stripped[2:]
        else:
            num_body = _strip_numbered_prefix(stripped)
            if num_body is not None:
                list_kind = "ol"
                item_body = num_body

        if in_list and list_kind != in_list:
            # Switching list type, or leaving the list entirely.
            close_list()
        if list_kind and in_list != list_kind:
            html_lines.append("<" + list_kind + ">")
            in_list = list_kind

        if list_kind:
            html_lines.append("<li>" + _render_inline(item_body) + "</li>")
            after_heading = False
            i += 1
            continue

        if (stripped.startswith("### ") or stripped.startswith("## ")
                or stripped.startswith("# ")):
            # Heading has its own margin-top; strip any trailing <br>s the
            # preceding body accumulated so they don't stack with the
            # heading's margin into a big gap.
            while html_lines and html_lines[-1] == "<br>":
                html_lines.pop()

        if stripped.startswith("### "):
            html_lines.append("<h3>" + _render_inline(stripped[4:]) + "</h3>")
            after_heading = True
        elif stripped.startswith("## "):
            html_lines.append("<h2>" + _render_inline(stripped[3:]) + "</h2>")
            after_heading = True
        elif stripped.startswith("# "):
            html_lines.append("<h1>" + _render_inline(stripped[2:]) + "</h1>")
            after_heading = True
        elif stripped.startswith("> "):
            html_lines.append(
                "<blockquote>" + _render_inline(stripped[2:])
                + "</blockquote>"
            )
            after_heading = False
        else:
            html_lines.append(_render_inline(line) + "<br>")
            after_heading = False
        i += 1

    close_list()
    return "".join(html_lines)


def _is_hr_line(stripped):
    if len(stripped) < 3:
        return False
    ch = stripped[0]
    if ch not in "-*_":
        return False
    return all(c == ch for c in stripped)


def _is_table_separator(stripped):
    if not stripped.startswith("|"):
        return False
    # Must contain at least one dash and only structural chars.
    if "-" not in stripped:
        return False
    return all(c in "|:- \t" for c in stripped)


def _split_table_row(row):
    """Split a markdown table row like `| a | b |` into ['a', 'b']."""
    s = row.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [c.strip() for c in s.split("|")]


def _render_md_table(header, body):
    out = [
        '<table class="mdtable" border="1" cellspacing="0" cellpadding="4" '
        'width="100%" style="border-color:#3a3835;">'
    ]
    out.append("<tr>")
    for cell in header:
        out.append("<th>" + _render_inline(cell) + "</th>")
    out.append("</tr>")
    for row in body:
        out.append("<tr>")
        # Pad short rows with empty cells so the table stays rectangular.
        while len(row) < len(header):
            row.append("")
        for cell in row[:len(header)] if header else row:
            out.append("<td>" + _render_inline(cell) + "</td>")
        out.append("</tr>")
    out.append("</table>")
    return "".join(out)


def _strip_numbered_prefix(s):
    i = 0
    while i < len(s) and s[i].isdigit():
        i += 1
    if i == 0 or i + 1 >= len(s):
        return None
    if s[i] != "." or s[i + 1] != " ":
        return None
    return s[i + 2:]


def _render_inline(text):
    escaped = html.escape(text)
    escaped = _inline_code(escaped)
    escaped = _auto_highlight(escaped)
    escaped = _inline_bold(escaped)
    return escaped


_FN_CALL_RE  = re.compile(r"([A-Za-z_][A-Za-z0-9_]{2,})(\()")
_HEX_ADDR_RE = re.compile(r"\b(0x[0-9A-Fa-f]+)\b")
_DEC_NUM_RE  = re.compile(r"(?<![A-Za-z0-9_])(\d{2,})(?![A-Za-z0-9_])")


def _auto_highlight(s):
    out = []
    i = 0
    n = len(s)
    while i < n:
        skipped = False
        for opener, closer in (
            ("<code", "</code>"),
            ("<pre", "</pre>"),
            ("<span", "</span>"),
        ):
            if s.startswith(opener, i):
                end = s.find(closer, i)
                if end == -1:
                    out.append(s[i:])
                    return "".join(out)
                end += len(closer)
                out.append(s[i:end])
                i = end
                skipped = True
                break
        if skipped:
            continue
        if s[i] == "<":
            close = s.find(">", i)
            if close == -1:
                out.append(s[i:])
                break
            out.append(s[i:close + 1])
            i = close + 1
            continue
        j = i
        while j < n and s[j] != "<":
            j += 1
        segment = s[i:j]
        segment = _FN_CALL_RE.sub(
            r'<span class="fn">\1</span>\2', segment
        )
        segment = _HEX_ADDR_RE.sub(
            r'<span class="addr">\1</span>', segment
        )
        segment = _DEC_NUM_RE.sub(
            r'<span class="num">\1</span>', segment
        )
        out.append(segment)
        i = j
    return "".join(out)


def _inline_code(escaped_text):
    result = []
    i = 0
    while i < len(escaped_text):
        if escaped_text[i] == "`":
            end = escaped_text.find("`", i + 1)
            if end == -1:
                result.append(escaped_text[i:])
                break
            result.append("<code>" + escaped_text[i + 1:end] + "</code>")
            i = end + 1
        else:
            result.append(escaped_text[i])
            i += 1
    return "".join(result)


def _inline_bold(escaped_text):
    """Apply **bold**. Skips single-* italic -- Claude uses * liberally for
    bullets and IDA wildcards (e.g. sub_*), which would yield false matches."""
    result = []
    i = 0
    while i < len(escaped_text):
        if escaped_text[i:i + 2] == "**":
            end = escaped_text.find("**", i + 2)
            if end == -1:
                result.append(escaped_text[i:])
                break
            result.append("<b>" + escaped_text[i + 2:end] + "</b>")
            i = end + 2
        else:
            result.append(escaped_text[i])
            i += 1
    return "".join(result)
