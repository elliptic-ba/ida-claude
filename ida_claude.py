"""
IDA Pro plugin: Claude Code
Drop this file (and the ida_claude/ package next to it) into your IDA plugins
directory, e.g. on Windows:
    %APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\
Then open a binary in IDA and press Ctrl-Shift-K (or use
View -> Open subviews -> Claude Code, or the Windows menu).

To use a custom icon, drop a 16x16 (or 24x24) PNG named `claude.png` next to
this file. If absent, the menu entry renders without an icon.
"""
import os
import sys
import idaapi

PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

from PyQt5 import QtWidgets, QtCore, QtGui

from ida_claude.chat_widget import ClaudeChatForm

PLUGIN_NAME = "Claude Code"
PLUGIN_HOTKEY = "Ctrl-Shift-K"
ACTION_NAME = "claude_chat:open"
ICON_FILENAME = "claude.png"


def _load_icon():
    """Load claude.png from the plugin dir. Returns an IDA icon id, or -1."""
    path = os.path.join(PLUGIN_DIR, ICON_FILENAME)
    if not os.path.isfile(path):
        return -1
    try:
        with open(path, "rb") as f:
            return idaapi.load_custom_icon(data=f.read(), format="png")
    except Exception as e:
        print("[Claude] failed to load %s: %s" % (ICON_FILENAME, e))
        return -1


def _is_class(obj, name):
    """Name-based `isinstance` that survives PyQt5/PySide6 binding mismatches."""
    try:
        for cls in type(obj).__mro__:
            if cls.__name__ == name:
                return True
    except Exception:
        pass
    return False


def _find_ida_main_window():
    """Return IDA's top-level QMainWindow (or None).

    This is the same window `Functions` lives on; adding our QDockWidget
    to its RightDockWidgetArea makes Claude globally visible instead of
    a central-area tab that vanishes when the user switches to Hex View
    or another central pane.
    """
    app = QtWidgets.QApplication.instance()
    if app is None:
        return None
    candidate = None
    for top in app.topLevelWidgets():
        if not _is_class(top, "QMainWindow"):
            continue
        if not top.isVisible():
            continue
        # Prefer the largest visible QMainWindow (guards against stray
        # helper QMainWindows that might be top-level).
        if candidate is None or top.width() * top.height() \
                > candidate.width() * candidate.height():
            candidate = top
    return candidate


class _OpenChatHandler(idaapi.action_handler_t):
    """IDA action wrapper so the plugin is reachable from the menu bar."""
    def __init__(self, plugin):
        idaapi.action_handler_t.__init__(self)
        self._plugin = plugin

    def activate(self, ctx):
        self._plugin.run(0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class ClaudeChatPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Ask Claude about the current disassembly"
    help = "Opens a dockable chat window wired to the Anthropic API."
    wanted_name = PLUGIN_NAME
    # Hotkey lives on the registered action (set in init) so the shortcut
    # carries the menu entry + icon. Leaving wanted_hotkey empty avoids a
    # duplicate binding that would conflict with the action.
    wanted_hotkey = ""

    def init(self):
        self.widget = None
        self.dock = None
        self._action_registered = False
        self._icon_id = _load_icon()

        desc = idaapi.action_desc_t(
            ACTION_NAME,
            PLUGIN_NAME,
            _OpenChatHandler(self),
            PLUGIN_HOTKEY,
            "Open the Claude Code panel",
            self._icon_id,
        )
        if idaapi.register_action(desc):
            self._action_registered = True
            # Primary home: alongside Functions / Imports / Strings.
            idaapi.attach_action_to_menu(
                "View/Open subviews/", ACTION_NAME, idaapi.SETMENU_APP
            )
            # Also surface in Windows so users who closed the panel can find
            # their way back without remembering the hotkey.
            idaapi.attach_action_to_menu(
                "Windows/", ACTION_NAME, idaapi.SETMENU_APP
            )
        else:
            print("[Claude] register_action failed; menu entry not added")

        print("[Claude] plugin loaded. Hotkey: %s" % PLUGIN_HOTKEY)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        # We skip idaapi.PluginForm because Show() deposits the widget into
        # IDA's central QStackedWidget (same container as IDA View-A /
        # Hex View-1 / Local Types / Imports / Exports). That makes Claude
        # a sibling tab of the central views, so it disappears whenever
        # the user clicks a different central tab. Instead, build our own
        # QDockWidget and add it straight to IDA's outer QMainWindow's
        # right dock area -- the same layout slot the Functions panel
        # occupies on the left -- so Claude stays visible regardless of
        # which central tab is active.
        main_window = _find_ida_main_window()
        if main_window is None:
            print("[Claude] cannot find IDA main window; aborting open")
            return

        if self.dock is None:
            self.widget = ClaudeChatForm()
            self.dock = QtWidgets.QDockWidget("Claude Code", main_window)
            self.dock.setObjectName("ClaudeDockWidget")
            self.dock.setWidget(self.widget)
            self.dock.setAllowedAreas(QtCore.Qt.AllDockWidgetAreas)
            self.dock.setFeatures(
                QtWidgets.QDockWidget.DockWidgetMovable
                | QtWidgets.QDockWidget.DockWidgetFloatable
                | QtWidgets.QDockWidget.DockWidgetClosable
            )
            icon_path = os.path.join(PLUGIN_DIR, ICON_FILENAME)
            if os.path.isfile(icon_path):
                icon = QtGui.QIcon(icon_path)
                if not icon.isNull():
                    self.dock.setWindowIcon(icon)
            main_window.addDockWidget(
                QtCore.Qt.RightDockWidgetArea, self.dock
            )

        self.dock.setFloating(False)
        self.dock.show()
        self.dock.raise_()
        self.dock.activateWindow()

    def term(self):
        if self._action_registered:
            try:
                idaapi.detach_action_from_menu(
                    "View/Open subviews/", ACTION_NAME
                )
                idaapi.detach_action_from_menu("Windows/", ACTION_NAME)
                idaapi.unregister_action(ACTION_NAME)
            except Exception:
                pass
            self._action_registered = False
        if self.widget is not None:
            # Tear down the local MCP server that fronts the IDA tools for
            # the `claude` CLI; otherwise its listener outlives the plugin.
            try:
                self.widget._stop_mcp()
            except Exception:
                pass
        if self.dock is not None:
            try:
                self.dock.close()
                self.dock.deleteLater()
            except Exception:
                pass
            self.dock = None
        self.widget = None
        if self._icon_id != -1:
            try:
                idaapi.free_custom_icon(self._icon_id)
            except Exception:
                pass
            self._icon_id = -1


def PLUGIN_ENTRY():
    return ClaudeChatPlugin()
