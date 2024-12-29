# coding: utf-8
# @author msm
# @category Search
# @menupath Search.Palette
# @toolbar

import re
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import SymbolType, SourceType
from ghidra.program.model.listing import BookmarkType
from ghidra.app.services import ConsoleService, CodeViewerService
from ghidra.util.task import TaskMonitor
from ghidra.app.script import GhidraScriptUtil, GhidraState
from ghidra.app.util.viewer.field import ListingColors
from javax.swing import JFrame, JTextField, JList, JScrollPane, SwingUtilities, JPanel, DefaultListCellRenderer, SwingWorker, UIManager
from javax.swing.event import DocumentListener
from java.lang import Object, System
from java.awt import BorderLayout, Color, Font, GraphicsEnvironment, Window
from java.awt.event import KeyAdapter, KeyEvent, ComponentAdapter
from java.util import Vector
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from __main__ import (
    getBytes,
    currentAddress,
    getState,
    getCurrentProgram,
    toAddr,
    goTo,
    monitor,
)


def matches(name, query):
    """Baby fuzzy matcher - splits query by whitespace, and matches
    if name contains every resulting element. For example,
    "aaa bbb ccc" matches "aaa ccc" but not "aaaccc" or "aaa ddd" """ 
    name = name.lower()
    query = query.lower()

    chunks = query.split()
    for c in chunks:
        # Special case - filtering by type, for example user searches for `wnd script`
        if c in ["fnc", "dat", "lbl", "bkm", "wnd", "act", "scr", "txt", "ref"]:
            if not name.startswith(c):
                return False

        ndx = name.find(c)
        if ndx < 0:
            return False
    return True


def makeState():
    """Creates a new (current) state object and returns it

    We can't just use getState(), because it's a snapshot of program state.
    For tool and project it doesn't matter. For program it also doesn't matter,
    but we need to remember to use getCurrentProgram() instead of currentProgram
    in the script code (the variable is also constant, while in some cases -
    like multitab windows - current project may change for a CtrlP window.
    Finally, selection changes all the time, so we need to update it here."""
    oldState = getState()

    codeViewerService = oldState.getTool().getService(CodeViewerService)
    if codeViewerService:
        currLocation = codeViewerService.getCurrentLocation()
        currSelection = codeViewerService.getCurrentSelection()
        currHighlight = codeViewerService.getListingPanel().getProgramHighlight()
    else:
        currLocation = oldState.getCurrentLocation()
        currSelection = oldState.getCurrentSelection()
        currHighlight = oldState.getCurrentHighlight()

    return GhidraState(
        oldState.getTool(),  # I think this can't change
        oldState.getProject(),  # I think this can't change
        getCurrentProgram(),
        currLocation,
        currSelection,
        currHighlight,
    )


def transientGoto(addr):
    """Goto, but without saving it in the history"""
    codeViewerService = makeState().getTool().getService(CodeViewerService)
    if codeViewerService:
        from ghidra.program.util import ProgramLocation
        codeViewerService.goTo(ProgramLocation(getCurrentProgram(), addr), True)
    else:
        # fallback
        goTo(addr)


def wrap_goto(addr):
    """This is a wrapper for goTo, returns a function that goToes to the addr

    the point is to capture addr in a closure (something that won't happen in a lambda"""
    return lambda: goTo(addr)


class ScriptExecutor(SwingWorker):
    def __init__(self, script):
        super(ScriptExecutor, self).__init__()
        self.script = script

    def doInBackground(self):
        con = makeState().getTool().getService(ConsoleService)
        prov = GhidraScriptUtil.getProvider(self.script)
        inst = prov.getScriptInstance(self.script, con.getStdOut())
        inst.execute(makeState(), monitor, con.getStdOut())

    def done(self):
        pass


class SymbolLoader(SwingWorker):
    def __init__(self, parent):
        super(SymbolLoader, self).__init__()
        self.parent = parent

    def get_everything(self):
        everything = []
        everything += get_symbols()
        everything += get_component_providers()
        everything += get_bookmarks()
        everything += get_actions()
        everything += get_scripts()
        return everything

    def doInBackground(self):
        try:
            return self.get_everything()
        except:
            # uncomment this for debug info:
            # import traceback
            # state.getTool().getService(ConsoleService).println(traceback.format_exc())

            # BUG TODO FIXME
            # When Ghidra window is closed and then reopened, the references in the window stop making sense.
            # and this thread/wtf is in a broken state.
            # We should probably watch when ghidra window exits and then cleanup, but...
            # Just kill ourselves and let user try again.
            self.parent.dispose()
            return []  # Just so we don't raise an exception in a second

    def done(self):
        def refresh_data():
            ndx = self.parent.symbolList.getSelectedIndex()
            self.parent.updateList(self.parent.inputField.getText())
            self.parent.symbolList.setSelectedIndex(ndx)

        try:
            symbols = self.get()
            self.parent.symbols = symbols
            SwingUtilities.invokeLater(refresh_data)
        except Exception as e:
            print("Error loading symbols" + str(e))


def prettyPrintAddress(source):
    func_manager = getCurrentProgram().getFunctionManager()
    xref_func = func_manager.getFunctionContaining(source)
    if xref_func is None:
        codeunit = getCurrentProgram().getListing().getCodeUnitContaining(source)
        if codeunit is not None:
            text = "lbl {:x} {}".format(source.getOffset(), str(codeunit))
        else:
            text = "dat {:x}".format(source.getOffset())
    else:
        offset = source.subtract(xref_func.getEntryPoint())
        text = "fnc {}+{:x}".format(xref_func.getPrototypeString(True, False), offset)
    return text


def get_color(sym):
    kind = sym.text.split()[0]
    return {
        "fnc": ListingColors.FunctionColors.NAME,
        "dat": ListingColors.REGISTER,
        "lbl": ListingColors.MnemonicColors.NORMAL,
        "bkm": ListingColors.FunctionColors.VARIABLE,
        "wnd": ListingColors.CommentColors.REPEATABLE,
        "act": ListingColors.XrefColors.DEFAULT,
        "scr": ListingColors.MnemonicColors.OVERRIDE,
        "txt": ListingColors.MnemonicColors.NORMAL,
        "ref": ListingColors.REGISTER,
    }[kind]


class SymbolFilterWindow(JFrame):
    def __init__(self, title, symbols):
        super(SymbolFilterWindow, self).__init__(title)
        self.special_symbols = []
        self.symbols = symbols
        self.filtered_symbols = symbols
        self.initUI()
        self.selected_index = 0
        self.initial_address = currentAddress
        # special_symbols are currently used in the "xref search mode" -
        # we are searching in them instead of self.symbols
        # Special search mode is enabled when self.special_symbols is not empty.
        # We don't reuse self.symbols for this, because populating self.symbols
        # takes time, and we want to have cached results when opening ctrl+p.

        self.recent_symbols = {}
        # keep track of recently used symbols. We want to show recent symbols
        # at the top of the search list, so it's easy to repeat the search.

    def initUI(self):
        self.setSize(1200, 600)
        self.setResizable(False)
        self.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
        self.getContentPane().setLayout(BorderLayout())

        me = self
        class MyComponentAdapter(ComponentAdapter):
            def componentShown(self, event):
                codeViewerService = makeState().getTool().getService(CodeViewerService)
                if codeViewerService:
                    # We can't just use currentAddress because of a technicality:
                    # the variable in script is never updated and stays the same.
                    new_address = codeViewerService.getCurrentLocation().getAddress()
                    me.initial_address = new_address  # so we can cancel navigation
                me.special_symbols = []  # disable special search mode when showing
                me.inputField.setText("")  # clear the input field
                if me.symbols:
                    me.symbolList.setSelectedIndex(0)
                    me.symbolList.ensureIndexIsVisible(me.symbolList.getSelectedIndex())
                SymbolLoader(me).execute()  # start updating symbols in the background

            def componentHidden(self, event): pass
            def componentMoved(self, event): pass
            def componentResized(self, event): pass

        self.addComponentListener(MyComponentAdapter())

        inputPanel = JPanel(BorderLayout())
        self.inputField = JTextField()
        self.inputField.addKeyListener(FilterKeyAdapter(self))

        inputPanel.add(self.inputField, BorderLayout.CENTER)

        fontname = None
        FONTS = ["FiraCode Nerd Font Mono", "Monospaced"]
        for fontname in FONTS:
            g = GraphicsEnvironment.getLocalGraphicsEnvironment()
            if fontname in g.getAvailableFontFamilyNames():
                break
        assert fontname is not None

        font = Font(fontname, Font.PLAIN, 14)
        self.inputField.setFont(font)
        self.inputField.getDocument().addDocumentListener(MyDocumentListener(self))

        self.symbolList = JList(Vector([]))
        self.updateList("")
        self.symbolList.setCellRenderer(SymbolCellRenderer(self))
        self.symbolList.addKeyListener(FilterKeyAdapter(self))
        self.symbolList.setFont(font)

        self.scrollPane = JScrollPane(self.symbolList)

        self.getContentPane().add(inputPanel, BorderLayout.NORTH)
        self.getContentPane().add(self.scrollPane, BorderLayout.CENTER)

        if self.symbols:
            self.symbolList.setSelectedIndex(0)

        self.symbolList.setFocusable(False)

        self.inputField.requestFocusInWindow()

    def entries_by_search(self, needle, ignore_case):
        if not needle:
            return [SearchEntry(
                "dat (entering search mode)",
                None,
                lambda: None
            )]

        pattern = re.escape(needle)
        if ignore_case:
            pattern = "(?i)" + pattern

        filtered_symbols = []
        flatapi = FlatProgramAPI(getCurrentProgram())
        occurs = list(flatapi.findBytes(getCurrentProgram().getMinAddress(), pattern, 100))

        mem = getCurrentProgram().getMemory()

        filtered_symbols = []
        for addr in occurs:
            start = addr.add(-10)
            rng = mem.getRangeContaining(addr)
            if start < rng.getMinAddress():
                start = rng.getMinAddress()

            context = getBytes(start, 130)
            filtered_symbols.append(SearchEntry(
                "dat " + str(addr) + " " + "".join(chr(b % 256) if 32 <= b < 127 else '.' for b in context),
                addr,
                wrap_goto(addr)
            ))
        return filtered_symbols

    def quick_exec(self, command):
        try:
            result = eval(command, {"__builtins__": None}, {})
        except Exception as e:
            result = e

        def set_clipboard(txt):
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            string_selection = StringSelection(txt)
            clipboard.setContents(string_selection, None)

        if isinstance(result, int) or isinstance(result, long):  # type: ignore (py2)
            strings = [
                "hex {:x}".format(result),
                "dec {}".format(result),
                "oct {:o}".format(result),
                "bin {:b}".format(result),
            ]
            func = getCurrentProgram().getFunctionManager().getFunctionContaining(toAddr(result))
            if func:
                off = toAddr(result).subtract(func.getEntryPoint())
                strings.append("sym " + func.getName() + ("+{:x}".format(off) if off else ""))
        elif isinstance(result, str):
            strings = [
                "str " + result,
                "hex " + result.encode("hex"),  # type: ignore (py2)
                "base64 " + result.encode("base64"),  # type: ignore (py2)
            ]
            try:
                strings.append("unhex " + result.replace(" ", "").decode("hex"))  # type: ignore (py2)
            except TypeError:
                pass
            try:
                strings.append("unbase64 " + result.decode("base64"))  # type: ignore (py2)
            except:  # binascii.error
                pass
        elif isinstance(result, list):
            strings = [str(r) for r in result]
        else:
            strings = [
                "str " + str(result)
            ]

        def set_clipboard_wrap(content):
            return lambda: set_clipboard(content)

        return [SearchEntry("txt " + s, None, set_clipboard_wrap(s[4:])) for s in strings]

    def get_order(self, sym):
        kind = sym.text.split()[0]
        primary_order = -self.recent_symbols.get(sym.text, -1)
        secondary_order = {
            "fnc": 0,
            "dat": 1,
            "lbl": 2,
            "bkm": 3,
            "wnd": 4,
            "act": 5,
            "scr": 6,
            "txt": 7,
            "ref": 8,
        }[kind]
        return (primary_order, secondary_order)

    def updateList(self, filter_text):
        if filter_text and filter_text[0] == '"':
            filtered_symbols = self.entries_by_search(filter_text[1:], False)
        elif filter_text and filter_text[0] == "'":
            filtered_symbols = self.entries_by_search(filter_text[1:], True)
        elif filter_text and filter_text[0] == "=":
            filtered_symbols = self.quick_exec(filter_text[1:])
        elif filter_text and filter_text[0] == "{":
            try:
                needle = filter_text[1:].replace(" ", "").decode("hex")
            except:
                needle = ""
            filtered_symbols = self.entries_by_search(needle, False)
        else:
            symbols_to_search = self.symbols
            if self.special_symbols:
                symbols_to_search = self.special_symbols
            filtered_symbols = [
                sym for sym in symbols_to_search if matches(sym.text, filter_text)
            ]
            # we have to search first, because we can't skip high-priority symbols :(
            filtered_symbols = sorted(filtered_symbols, key=self.get_order)
            if len(filtered_symbols) > 1000:
                overflow = len(filtered_symbols) - 1000
                filtered_symbols = filtered_symbols[:1000]
                filtered_symbols.append(SearchEntry(
                    "txt and " + str(overflow) + " more...",
                    None,
                    lambda: None
                ))

        self.filtered_symbols = filtered_symbols
        self.symbolList.setListData(Vector([sym.text for sym in filtered_symbols]))

        if filtered_symbols:
            self.symbolList.setSelectedIndex(0)
        else:
            self.symbolList.clearSelection()

    def current_symbol(self):
        selected_index = self.symbolList.getSelectedIndex()
        if selected_index < 0:
            return None
        return self.filtered_symbols[selected_index]

    def updateRecent(self, selected_symbol):
        next_index = len(self.recent_symbols)
        self.recent_symbols[selected_symbol.text] = next_index

    def runSelectedAction(self):
        selected_symbol = self.current_symbol()
        if selected_symbol:
            self.updateRecent(selected_symbol)
            selected_symbol.action()

    def navigateToSelectedSymbol(self):
        selected_symbol = self.current_symbol()
        if selected_symbol and selected_symbol.address:
            transientGoto(selected_symbol.address)
        else:
            transientGoto(self.initial_address)

    def enterXrefMode(self):
        selected_symbol = self.current_symbol()
        if selected_symbol and selected_symbol.address:
            ref_manager = getCurrentProgram().getReferenceManager()
            self.special_symbols = []
            for ref in ref_manager.getReferencesTo(selected_symbol.address):
                source = ref.getFromAddress()

                text = prettyPrintAddress(source)
                sym = SearchEntry(
                    text,
                    source,
                    wrap_goto(source)
                )
                self.special_symbols.append(sym)
        self.updateList(self.inputField.getText())

    def bookmarkSelectedLocation(self):
        selected_symbol = self.current_symbol()
        if selected_symbol and selected_symbol.address:
            transaction = getCurrentProgram().startTransaction("Add Bookmark")

            # Flip the bookmarkstate
            if selected_symbol.has_bookmark:
                for bm in getCurrentProgram().getBookmarkManager().getBookmarks(selected_symbol.address):
                    getCurrentProgram().getBookmarkManager().removeBookmark(bm)
            else:
                getCurrentProgram().getBookmarkManager().setBookmark(
                    selected_symbol.address,
                    BookmarkType.NOTE,
                    "CtrlP",
                    "Quick bookmark. Query: " + self.inputField.getText()
                )

            selected_symbol.has_bookmark_cache = not selected_symbol.has_bookmark_cache

            getCurrentProgram().endTransaction(transaction, True)

            # Update the bookmark "star"
            ndx = self.symbolList.getSelectedIndex()
            self.updateList(self.inputField.getText())
            self.symbolList.setSelectedIndex(ndx)

    def copyToClipboard(self):
        selected_symbol = self.current_symbol()
        if selected_symbol:
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            string_selection = StringSelection(selected_symbol.text)
            clipboard.setContents(string_selection, None)

    def copyAddressToClipboard(self):
        selected_symbol = self.current_symbol()
        if selected_symbol and selected_symbol.address:
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            string_selection = StringSelection("0x" + str(selected_symbol.address))
            clipboard.setContents(string_selection, None)

    def goToFirstXRef(self):
        success = False
        selected_symbol = self.current_symbol()
        if selected_symbol and selected_symbol.address:
            ref_manager = getCurrentProgram().getReferenceManager()
            if ref_manager.getReferenceCountTo(selected_symbol.address) > 0:
                goTo(ref_manager.getReferencesTo(selected_symbol.address).next().getFromAddress())
                success = True
        return success

    def cancelNavigation(self):
        goTo(self.initial_address)


class MyDocumentListener(DocumentListener):
    def __init__(self, parent):
        self.parent = parent

    def insertUpdate(self, e): self.update()
    def removeUpdate(self, e): self.update()
    def changedUpdate(self, e): self.update()
    def update(self):
        self.parent.updateList(self.parent.inputField.getText())


class FilterKeyAdapter(KeyAdapter):
    def __init__(self, parent):
        self.parent = parent

    def navigate(self, diff):
        symlist = self.parent.symbolList
        curr_pos = symlist.getSelectedIndex()
        curr_pos += diff
        if curr_pos < 0:
            curr_pos = 0
        if curr_pos >= symlist.getModel().getSize():
            curr_pos = symlist.getModel().getSize() - 1
        symlist.setSelectedIndex(curr_pos)
        symlist.ensureIndexIsVisible(symlist.getSelectedIndex())
        self.parent.navigateToSelectedSymbol()

    def keyPressed(self, event):
        if event.isControlDown() and event.getKeyCode() == KeyEvent.VK_ENTER:
            if self.parent.goToFirstXRef():
                self.parent.setVisible(False)
        elif event.getKeyCode() == KeyEvent.VK_ENTER:
            self.parent.setVisible(False)
            self.parent.runSelectedAction()
        elif event.getKeyCode() == KeyEvent.VK_UP:
            self.navigate(-1)
        elif event.getKeyCode() == KeyEvent.VK_DOWN:
            self.navigate(1)
        elif event.getKeyCode() == KeyEvent.VK_ESCAPE:
            if self.parent.special_symbols:
                # If we are in a special mode, clean it instead of closing entirely
                self.parent.special_symbols = []
                self.parent.updateList(self.parent.inputField.getText())
            else:
                self.parent.cancelNavigation()
                self.parent.setVisible(False)
        elif event.getKeyCode() == KeyEvent.VK_PAGE_DOWN:
            self.navigate(20)
        elif event.getKeyCode() == KeyEvent.VK_PAGE_UP:
            self.navigate(-20)
        elif event.getKeyCode() == KeyEvent.VK_END:
            self.navigate(2**30)
        elif event.getKeyCode() == KeyEvent.VK_HOME:
            self.navigate(-2**30)
        elif event.isControlDown() and event.getKeyCode() == KeyEvent.VK_D:
            self.parent.bookmarkSelectedLocation()
        elif event.isControlDown() and event.getKeyCode() == KeyEvent.VK_R:
            self.parent.enterXrefMode()
        elif event.isControlDown() and event.isShiftDown() and event.getKeyCode() == KeyEvent.VK_C:
            self.parent.copyAddressToClipboard()
        elif event.isControlDown() and event.getKeyCode() == KeyEvent.VK_C:
            self.parent.copyToClipboard()
        elif event.isControlDown() and event.getKeyCode() == KeyEvent.VK_Q:
            self.parent.dispose()
            System.gc()


class SymbolCellRenderer(DefaultListCellRenderer):
    def __init__(self, parent):
        self.window = parent

    def getListCellRendererComponent(self, list, value, index, isSelected, cellHasFocus):
        component = super(SymbolCellRenderer, self).getListCellRendererComponent(
            list, value, index, isSelected, cellHasFocus)

        symbol = self.window.filtered_symbols[index]
        component.setForeground(symbol.color)

        return component


class SearchEntry:
    def __init__(self, text, address, action):
        self.raw_text = text
        self.address = address
        self.action = action
        self.has_bookmark_cache = None

    @property
    def color(self):
        return get_color(self)

    @property
    def text(self):
        if self.has_bookmark:
            return self.raw_text + u" [*]"
        return self.raw_text

    @property
    def has_bookmark(self):
        if self.has_bookmark_cache is None:
            self.has_bookmark_cache = self.address and len(getCurrentProgram().getBookmarkManager().getBookmarks(self.address)) > 0
        return self.has_bookmark_cache


def data_symbol_entry(sym):
    listing = getCurrentProgram().getListing()
    data = listing.getDataAt(sym.getAddress())
    addr = toAddr(sym.getAddress().getOffset())
    if data is not None:
        textrepr = data.getDefaultValueRepresentation()
        if len(textrepr) > 80:
            textrepr = textrepr[:80]
        if textrepr:
            textrepr = " (" + textrepr + ")"
        return SearchEntry(
            "dat " + data.getDataType().displayName + " " + sym.getName() + textrepr,
            addr,
            lambda: goTo(addr)
        )

    return SearchEntry(
        "lbl " + sym.getName(),
        addr,
        lambda: goTo(addr)
    )


def function_symbol_entry(sym):
    listing = getCurrentProgram().getListing()
    func = listing.getFunctionAt(sym.getAddress())
    addr = toAddr(sym.getAddress().getOffset())
    return SearchEntry(
        "fnc " + func.getPrototypeString(True, False),
        addr,
        lambda: goTo(addr)
    )


def action_entry(context, act):
    def execme():
        act.actionPerformed(context)

    suffix = ""
    if act.keyBinding:
        binding = str(act.keyBinding)
        binding = binding.replace("pressed ", "")
        binding = binding.replace(" ", "+")
        # This will produce things like ctrl+shift+alt+A.
        # I prefer emacs notation, so C-S-M-a, but I guess not everyone knows it.
        suffix = " (" + binding + ")"

    return SearchEntry(
        "act " + act.name + suffix,
        None,
        execme
    )


def run_script(scr_file):
    scr = GhidraScriptUtil.findScriptByName(scr_file.getName())
    ScriptExecutor(scr).execute()


def script_entry(scr):
    return SearchEntry(
        "scr " + scr.getName(),
        None,
        lambda: run_script(scr),
    )


def component_provider_entry(cp):
    def show_and_focus():
        makeState().getTool().showComponentProvider(cp, True)
        cp.toFront()

    return SearchEntry(
        "wnd " + str(cp),
        None,
        show_and_focus
    )


def bookmark_entry(bookmark):
    addr = toAddr(bookmark.getAddress().getOffset())

    category = bookmark.getCategory()
    if category:
        category = " (" + category + ")"
    return SearchEntry(
        "bkm " + str(bookmark.getComment()) + category,
        addr,
        lambda: goTo(addr)
    )


def get_actions():
    prov = makeState().getTool().getActiveComponentProvider()
    if prov is None:
        return []

    symbols = []
    context = prov.getActionContext(None)
    for act in makeState().getTool().getAllActions():
        if not issubclass(type(context), act.getContextClass()):
            continue

        try:
            if not act.isValidContext(context):
                continue
        except:
            # Sometimes this raises an exception - even though it shouldn't
            continue

        if not act.isEnabledForContext(context):
            continue

        symbols.append(action_entry(context, act))

    return symbols


def get_symbols():
    symbols = []
    symbolTable = getCurrentProgram().getSymbolTable()
    mem = getCurrentProgram().getMemory()
    for symbol in symbolTable.getAllSymbols(True):
        if not mem.contains(symbol.getAddress()):
            continue

        if symbol.source == SourceType.DEFAULT:
            if symbol.getName().startswith("LAB_"):
                # Really boring symbols.
                continue

        if symbol.symbolType == SymbolType.FUNCTION:
            symbols.append(function_symbol_entry(symbol))
        else:
            symbols.append(data_symbol_entry(symbol))

    return symbols


def get_component_providers():
    symbols = []
    for cp in getState().getTool().getWindowManager().getComponentProviders(Object):
        symbols.append(component_provider_entry(cp))

    return symbols


def get_scripts():
    symbols = []
    for script_dir in GhidraScriptUtil.getScriptSourceDirectories():
        script_files = script_dir.listFiles()        
        for scr_file in script_files:
            symbols.append(script_entry(scr_file))

    return symbols


def get_bookmarks():
    symbols = []
    for mark in getCurrentProgram().getBookmarkManager().getBookmarksIterator():
        symbols.append(bookmark_entry(mark))

    return symbols


WINDOW_NAME = "CtrlP - " + str(getCurrentProgram().getDomainFile())


def run():
    symbols = []
    SwingUtilities.invokeLater(lambda: SymbolFilterWindow(WINDOW_NAME, symbols).setVisible(True))


def run_or_restore():
    for window in Window.getWindows():
        if isinstance(window, JFrame):
            if window.getTitle() == WINDOW_NAME and window.isDisplayable():
                if not window.isShowing():
                    window.setVisible(True)
                else:
                    print("Window is alredy visible. Doing nothing")
                return
    run()


if __name__ == "__main__":
    run_or_restore()
