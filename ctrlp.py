# coding: utf-8
# @author msm
# @category Search
# @menupath Search.Palette
# @toolbar

import re
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import SymbolType, SourceType
from ghidra.program.model.listing import BookmarkType
from ghidra.app.services import ConsoleService
from ghidra.util.task import TaskMonitor
from ghidra.app.script import GhidraScriptUtil
from ghidra.app.util.viewer.field import ListingColors
from javax.swing import JFrame, JTextField, JList, JScrollPane, SwingUtilities, JPanel, DefaultListCellRenderer, SwingWorker, UIManager
from java.lang import Object
from java.awt import BorderLayout, Color, Font, GraphicsEnvironment
from java.awt.event import KeyAdapter, KeyEvent
from java.util import Vector
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection


def matches(name, query):
    """Baby fuzzy matcher - splits query by whitespace, and matches
    if name contains every resulting element. For example,
    "aaa bbb ccc" matches "aaa ccc" but not "aaaccc" or "aaa ddd" """ 
    name = name.lower()
    query = query.lower()

    chunks = query.split()
    for c in chunks:
        # Special case - filtering by type, for example user searches for `wnd script`
        if c in ["fnc", "dat", "lbl", "bkm", "wnd", "act", "scr"]:
            if not name.startswith(c):
                return False

        ndx = name.find(c)
        if ndx < 0:
            return False
    return True

class SymbolLoader(SwingWorker):
    def __init__(self, parent, func):
        super(SymbolLoader, self).__init__()
        self.parent = parent
        self.func = func

    def doInBackground(self):
        return self.func()

    def done(self):
        try:
            symbols = self.get()
            self.parent.symbols += symbols
            SwingUtilities.invokeLater(lambda: self.parent.updateList(self.parent.inputField.getText()))
        except Exception as e:
            print("Error loading symbols" + str(e))

def get_order(sym):
    kind = sym.text.split()[0]
    return {
        "fnc": 0,
        "dat": 1,
        "lbl": 2,
        "bkm": 3,
        "wnd": 4,
        "act": 5,
        "scr": 6,
    }[kind]


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
    }[kind]


class SymbolFilterWindow(JFrame):
    def __init__(self, title, symbols):
        super(SymbolFilterWindow, self).__init__(title)
        self.symbols = symbols
        self.filtered_symbols = symbols
        self.initUI()
        self.selected_index = 0
        
        SymbolLoader(self, get_symbols).execute()
        SymbolLoader(self, get_component_providers).execute()
        SymbolLoader(self, get_bookmarks).execute()
        SymbolLoader(self, get_actions).execute()
        SymbolLoader(self, get_scripts).execute()

    def initUI(self):
        self.setSize(1200, 600)
        self.setResizable(False)
        self.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
        self.getContentPane().setLayout(BorderLayout())
        # self.setUndecorated(True)

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
        occurs = list(flatapi.findBytes(currentProgram.getMinAddress(), pattern, 100))

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
                lambda: goTo(addr)
            ))
        return filtered_symbols

    def updateList(self, filter_text):
        if filter_text and filter_text[0] == '"':
            filtered_symbols = self.entries_by_search(filter_text[1:], False)
        elif filter_text and filter_text[0] == "'":
            filtered_symbols = self.entries_by_search(filter_text[1:], True)
        elif filter_text and filter_text[0] == "{":
            try:
                needle = filter_text[1:].replace(" ", "").decode("hex")
            except:
                needle = ""
            filtered_symbols = self.entries_by_search(needle, False)
        else:
            filtered_symbols = [
                sym for sym in self.symbols if matches(sym.text, filter_text)
            ]
            filtered_symbols = sorted(filtered_symbols, key=get_order)

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

    def runSelectedAction(self):
        selected_symbol = self.current_symbol()
        if selected_symbol:
            selected_symbol.action()

    def navigateToSelectedSymbol(self):
        selected_symbol = self.current_symbol()
        if selected_symbol and selected_symbol.address:
            goTo(selected_symbol.address)

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
            string_selection = StringSelection(str(selected_symbol.address))
            clipboard.setContents(string_selection, None)


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
        if event.getKeyCode() == KeyEvent.VK_ENTER:
            self.parent.dispose()
            self.parent.runSelectedAction()
        elif event.getKeyCode() == KeyEvent.VK_UP:
            self.navigate(-1)
        elif event.getKeyCode() == KeyEvent.VK_DOWN:
            self.navigate(1)
        elif event.getKeyCode() == KeyEvent.VK_ESCAPE:
            self.parent.dispose()
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
        elif event.isShiftDown() and event.getKeyCode() == KeyEvent.VK_C:
            self.parent.copyAddressToClipboard()
        elif event.isControlDown() and event.getKeyCode() == KeyEvent.VK_C:
            self.parent.copyToClipboard()

    def keyReleased(self, event):
        try:
            if not event.getKeyChar() or event.isControlDown():
                return
        except:
            return
        self.parent.updateList(self.parent.inputField.getText())


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
    con = state.getTool().getService(ConsoleService)
    scr = GhidraScriptUtil.findScriptByName(scr_file.getName())
    prov = GhidraScriptUtil.getProvider(scr)
    inst = prov.getScriptInstance(scr, con.getStdOut())
    inst.execute(state, TaskMonitor.DUMMY, con.getStdOut())


def script_entry(scr):
    return SearchEntry(
        "scr " + scr.getName(),
        None,
        lambda: run_script(scr),
    )


def component_provider_entry(cp):
    def show_and_focus():
        state.getTool().showComponentProvider(cp, True)
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
    symbols = []
    context = state.getTool().getActiveComponentProvider().getActionContext(None)
    for act in state.getTool().getAllActions():
        if not issubclass(type(context), act.getContextClass()):
            continue

        if not act.isValidContext(context):
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
    for cp in state.getTool().getWindowManager().getComponentProviders(Object):
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


def run():
    symbols = []
    SwingUtilities.invokeLater(lambda: SymbolFilterWindow("CtrlP", symbols).setVisible(True))


run()
