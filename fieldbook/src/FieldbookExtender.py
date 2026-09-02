"""
Main Burp Suite Extension Entry Point for Fieldbook Research Notebook.
"""

import sys
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Fieldbook.Extender")

# Try to resolve path at top-level if __file__ exists (e.g. CLI tests)
try:
    src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
except NameError:
    pass

try:
    from burp import IBurpExtender, ITab, IContextMenuFactory, IExtensionStateListener
    BURP_AVAILABLE = True
except ImportError:
    BURP_AVAILABLE = False
    class IBurpExtender(object): pass
    class ITab(object): pass
    class IContextMenuFactory(object): pass
    class IExtensionStateListener(object): pass

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IExtensionStateListener):
    """
    Main Burp Extender implementation for Fieldbook.
    """
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Fieldbook Research Notebook")

        # Resolve paths dynamically using callbacks.getExtensionFilename()
        ext_filename = callbacks.getExtensionFilename()
        if ext_filename:
            ext_dir = os.path.dirname(os.path.abspath(ext_filename)) # .../fieldbook/src
            fieldbook_root = os.path.dirname(ext_dir)                 # .../fieldbook
            repo_root = os.path.dirname(fieldbook_root)               # repo root
            for p in (repo_root, fieldbook_root, ext_dir):
                if p and p not in sys.path:
                    sys.path.insert(0, p)

        # Import Fieldbook modules after sys.path is updated
        from fieldbook.src.model.notebook import NotebookStore
        from fieldbook.src.ui.main_tab import FieldbookMainTab, GUI_AVAILABLE
        from fieldbook.src.integration.context_menu import FieldbookContextMenuFactory
        from fieldbook.src.integration.hotkey_manager import FieldbookHotkeyDispatcher

        self.GUI_AVAILABLE = GUI_AVAILABLE

        # Load notebook file path setting
        saved_path = callbacks.loadExtensionSetting("fieldbook_notebook_path")
        if not saved_path or not saved_path.strip():
            saved_path = os.path.expanduser("~/.fieldbook/notebook.json")
            callbacks.saveExtensionSetting("fieldbook_notebook_path", saved_path)

        logger.info("Initializing Fieldbook NotebookStore at: %s", saved_path)
        self.store = NotebookStore(filepath=saved_path)

        # Main Tab UI
        if GUI_AVAILABLE:
            self.main_tab = FieldbookMainTab(self.store, self.callbacks, self.helpers)
        else:
            self.main_tab = None

        # Helper for main frame lookup
        def get_main_frame():
            try:
                if hasattr(self.main_tab, "getTopLevelAncestor"):
                    return self.main_tab.getTopLevelAncestor()
            except Exception:
                pass
            return None

        # Context Menu Factory
        self.context_menu_factory = FieldbookContextMenuFactory(
            callbacks=self.callbacks,
            helpers=self.helpers,
            store=self.store,
            main_frame_getter=get_main_frame,
            on_save_callback=lambda entry: self.main_tab.on_entry_created(entry) if self.main_tab else None
        )
        callbacks.registerContextMenuFactory(self)

        # Global Hotkey Manager (Ctrl+Shift+N)
        self.hotkey_dispatcher = FieldbookHotkeyDispatcher(
            store=self.store,
            main_frame_getter=get_main_frame,
            on_save_callback=lambda entry: self.main_tab.on_entry_created(entry) if self.main_tab else None
        )
        self.hotkey_dispatcher.register()

        # Add Suite Tab
        callbacks.addSuiteTab(self)

        # Unload listener
        callbacks.registerExtensionStateListener(self)

        logger.info("Fieldbook Research Notebook loaded successfully!")

    # ITab Implementation
    def getTabCaption(self):
        return "Fieldbook"

    def getUiComponent(self):
        return getattr(self, "main_tab", None)

    # IContextMenuFactory Implementation
    def createMenuItems(self, invocation):
        if hasattr(self, "context_menu_factory") and self.context_menu_factory:
            return self.context_menu_factory.createMenuItems(invocation)
        return None

    # IExtensionStateListener Implementation
    def extensionUnloaded(self):
        logger.info("Unloading Fieldbook extension...")
        if hasattr(self, "hotkey_dispatcher") and self.hotkey_dispatcher:
            self.hotkey_dispatcher.unregister()
        if hasattr(self, "store") and self.store:
            try:
                self.store.save()
            except Exception as e:
                logger.error("Error saving notebook on extension unload: %s", e)
