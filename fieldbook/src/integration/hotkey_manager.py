"""
Global Hotkey Manager for Fieldbook (Ctrl+Shift+N / Cmd+Shift+N).
Uses KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(...)
to capture quick note hotkeys across any active Burp tab.
"""

import logging

try:
    from javax.swing import SwingUtilities
    from java.awt import KeyboardFocusManager, KeyEventDispatcher
    from java.awt.event import KeyEvent
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

from fieldbook.src.ui.capture_dialog import QuickCaptureDialog

logger = logging.getLogger("Fieldbook.Hotkey")

if GUI_AVAILABLE:
    class FieldbookHotkeyDispatcher(KeyEventDispatcher):
        """
        Swing KeyEventDispatcher capturing Ctrl+Shift+N or Cmd+Shift+N.
        """
        def __init__(self, store, main_frame_getter=None, on_save_callback=None):
            self.store = store
            self.main_frame_getter = main_frame_getter
            self.on_save_callback = on_save_callback
            self.registered = False

        def register(self):
            if not self.registered:
                KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(self)
                self.registered = True
                logger.info("Fieldbook global hotkey (Ctrl+Shift+N) registered.")

        def unregister(self):
            if self.registered:
                KeyboardFocusManager.getCurrentKeyboardFocusManager().removeKeyEventDispatcher(self)
                self.registered = False
                logger.info("Fieldbook global hotkey unregistered.")

        def dispatchKeyEvent(self, e):
            if not e or e.getID() != KeyEvent.KEY_PRESSED:
                return False

            is_ctrl_or_cmd = (e.getModifiers() & (KeyEvent.CTRL_MASK | KeyEvent.META_MASK)) != 0
            is_shift = (e.getModifiers() & KeyEvent.SHIFT_MASK) != 0

            if is_ctrl_or_cmd and is_shift and e.getKeyCode() == KeyEvent.VK_N:
                # Hotkey matched! Trigger Quick Capture Dialog
                def open_capture():
                    try:
                        parent_frame = self.main_frame_getter() if self.main_frame_getter else None
                        dlg = QuickCaptureDialog(
                            parent_frame=parent_frame,
                            store=self.store,
                            linked_requests=[],
                            default_target="",
                            on_save_callback=self.on_save_callback
                        )
                        dlg.setVisible(True)
                    except Exception as ex:
                        logger.error("Error opening quick capture via hotkey: %s", ex)

                SwingUtilities.invokeLater(open_capture)
                return True  # Event consumed

            return False
else:
    class FieldbookHotkeyDispatcher(object):
        def __init__(self, *args, **kwargs):
            pass
        def register(self):
            pass
        def unregister(self):
            pass
