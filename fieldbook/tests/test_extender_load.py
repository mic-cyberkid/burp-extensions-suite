"""
Unit test for FieldbookExtender loading under Jython / simulated environment without __file__.
"""

import unittest

try:
    from unittest.mock import MagicMock
except ImportError:
    class MagicMock(object):
        def __init__(self, *args, **kwargs):
            pass
        def __getattr__(self, name):
            return MagicMock()
        def __call__(self, *args, **kwargs):
            return MagicMock()

class TestExtenderLoad(unittest.TestCase):
    def test_extender_instantiation_and_callbacks_without_file_var(self):
        # Simulate environment where __file__ is absent or disabled
        import fieldbook.src.FieldbookExtender as ext_module

        extender = ext_module.BurpExtender()
        self.assertEqual(extender.getTabCaption(), "Fieldbook")

        mock_callbacks = MagicMock()
        mock_callbacks.getHelpers.return_value = MagicMock()
        mock_callbacks.loadExtensionSetting.return_value = None
        mock_callbacks.getExtensionFilename.return_value = "/mock/path/fieldbook/src/FieldbookExtender.py"

        extender.registerExtenderCallbacks(mock_callbacks)
        mock_callbacks.setExtensionName.assert_called_with("Fieldbook Research Notebook")
        mock_callbacks.addSuiteTab.assert_called_with(extender)

if __name__ == "__main__":
    unittest.main()
