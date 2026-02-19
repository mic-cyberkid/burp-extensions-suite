# Shared Python utilities for Burp Legacy API extensions

import logging

def get_logger(name):
    """
    Returns a configured logger that outputs to stdout.
    Burp redirects stdout to its extension console.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger

class BurpUIUtils:
    """
    Common UI helpers for Swing-based Burp interfaces.
    """
    @staticmethod
    def create_table_model(columns, data):
        from javax.swing.table import DefaultTableModel
        model = DefaultTableModel(columns, 0)
        for row in data:
            model.addRow(row)
        return model
