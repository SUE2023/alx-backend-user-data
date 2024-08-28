#!/usr/bin/env python3
"""Data Encryption Module"""
import re  # Import regex module
from typing import List
import logging


def filter_datum(
        fields: List[str], redaction: str, message: str, separator: str
        ) -> str:
    """Obfuscates the log message by replacing specified fields
    with a redaction."""
    # Create a single regex pattern to match any field that needs obfuscation
    patterns = {
        'extract': lambda x, y: r'(?P<field>{})=[^{}]*'.format('|'.join(x), y),
        'replace': lambda x: r'\g<field>={}'.format(x),
    }
    # Example list of fields that are PII
    PII_FIELDS = ['password', 'date_of_birth']

    extract, replace = (patterns["extract"], patterns["replace"])
    return re.sub(extract(fields, separator), replace(redaction), message)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    FORMAT_FIELDS = ('name', 'levelname', 'asctime', 'message')
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Formats a LogRecord."""
        msg = super(RedactingFormatter, self).format(record)
        txt = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return txt
