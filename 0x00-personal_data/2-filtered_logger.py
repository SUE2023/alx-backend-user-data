#!/usr/bin/env python3
"""Data Encryption Module"""
import re  # Import regex module
from typing import List
import logging

PII_FIELDS = ("name","email", "phone", "ssn", "password")


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


def get_logger() -> logging.Logger:
    """Create a logger named 'user_data'
    Sets logging level to INFO.
    logs are INFO, WARNING, ERROR, CRITICAL; ignores DEBUG)
    Disable message propagation(False)
    to prevent messages from being sent to parent loggers/escalleted
    Create a StreamHandler for console output(streams:sys.stdout/ sys.stderr)
    Define fields to redact
    Create an instance of RedactingFormatter with fields to redact
    Set the formatter for the StreamHandler
    Add the StreamHandler to the logger
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    stream_handler = logging.StreamHandler()
    fields_to_redact = ["email", "ssn", "password"]
    formatter = RedactingFormatter(fields=fields_to_redact)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger

    # logger = logging.getLogger("user_data")
    # stream_handler = logging.StreamHandler()
    # stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    # logger.setLevel(logging.INFO)
    # logger.propagate = False
    # logger.addHandler(stream_handler)


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
