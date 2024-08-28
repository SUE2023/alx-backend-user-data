#!/usr/bin/env python3
"""Data Encryption Module"""
import re  # Import regex module
from typing import List


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
