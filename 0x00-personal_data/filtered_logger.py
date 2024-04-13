#!/usr/bin/env python3
"""
Module for Personal Data handling
"""

from typing import List
import re
import logging

def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """
    Returns a log message obfuscated
    """
    for f in fields:
        message = re.sub(f'{f}=.*?{separator}',
                         f'{f}={redaction}{separator}', message)
    return message

class RedactingFormatter(logging.Formatter):
    """
    Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self):
        super(RedactingFormatter, self).__init__(self.FORMAT)

    def format(self, record: logging.LogRecord) -> str:
    """
    Filters incoming log records
    """
    record.msg = filter_datum(self.fields, self.REDACTION,
                              record.getMessage(), self.SEPARATOR)
    return super(RedactingFormatter, self).format(record)
