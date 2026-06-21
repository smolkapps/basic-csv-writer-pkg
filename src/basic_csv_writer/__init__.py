"""basic_csv_writer - a tiny, safe CSV writer for flat key/value dicts.

The original idea (2021): you build an extremely basic two-column dict and the
library writes it out as a CSV with a header row and one row per item::

    import basic_csv_writer

    fieldnames = ["username", "password"]
    rows = {
        "jack": "password",
        "jill": "password",
        "mike": "123456",
    }

    with open("passwords.csv", "w", newline="") as fh:
        basic_csv_writer.write(fh, fieldnames, rows)

produces ``passwords.csv``::

    username,password
    jack,password
    jill,password
    mike,123456

The headline feature is *safe by default* output. A bare CSV is a notorious
injection vector: a cell whose text starts with ``=``, ``+``, ``-``, ``@`` (or
certain control characters) is interpreted as a **formula** by Excel / Google
Sheets / LibreOffice when the file is opened, so an attacker-controlled value
such as ``=cmd|'/c calc'!A1`` can run on the victim's machine. This is CSV /
formula injection (a.k.a. CSV injection). By default this library neutralises
those cells (OWASP-recommended single-quote prefix) so the data is rendered
literally instead of executed.
"""

from .writer import (
    DEFAULT_DANGEROUS_PREFIXES,
    SanitizeMode,
    is_dangerous,
    sanitize_value,
    write,
    write_path,
    writes,
)

__all__ = [
    "write",
    "write_path",
    "writes",
    "sanitize_value",
    "is_dangerous",
    "SanitizeMode",
    "DEFAULT_DANGEROUS_PREFIXES",
]

__version__ = "0.1.0"
