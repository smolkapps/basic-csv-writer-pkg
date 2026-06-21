"""Core implementation of :mod:`basic_csv_writer`.

Everything here is pure standard library (:mod:`csv`). The public surface is
small on purpose: :func:`write` (and the convenience helpers :func:`write_path`
and :func:`writes`) takes a flat ``{key: value}`` mapping and emits a two-column
CSV with a header.

Security note
-------------
CSV is a data format, not a programming language: nothing this module writes can
"execute" on its own. The real risk is **formula injection** -- spreadsheet
applications treat a leading ``=``, ``+``, ``-`` or ``@`` (and a few control
characters) as the start of a formula. We default to neutralising such cells so
that, e.g., a password stored as ``=2+5`` round-trips as the literal text
``=2+5`` rather than the number ``7`` (or worse, a ``=cmd|...`` payload).
"""

from __future__ import annotations

import csv
import enum
import io
import os
from typing import Any, Iterable, Iterator, Mapping, Tuple, Union

__all__ = [
    "write",
    "write_path",
    "writes",
    "sanitize_value",
    "is_dangerous",
    "SanitizeMode",
    "DEFAULT_DANGEROUS_PREFIXES",
]

# Characters that, when leading a cell, can trigger formula evaluation in
# Excel / Google Sheets / LibreOffice Calc. See OWASP "CSV Injection".
#   =  +  -  @  : formula leaders
#   \t \r       : can be used to smuggle a leading formula char past naive checks
DEFAULT_DANGEROUS_PREFIXES: Tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r")

# What we prepend to neutralise a dangerous cell. A single quote is the
# canonical, widely-recommended choice: spreadsheets treat a leading apostrophe
# as "the rest of this cell is literal text" and do not display it as data.
_NEUTRALISER = "'"


class SanitizeMode(str, enum.Enum):
    """How to handle cells that look like spreadsheet formulas.

    * ``ESCAPE``  -- prefix dangerous cells with ``'`` so they render as text
      (default; safe and lossless for everyday data).
    * ``ERROR``   -- raise :class:`ValueError` on the first dangerous cell
      (for pipelines that must never emit one).
    * ``NONE``    -- write values verbatim (opt-in, unsafe; only for trusted
      data that will never be opened in a spreadsheet).
    """

    ESCAPE = "escape"
    ERROR = "error"
    NONE = "none"


def is_dangerous(
    value: str,
    dangerous_prefixes: Iterable[str] = DEFAULT_DANGEROUS_PREFIXES,
) -> bool:
    """Return ``True`` if ``value`` would be treated as a formula by a spreadsheet.

    Only non-empty strings can be dangerous; the check is purely on the first
    character.
    """
    if not isinstance(value, str) or value == "":
        return False
    return value[0] in tuple(dangerous_prefixes)


def sanitize_value(
    value: Any,
    mode: SanitizeMode = SanitizeMode.ESCAPE,
    dangerous_prefixes: Iterable[str] = DEFAULT_DANGEROUS_PREFIXES,
) -> str:
    """Coerce ``value`` to ``str`` and neutralise formula-injection risk.

    Non-string values (``int``, ``float``, ``bool``, ``None``, ...) are first
    converted with :func:`str`. ``None`` becomes the empty string ``""`` (rather
    than the literal text ``"None"``), which is the conventional CSV
    representation of a missing value.

    Then, depending on ``mode``:

    * ``ESCAPE`` -- if the resulting string starts with a dangerous character it
      is prefixed with ``'``.
    * ``ERROR``  -- a dangerous string raises :class:`ValueError`.
    * ``NONE``   -- the string is returned unchanged.

    This resolves the classic ``123`` vs ``'123'`` ambiguity from the original
    idea: whatever you pass, the value lands in the file as deterministic,
    literal text; it can never be silently reinterpreted as a formula.
    """
    if value is None:
        text = ""
    elif isinstance(value, str):
        text = value
    else:
        text = str(value)

    prefixes = tuple(dangerous_prefixes)
    if not text or text[0] not in prefixes:
        return text

    if mode == SanitizeMode.NONE:
        return text
    if mode == SanitizeMode.ERROR:
        raise ValueError(
            f"refusing to write potential CSV/formula-injection value: {text!r} "
            f"(starts with {text[0]!r}); pass mode=SanitizeMode.ESCAPE to "
            f"neutralise it or mode=SanitizeMode.NONE to write it verbatim"
        )
    # SanitizeMode.ESCAPE
    return _NEUTRALISER + text


def _normalise_fieldnames(fieldnames: Iterable[str]) -> Tuple[str, str]:
    """Validate ``fieldnames`` and return it as an exactly-two-element tuple."""
    names = tuple(fieldnames)
    if len(names) != 2:
        raise ValueError(
            f"fieldnames must contain exactly 2 names (a key column and a value "
            f"column); got {len(names)}: {names!r}"
        )
    if not all(isinstance(n, str) for n in names):
        raise TypeError(f"fieldnames must all be strings; got {names!r}")
    return names  # type: ignore[return-value]


def _rows(
    fieldnames: Tuple[str, str],
    mapping: Mapping[Any, Any],
    mode: SanitizeMode,
    dangerous_prefixes: Tuple[str, ...],
) -> Iterator[dict]:
    """Yield sanitised :class:`csv.DictWriter` row dicts for ``mapping``."""
    key_field, value_field = fieldnames
    for raw_key, raw_value in mapping.items():
        yield {
            key_field: sanitize_value(raw_key, mode, dangerous_prefixes),
            value_field: sanitize_value(raw_value, mode, dangerous_prefixes),
        }


def write(
    file: io.TextIOBase,
    fieldnames: Iterable[str],
    mapping: Mapping[Any, Any],
    *,
    mode: SanitizeMode = SanitizeMode.ESCAPE,
    write_header: bool = True,
    dangerous_prefixes: Iterable[str] = DEFAULT_DANGEROUS_PREFIXES,
    **dictwriter_kwargs: Any,
) -> int:
    """Write ``mapping`` to an open text ``file`` as a two-column CSV.

    Parameters
    ----------
    file:
        An already-open, writable **text** file object (e.g. the result of
        ``open(path, "w", newline="")``). To avoid spurious blank rows on
        Windows the file should be opened with ``newline=""`` per the
        :mod:`csv` docs; this function does not own or close the file.
    fieldnames:
        Exactly two column names: ``(key_column, value_column)``.
    mapping:
        A flat ``{key: value}`` dict. Each item becomes one CSV row.
    mode:
        Formula-injection handling; see :class:`SanitizeMode`. Defaults to
        ``ESCAPE`` (safe).
    write_header:
        Whether to emit the header row first (default ``True``).
    dangerous_prefixes:
        Override the set of leading characters treated as dangerous.
    **dictwriter_kwargs:
        Forwarded to :class:`csv.DictWriter` (e.g. ``dialect``, ``delimiter``,
        ``quoting``).

    Returns
    -------
    int
        The number of data rows written (excluding the header).

    Notes
    -----
    The original sketch wrote ``write(file, fieldnames=fieldnames, simple_dict)``
    which is not valid Python (a positional argument cannot follow a keyword
    argument). The real signature is ``write(file, fieldnames, mapping)``; call
    it positionally as ``write(fh, fieldnames, rows)`` or name any of the args.
    """
    if isinstance(mapping, (str, bytes)):
        raise TypeError(
            "mapping must be a dict-like object of {key: value}, not a string"
        )
    if not isinstance(mapping, Mapping):
        raise TypeError(
            f"mapping must be a Mapping (dict); got {type(mapping).__name__}"
        )

    names = _normalise_fieldnames(fieldnames)
    prefixes = tuple(dangerous_prefixes)

    writer = csv.DictWriter(file, fieldnames=list(names), **dictwriter_kwargs)
    if write_header:
        writer.writeheader()

    count = 0
    for row in _rows(names, mapping, mode, prefixes):
        writer.writerow(row)
        count += 1
    return count


def write_path(
    path: Union[str, os.PathLike],
    fieldnames: Iterable[str],
    mapping: Mapping[Any, Any],
    *,
    mode: SanitizeMode = SanitizeMode.ESCAPE,
    write_header: bool = True,
    encoding: str = "utf-8",
    dangerous_prefixes: Iterable[str] = DEFAULT_DANGEROUS_PREFIXES,
    **dictwriter_kwargs: Any,
) -> int:
    """Like :func:`write`, but opens (and closes) ``path`` for you.

    Opens the file with ``newline=""`` (required by the :mod:`csv` module to
    avoid extra blank rows) and the given ``encoding``.
    """
    with open(path, "w", newline="", encoding=encoding) as fh:
        return write(
            fh,
            fieldnames,
            mapping,
            mode=mode,
            write_header=write_header,
            dangerous_prefixes=dangerous_prefixes,
            **dictwriter_kwargs,
        )


def writes(
    fieldnames: Iterable[str],
    mapping: Mapping[Any, Any],
    *,
    mode: SanitizeMode = SanitizeMode.ESCAPE,
    write_header: bool = True,
    dangerous_prefixes: Iterable[str] = DEFAULT_DANGEROUS_PREFIXES,
    **dictwriter_kwargs: Any,
) -> str:
    """Like :func:`write`, but return the CSV as a string instead of writing.

    Handy for tests and in-memory use. Uses ``newline=""`` semantics via
    :class:`io.StringIO`.
    """
    buffer = io.StringIO(newline="")
    write(
        buffer,
        fieldnames,
        mapping,
        mode=mode,
        write_header=write_header,
        dangerous_prefixes=dangerous_prefixes,
        **dictwriter_kwargs,
    )
    return buffer.getvalue()
