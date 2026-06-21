"""Command-line interface for :mod:`basic_csv_writer`.

Write a flat key/value mapping to a safe two-column CSV without writing any
Python. Pairs come either from ``KEY=VALUE`` arguments or from a JSON object on
stdin / in a file.

Examples
--------
From ``KEY=VALUE`` pairs::

    python -m basic_csv_writer -o creds.csv --columns username,password \\
        jack=password jill=password mike=123456

From a JSON object file::

    python -m basic_csv_writer -o out.csv --columns key,value --json data.json

From stdin::

    echo '{"a": "=2+5", "b": 3}' | python -m basic_csv_writer --columns k,v --json -

By default formula-injection-prone values (``=2+5`` above) are neutralised; use
``--unsafe`` to write them verbatim or ``--strict`` to error out instead.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Dict, List, Optional, Sequence

from .writer import SanitizeMode, write, write_path


def _parse_kv_pairs(pairs: Sequence[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in pairs:
        if "=" not in item:
            raise SystemExit(
                f"error: positional pair {item!r} is not in KEY=VALUE form"
            )
        key, value = item.split("=", 1)
        out[key] = value
    return out


def _load_json(path: str) -> Dict[str, object]:
    if path == "-":
        data = json.load(sys.stdin)
    else:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    if not isinstance(data, dict):
        raise SystemExit("error: --json input must be a JSON object (dict)")
    return data


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="basic_csv_writer",
        description="Write a flat key/value mapping to a safe two-column CSV.",
    )
    parser.add_argument(
        "pairs",
        nargs="*",
        metavar="KEY=VALUE",
        help="key/value pairs to write (mutually exclusive with --json)",
    )
    parser.add_argument(
        "-c",
        "--columns",
        default="key,value",
        help='comma-separated header, exactly two names (default: "key,value")',
    )
    parser.add_argument(
        "-o",
        "--output",
        default="-",
        help='output CSV path, or "-" for stdout (default: stdout)',
    )
    parser.add_argument(
        "--json",
        metavar="PATH",
        help='read the mapping from a JSON object file, or "-" for stdin',
    )
    parser.add_argument(
        "--no-header",
        action="store_true",
        help="do not write the header row",
    )
    sanitize = parser.add_mutually_exclusive_group()
    sanitize.add_argument(
        "--unsafe",
        action="store_true",
        help="write values verbatim (no formula-injection protection)",
    )
    sanitize.add_argument(
        "--strict",
        action="store_true",
        help="error out on any formula-injection-prone value",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    columns: List[str] = [c for c in args.columns.split(",")]
    if len(columns) != 2:
        parser.error("--columns must contain exactly two comma-separated names")

    if args.json and args.pairs:
        parser.error("provide either KEY=VALUE pairs or --json, not both")
    if not args.json and not args.pairs:
        parser.error("no data: provide KEY=VALUE pairs or --json")

    mapping = _load_json(args.json) if args.json else _parse_kv_pairs(args.pairs)

    if args.unsafe:
        mode = SanitizeMode.NONE
    elif args.strict:
        mode = SanitizeMode.ERROR
    else:
        mode = SanitizeMode.ESCAPE

    write_header = not args.no_header

    if args.output == "-":
        count = write(
            sys.stdout, columns, mapping, mode=mode, write_header=write_header
        )
    else:
        count = write_path(
            args.output, columns, mapping, mode=mode, write_header=write_header
        )
        print(f"wrote {count} row(s) to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
