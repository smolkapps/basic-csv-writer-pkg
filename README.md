# basic-csv-writer

A tiny, dependency-free CSV writer for the most common boring case: you have a
**flat `{key: value}` dict** and you want a clean two-column CSV out of it — a
header plus one row per item. Pure Python standard library (`csv`), packaged for
PyPI.

The one thing it does beyond `csv.DictWriter`: it is **safe by default**. A
naive CSV is a well-known injection vector — a cell whose text starts with `=`,
`+`, `-` or `@` is treated as a *formula* by Excel / Google Sheets / LibreOffice
when the file is opened, so an attacker-controlled value like
`=cmd|'/c calc'!A1` can run code on whoever opens your "data" file. This library
neutralises those cells automatically.

## Install

```bash
pip install basic-csv-writer
```

## Usage

```python
import basic_csv_writer

fieldnames = ["username", "password"]
rows = {
    "jack": "password",
    "jill": "password",
    "mike": "123456",
}
rows["sam"] = "secretpassword"

with open("passwords.csv", "w", newline="") as fh:
    basic_csv_writer.write(fh, fieldnames, rows)
```

`passwords.csv`:

```csv
username,password
jack,password
jill,password
mike,123456
sam,secretpassword
```

> **Note on the original sketch.** The first idea wrote
> `write(file, fieldnames=fieldnames, simple_dict)`, which is not valid Python (a
> positional argument cannot follow a keyword argument). The real signature is
> `write(file, fieldnames, mapping)` — call it positionally as
> `write(fh, fieldnames, rows)`.

### Don't want to manage the file handle?

```python
basic_csv_writer.write_path("passwords.csv", fieldnames, rows)
```

### Just want the CSV as a string?

```python
text = basic_csv_writer.writes(["k", "v"], {"a": 1, "b": 2})
# 'k,v\r\na,1\r\nb,2\r\n'
```

## Safe by default: CSV / formula injection

CSV is a *data* format — nothing this library writes can execute on its own. The
risk lives in the program that opens the file. By default, any cell that would be
interpreted as a formula is prefixed with a single quote (`'`), the
OWASP-recommended fix, so it renders as literal text:

```python
basic_csv_writer.writes(["user", "pw"], {"eve": "=2+5"}, write_header=False)
# "eve,'=2+5\r\n"   -> opens as the text =2+5, never the number 7
```

You choose the policy via `mode`:

| mode                   | behaviour                                              |
|------------------------|-------------------------------------------------------|
| `SanitizeMode.ESCAPE`  | prefix dangerous cells with `'` (**default**, safe)   |
| `SanitizeMode.ERROR`   | raise `ValueError` on the first dangerous cell        |
| `SanitizeMode.NONE`    | write everything verbatim (opt-in, unsafe)            |

```python
from basic_csv_writer import SanitizeMode

# Refuse to emit a risky file at all:
basic_csv_writer.writes(["k", "v"], data, mode=SanitizeMode.ERROR)
```

This also resolves the classic `123` (int) vs `'123'` (str) ambiguity from the
original idea: whatever you pass in lands in the file as deterministic, literal
text and can never be silently reinterpreted.

The dangerous-character set is overridable via `dangerous_prefixes=(...)`.

## Command line

```bash
# KEY=VALUE pairs
python -m basic_csv_writer --columns username,password jack=password mike=123456

# from a JSON object (file or stdin)
echo '{"a": "=2+5", "b": 3}' | python -m basic_csv_writer --columns k,v --json -

# write to a file; --strict refuses formula-injection values, --unsafe disables protection
python -m basic_csv_writer -o out.csv --columns k,v --strict a=1 b=2
```

(An installed console script `basic-csv-writer` is provided too.)

## API

- `write(file, fieldnames, mapping, *, mode=SanitizeMode.ESCAPE, write_header=True, dangerous_prefixes=..., **dictwriter_kwargs) -> int`
  Write to an open text file (open it with `newline=""`). Returns the number of
  data rows written. Extra keyword args are forwarded to `csv.DictWriter`
  (`delimiter`, `dialect`, `quoting`, ...).
- `write_path(path, fieldnames, mapping, *, encoding="utf-8", ...) -> int`
  Open `path` (with `newline=""`), write, and close.
- `writes(fieldnames, mapping, ...) -> str`
  Return the CSV as a string.
- `sanitize_value(value, mode=..., dangerous_prefixes=...) -> str`,
  `is_dangerous(value, dangerous_prefixes=...) -> bool` — the sanitization
  primitives, exposed for reuse.

`fieldnames` must contain **exactly two** names (a key column and a value
column). `mapping` must be a dict-like object.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[test]"
pytest -q
```

## License

MIT © Michael Smolkin
