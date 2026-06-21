"""Tests for the core writer behaviour and sanitization."""

from __future__ import annotations

import csv
import io

import pytest

import basic_csv_writer as bcw
from basic_csv_writer import SanitizeMode, is_dangerous, sanitize_value, writes


# --------------------------------------------------------------------------- #
# The canonical example from the original idea note.
# --------------------------------------------------------------------------- #
def test_basic_example_matches_idea_note():
    fieldnames = ["username", "password"]
    rows = {
        "jack": "password",
        "jill": "password",
        "john": "123",
        "lily": "1234",
        "mike": "123456",
    }
    rows["sam"] = "secretpassword"

    out = writes(fieldnames, rows)
    expected = (
        "username,password\r\n"
        "jack,password\r\n"
        "jill,password\r\n"
        "john,123\r\n"
        "lily,1234\r\n"
        "mike,123456\r\n"
        "sam,secretpassword\r\n"
    )
    assert out == expected


def test_write_returns_row_count():
    n = bcw.write(io.StringIO(newline=""), ["k", "v"], {"a": 1, "b": 2, "c": 3})
    assert n == 3


def test_write_to_file_object_roundtrips_with_dictreader():
    fieldnames = ["k", "v"]
    data = {"alpha": "1", "beta": "two"}
    buf = io.StringIO(newline="")
    bcw.write(buf, fieldnames, data)
    buf.seek(0)
    reader = csv.DictReader(buf)
    assert reader.fieldnames == fieldnames
    got = list(reader)
    assert got == [
        {"k": "alpha", "v": "1"},
        {"k": "beta", "v": "two"},
    ]


def test_no_header_option():
    out = writes(["k", "v"], {"a": "b"}, write_header=False)
    assert out == "a,b\r\n"


def test_empty_mapping_writes_only_header():
    out = writes(["k", "v"], {})
    assert out == "k,v\r\n"


def test_empty_mapping_no_header_is_empty_string():
    out = writes(["k", "v"], {}, write_header=False)
    assert out == ""


# --------------------------------------------------------------------------- #
# Type coercion: the `123` (int) vs `'123'` (str) ambiguity from the note.
# --------------------------------------------------------------------------- #
def test_non_string_values_are_coerced_to_text():
    out = writes(["k", "v"], {"int": 123, "float": 4.5, "bool": True})
    assert out == ("k,v\r\nint,123\r\nfloat,4.5\r\nbool,True\r\n")


def test_none_value_becomes_empty_string_not_literal_none():
    out = writes(["k", "v"], {"missing": None}, write_header=False)
    assert out == "missing,\r\n"


def test_non_string_keys_are_coerced():
    out = writes(["k", "v"], {1: "one", 2: "two"}, write_header=False)
    assert out == "1,one\r\n2,two\r\n"


def test_values_with_commas_and_quotes_are_quoted_by_csv_module():
    out = writes(["k", "v"], {"a": "x,y", "b": 'he said "hi"'}, write_header=False)
    assert out == 'a,"x,y"\r\nb,"he said ""hi"""\r\n'


# --------------------------------------------------------------------------- #
# Formula / CSV injection -- the headline security feature.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("lead", ["=", "+", "-", "@", "\t", "\r"])
def test_is_dangerous_detects_each_formula_leader(lead):
    assert is_dangerous(lead + "danger") is True


@pytest.mark.parametrize("safe", ["", "hello", "123", "a=b", "normal text"])
def test_is_dangerous_false_for_safe_values(safe):
    assert is_dangerous(safe) is False


def test_is_dangerous_false_for_non_strings():
    assert is_dangerous(123) is False  # type: ignore[arg-type]
    assert is_dangerous(None) is False  # type: ignore[arg-type]


def test_escape_mode_neutralises_formula_value():
    # The exact threat from the note: a value that looks like code/formula.
    out = writes(
        ["username", "password"],
        {"john": "=2+5", "attacker": "=cmd|'/c calc'!A1"},
        write_header=False,
    )
    # Each dangerous cell gets a leading single quote; neither value contains a
    # comma so the csv module does not need to quote them.
    assert out == "john,'=2+5\r\nattacker,'=cmd|'/c calc'!A1\r\n"


def test_escape_and_csv_quoting_compose():
    # A value that is BOTH a formula AND contains a comma must be escaped with
    # the leading quote AND wrapped in double quotes by the csv module.
    out = writes(["k", "v"], {"x": "=1,2,3"}, write_header=False)
    assert out == 'x,"\'=1,2,3"\r\n'
    # Parsed back, the cell is literal text, no longer a bare formula.
    (row,) = list(csv.reader(io.StringIO(out)))
    assert row == ["x", "'=1,2,3"]
    assert not row[1].startswith("=")


def test_escape_mode_neutralises_dangerous_key_too():
    out = writes(["k", "v"], {"=evil": "ok"}, write_header=False)
    assert out == "'=evil,ok\r\n"


def test_escaped_value_roundtrips_as_literal_text():
    # After escaping, reading the CSV back yields the original text WITH the
    # protective apostrophe -- it is never evaluated. We verify the cell is no
    # longer a bare formula.
    out = writes(["k", "v"], {"x": "=HYPERLINK(1)"}, write_header=False)
    buf = io.StringIO(out)
    (row,) = list(csv.reader(buf))
    assert row == ["x", "'=HYPERLINK(1)"]
    assert not row[1].startswith("=")


def test_error_mode_raises_on_dangerous_value():
    with pytest.raises(ValueError) as exc:
        writes(["k", "v"], {"x": "=2+5"}, mode=SanitizeMode.ERROR)
    assert "injection" in str(exc.value)


def test_error_mode_allows_safe_values():
    out = writes(["k", "v"], {"x": "safe"}, mode=SanitizeMode.ERROR)
    assert out == "k,v\r\nx,safe\r\n"


def test_none_mode_writes_formula_verbatim():
    out = writes(["k", "v"], {"x": "=2+5"}, mode=SanitizeMode.NONE, write_header=False)
    assert out == "x,=2+5\r\n"


def test_sanitize_value_direct():
    assert sanitize_value("=2+5") == "'=2+5"
    assert sanitize_value("safe") == "safe"
    assert sanitize_value(123) == "123"
    assert sanitize_value(None) == ""
    assert sanitize_value("=2+5", mode=SanitizeMode.NONE) == "=2+5"
    with pytest.raises(ValueError):
        sanitize_value("=2+5", mode=SanitizeMode.ERROR)


def test_custom_dangerous_prefixes():
    # Treat '!' as dangerous, and (deliberately) not '='.
    out = writes(
        ["k", "v"],
        {"a": "!bang", "b": "=eq"},
        write_header=False,
        dangerous_prefixes=("!",),
    )
    assert out == "a,'!bang\r\nb,=eq\r\n"


# --------------------------------------------------------------------------- #
# Error paths.
# --------------------------------------------------------------------------- #
def test_fieldnames_must_be_exactly_two():
    with pytest.raises(ValueError):
        writes(["only_one"], {"a": "b"})
    with pytest.raises(ValueError):
        writes(["a", "b", "c"], {"a": "b"})


def test_fieldnames_must_be_strings():
    with pytest.raises(TypeError):
        writes([1, 2], {"a": "b"})  # type: ignore[list-item]


def test_mapping_must_be_a_mapping():
    with pytest.raises(TypeError):
        bcw.write(io.StringIO(), ["k", "v"], ["not", "a", "dict"])  # type: ignore[arg-type]


def test_mapping_string_is_rejected():
    with pytest.raises(TypeError):
        bcw.write(io.StringIO(), ["k", "v"], "abc")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Dialect passthrough to csv.DictWriter.
# --------------------------------------------------------------------------- #
def test_custom_delimiter_passthrough():
    out = writes(["k", "v"], {"a": "b"}, delimiter=";", write_header=False)
    assert out == "a;b\r\n"


def test_package_exposes_version():
    assert isinstance(bcw.__version__, str)
    assert bcw.__version__
