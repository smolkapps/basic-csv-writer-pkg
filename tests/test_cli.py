"""Tests for the ``python -m basic_csv_writer`` command-line interface."""

from __future__ import annotations

import io
import json

import pytest

from basic_csv_writer.__main__ import main


def _run(argv, monkeypatch, stdin_text=None):
    """Run the CLI capturing stdout/stderr; return (rc, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", err)
    if stdin_text is not None:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin_text))
    rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


def test_cli_kv_pairs_to_stdout(monkeypatch):
    rc, out, _ = _run(
        ["--columns", "username,password", "jack=password", "mike=123456"],
        monkeypatch,
    )
    assert rc == 0
    assert out == "username,password\r\njack,password\r\nmike,123456\r\n"


def test_cli_kv_pair_value_may_contain_equals(monkeypatch):
    rc, out, _ = _run(["--no-header", "key=a=b=c"], monkeypatch)
    assert rc == 0
    assert out == "key,a=b=c\r\n"


def test_cli_json_stdin(monkeypatch):
    rc, out, _ = _run(
        ["--columns", "k,v", "--json", "-"],
        monkeypatch,
        stdin_text=json.dumps({"a": 1, "b": "two"}),
    )
    assert rc == 0
    assert out == "k,v\r\na,1\r\nb,two\r\n"


def test_cli_json_file(monkeypatch, tmp_path):
    src = tmp_path / "data.json"
    src.write_text(json.dumps({"x": "y"}), encoding="utf-8")
    rc, out, _ = _run(["--no-header", "--json", str(src)], monkeypatch)
    assert rc == 0
    assert out == "x,y\r\n"


def test_cli_writes_file(monkeypatch, tmp_path):
    dest = tmp_path / "out.csv"
    rc, _, err = _run(
        ["-o", str(dest), "--no-header", "a=b"],
        monkeypatch,
    )
    assert rc == 0
    # Read with newline="" so the CSV \r\n terminators are NOT translated by
    # universal-newline mode (Path.read_text would collapse \r\n -> \n).
    with open(dest, "r", encoding="utf-8", newline="") as fh:
        assert fh.read() == "a,b\r\n"
    assert "wrote 1 row" in err


def test_cli_default_escapes_formula(monkeypatch):
    rc, out, _ = _run(["--no-header", "x==2+5"], monkeypatch)
    assert rc == 0
    assert out == "x,'=2+5\r\n"


def test_cli_unsafe_writes_formula_verbatim(monkeypatch):
    rc, out, _ = _run(["--no-header", "--unsafe", "x==2+5"], monkeypatch)
    assert rc == 0
    assert out == "x,=2+5\r\n"


def test_cli_strict_errors_on_formula(monkeypatch):
    with pytest.raises(ValueError):
        _run(["--strict", "x==2+5"], monkeypatch)


def test_cli_requires_data(monkeypatch):
    with pytest.raises(SystemExit):
        _run([], monkeypatch)


def test_cli_rejects_both_pairs_and_json(monkeypatch):
    with pytest.raises(SystemExit):
        _run(["--json", "-", "a=b"], monkeypatch, stdin_text="{}")


def test_cli_rejects_bad_kv_pair(monkeypatch):
    with pytest.raises(SystemExit):
        _run(["nopair"], monkeypatch)


def test_cli_columns_must_be_two(monkeypatch):
    with pytest.raises(SystemExit):
        _run(["--columns", "only_one", "a=b"], monkeypatch)


def test_cli_json_must_be_object(monkeypatch):
    with pytest.raises(SystemExit):
        _run(["--json", "-"], monkeypatch, stdin_text="[1,2,3]")
