"""review-brief.md stays readable: a whole-file finding does not paste the file."""
from baseline import _Source
from brief import _MAX_FLAGGED, _snippet
from normalize import Finding


def test_a_whole_file_span_shows_its_start_and_says_how_much_is_left(tmp_path):
    (tmp_path / "openapi.yml").write_text("".join(f"line {n}\n" for n in range(1, 438)))
    f = Finding("checkov", "iac", "CKV_OPENAPI_4", "high", "m", "openapi.yml", 1, end_line=437)
    rows = _snippet(f, _Source(str(tmp_path)), {}).splitlines()
    assert len(rows) == _MAX_FLAGGED + 1
    assert rows[0].startswith(">   1 |") and "429 more flagged line(s)" in rows[-1]


def test_a_short_span_keeps_its_context(tmp_path):
    (tmp_path / "app.py").write_text("".join(f"x{n} = {n}\n" for n in range(1, 11)))
    f = Finding("semgrep", "sast", "r", "high", "m", "app.py", 5, end_line=6)
    rows = _snippet(f, _Source(str(tmp_path)), {}).splitlines()
    assert [r[:5] for r in rows] == ["    3", "    4", ">   5", ">   6", "    7", "    8"]
