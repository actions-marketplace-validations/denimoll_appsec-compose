"""Placeholder "secrets": a dummy value in a real token format is not a credential."""
import placeholders as ph
from normalize import Finding

# Assembled at run time so this file is not itself a finding for Gitleaks.
REAL = "ghp_" "R8f2Lq9ZtW3mXc7Vb1Nk4Hs6Pd0Yj5Ga2Ue8"


def _secret(line, column=None, end_column=None):
    return Finding(tool="trivy", category="secrets", rule_id="github-pat", severity="high",
                   message="m", file="a.js", line=line, column=column, end_column=end_column)


def test_only_unmistakable_placeholders_move(tmp_path):
    (tmp_path / "a.js").write_text("\n".join([
        "const A = 'ghp_" + "x" * 36 + "';",          # 1: one repeated character
        f"const B = '{REAL}';",                        # 2: a real-looking token
        "API_KEY = 'your_api_key_here'",               # 3: spelled as a placeholder
        f"const C = '{REAL}', D = 'ghp_" + "x" * 36 + "';",   # 4: real next to dummy
        "token: '<your-token>'",                       # 5
    ]) + "\n")
    findings = [_secret(n) for n in range(1, 6)]
    kept, moved = ph.split(findings, str(tmp_path))
    assert [f.line for f in moved] == [1, 3, 5]
    assert [f.line for f in kept] == [2, 4]


def test_the_engines_span_decides_when_it_gives_one(tmp_path):
    line = f"const C = '{REAL}', D = 'ghp_" + "x" * 36 + "';"
    (tmp_path / "a.js").write_text(line + "\n")
    start = line.index("'ghp_x") + 1
    dummy = _secret(1, column=start, end_column=start + 41)
    real = _secret(1, column=line.index(REAL) + 1, end_column=line.index(REAL) + 1 + len(REAL))
    kept, moved = ph.split([dummy, real], str(tmp_path))
    assert moved == [dummy] and kept == [real]


def test_nothing_moves_without_the_code_or_outside_secrets(tmp_path):
    (tmp_path / "a.js").write_text("const A = 'ghp_" + "x" * 36 + "';\n")
    f = _secret(1)
    assert ph.split([f], None) == ([f], [])
    sast = Finding(tool="semgrep", category="sast", rule_id="r", severity="high",
                   message="m", file="a.js", line=1)
    assert ph.split([sast], str(tmp_path)) == ([sast], [])
