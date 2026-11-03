"""scripts/engine-timings.py and the timings in provenance."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("engine_timings", ROOT / "scripts" / "engine-timings.py")
et = importlib.util.module_from_spec(spec)
spec.loader.exec_module(et)


def container(service, start, end):
    return {"Config": {"Labels": {"com.docker.compose.service": service}},
            "State": {"StartedAt": start, "FinishedAt": end}}


def test_durations_come_from_docker_state_slowest_first():
    out = et.timings([
        container("trivy", "2026-11-03T07:00:00.100000000Z", "2026-11-03T07:00:05.150000000Z"),
        container("semgrep", "2026-11-03T07:00:00.000000001Z", "2026-11-03T07:00:18.400000000Z"),
    ])
    assert out == {"semgrep": 18.4, "trivy": 5.0} and list(out) == ["semgrep", "trivy"]


def test_unusable_entries_are_skipped_not_fatal():
    assert et.timings([
        container("checkov", "0001-01-01T00:00:00Z", ""),             # never finished
        {"State": {"StartedAt": "2026-11-03T07:00:00Z", "FinishedAt": "2026-11-03T07:00:01Z"}},
        container("gitleaks", "2026-11-03T07:00:02Z", "2026-11-03T07:00:01Z"),  # clock went back
    ]) == {}
    assert et.main(["engine-timings.py"]) == 0                          # no ids: {}


def test_the_label_names_the_slowest_engines():
    from summary import timing_label
    assert timing_label({"engines": {"semgrep": 18.4, "checkov": 13.0, "trivy": 5.0, "zizmor": 4.0},
                         "scanners_s": 19, "collector_s": 0.8, "total_s": 24}) == \
        "took 24 s (scanners 19 s: semgrep 18.4 s, checkov 13 s, trivy 5 s)"
    assert timing_label({}) == "" and timing_label(None) == ""
