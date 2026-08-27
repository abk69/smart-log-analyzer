"""Tests for the synthetic security-log dataset generator (M10)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzer.config import AnalyzerConfig
from analyzer.parsers.parser_dispatcher import parse_logs
from analyzer.services.analysis_service import AnalysisService
from tools.generate_logs import (
    DEFAULT_OUTPUT,
    generate_dataset,
    generate_events,
    main,
    normalize_scenario,
    validate_attack_rate,
)


def test_default_generation(tmp_path: Path):
    path, events, stats = generate_dataset(
        entries=50,
        seed=1,
        output=tmp_path / "out.log",
        quiet=True,
    )
    assert path.exists()
    assert len(events) == 50
    assert stats.total == 50
    assert path.read_text(encoding="utf-8").count("\n") == 50


def test_entries_count_exact(tmp_path: Path):
    for n in (0, 1, 10, 100):
        _, events, _ = generate_dataset(
            entries=n, seed=7, output=tmp_path / f"e{n}.log", quiet=True
        )
        assert len(events) == n


def test_seed_reproducibility(tmp_path: Path):
    a = tmp_path / "a.log"
    b = tmp_path / "b.log"
    generate_dataset(entries=200, seed=42, scenario="demo", output=a, quiet=True)
    generate_dataset(entries=200, seed=42, scenario="demo", output=b, quiet=True)
    assert a.read_text(encoding="utf-8") == b.read_text(encoding="utf-8")


def test_different_seeds_differ(tmp_path: Path):
    a = tmp_path / "a.log"
    c = tmp_path / "c.log"
    generate_dataset(entries=200, seed=42, scenario="demo", output=a, quiet=True)
    generate_dataset(entries=200, seed=43, scenario="demo", output=c, quiet=True)
    assert a.read_text(encoding="utf-8") != c.read_text(encoding="utf-8")


def test_output_path_creates_parents(tmp_path: Path):
    out = tmp_path / "nested" / "dir" / "dataset.log"
    path, events, _ = generate_dataset(
        entries=20, seed=2, output=out, quiet=True
    )
    assert path == out
    assert out.exists()
    assert len(events) == 20


def test_scenario_aliases():
    assert normalize_scenario("mixed") == "demo"
    assert normalize_scenario("brute-force") == "bruteforce"
    assert normalize_scenario("sqli") == "sql"
    assert normalize_scenario("password_spray") == "passwordspray"
    with pytest.raises(ValueError):
        normalize_scenario("not-a-real-scenario")


def test_invalid_entries_cli():
    assert main(["--entries", "-1"]) == 2


def test_invalid_attack_rate():
    with pytest.raises(ValueError):
        validate_attack_rate(1.5)
    with pytest.raises(ValueError):
        validate_attack_rate(-0.1)
    assert validate_attack_rate(0.0) == 0.0
    assert validate_attack_rate(1.0) == 1.0
    assert main(["--attack-rate", "2"]) == 2
    assert main(["--attack-rate", "-0.5"]) == 2


def test_invalid_scenario_cli():
    assert main(["--scenario", "bogus"]) == 2


def test_normal_scenario_all_normal(tmp_path: Path):
    _, events, stats = generate_dataset(
        entries=80,
        seed=11,
        scenario="normal",
        output=tmp_path / "normal.log",
        quiet=True,
    )
    assert stats.normal == 80
    assert stats.suspicious == 0
    assert all(e.kind == "normal" for e in events)


def test_demo_includes_attack_kinds(tmp_path: Path):
    _, events, stats = generate_dataset(
        entries=300,
        seed=42,
        scenario="demo",
        attack_rate=0.15,
        intensity="medium",
        output=tmp_path / "demo.log",
        quiet=True,
    )
    kinds = {e.kind for e in events}
    for expected in (
        "normal",
        "bruteforce",
        "passwordspray",
        "sql",
        "xss",
        "impossible_travel",
        "insider",
    ):
        assert expected in kinds
    assert stats.has_kind("bruteforce")
    assert stats.has_kind("insider")


def test_attack_scenarios_tag_kinds(tmp_path: Path):
    cases = {
        "bruteforce": "bruteforce",
        "passwordspray": "passwordspray",
        "sql": "sql",
        "xss": "xss",
    }
    for scenario, kind in cases.items():
        _, events, stats = generate_dataset(
            entries=60,
            seed=5,
            scenario=scenario,
            output=tmp_path / f"{scenario}.log",
            quiet=True,
        )
        assert stats.has_kind(kind)
        assert any(e.kind == kind for e in events)


def test_generated_lines_are_parser_compatible(tmp_path: Path):
    path, events, _ = generate_dataset(
        entries=250,
        seed=42,
        scenario="demo",
        output=tmp_path / "parse.log",
        quiet=True,
    )
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 250
    assert all(isinstance(line, str) and line.strip() for line in lines)

    parsed = parse_logs(lines, config=AnalyzerConfig(default_log_year=2026))
    # Generator only emits supported formats — expect near-full parse success.
    assert len(parsed) == 250
    sources = {e.source for e in parsed}
    assert sources <= {"linux", "windows", "apache"}
    assert "linux" in sources and "apache" in sources


def test_bruteforce_scenario_detected(tmp_path: Path):
    path, _, _ = generate_dataset(
        entries=80,
        seed=42,
        scenario="bruteforce",
        output=tmp_path / "bf.log",
        quiet=True,
    )
    result = AnalysisService(
        config=AnalyzerConfig(default_log_year=2026)
    ).analyze_file(path)
    assert any(a.alert_type == "BRUTE_FORCE" for a in result.alerts)


def test_passwordspray_scenario_detected(tmp_path: Path):
    path, _, _ = generate_dataset(
        entries=80,
        seed=42,
        scenario="passwordspray",
        output=tmp_path / "ps.log",
        quiet=True,
    )
    result = AnalysisService(
        config=AnalyzerConfig(default_log_year=2026)
    ).analyze_file(path)
    assert any(a.alert_type == "PASSWORD_SPRAY" for a in result.alerts)


def test_sql_and_xss_scenarios_detected(tmp_path: Path):
    sql_path, _, _ = generate_dataset(
        entries=40, seed=42, scenario="sql", output=tmp_path / "sql.log", quiet=True
    )
    xss_path, _, _ = generate_dataset(
        entries=40, seed=42, scenario="xss", output=tmp_path / "xss.log", quiet=True
    )
    sql_result = AnalysisService(
        config=AnalyzerConfig(default_log_year=2026)
    ).analyze_file(sql_path)
    xss_result = AnalysisService(
        config=AnalyzerConfig(default_log_year=2026)
    ).analyze_file(xss_path)
    assert any(a.alert_type == "SQL_INJECTION" for a in sql_result.alerts)
    assert any(a.alert_type == "XSS" for a in xss_result.alerts)


def test_demo_end_to_end_detections(tmp_path: Path):
    path, _, _ = generate_dataset(
        entries=400,
        seed=42,
        scenario="demo",
        attack_rate=0.12,
        intensity="medium",
        output=tmp_path / "demo_e2e.log",
        quiet=True,
    )
    result = AnalysisService(
        config=AnalyzerConfig(default_log_year=2026)
    ).analyze_file(path)

    types = {a.alert_type for a in result.alerts}
    assert "BRUTE_FORCE" in types
    assert "PASSWORD_SPRAY" in types
    assert "SQL_INJECTION" in types
    assert "XSS" in types
    assert "IMPOSSIBLE_TRAVEL" in types
    assert "INSIDER_THREAT" in types
    assert result.log_count == 400
    assert result.statistics["total_logs"] == 400
    assert len(result.incidents) >= 1
    assert all(0 <= i.risk_score <= 100 for i in result.incidents)


def test_generate_events_direct_api():
    events = generate_events(25, scenario="linux", seed=9)
    assert len(events) == 25
    assert all(e.source == "linux" for e in events)


def test_cli_main_writes_default_style_path(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code = main(
        [
            "--entries",
            "30",
            "--seed",
            "42",
            "--scenario",
            "normal",
            "--output",
            "logs/security.log",
            "--quiet",
        ]
    )
    assert code == 0
    assert (tmp_path / "logs" / "security.log").exists()
    assert DEFAULT_OUTPUT.as_posix() == "logs/security.log"


def test_source_scenarios(tmp_path: Path):
    for scenario, source in (
        ("linux", "linux"),
        ("windows", "windows"),
        ("apache", "apache"),
    ):
        _, events, _ = generate_dataset(
            entries=40,
            seed=3,
            scenario=scenario,
            output=tmp_path / f"{scenario}.log",
            quiet=True,
        )
        assert all(e.source == source for e in events)
