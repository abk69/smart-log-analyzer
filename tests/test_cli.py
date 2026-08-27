"""Tests for the CLI entry point."""

from pathlib import Path

from main import EXIT_APP_ERROR, EXIT_OK, EXIT_USAGE, main


def test_cli_success(tmp_path: Path, capsys):
    log = tmp_path / "sample.log"
    log.write_text(
        "Jun 26 09:01:20 server sshd[1014]: "
        "Accepted password for alice from 192.168.1.18 port 46945 ssh2\n",
        encoding="utf-8",
    )
    code = main([str(log), "--no-color", "--quiet"])
    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert "SMART LOG ANALYZER" in captured.out
    assert "PARSING" in captured.out
    assert "Analysis Complete" in captured.out


def test_cli_missing_file(capsys):
    code = main(["logs/does_not_exist_m7.log", "--no-color"])
    captured = capsys.readouterr()
    assert code == EXIT_APP_ERROR
    assert "Error:" in captured.err


def test_cli_verbose_quiet_conflict(capsys):
    code = main(["logs/security.log", "--verbose", "--quiet"])
    assert code == EXIT_USAGE
    assert "cannot be used together" in capsys.readouterr().err


def test_cli_report_all(tmp_path: Path, capsys):
    log = tmp_path / "sample.log"
    log.write_text(
        "Jun 26 09:02:01 server sshd[1020]: Failed password for admin from 203.0.113.10 port 53769 ssh2\n"
        "Jun 26 09:02:07 server sshd[1021]: Failed password for admin from 203.0.113.10 port 50490 ssh2\n"
        "Jun 26 09:02:11 server sshd[1022]: Failed password for admin from 203.0.113.10 port 59221 ssh2\n"
        "Jun 26 09:02:15 server sshd[1023]: Failed password for admin from 203.0.113.10 port 52800 ssh2\n"
        "Jun 26 09:02:21 server sshd[1024]: Failed password for admin from 203.0.113.10 port 42959 ssh2\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "out"
    code = main(
        [str(log), "--no-color", "--quiet", "--report", "all", "--output", str(out_dir)]
    )
    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert "REPORTS" in captured.out
    assert (out_dir / "security_report.json").exists()
    assert (out_dir / "security_alerts.csv").exists()
    assert (out_dir / "security_incidents.csv").exists()
    assert (out_dir / "security_report.html").exists()
    assert (out_dir / "summary.txt").exists()


def test_cli_empty_file(tmp_path: Path, capsys):
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    code = main([str(empty), "--no-color", "--quiet"])
    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert "Total Events      : 0" in captured.out
    assert "Total Alerts      : 0" in captured.out
    assert "Total Incidents   : 0" in captured.out


def test_cli_alerts_still_exit_zero(tmp_path: Path):
    """Security findings must not cause a non-zero exit code."""
    log = tmp_path / "threats.log"
    log.write_text(
        "\n".join(
            [
                "Jun 26 09:02:01 server sshd[1020]: Failed password for admin from 203.0.113.10 port 53769 ssh2",
                "Jun 26 09:02:07 server sshd[1021]: Failed password for admin from 203.0.113.10 port 50490 ssh2",
                "Jun 26 09:02:11 server sshd[1022]: Failed password for admin from 203.0.113.10 port 59221 ssh2",
                "Jun 26 09:02:15 server sshd[1023]: Failed password for admin from 203.0.113.10 port 52800 ssh2",
                "Jun 26 09:02:21 server sshd[1024]: Failed password for admin from 203.0.113.10 port 42959 ssh2",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    code = main([str(log), "--no-color", "--quiet"])
    assert code == EXIT_OK


def test_cli_verbose(tmp_path: Path):
    log = tmp_path / "sample.log"
    log.write_text(
        "Jun 26 09:01:20 server sshd[1014]: "
        "Accepted password for alice from 192.168.1.18 port 46945 ssh2\n",
        encoding="utf-8",
    )
    assert main([str(log), "--verbose", "--no-color"]) == EXIT_OK


def test_cli_no_color(tmp_path: Path, capsys):
    log = tmp_path / "sample.log"
    log.write_text(
        "Jun 26 09:01:20 server sshd[1014]: "
        "Accepted password for alice from 192.168.1.18 port 46945 ssh2\n",
        encoding="utf-8",
    )
    code = main([str(log), "--no-color"])
    assert code == EXIT_OK
    assert "\033[" not in capsys.readouterr().out


def test_cli_unknown_report_format():
    code = main(["logs/security.log", "--report", "xml"])
    assert code == EXIT_USAGE


def test_cli_invalid_arguments():
    assert main([]) == EXIT_USAGE
    assert main(["--no-color"]) == EXIT_USAGE


def test_cli_invalid_output_directory(tmp_path: Path, capsys):
    log = tmp_path / "sample.log"
    log.write_text(
        "Jun 26 09:01:20 server sshd[1014]: "
        "Accepted password for alice from 192.168.1.18 port 46945 ssh2\n",
        encoding="utf-8",
    )
    blocked = tmp_path / "blocked_as_file"
    blocked.write_text("not a directory", encoding="utf-8")
    code = main(
        [str(log), "--no-color", "--quiet", "--report", "json", "--output", str(blocked)]
    )
    assert code == EXIT_APP_ERROR
    assert "Report error:" in capsys.readouterr().err


def test_cli_empty_file_with_reports(tmp_path: Path):
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    out = tmp_path / "reports"
    code = main(
        [str(empty), "--no-color", "--quiet", "--report", "all", "--output", str(out)]
    )
    assert code == EXIT_OK
    assert (out / "security_report.json").exists()
    assert (out / "security_report.html").exists()
    assert (out / "summary.txt").exists()
