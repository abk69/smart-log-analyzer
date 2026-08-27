"""Shared fixtures/helpers for reporting tests."""

from datetime import datetime

from analyzer.config import AnalyzerConfig
from analyzer.models import AnalysisResult
from analyzer.services.analysis_service import AnalysisService


SAMPLE_LINES = [
    "Jun 26 09:02:01 server sshd[1020]: Failed password for admin from 203.0.113.10 port 53769 ssh2",
    "Jun 26 09:02:07 server sshd[1021]: Failed password for admin from 203.0.113.10 port 50490 ssh2",
    "Jun 26 09:02:11 server sshd[1022]: Failed password for admin from 203.0.113.10 port 59221 ssh2",
    "Jun 26 09:02:15 server sshd[1023]: Failed password for admin from 203.0.113.10 port 52800 ssh2",
    "Jun 26 09:02:21 server sshd[1024]: Failed password for admin from 203.0.113.10 port 42959 ssh2",
    (
        '172.16.1.11 - - [26/Jun/2026:09:03:05 +0000] '
        '"GET /login?id=1 UNION SELECT username,password FROM users HTTP/1.1" 500 777'
    ),
    (
        '172.16.1.16 - - [26/Jun/2026:09:01:04 +0000] '
        '"GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 266'
    ),
]


def sample_result() -> AnalysisResult:
    service = AnalysisService(config=AnalyzerConfig(default_log_year=2026))
    return service.analyze_lines(SAMPLE_LINES, input_file="fixture.log")
