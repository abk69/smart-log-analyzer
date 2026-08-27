"""End-to-end analysis orchestration service."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from analyzer.config import AnalyzerConfig, DEFAULT_CONFIG
from analyzer.correlation import correlate_alerts
from analyzer.detectors.brute_force import detect_brute_force
from analyzer.detectors.impossible_travel import detect_impossible_travel
from analyzer.detectors.insider_threat import detect_insider_threat
from analyzer.detectors.password_spray import detect_password_spray
from analyzer.detectors.sql_injection import detect_sql_injection
from analyzer.detectors.xss import detect_xss
from analyzer.models import AnalysisResult, LogEntry, SecurityAlert
from analyzer.parser import read_log_file
from analyzer.parsers.parser_dispatcher import ParseStats, parse_logs_with_stats
from analyzer.risk import score_incidents
from analyzer.statistics import generate_statistics
from analyzer.utils import get_logger

logger = get_logger("services.analysis")

DetectorFn = Callable[[list[LogEntry]], list[SecurityAlert]]
ParseFn = Callable[..., tuple[list[LogEntry], ParseStats]]
CorrelateFn = Callable[..., list]
ScoreFn = Callable[..., list]
StatsFn = Callable[[list[LogEntry]], dict[str, Any]]
ReadFn = Callable[[str | Path], list[str]]


@dataclass(frozen=True)
class DetectorSpec:
    """Named detector with a config enablement check."""

    name: str
    detect: DetectorFn
    is_enabled: Callable[[AnalyzerConfig], bool]


def _default_detectors() -> list[DetectorSpec]:
    return [
        DetectorSpec(
            "brute_force",
            detect_brute_force,
            lambda c: c.brute_force.enabled,
        ),
        DetectorSpec(
            "password_spray",
            detect_password_spray,
            lambda c: c.password_spray.enabled,
        ),
        DetectorSpec(
            "sql_injection",
            detect_sql_injection,
            lambda c: c.sql_injection.enabled,
        ),
        DetectorSpec(
            "xss",
            detect_xss,
            lambda c: c.xss.enabled,
        ),
        DetectorSpec(
            "impossible_travel",
            detect_impossible_travel,
            lambda c: c.impossible_travel.enabled,
        ),
        DetectorSpec(
            "insider_threat",
            detect_insider_threat,
            lambda c: c.insider_threat.enabled,
        ),
    ]


def _evidence_key(evidence: Any) -> str:
    try:
        return json.dumps(evidence, sort_keys=True, default=str)
    except TypeError:
        return repr(evidence)


def deduplicate_alerts(alerts: Sequence[SecurityAlert]) -> list[SecurityAlert]:
    """Remove exact duplicate alerts; leave distinct findings intact."""
    seen: set[tuple] = set()
    unique: list[SecurityAlert] = []
    for alert in alerts:
        key = (
            alert.alert_type,
            alert.timestamp.isoformat() if alert.timestamp else "",
            alert.ip_address,
            alert.username,
            _evidence_key(alert.evidence),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(alert)
    return unique


class AnalysisService:
    """Coordinate parse → statistics → detect → correlate → risk."""

    def __init__(
        self,
        config: AnalyzerConfig | None = None,
        *,
        read_file: ReadFn = read_log_file,
        parse_logs: ParseFn = parse_logs_with_stats,
        statistics_fn: StatsFn = generate_statistics,
        detectors: Sequence[DetectorSpec] | None = None,
        correlate_fn: CorrelateFn = correlate_alerts,
        score_fn: ScoreFn = score_incidents,
    ) -> None:
        self.config = config if config is not None else DEFAULT_CONFIG
        self._read_file = read_file
        self._parse_logs = parse_logs
        self._statistics_fn = statistics_fn
        self._detectors = list(detectors) if detectors is not None else _default_detectors()
        self._correlate_fn = correlate_fn
        self._score_fn = score_fn

    def analyze_file(self, path: str | Path) -> AnalysisResult:
        """Analyze a security log file and return a structured result."""
        started = time.perf_counter()
        analyzed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        file_path = Path(path)

        logger.info("Reading log file: %s", file_path)
        lines = self._read_file(file_path)
        if not lines:
            logger.info("Log file is empty: %s", file_path)

        logger.info("Parsing log lines")
        entries, parse_stats = self._parse_logs(lines, config=self.config)
        logger.info(
            "Parsed %s events (malformed=%s unsupported=%s)",
            parse_stats.parsed_lines,
            parse_stats.malformed_lines,
            parse_stats.unsupported_lines,
        )

        statistics = self._statistics_fn(entries)

        alerts: list[SecurityAlert] = []
        logger.info("Running detectors")
        for spec in self._detectors:
            if not spec.is_enabled(self.config):
                logger.info("Skipping disabled detector: %s", spec.name)
                continue
            # Pass AnalyzerConfig so detectors honor nested settings.
            found = spec.detect(entries, self.config)  # type: ignore[call-arg]
            logger.info("Detector %s produced %s alert(s)", spec.name, len(found))
            alerts.extend(found)

        alerts = deduplicate_alerts(alerts)
        logger.info("Collected %s unique alert(s)", len(alerts))

        incidents = self._correlate_fn(alerts, config=self.config)
        incidents = self._score_fn(incidents, config=self.config)
        logger.info(
            "Correlated %s alerts into %s incident(s)",
            len(alerts),
            len(incidents),
        )

        duration = time.perf_counter() - started
        return AnalysisResult(
            input_file=str(file_path),
            analyzed_at=analyzed_at,
            duration_seconds=duration,
            log_count=len(entries),
            parse_stats=parse_stats.as_dict(),
            statistics=statistics,
            alerts=alerts,
            incidents=incidents,
            logs=entries,
        )

    def analyze_lines(self, lines: list[str], *, input_file: str = "<memory>") -> AnalysisResult:
        """Analyze in-memory log lines (useful for tests)."""
        started = time.perf_counter()
        analyzed_at = datetime.now(timezone.utc).replace(tzinfo=None)

        entries, parse_stats = self._parse_logs(lines, config=self.config)
        statistics = self._statistics_fn(entries)

        alerts: list[SecurityAlert] = []
        for spec in self._detectors:
            if not spec.is_enabled(self.config):
                continue
            found = spec.detect(entries, self.config)  # type: ignore[call-arg]
            alerts.extend(found)

        alerts = deduplicate_alerts(alerts)
        incidents = self._score_fn(
            self._correlate_fn(alerts, config=self.config),
            config=self.config,
        )
        return AnalysisResult(
            input_file=input_file,
            analyzed_at=analyzed_at,
            duration_seconds=time.perf_counter() - started,
            log_count=len(entries),
            parse_stats=parse_stats.as_dict(),
            statistics=statistics,
            alerts=alerts,
            incidents=incidents,
            logs=entries,
        )
