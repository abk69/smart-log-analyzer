"""JSON security report writer."""

from __future__ import annotations

import json
from pathlib import Path

from analyzer.exceptions import ReportGenerationError
from analyzer.models import AnalysisResult
from analyzer.reporting.serialize import build_report_document


def write_json_report(result: AnalysisResult, output_dir: Path) -> Path:
    """Write ``security_report.json`` and return the output path."""
    output_dir = Path(output_dir)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / "security_report.json"
        document = build_report_document(result)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, ensure_ascii=False)
        return path
    except OSError as exc:
        raise ReportGenerationError(f"Unable to write JSON report: {exc}") from exc
