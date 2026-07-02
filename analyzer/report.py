import csv
import json
from pathlib import Path


def generate_csv_report(stats: dict, alerts: list):

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    file_path = reports_dir / "security_report.csv"

    with open(file_path, "w", newline="", encoding="utf-8") as file:

        writer = csv.writer(file)

        writer.writerow(["Metric", "Value"])

        for key, value in stats.items():
            writer.writerow([key, value])

        writer.writerow([])
        writer.writerow(["Security Alerts"])

        if alerts:
            writer.writerow(["Username", "IP Address", "Attempts", "Window"])

            for alert in alerts:
                writer.writerow([
                    alert["username"],
                    alert["ip_address"],
                    alert["attempts"],
                    alert["window"],
                ])

def generate_json_report(stats: dict, alerts: list):

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    file_path = reports_dir / "security_report.json"

    report = {
        "statistics": stats,
        "alerts": alerts,
    }

    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, default=str)