from pathlib import Path


def read_log_file(file_path: str) -> list[str]:
    """
    Reads a log file and returns all lines without newline characters.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file '{file_path}' not found.")

    with path.open("r", encoding="utf-8") as file:
        return [line.strip() for line in file if line.strip()]