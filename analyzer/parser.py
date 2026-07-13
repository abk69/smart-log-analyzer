from pathlib import Path

def read_log_file(path):
 p=Path(path)
 return [l.strip() for l in p.open() if l.strip()]
