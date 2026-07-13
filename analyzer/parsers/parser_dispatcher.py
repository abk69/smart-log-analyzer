from analyzer.parsers.linux_parser import parse_linux_logs
from analyzer.parsers.windows_parser import parse_windows_logs
from analyzer.parsers.apache_parser import parse_apache_logs

def parse_logs(lines):
 l=lines[0] if lines else ''

 if 'sshd[' in l:return parse_linux_logs(lines)
 if 'EVENT_ID=' in l:return parse_windows_logs(lines)
 if 'HTTP/1.1' in l:return parse_apache_logs(lines)
 return []