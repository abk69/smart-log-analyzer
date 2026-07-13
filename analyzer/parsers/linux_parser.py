import re
from datetime import datetime
from analyzer.models import LogEntry
pat=re.compile(r'^(?P<t>\w+\s+\d+\s+\d+:\d+:\d+).*?(?P<s>Accepted|Failed) password for (?P<u>\w+) from (?P<i>\d+\.\d+\.\d+\.\d+)')
def parse_linux_logs(lines):
 o=[]

 for line in lines:
  m=pat.search(line)
  if m:o.append(LogEntry(datetime.strptime('2026 '+m.group('t'),'%Y %b %d %H:%M:%S'),m.group('u'),m.group('i'),'SUCCESS' if m.group('s')=='Accepted' else 'FAILED'))
 return o
