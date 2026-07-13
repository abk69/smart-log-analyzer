from dataclasses import dataclass
from datetime import datetime
@dataclass
class LogEntry:
 timestamp:datetime
 username:str
 ip_address:str
 status:str
