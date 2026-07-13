import argparse
from analyzer.parser import read_log_file
from analyzer.parsers.parser_dispatcher import parse_logs
p=argparse.ArgumentParser();p.add_argument('logfile');a=p.parse_args();print(len(parse_logs(read_log_file(a.logfile))))