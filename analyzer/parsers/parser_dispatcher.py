from analyzer.parsers.linux_parser import parse_linux_line
from analyzer.parsers.windows_parser import parse_windows_line
from analyzer.parsers.apache_parser import parse_apache_line


PARSERS = [
    parse_linux_line,
    parse_windows_line,
    parse_apache_line,
]


def parse_logs(log_lines):

    parsed_logs = []

    for line in log_lines:

        for parser in PARSERS:

            result = parser(line)

            if result:

                parsed_logs.append(result)

                break

    return parsed_logs