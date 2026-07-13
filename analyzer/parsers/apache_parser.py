def parse_apache_line(line):

    if "HTTP/1.1" not in line:
        return None

    return None