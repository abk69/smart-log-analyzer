"""Tests for the base parser contract."""

from analyzer.parsers.apache_parser import ApacheParser
from analyzer.parsers.base_parser import BaseParser
from analyzer.parsers.linux_parser import LinuxParser
from analyzer.parsers.windows_parser import WindowsParser


def test_base_parser_is_abstract():
    assert issubclass(BaseParser, object)
    assert hasattr(BaseParser, "can_parse")
    assert hasattr(BaseParser, "parse_line")


def test_concrete_parsers_satisfy_contract():
    parsers = [LinuxParser(year=2026), WindowsParser(), ApacheParser()]
    for parser in parsers:
        assert isinstance(parser, BaseParser)
        assert callable(parser.can_parse)
        assert callable(parser.parse_line)
