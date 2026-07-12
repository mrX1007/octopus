#!/usr/bin/env python3

from collections.abc import Iterable
from typing import Optional

from .ad import ADParser
from .api import APIParser
from .asm import ASMParser
from .cloud import CloudParser
from .code import CodeParser
from .common import BaseParser, Fact
from .msf import MSFParser
from .network import NetworkGraphParser
from .nmap import NmapParser
from .plugin import PluginParser
from .secrets import SecretsParser
from .ssh import SSHParser
from .template import TemplateParser
from .web import WebParser


class ParserFamilyPipeline:
    def __init__(self, parsers: Optional[Iterable[BaseParser]] = None):
        self.parsers = list(parsers or [
            NmapParser(),
            WebParser(),
            SSHParser(),
            MSFParser(),
            PluginParser(),
            TemplateParser(),
            NetworkGraphParser(),
            ASMParser(),
            APIParser(),
            ADParser(),
            CloudParser(),
            SecretsParser(),
            CodeParser(),
        ])

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> list[Fact]:
        facts: list[Fact] = []
        for parser in self.parsers:
            facts.extend(parser.parse(tool_name, raw_output, session_id))
        return facts
