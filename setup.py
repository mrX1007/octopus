"""Setuptools build customizations for top-level runtime data."""

from __future__ import annotations

import os

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py


class BuildPyWithConfig(_build_py):
    """Install the shipped configuration beside the top-level config module."""

    def run(self) -> None:
        super().run()
        self.copy_file("config.yaml", os.path.join(self.build_lib, "config.yaml"))

    def get_outputs(self, include_bytecode: bool = True) -> list[str]:
        outputs = super().get_outputs(include_bytecode=include_bytecode)
        outputs.append(os.path.join(self.build_lib, "config.yaml"))
        return outputs


setup(cmdclass={"build_py": BuildPyWithConfig})
