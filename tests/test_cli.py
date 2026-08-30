"""Tests for CLI commands."""

import pytest
from click.testing import CliRunner
from docker_monitor.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


class TestCLI:
    def test_help(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Docker Monitor" in result.output

    def test_status(self, runner, tmp_config):
        result = runner.invoke(cli, ["--config", str(tmp_config), "status"])
        assert result.exit_code == 0
        assert "Tool Status" in result.output

    def test_audit_help(self, runner):
        result = runner.invoke(cli, ["audit", "--help"])
        assert result.exit_code == 0

    def test_monitor_help(self, runner):
        result = runner.invoke(cli, ["monitor", "--help"])
        assert result.exit_code == 0

    def test_report_help(self, runner):
        result = runner.invoke(cli, ["report", "--help"])
        assert result.exit_code == 0
