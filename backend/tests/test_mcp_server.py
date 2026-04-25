"""Tests for MCP tool routing."""
import pytest

from backend.app.integrations.mcp_server import MCPServer, ToolError
from backend.app.investigations.store import store


def setup_function():
    store.clear()


class TestMCPServer:
    def test_lists_tools_with_json_schemas(self):
        server = MCPServer()

        tools = server.list_tools()

        assert {tool["name"] for tool in tools} == {
            "investigate_alert",
            "lookup_threat_intel",
            "get_investigation",
        }
        assert all(tool["inputSchema"]["type"] == "object" for tool in tools)

    def test_investigate_persists_report_for_lookup(self):
        server = MCPServer()

        report = server.call_tool("investigate_alert", {
            "source_tool": "CrowdStrike",
            "description": "Mimikatz execution on WORKSTATION-042",
            "process_name": "mimikatz.exe",
        })
        fetched = server.call_tool("get_investigation", {
            "investigation_id": report["id"],
        })

        assert fetched["id"] == report["id"]
        assert fetched["severity"] == "critical"

    def test_unknown_investigation_returns_not_found_error(self):
        server = MCPServer()

        with pytest.raises(ToolError) as exc:
            server.call_tool("get_investigation", {"investigation_id": "missing"})

        assert exc.value.code == "not_found"

    def test_validation_rejects_missing_required_arguments(self):
        server = MCPServer()

        with pytest.raises(ToolError) as exc:
            server.call_tool("lookup_threat_intel", {"indicator_type": "ip"})

        assert exc.value.code == "invalid_arguments"

    def test_safe_call_returns_structured_error(self):
        server = MCPServer()

        result = server.call_tool_safe("does_not_exist", {})

        assert result["error"]["code"] == "tool_not_found"

    def test_threat_intel_unknown_by_default(self):
        server = MCPServer()

        result = server.call_tool("lookup_threat_intel", {
            "indicator": "example.com",
            "indicator_type": "domain",
        })

        assert result["overall"] == "unknown"
