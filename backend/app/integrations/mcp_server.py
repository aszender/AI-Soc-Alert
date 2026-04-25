"""MCP tools for the AI SOC Alert service.

The module exposes two layers:
- ``MCPToolRouter``: testable, SDK-independent tool listing/call handling.
- ``create_fastmcp_server``: real MCP runtime wiring using FastMCP when the
  optional ``mcp`` package is installed.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..governance import audit
from ..investigations.service import InvestigationService, service
from ..models import Alert


class ToolError(Exception):
    def __init__(self, code: str, message: str, details: Any | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details is not None:
            payload["details"] = self.details
        return payload


class InvestigateAlertArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_tool: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=10000)
    alert_type: str = Field(default="", max_length=100)
    source_ip: str | None = Field(default=None, max_length=128)
    destination_ip: str | None = Field(default=None, max_length=128)
    hostname: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    process_name: str | None = Field(default=None, max_length=255)
    raw_event: dict[str, Any] = Field(default_factory=dict)


class LookupThreatIntelArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator: str = Field(min_length=1, max_length=512)
    indicator_type: Literal["ip", "hash", "domain"]


class GetInvestigationArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    investigation_id: str = Field(min_length=1, max_length=64)


class ThreatIntelProvider:
    """Threat intel provider interface.

    Deployments can inject a provider backed by VirusTotal, AbuseIPDB, MISP,
    a commercial TIP, or an internal intelligence service.
    """

    def lookup(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        raise NotImplementedError


class FixtureThreatIntelProvider(ThreatIntelProvider):
    _known: dict[tuple[str, str], dict[str, Any]] = {
        ("45.33.32.156", "ip"): {
            "sources": [
                {
                    "source": "VirusTotal",
                    "is_malicious": True,
                    "confidence": 0.91,
                    "details": "Flagged by 12/90 vendors",
                },
                {
                    "source": "AbuseIPDB",
                    "is_malicious": True,
                    "confidence": 0.87,
                    "details": "Reported for SSH brute force activity",
                },
            ],
            "overall": "malicious",
        }
    }

    def lookup(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        result = self._known.get((indicator, indicator_type))
        if result is None:
            result = {
                "sources": [],
                "overall": "unknown",
                "note": "No fixture threat intel match. Configure an external provider for enrichment.",
            }
        return {"indicator": indicator, "type": indicator_type, **result}


class MCPToolRouter:
    def __init__(
        self,
        investigation_service: InvestigationService = service,
        threat_intel: ThreatIntelProvider | None = None,
    ):
        self.name = "soc-investigator"
        self.version = "1.0.0"
        self.investigation_service = investigation_service
        self.threat_intel = threat_intel or FixtureThreatIntelProvider()
        self._tools: dict[str, tuple[type[BaseModel], Any, str]] = {
            "investigate_alert": (
                InvestigateAlertArgs,
                self._handle_investigate,
                "Run an AI-powered investigation on a security alert",
            ),
            "lookup_threat_intel": (
                LookupThreatIntelArgs,
                self._handle_threat_intel,
                "Check whether an IP, hash, or domain is known malicious",
            ),
            "get_investigation": (
                GetInvestigationArgs,
                self._handle_get_investigation,
                "Retrieve a completed investigation report by ID",
            ),
        }

    def list_tools(self) -> list[dict[str, Any]]:
        tools = []
        for name, (model, _handler, description) in self._tools.items():
            tools.append({
                "name": name,
                "description": description,
                "inputSchema": model.model_json_schema(),
            })
        return tools

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        tool = self._tools.get(tool_name)
        if tool is None:
            raise ToolError("tool_not_found", f"Unknown tool: {tool_name}")

        model, handler, _description = tool
        try:
            parsed = model.model_validate(arguments)
        except ValidationError as exc:
            raise ToolError("invalid_arguments", "Tool arguments failed validation", exc.errors()) from exc

        try:
            audit.log_action("mcp", f"call_{tool_name}", {"arguments": parsed.model_dump(exclude_none=True)})
            return handler(parsed)
        except ToolError:
            raise
        except Exception as exc:
            raise ToolError("tool_execution_failed", str(exc)) from exc

    def call_tool_safe(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        try:
            return self.call_tool(tool_name, arguments)
        except ToolError as exc:
            audit.log_action("mcp", "tool_error", {"tool": tool_name, **exc.to_dict()})
            return {"error": exc.to_dict()}

    def get_server_info(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "tools_count": len(self._tools),
            "runtime": "FastMCP",
        }

    def _handle_investigate(self, args: InvestigateAlertArgs) -> dict[str, Any]:
        alert = Alert(**args.model_dump())
        report = self.investigation_service.investigate(alert)
        return report.model_dump()

    def _handle_threat_intel(self, args: LookupThreatIntelArgs) -> dict[str, Any]:
        return self.threat_intel.lookup(args.indicator, args.indicator_type)

    def _handle_get_investigation(self, args: GetInvestigationArgs) -> dict[str, Any]:
        report = self.investigation_service.get(args.investigation_id)
        if report is None:
            raise ToolError("not_found", f"Investigation not found: {args.investigation_id}")
        return report.model_dump()


class MCPServer(MCPToolRouter):
    """Backward-compatible name for tests and local direct calls."""


def create_fastmcp_server(router: MCPToolRouter | None = None):
    """Create the real MCP server.

    The import is local so unit tests and FastAPI deployments do not require the
    MCP runtime unless this entrypoint is used.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError("Install the 'mcp' package to run the MCP server runtime.") from exc

    tool_router = router or MCPToolRouter()
    mcp = FastMCP(tool_router.name)

    @mcp.tool()
    def investigate_alert(
        source_tool: str,
        description: str,
        alert_type: str = "",
        source_ip: str | None = None,
        destination_ip: str | None = None,
        hostname: str | None = None,
        username: str | None = None,
        process_name: str | None = None,
        raw_event: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run an AI-powered investigation on a security alert."""
        return tool_router.call_tool(
            "investigate_alert",
            {
                "source_tool": source_tool,
                "description": description,
                "alert_type": alert_type,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "hostname": hostname,
                "username": username,
                "process_name": process_name,
                "raw_event": raw_event or {},
            },
        )

    @mcp.tool()
    def lookup_threat_intel(indicator: str, indicator_type: Literal["ip", "hash", "domain"]) -> dict[str, Any]:
        """Check whether an IP, hash, or domain is known malicious."""
        return tool_router.call_tool(
            "lookup_threat_intel",
            {"indicator": indicator, "indicator_type": indicator_type},
        )

    @mcp.tool()
    def get_investigation(investigation_id: str) -> dict[str, Any]:
        """Retrieve a completed investigation report by ID."""
        return tool_router.call_tool("get_investigation", {"investigation_id": investigation_id})

    return mcp


def main() -> None:
    create_fastmcp_server().run()


if __name__ == "__main__":
    main()
