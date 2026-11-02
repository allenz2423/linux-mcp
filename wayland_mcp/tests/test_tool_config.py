from __future__ import annotations

import asyncio
import inspect
from typing import get_args, get_type_hints

import pytest
from mcp.server.elicitation import render_elicitation_schema

from wayland_mcp import server as server_module
from wayland_mcp.server import _parse_startup_selection, create_server
from wayland_mcp.tool_config import TOOL_CATEGORIES, TOOL_CATEGORY_MEMBERSHIPS, ToolSelection


def _registered_names(selection: ToolSelection | None = None) -> set[str]:
    tools = asyncio.run(create_server(selection or ToolSelection()).list_tools())
    return {tool.name for tool in tools}


def test_category_catalog_covers_every_registered_tool() -> None:
    assert _registered_names() == set(TOOL_CATEGORIES)


def test_disabling_networking_omits_network_tools_and_allows_tool_override() -> None:
    selection = ToolSelection(disabled_categories=frozenset({"networking"}))
    disabled = _registered_names(selection)
    network_tools = {
        name for name, memberships in TOOL_CATEGORY_MEMBERSHIPS.items() if "networking" in memberships
    }
    assert not (disabled & network_tools)
    assert "create_systemd_netdev_profile" not in disabled
    assert "run_shell_command" not in disabled

    with_exception = ToolSelection(
        disabled_categories=frozenset({"networking"}),
        enabled_tools=frozenset({"list_network_interfaces", "create_systemd_netdev_profile"}),
    )
    assert {"list_network_interfaces", "create_systemd_netdev_profile"} <= _registered_names(with_exception)


def test_individual_tool_can_be_disabled() -> None:
    selected = _registered_names(
        ToolSelection(disabled_tools=frozenset({"get_dns_configuration"}))
    )
    assert "get_dns_configuration" not in selected
    assert len(selected) == len(TOOL_CATEGORIES) - 1


def test_environment_and_cli_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LINUX_MCP_DISABLE_CATEGORIES", "networking")
    monkeypatch.setenv("LINUX_MCP_DISABLE_TOOLS", "list_processes")
    selection = _parse_startup_selection(["--enable-tool", "get_dns_configuration"])
    names = _registered_names(selection)
    assert "get_dns_configuration" in names
    assert "list_network_interfaces" not in names
    assert "list_processes" not in names


def test_unknown_category_or_tool_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unknown tool category"):
        ToolSelection(disabled_categories=frozenset({"network"}))
    with pytest.raises(ValueError, match="Unknown tool name"):
        ToolSelection(disabled_tools=frozenset({"not_a_real_tool"}))


def test_binary_upload_schema_matches_runtime_limit() -> None:
    from wayland_mcp.tools.filesystem_uploads import MAX_BINARY_UPLOAD_BYTES

    tools = asyncio.run(create_server().list_tools())
    upload = next(tool for tool in tools if tool.name == "begin_binary_file_upload")
    append = next(tool for tool in tools if tool.name == "append_binary_file_upload")

    assert upload.input_schema["properties"]["expected_size"]["maximum"] == MAX_BINARY_UPLOAD_BYTES
    assert append.input_schema["properties"]["offset"]["maximum"] == MAX_BINARY_UPLOAD_BYTES


def test_python_environment_create_confirmation_accepts_empty_optional_fields() -> None:
    from wayland_mcp.models import PythonEnvironmentActionConfirmation

    confirmation = PythonEnvironmentActionConfirmation.model_validate(
        {
            "confirm": True,
            "action": "create",
            "environment_name": "live-check",
            "package_name": "",
            "version": "",
            "expected_state_token": "0" * 64,
        }
    )

    assert confirmation.package_name == ""
    assert confirmation.version == ""


def test_all_confirmation_models_render_supported_mcp_elicitation_schemas() -> None:
    confirmation_models = set()
    for name, function in vars(server_module).items():
        if not name.startswith("_confirm_") or not inspect.isfunction(function):
            continue
        return_annotation = get_type_hints(function).get("return")
        model_arguments = get_args(return_annotation)
        assert len(model_arguments) == 1, f"{name} must return one typed elicitation model"
        confirmation_models.add(model_arguments[0])

    assert len(confirmation_models) >= 100
    for model in confirmation_models:
        render_elicitation_schema(model)
