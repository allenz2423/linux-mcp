from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from wayland_mcp.tools import luks_tokens
from wayland_mcp.tools.luks_tokens import LUKSTokenState, TokenRecord


TEST_UUID = "72cd7396-9a68-4a97-8baf-d8c315f2cd6a"


def test_parse_metadata_reads_bound_token_from_luks2_json() -> None:
    metadata = {
        "keyslots": {"0": {"type": "luks2"}},
        "tokens": {
            "7": {
                "type": "mcp-audit-test",
                "keyslots": ["0"],
                "provider_secret": "must-not-be-returned",
            },
        },
        "segments": {"0": {"type": "crypt"}},
    }

    state, error = luks_tokens._parse_metadata(json.dumps(metadata), TEST_UUID)

    assert error is None
    assert state is not None
    assert state.active_keyslots == (0,)
    assert len(state.tokens) == 1
    assert state.tokens[0].token_id == 7
    assert state.tokens[0].token_type == "mcp-audit-test"
    assert state.tokens[0].keyslots == (0,)


def test_parse_metadata_accepts_an_unassigned_token() -> None:
    state, error = luks_tokens._parse_metadata(
        json.dumps({"keyslots": {"0": {}}, "tokens": {"7": {"type": "mcp-audit-test", "keyslots": []}}}),
        TEST_UUID,
    )

    assert error is None
    assert state is not None
    assert state.tokens[0].keyslots == ()


def test_parse_metadata_rejects_duplicate_keys_and_inactive_bindings() -> None:
    duplicate_keys, duplicate_error = luks_tokens._parse_metadata(
        '{"keyslots":{},"tokens":{},"tokens":{}}', TEST_UUID,
    )
    inactive_binding, binding_error = luks_tokens._parse_metadata(
        json.dumps({"keyslots": {"0": {}}, "tokens": {"7": {"type": "test", "keyslots": ["1"]}}}),
        TEST_UUID,
    )

    assert duplicate_keys is None
    assert duplicate_error is not None
    assert inactive_binding is None
    assert binding_error is not None


def test_list_luks_tokens_returns_bounded_type_without_provider_payload(monkeypatch) -> None:
    state = LUKSTokenState(
        luks_uuid=TEST_UUID,
        active_keyslots=(0,),
        tokens=(TokenRecord(7, "provider\nsecret", (0,), "a" * 64),),
        metadata_digest="b" * 64,
        keyslots_digest="c" * 64,
        other_metadata_digest="d" * 64,
    )
    monkeypatch.setattr(
        luks_tokens,
        "_resolve_block_device",
        lambda path: (Path(path), SimpleNamespace(), None),
    )
    monkeypatch.setattr(luks_tokens, "find_session_binary", lambda *_args: "/usr/bin/cryptsetup")
    monkeypatch.setattr(luks_tokens, "_read_luks2_state", lambda *_args: (state, None))

    result = luks_tokens.list_luks_tokens("/dev/test-luks")
    serialized = json.dumps(result.model_dump())

    assert result.success
    assert result.active_keyslots == [0]
    assert result.tokens[0].token_type == r"provider\nsecret"
    assert result.tokens[0].keyslots == [0]
    assert "provider\nsecret" not in serialized
    assert "must-not-be-returned" not in serialized
