from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace


CLIENT_PATH = Path(__file__).resolve().parents[2] / "live_acceptance_client.py"
SPEC = importlib.util.spec_from_file_location("linux_mcp_live_acceptance", CLIENT_PATH)
assert SPEC and SPEC.loader
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)


def test_empty_model_response_is_recovered_and_never_counted_as_success():
    text, tool_calls, finish_reason = client.parse_model_turn(
        {"choices": [{"message": {"content": None, "tool_calls": []}, "finish_reason": "stop"}]}
    )

    assert text == ""
    assert tool_calls == []
    assert finish_reason == "stop"
    assert client.should_recover_empty_turn(text, tool_calls, retries_used=0, retry_limit=1)
    assert not client.should_recover_empty_turn(text, tool_calls, retries_used=1, retry_limit=1)


def test_mcp_structured_result_uses_python_sdk_snake_case_field():
    result = SimpleNamespace(structured_content={"success": True, "window": {"id": "42"}})

    assert client.structured_result(result) == {"success": True, "window": {"id": "42"}}


def test_focus_confirmation_requires_exact_focused_browser_window():
    response = {
        "success": True,
        "window": {"id": "0xabc", "app_id": "microsoft-edge", "is_focused": True},
    }

    assert client.exact_browser_focus(response, "0xabc")
    assert not client.exact_browser_focus(response, "0xdef")
    assert not client.exact_browser_focus(
        {**response, "window": {**response["window"], "is_focused": False}}, "0xabc"
    )
    assert not client.exact_browser_focus(
        {**response, "window": {**response["window"], "app_id": "terminal"}}, "0xabc"
    )


def test_youtube_video_title_requires_a_youtube_site_suffix():
    assert client.is_youtube_video_title(
        "3D-printed refrigerator - YouTube - Microsoft Edge"
    )
    assert not client.is_youtube_video_title(
        "Your task is to open YouTube and click a video - Bing Search"
    )
    assert not client.is_youtube_video_title("YouTube - Microsoft Edge")


def test_keyboard_aliases_normalize_only_to_bounded_canonical_forms():
    assert client.normalize_keyboard_args({"action": "press", "key": "ctrl+t"}) == {
        "action": "press_key",
        "key": "Ctrl+T",
    }
    assert client.normalize_keyboard_args({"action": "press_key", "key": "ctrl+w"}) == {
        "action": "press_key",
        "key": "ctrl+w",
    }
    assert client.normalize_keyboard_args({"action": "key", "key": "ctrl+t"}) == {
        "action": "press_key",
        "key": "Ctrl+T",
    }
    assert client.normalize_keyboard_args({"action": "type", "text": "youtube.com"}) == {
        "action": "type_text",
        "text": "youtube.com",
    }


def test_new_permission_requires_reobservation_without_classifying_grant_as_denial():
    assert client.classify_input_failure(
        "Keyboard permission was just granted; capture a fresh screenshot and retry before sending input."
    ) == ("permission_granted_reobserve", False, True)
    assert client.classify_input_failure(
        "The desktop portal rejected the request. The user denied permission."
    ) == ("portal_permission_failure", True, False)
    assert client.INPUT_TOOL_TIMEOUT_SECONDS > client.PORTAL_PROMPT_TIMEOUT_SECONDS


def test_screenshot_message_uses_valid_data_url_and_exact_observation():
    message = client.screenshot_message(
        target="0xabc",
        token_id="fresh-token",
        width=800,
        height=600,
        mime_type="image/png",
        image_base64="cG5n",
    )

    text = message["content"][0]["text"]
    image_url = message["content"][1]["image_url"]["url"]
    assert '"observed_browser_window_id":"0xabc"' in text
    assert '"fresh_screenshot_token":"fresh-token"' in text
    assert image_url == "data:image/png;base64,cG5n"


def test_input_guard_requires_fresh_exact_window_and_token():
    observation = {
        "target": "0xabc",
        "token_id": "fresh-token",
        "size": (800, 600),
        "captured_at": 100.0,
    }
    common = {
        "name": "keyboard_action",
        "args": {
            "target_window_id": "0xabc",
            "token_id": "fresh-token",
            "action": "press_key",
            "key": "Ctrl+T",
        },
        "observation": observation,
        "now": 101.0,
        "navigated_to_youtube": False,
        "youtube_url_pending": False,
        "first_input": True,
        "rationale": "",
    }

    assert client.validate_input_action(**common) is None
    assert "exact window" in client.validate_input_action(
        **{**common, "args": {**common["args"], "target_window_id": "0xdef"}}
    )
    assert "fresh token" in client.validate_input_action(
        **{**common, "args": {**common["args"], "token_id": "old-token"}}
    )
    assert "too old" in client.validate_input_action(**{**common, "now": 113.0})


def test_video_click_requires_youtube_state_thumbnail_rationale_and_current_bounds():
    observation = {
        "target": "0xabc",
        "token_id": "fresh-token",
        "size": (800, 600),
        "captured_at": 100.0,
    }
    args = {
        "target_window_id": "0xabc",
        "token_id": "fresh-token",
        "action": "click",
        "button": "left",
        "x": 400,
        "y": 300,
    }
    common = {
        "name": "pointer_action",
        "args": args,
        "observation": observation,
        "now": 101.0,
        "navigated_to_youtube": True,
        "youtube_url_pending": False,
        "first_input": False,
        "rationale": "Clicking the visible video thumbnail.",
    }

    assert client.validate_input_action(**common) is None
    assert "only after" in client.validate_input_action(
        **{**common, "navigated_to_youtube": False}
    )
    assert "Before clicking" in client.validate_input_action(
        **{**common, "rationale": "Clicking this button."}
    )
    assert "outside" in client.validate_input_action(
        **{**common, "args": {**args, "x": 800}}
    )


def test_youtube_url_can_be_submitted_only_after_it_was_typed():
    observation = {
        "target": "0xabc",
        "token_id": "fresh-token",
        "size": (800, 600),
        "captured_at": 100.0,
    }
    args = {
        "target_window_id": "0xabc",
        "token_id": "fresh-token",
        "action": "press_key",
        "key": "Return",
    }
    common = {
        "name": "keyboard_action",
        "args": args,
        "observation": observation,
        "now": 101.0,
        "navigated_to_youtube": False,
        "youtube_url_pending": False,
        "first_input": False,
        "rationale": "",
    }

    assert "Do not submit" in client.validate_input_action(**common)
    assert client.validate_input_action(**{**common, "youtube_url_pending": True}) is None
    assert "press Return next" in client.validate_input_action(
        **{
            **common,
            "youtube_url_pending": True,
            "args": {**args, "key": "Ctrl+L"},
        }
    )
    assert "first input must open" in client.validate_input_action(
        **{
            **common,
            "args": {
                "target_window_id": "0xabc",
                "token_id": "fresh-token",
                "action": "type_text",
                "text": "youtube.com",
            },
            "youtube_url_pending": False,
            "first_input": True,
        }
    )
