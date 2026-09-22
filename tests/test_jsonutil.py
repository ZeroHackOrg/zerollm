# tests/test_jsonutil.py
import json

from zerollm.proxy import jsonutil


def test_extract_chunks_content_fields():
    body = {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "you are helpful"},
            {"role": "user", "content": "hello world"},
            {"role": "user", "content": ["part one", "part two"]},
            {"role": "assistant", "content": "hi there"},
        ],
    }
    chunks = jsonutil.extract_chunks(body)
    texts = [text for _, text in chunks]
    assert "hello world" in texts
    assert "part one" in texts and "part two" in texts
    assert "you are helpful" in texts
    assert "hi there" in texts


def test_meta_fields_skipped():
    body = {
        "model": "gpt-4o-mini",
        "id": "chatcmpl-xyz",
        "usage": {"total_tokens": 12},
        "messages": [{"role": "user", "content": "keep me"}],
    }
    texts = [text for _, text in jsonutil.extract_chunks(body)]
    assert "keep me" in texts
    assert "gpt-4o-mini" not in texts
    assert "chatcmpl-xyz" not in texts


def test_plain_strings_found():
    body = {"prompt": "please summarize", "input": "data input", "text": "some text"}
    texts = [text for _, text in jsonutil.extract_chunks(body)]
    for expected in ("please summarize", "data input", "some text"):
        assert expected in texts


def test_nested_paths_are_pointer_like():
    body = {"a": [{"b": {"content": "deep"}}]}
    chunks = jsonutil.extract_chunks(body)
    paths = [path for path, _ in chunks]
    assert ["a", "0", "b", "content"] in paths


def test_apply_redaction_nested_list_item():
    body = {"messages": [{"content": "cc 4111 1111 1111 1111 ok"}, {"content": "fine"}]}
    out = jsonutil.apply_redaction(body, ["messages", "0", "content"], "[REDACTED]")
    assert out["messages"][0]["content"] == "[REDACTED]"
    assert out["messages"][1]["content"] == "fine"


def test_apply_redaction_does_not_mutate_input():
    body = {"messages": [{"content": "secret"}]}
    jsonutil.apply_redaction(body, ["messages", "0", "content"], "[REDACTED]")
    assert body["messages"][0]["content"] == "secret"


def test_apply_redaction_bad_path_returns_original():
    body = {"messages": [{"content": "secret"}]}
    assert jsonutil.apply_redaction(body, ["messages", "9", "content"], "[X]") is body


def test_body_text_joins_chunks():
    body = json.dumps({"messages": [{"role": "user", "content": "line one"}, {"content": "line two"}]})
    text = jsonutil.body_text(body)
    assert "line one" in text
    assert "line two" in text


def test_body_text_passthrough_for_non_json():
    assert jsonutil.body_text("not json at all") == "not json at all"


def test_raw_to_json_valid_and_invalid():
    assert jsonutil.raw_to_json(b'{"a": 1}') == {"a": 1}
    assert jsonutil.raw_to_json(b"garbage") is None
    assert jsonutil.raw_to_json(b"\xff\xfe") is None
