import pytest
from simple_defender.field_extractor import FieldExtractor
from simple_defender.config import MAX_DEPTH, LARGE_ARRAY_THRESHOLD

fe = FieldExtractor()


def test_risky_field_by_name():
    assert fe._is_risky_field("name") is True
    assert fe._is_risky_field("body") is True
    assert fe._is_risky_field("content") is True


def test_risky_field_by_pattern():
    assert fe._is_risky_field("employee_name") is True
    assert fe._is_risky_field("job_description") is True


def test_non_risky_fields():
    assert fe._is_risky_field("id") is False
    assert fe._is_risky_field("created_at") is False
    assert fe._is_risky_field("url") is False


def test_tool_override_risky():
    # gmail_* override includes "subject" and "snippet"
    assert fe._is_risky_field("subject", "gmail_get_message") is True
    assert fe._is_risky_field("snippet", "gmail_get_message") is True


def test_tool_override_replaces_defaults():
    # gmail_* override does NOT include "name", so it should NOT be risky
    assert fe._is_risky_field("name", "gmail_get_message") is False


def test_wildcard_exact():
    assert fe._matches_wildcard("gmail_get_message", "gmail_*") is True


def test_wildcard_no_match():
    assert fe._matches_wildcard("slack_send", "gmail_*") is False


def test_extract_flat_object():
    fields = fe.extract({"name": "foo", "id": "123"})
    names = [f.field_name for f in fields]
    assert "name" in names
    assert "id" not in names


def test_extract_skip_non_risky():
    fields = fe.extract({"id": "1", "created_at": "2024-01-01", "name": "Alice"})
    names = [f.field_name for f in fields]
    assert "id" not in names
    assert "created_at" not in names
    assert "name" in names


def test_extract_nested():
    data = {"user": {"name": "Bob", "id": "42"}}
    fields = fe.extract(data)
    assert any(f.field_name == "name" and f.text == "Bob" for f in fields)


def test_extract_paginated():
    data = {
        "data": [{"name": "Alice"}, {"name": "Bob"}],
        "next": "cursor123",
        "total": 2,
    }
    fields = fe.extract(data)
    names = [f.text for f in fields]
    assert "Alice" in names
    assert "Bob" in names
    # pagination metadata fields should not appear as extracted text
    assert "cursor123" not in names


def test_extract_wrapped():
    data = {"data": [{"body": "Hello world"}]}
    fields = fe.extract(data)
    assert any(f.field_name == "body" and f.text == "Hello world" for f in fields)


def test_extract_raw_string():
    fields = fe.extract("plain text")
    assert len(fields) == 1
    assert fields[0].field_name == "_raw"
    assert fields[0].text == "plain text"


def test_extract_large_array():
    big = [{"name": f"item{i}"} for i in range(LARGE_ARRAY_THRESHOLD + 100)]
    fields = fe.extract(big)
    # Only first 100 processed
    assert len(fields) == 100


def test_depth_limit():
    # Build object nested deeper than MAX_DEPTH
    obj = current = {}
    for _ in range(MAX_DEPTH + 5):
        child = {"name": "deep"}
        current["nested"] = child
        current = child
    fields = fe.extract(obj)
    # Should not crash; results may be empty or partial but not infinite
    assert isinstance(fields, list)


def test_should_skip_field():
    assert fe._should_skip_field("id", "gmail_get_message") is True
    assert fe._should_skip_field("thread_id", "gmail_get_message") is True
    assert fe._should_skip_field("date", "gmail_get_message") is True
    assert fe._should_skip_field("subject", "gmail_get_message") is False
