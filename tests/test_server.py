"""HTTP server tests — deferred to Stage 3."""

import pytest

pytestmark = pytest.mark.skip(reason="TODO: HTTP server stage")


def test_health_endpoint():
    pass


def test_scan_endpoint_text():
    pass


def test_scan_endpoint_json():
    pass


def test_scan_endpoint_invalid_request():
    pass


def test_scan_endpoint_empty_body():
    pass
