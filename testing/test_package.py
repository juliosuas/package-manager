"""Tests for package metadata helpers."""

from zeekpkg.package import short_description


def test_summary_preferred_over_description() -> None:
    metadata = {
        "summary": "Preferred summary line.",
        "description": "This description should not be shown.\nIt has more text.",
    }

    assert short_description(metadata) == "Preferred summary line."


def test_summary_keeps_text_after_a_period() -> None:
    metadata = {
        "summary": "Detects scans. Supports IPv6.",
        "description": "Unused longer description.",
    }

    assert short_description(metadata) == "Detects scans. Supports IPv6."


def test_wrapped_summary_is_joined_into_one_line() -> None:
    metadata = {
        "summary": "Detects scans.\n    Supports IPv6.",
    }

    assert short_description(metadata) == "Detects scans. Supports IPv6."


def test_summary_absent_uses_description_first_sentence() -> None:
    metadata = {
        "description": "First line of the description.\n    Second sentence stays hidden.",
    }

    assert short_description(metadata) == "First line of the description."


def test_description_sentence_may_span_lines() -> None:
    metadata = {
        "description": "This package does foo\n    and bar. Then more text.",
    }

    assert short_description(metadata) == "This package does foo and bar."


def test_blank_summary_falls_back_to_description() -> None:
    metadata = {
        "summary": "  \n\t",
        "description": "Fallback sentence. Extra detail.",
    }

    assert short_description(metadata) == "Fallback sentence."


def test_summary_and_description_absent() -> None:
    assert short_description({}) == ""
    assert short_description({"tags": "scan detection"}) == ""
    assert short_description({"description": ""}) == ""
