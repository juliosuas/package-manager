"""Regression tests for one-line package summaries."""

import pytest

from zeekpkg.package import Package, PackageInfo, short_description


class TestShortDescription:
    """Prefer zkg.meta ``summary`` and fall back to ``description``."""

    def test_prefers_nonempty_summary(self) -> None:
        metadata = {
            "summary": "One-line summary.",
            "description": "A longer description. More detail here.",
        }

        assert short_description(metadata) == "One-line summary."

    def test_strips_summary_whitespace(self) -> None:
        metadata = {
            "summary": "  One-line summary.  ",
            "description": "A longer description.",
        }

        assert short_description(metadata) == "One-line summary."

    @pytest.mark.parametrize("summary", ["", "   ", "\n"])
    def test_empty_summary_falls_back_to_description(self, summary: str) -> None:
        metadata = {
            "summary": summary,
            "description": "First sentence. Second sentence.",
        }

        assert short_description(metadata) == "First sentence."

    def test_missing_summary_uses_first_description_sentence(self) -> None:
        metadata = {
            "description": "First sentence spans\nmultiple lines. Second sentence.",
        }

        assert short_description(metadata) == "First sentence spans multiple lines."

    def test_description_only_without_period(self) -> None:
        metadata = {"description": "No period here\nstill the summary"}

        assert short_description(metadata) == "No period here still the summary"

    def test_missing_both_returns_empty(self) -> None:
        assert short_description({}) == ""

    def test_package_and_info_prefer_summary(self) -> None:
        metadata = {
            "summary": "From summary.",
            "description": "From description.",
        }
        package = Package(
            git_url="https://example.com/pkg.git",
            metadata=metadata,
            name="pkg",
        )
        info = PackageInfo(package, metadata=metadata)

        assert package.short_description() == "From summary."
        assert info.short_description() == "From summary."
        assert "description" in package.metadata
        assert "description" in info.metadata
