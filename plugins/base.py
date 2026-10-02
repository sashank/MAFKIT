"""Base plugin interface for MAFKit unpackers and analyzers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..model import Report


class Plugin:
    """Abstract base class for custom unpacking and analysis plugins."""

    name: str = "base"

    def analyze(self, ctx: dict[str, Any], report: Report) -> None:
        """Execute plugin analysis given the APK context and target Report object.

        Args:
            ctx: Dictionary containing loaded APK context (zipfile, entries, strings, etc.)
            report: The Report instance to populate with findings, packer metadata, etc.
        """
        raise NotImplementedError
