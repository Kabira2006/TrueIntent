"""Sandbox package for browser-based page analysis."""

# Lazy imports to avoid requiring playwright for DOM analyzer tests
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.sandbox.browser import VisitResult, get_browser, visit
    from app.sandbox.dom_analyzer import analyze as analyze_dom, DOMAnalysisResult

__all__ = ["VisitResult", "get_browser", "visit", "analyze_dom", "DOMAnalysisResult"]
