"""Tests for structured use case narrative builder (stdlib only)."""

from __future__ import annotations

import unittest

from intake_builder import build_use_case_description


class TestBuildUseCaseDescription(unittest.TestCase):
    def test_includes_core_fields(self) -> None:
        text = build_use_case_description(
            "Financial Services",
            "Banking",
            "Compliance",
            "Decision Support",
            "Employees",
            ("Internal Business Data", "Regulated Data"),
            "RAG",
            ("Answer Questions", "Support Decisions"),
            "Always Required",
        )
        self.assertIn("Financial Services", text)
        self.assertIn("Banking", text)
        self.assertIn("Compliance", text)
        self.assertIn("Decision Support", text)
        self.assertIn("Employees", text)
        self.assertIn("RAG", text)
        self.assertIn("Always Required", text)

    def test_non_empty_without_optional_multiselects(self) -> None:
        text = build_use_case_description(
            "Technology",
            "SaaS / Enterprise Software",
            "Engineering / Product Development",
            "Content Generation",
            "Developers",
            [],
            "External LLM",
            [],
            "Not Yet Defined",
        )
        self.assertGreater(len(text), 80)
        self.assertIn("External LLM", text)


if __name__ == "__main__":
    unittest.main()
