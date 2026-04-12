"""Unit tests for rule-based governance triage (stdlib only)."""

from __future__ import annotations

import unittest

from governance_workflow import (
    build_triage_rationale,
    classify_use_case_category,
    determine_review_path,
    determine_risk_tier,
    generate_use_case_id,
)


class TestUseCaseId(unittest.TestCase):
    def test_id_format(self) -> None:
        from datetime import datetime, timezone

        fixed = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        uid = generate_use_case_id(fixed)
        self.assertTrue(uid.startswith("AIRA-20260115-"))
        self.assertEqual(len(uid.split("-")[-1]), 4)


class TestCategory(unittest.TestCase):
    def test_agentic_from_tags(self) -> None:
        c = classify_use_case_category("internal helper", ["agentic_tools"])
        self.assertEqual(c, "Agentic Workflow")

    def test_chatbot_from_tags(self) -> None:
        c = classify_use_case_category("anything", ["customer_facing"])
        self.assertEqual(c, "Chatbot / Assistant")

    def test_low_signal_other(self) -> None:
        c = classify_use_case_category("misc experiment", [])
        self.assertEqual(c, "Other AI Use Case")


class TestRiskTier(unittest.TestCase):
    def test_high_from_pii_tag(self) -> None:
        self.assertEqual(determine_risk_tier("internal wiki", ["pii", "internal_only"]), "High")

    def test_high_from_text(self) -> None:
        self.assertEqual(
            determine_risk_tier("Customer-facing chat using OpenAI API", []),
            "High",
        )

    def test_medium_from_retrieval_internal(self) -> None:
        self.assertEqual(
            determine_risk_tier("Search internal Confluence", ["retrieval", "internal_knowledge"]),
            "Medium",
        )

    def test_low_default(self) -> None:
        self.assertEqual(determine_risk_tier("Low sensitivity draft", []), "Low")


class TestReviewPath(unittest.TestCase):
    def test_paths(self) -> None:
        self.assertIn("Standard", determine_review_path("Low"))
        self.assertIn("Security", determine_review_path("Medium"))
        self.assertIn("Model Validation", determine_review_path("High"))


class TestRationale(unittest.TestCase):
    def test_mentions_tier_and_category(self) -> None:
        r = build_triage_rationale(
            "Uses PII in prompts",
            ["pii"],
            risk_tier="High",
            category="Other AI Use Case",
        )
        self.assertIn("High", r)
        self.assertIn("Other AI Use Case", r)


if __name__ == "__main__":
    unittest.main()
