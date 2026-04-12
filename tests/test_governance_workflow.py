"""Unit tests for rule-based governance triage (stdlib only)."""

from __future__ import annotations

import unittest

from governance_workflow import (
    build_triage_rationale,
    classify_use_case_category,
    determine_review_path,
    determine_risk_tier,
    generate_use_case_id,
    get_launch_recommendation,
    get_required_reviewers,
    get_risk_tier_rationale_bullets,
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


class TestRequiredReviewers(unittest.TestCase):
    def test_always_governance_and_owner(self) -> None:
        roles = get_required_reviewers(
            risk_tier="Low",
            business_function="Knowledge Management",
            regulation_labels=[],
            tags=["internal_only"],
        )
        self.assertEqual(roles[0], "AI Governance")
        self.assertEqual(roles[-1], "Business Owner")

    def test_high_tier_adds_model_validation(self) -> None:
        roles = get_required_reviewers(
            risk_tier="High",
            business_function="Knowledge Management",
            regulation_labels=["GDPR"],
            tags=["pii"],
        )
        self.assertIn("Model Validation", roles)
        self.assertIn("Security", roles)


class TestLaunchRecommendation(unittest.TestCase):
    def test_not_ready_when_no_controls(self) -> None:
        r = get_launch_recommendation(
            risk_tier="Medium",
            readiness_opinion="Complete required-control definitions for this use case",
            open_remediation_count=0,
        )
        self.assertEqual(r, "Not ready")

    def test_ready_when_flag_set_low_path(self) -> None:
        r = get_launch_recommendation(
            risk_tier="Low",
            readiness_opinion="Required controls specified; evidence review flag set",
            open_remediation_count=0,
        )
        self.assertEqual(r, "Ready for standard review")

    def test_high_escalates(self) -> None:
        r = get_launch_recommendation(
            risk_tier="High",
            readiness_opinion="Document evidence specifications per required control",
            open_remediation_count=0,
        )
        self.assertEqual(r, "Escalate")


class TestTierRationaleBullets(unittest.TestCase):
    def test_length_between_three_and_five(self) -> None:
        bullets = get_risk_tier_rationale_bullets(
            "internal wiki search",
            ["internal_knowledge", "retrieval"],
            regulation_label_count=0,
            business_function="Knowledge Management",
            final_tier="Medium",
        )
        self.assertGreaterEqual(len(bullets), 3)
        self.assertLessEqual(len(bullets), 5)


if __name__ == "__main__":
    unittest.main()
