"""Tests for regulatory overlay and risk tagging (stdlib only)."""

from __future__ import annotations

import unittest

from regulatory_intelligence import (
    assign_remediation_owner,
    assign_remediation_priority,
    enrich_remediation_gaps,
    get_regulatory_overlay,
    tag_all_material_risks,
    tag_risk,
    themes_for_selected_regulations,
)


class TestOverlay(unittest.TestCase):
    def test_banking_overlay(self) -> None:
        o = get_regulatory_overlay("Financial Services", "Banking")
        self.assertIn("GLBA", " ".join(o["frameworks"]))

    def test_themes_from_labels(self) -> None:
        t = themes_for_selected_regulations(["HIPAA Privacy Rule", "PCI DSS"])
        self.assertTrue(any("access" in x.lower() or "audit" in x.lower() for x in t))


class TestTagging(unittest.TestCase):
    def test_tag_risk_pii(self) -> None:
        row = {
            "risk_id": "R-002",
            "risk_name": "Data exposure",
            "operational_stake": "PII in prompts",
            "failure_mode": "breach",
        }
        tags = tag_risk(
            row,
            industry="Retail / E-Commerce",
            specialization="Direct-to-Consumer",
            business_function="Customer Support",
            selected_regulations=["GDPR"],
            derived_tags=["pii"],
        )
        self.assertIn("Privacy Risk", tags)

    def test_tag_all(self) -> None:
        enriched, by_id = tag_all_material_risks(
            [{"risk_id": "R-001", "risk_name": "X", "operational_stake": "", "failure_mode": ""}],
            industry="Technology",
            specialization="SaaS / Enterprise Software",
            business_function="Customer Support",
            selected_regulations=[],
            derived_tags=[],
        )
        self.assertTrue(enriched[0].get("governance_risk_tags"))


class TestRemediationEnrich(unittest.TestCase):
    def test_enrich_gap(self) -> None:
        gaps = [
            {
                "control_id": "C1",
                "required_control": "Test control",
                "control_status": "partial",
                "related_risks": [{"risk_id": "R-002", "risk_name": "Leak"}],
                "remediation_action": "Fix logging",
                "remediation_priority": "Medium",
            }
        ]
        _, by_id = tag_all_material_risks(
            [{"risk_id": "R-002", "risk_name": "Leak", "operational_stake": "PII", "failure_mode": ""}],
            industry="Healthcare",
            specialization="Provider",
            business_function="Clinical Operations",
            selected_regulations=["HIPAA Privacy Rule"],
            derived_tags=["phi"],
        )
        out = enrich_remediation_gaps(
            gaps,
            risk_tags_by_id=by_id,
            industry="Healthcare",
            specialization="Provider",
            selected_regulations=["HIPAA Privacy Rule"],
            regulation_themes=["access control"],
            overlay_frameworks=("HIPAA",),
        )
        self.assertEqual(len(out), 1)
        self.assertIn("remediation_owner_suggested", out[0])
        self.assertIn("enrichment_rationale", out[0])


class TestOwnerPriority(unittest.TestCase):
    def test_privacy_owner(self) -> None:
        o = assign_remediation_owner(["Privacy Risk"], industry="Retail", specialization="X")
        self.assertEqual(o, "Privacy / Legal")

    def test_priority_elevate(self) -> None:
        p = assign_remediation_priority("Medium", ["Safety Risk", "Consumer Harm Risk"])
        self.assertEqual(p, "High")


if __name__ == "__main__":
    unittest.main()
