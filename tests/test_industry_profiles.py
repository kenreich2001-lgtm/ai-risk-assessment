"""Tests for enterprise intake taxonomy helpers."""

from __future__ import annotations

import unittest

from industry_profiles import (
    compute_enriched_tier,
    get_combined_context_tags,
    get_default_regulations,
    get_specializations,
)


class TestSpecializations(unittest.TestCase):
    def test_financial_services_has_banking(self) -> None:
        specs = get_specializations("Financial Services")
        self.assertIn("Banking", specs)

    def test_unknown_industry_empty(self) -> None:
        self.assertEqual(get_specializations("Not An Industry"), [])


class TestDefaultRegulations(unittest.TestCase):
    def test_banking_defaults(self) -> None:
        labs = get_default_regulations("Financial Services", "Banking")
        self.assertTrue(any("GLBA" in x for x in labs))


class TestCombinedTags(unittest.TestCase):
    def test_merges_function_and_industry(self) -> None:
        tags = get_combined_context_tags(
            "Financial Services",
            "Banking",
            "Underwriting / Risk Decisioning",
            [],
            [],
        )
        self.assertIn("financial_services", tags)
        self.assertIn("bias_sensitive", tags)


class TestEnrichedTier(unittest.TestCase):
    def test_underwriting_bumps_high(self) -> None:
        tier = compute_enriched_tier(
            "internal notes only",
            [],
            regulation_label_count=0,
            business_function="Underwriting / Risk Decisioning",
        )
        self.assertEqual(tier, "High")


if __name__ == "__main__":
    unittest.main()
