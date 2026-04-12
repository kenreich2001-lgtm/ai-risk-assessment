"""Tests for technical intake → tag mapping."""

from __future__ import annotations

import unittest

from intake_signals import (
    build_technical_intake_block,
    merge_intake_tags,
    tags_from_intake_signals,
)


class TestTagsFromIntakeSignals(unittest.TestCase):
    def test_customer_hyperscaler_agent(self) -> None:
        tags = tags_from_intake_signals(
            "External customers (self-service digital)",
            ["PII (identifiers, contact, account data)"],
            "Hyperscaler managed AI (e.g., Azure OpenAI, Bedrock, Vertex)",
            "Autonomous agent with tools, APIs, or workflows",
            "Can invoke tools, APIs, transactions, or system changes",
            "Only curated internal or licensed sources",
        )
        self.assertIn("customer_facing", tags)
        self.assertIn("pii", tags)
        self.assertIn("third_party_model", tags)
        self.assertIn("agentic_tools", tags)

    def test_internal_rag(self) -> None:
        tags = tags_from_intake_signals(
            "Internal employees only",
            ["No structured sensitive personal data in scope"],
            "Organization-controlled environment (on-prem or private cloud)",
            "Q&A over internal documents (RAG)",
            "Recommendations only; humans perform all actions",
            "Only curated internal or licensed sources",
        )
        self.assertIn("internal_only", tags)
        self.assertIn("retrieval", tags)
        self.assertIn("internal_knowledge", tags)
        self.assertNotIn("third_party_model", tags)

    def test_merge_dedupes(self) -> None:
        m = merge_intake_tags(["pii", "regulated"], ["pii", "phi", "healthcare"])
        self.assertEqual(m, ["pii", "regulated", "phi", "healthcare"])


class TestTechnicalBlock(unittest.TestCase):
    def test_contains_audience_and_keywords(self) -> None:
        b = build_technical_intake_block(
            "Internal employees only",
            [],
            "Hyperscaler managed AI (e.g., Azure OpenAI, Bedrock, Vertex)",
            "Other / hybrid",
            "Unknown / not yet defined",
            "Public web, news, or third-party feeds",
        )
        self.assertIn("Internal employees only", b)
        self.assertIn("Azure OpenAI", b)


if __name__ == "__main__":
    unittest.main()
