"""
Rule-based governance triage helpers (plain Python, no third-party deps).

Used by the Streamlit UI only. Does **not** replace the mapping engine (`map_use_case`).
Triage tier is computed from **intake text + inferred/optional tags** using fixed rules so
behavior is easy to explain in an interview or review.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Tier rules (documented for maintainability)
# ---------------------------------------------------------------------------
# HIGH: customer-facing channels, regulated/sensitive data, third-party models,
#       tool-mediated or automated actions, or explicit high-stakes / regulated context.
# MEDIUM: internal assistants touching enterprise knowledge bases or moderate-risk
#         generation (e.g. copilot/code assist) without HIGH triggers.
# LOW: default when no MEDIUM or HIGH rule matches (e.g. low-sensitivity internal productivity).

_HIGH_TAGS: frozenset[str] = frozenset(
    {
        "customer_facing",
        "customer_support_bot",
        "pii",
        "phi",
        "financial_data",
        "third_party_model",
        "agentic_tools",
        "action_execution",
        "regulated",
        "high_stakes",
        "hr_employment",
        "healthcare",
        "financial_services",
        "public_sector",
        "bias_sensitive",
    }
)

# Phrases in intake text that imply HIGH exposure (substring match on lowercased text).
_HIGH_TEXT_FRAGMENTS: tuple[str, ...] = (
    "customer-facing",
    "customer facing",
    "external customer",
    "pii",
    "personally identifiable",
    "phi",
    "hipaa",
    "patient",
    "pci",
    "credit decision",
    "loan decision",
    "eligibility",
    "hiring decision",
    "underwriting",
    "openai",
    "anthropic",
    "bedrock",
    "vertex ai",
    "azure openai",
    "third-party model",
    "third party model",
    "hosted llm",
    "external llm",
    "function calling",
    "tool use",
    "mcp",
    "invoke api",
    "automated action",
    "automated decision",
)

_MEDIUM_TAGS: frozenset[str] = frozenset(
    {
        "retrieval",
        "internal_knowledge",
        "internal_only",
        "copilot_pattern",
        "code_generation",
        "developer_tools",
        "fine_tuned",
    }
)

_MEDIUM_TEXT_FRAGMENTS: tuple[str, ...] = (
    "internal assistant",
    "employee",
    "confluence",
    "sharepoint",
    "knowledge base",
    "rag",
    "retrieval",
    "copilot",
    "code generation",
    "developer",
    "summarize document",
)

_DEFAULT_STATUS = "Draft Assessment"


def _tagset(tags: list[str] | None) -> frozenset[str]:
    if not tags:
        return frozenset()
    return frozenset(tags)


def _text_hits_fragments(text_lower: str, fragments: tuple[str, ...]) -> list[str]:
    return [f for f in fragments if f in text_lower]


def generate_use_case_id(now: datetime | None = None) -> str:
    """Return AIRA-YYYYMMDD-XXXX (XXXX = four hex digits, cryptographically random)."""
    dt = now if now is not None else datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    suffix = secrets.token_hex(2).upper()
    return f"AIRA-{dt.strftime('%Y%m%d')}-{suffix}"


def format_assessment_timestamp(now: datetime | None = None) -> str:
    dt = now if now is not None else datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def classify_use_case_category(use_case_text: str, tags: list[str] | None = None) -> str:
    """
    Single label for the use case shape. First matching rule wins (deterministic order).
    """
    t = _tagset(tags)
    text_l = (use_case_text or "").lower()

    # Agentic / tool execution (highest precedence for category)
    if "agentic_tools" in t or "action_execution" in t:
        return "Agentic Workflow"
    if any(k in text_l for k in ("function calling", "mcp", "tool use", "invoke api", "agentic")):
        return "Agentic Workflow"

    # Customer-channel assistants
    if "customer_support_bot" in t or "customer_facing" in t:
        return "Chatbot / Assistant"
    if "support chatbot" in text_l or "chatbot" in text_l and "internal" not in text_l:
        return "Chatbot / Assistant"
    if "customer-facing" in text_l or "customer facing" in text_l:
        return "Chatbot / Assistant"

    # Developer / drafting productivity
    if "code_generation" in t or "developer_tools" in t:
        return "Content Generation"
    if "copilot_pattern" in t:
        return "Content Generation"
    if any(k in text_l for k in ("generate code", "pull request", "ide assistant", "developer")):
        return "Content Generation"

    # Regulated or consequential decision support
    if t & {
        "high_stakes",
        "regulated",
        "hr_employment",
        "bias_sensitive",
        "phi",
        "healthcare",
        "financial_services",
        "public_sector",
    }:
        return "Decision Support"

    # Internal search / analytics over documents
    if "retrieval" in t and t & {"internal_knowledge", "internal_only"}:
        return "Analytics / Insight"

    return "Other AI Use Case"


def determine_risk_tier(use_case_text: str, tags: list[str] | None = None) -> str:
    """
    Governance triage tier: High / Medium / Low from tags + intake text only.
    """
    t = _tagset(tags)
    text_l = (use_case_text or "").lower()

    if t & _HIGH_TAGS:
        return "High"
    if _text_hits_fragments(text_l, _HIGH_TEXT_FRAGMENTS):
        return "High"

    if t & _MEDIUM_TAGS:
        return "Medium"
    if _text_hits_fragments(text_l, _MEDIUM_TEXT_FRAGMENTS):
        return "Medium"

    return "Low"


def determine_review_path(risk_tier: str) -> str:
    tier = (risk_tier or "").strip().title()
    if tier == "Low":
        return "Standard Governance Review"
    if tier == "High":
        return "Governance + Security + Model Validation Review"
    return "Governance + Security Review"


def build_triage_rationale(
    use_case_text: str,
    tags: list[str] | None = None,
    risk_tier: str = "",
    category: str = "",
    domain_context: str = "",
) -> str:
    """
    Plain-language rationale listing drivers (suitable for CSV and UI).
    """
    t = _tagset(tags)
    text_l = (use_case_text or "").lower()
    tier = (risk_tier or "").strip() or "—"
    cat = (category or "").strip() or "—"

    parts: list[str] = [
        f"Governance triage category: {cat}. Rule-based risk tier: {tier}.",
    ]
    if (domain_context or "").strip():
        parts.append((domain_context or "").strip())

    high_tag_hits = sorted(t & _HIGH_TAGS)
    if high_tag_hits:
        parts.append("High-sensitivity tag signals: " + ", ".join(high_tag_hits) + ".")

    high_text_hits = _text_hits_fragments(text_l, _HIGH_TEXT_FRAGMENTS)
    if high_text_hits:
        parts.append("Intake text matched high-tier patterns (examples): " + "; ".join(high_text_hits[:6]) + ".")

    if tier in ("Medium", "Low"):
        med_tag_hits = sorted(t & _MEDIUM_TAGS)
        if med_tag_hits:
            parts.append("Moderate-context tag signals: " + ", ".join(med_tag_hits) + ".")
        med_text_hits = _text_hits_fragments(text_l, _MEDIUM_TEXT_FRAGMENTS)
        if med_text_hits and tier == "Medium":
            parts.append("Intake text suggests internal or generative productivity context.")

    parts.append(
        f"Recommended review path follows tier: {determine_review_path(tier)}."
    )
    return " ".join(parts)


def governance_export_row(
    *,
    use_case_id: str,
    assessment_timestamp: str,
    assessment_status: str,
    use_case_category: str,
    risk_tier: str,
    recommended_review_path: str,
    triage_rationale: str,
    industry: str = "",
    specialization: str = "",
    business_function: str = "",
    selected_regulations: str = "",
    derived_context_tags: str = "",
    technical_intake_summary: str = "",
    review_path: str = "",
) -> dict[str, str]:
    """Single-row dict for CSV export (companion summary or repeated per mapping row)."""
    rp = review_path or recommended_review_path
    return {
        "use_case_id": use_case_id,
        "assessment_timestamp": assessment_timestamp,
        "assessment_status": assessment_status,
        "industry": industry,
        "specialization": specialization,
        "business_function": business_function,
        "selected_regulations": selected_regulations,
        "derived_context_tags": derived_context_tags,
        "technical_intake_summary": technical_intake_summary.replace("\n", " ").strip(),
        "use_case_category": use_case_category,
        "risk_tier": risk_tier,
        "recommended_review_path": rp,
        "review_path": rp,
        "triage_rationale": triage_rationale.replace("\n", " ").strip(),
    }


# Backward-compatible name for older imports
DEFAULT_ASSESSMENT_STATUS = _DEFAULT_STATUS
