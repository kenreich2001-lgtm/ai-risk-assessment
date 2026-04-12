"""
Rule-based governance triage helpers (plain Python, no third-party deps).

Used by the Streamlit UI only. Does **not** replace the mapping engine (`map_use_case`).
Triage tier is computed from **intake text + inferred/optional tags** using fixed rules so
behavior is easy to explain in an interview or review.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Sequence

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


def get_required_reviewers(
    *,
    risk_tier: str,
    business_function: str,
    regulation_labels: Sequence[str],
    tags: Sequence[str] | None,
) -> list[str]:
    """
    Demo-oriented reviewer roster from a fixed role catalog, driven by tier, tags, and regulatory context.
    Order is stable for display.
    """
    tier = (risk_tier or "").strip().title()
    t = _tagset(tags)
    regs = list(regulation_labels or [])
    reg_blob = " ".join(r.lower() for r in regs)

    reviewers: list[str] = ["AI Governance"]

    if tier in ("Medium", "High") or t & {
        "customer_facing",
        "customer_support_bot",
        "agentic_tools",
        "third_party_model",
        "action_execution",
    }:
        reviewers.append("Security")

    if t & {"pii", "phi"} or any(
        k in reg_blob for k in ("gdpr", "ccpa", "hipaa", "glba", "ferpa", "coppa", "privacy")
    ):
        reviewers.append("Privacy")

    if regs or "regulated" in t:
        reviewers.append("Compliance")

    high_material_functions = {
        "Underwriting / Risk Decisioning",
        "Clinical Operations",
        "Fraud Detection / Investigations",
        "Executive Decision Support",
        "Legal",
        "Quality Assurance",
    }
    if (
        tier == "High"
        or business_function in high_material_functions
        or t & {"high_stakes", "financial_services", "phi", "healthcare", "bias_sensitive"}
    ):
        reviewers.append("Model Validation")

    reviewers.append("Business Owner")

    seen: set[str] = set()
    out: list[str] = []
    for role in reviewers:
        if role not in seen:
            seen.add(role)
            out.append(role)
    return out


def get_launch_recommendation(
    *,
    risk_tier: str,
    readiness_opinion: str,
    open_remediation_count: int,
) -> str:
    """
    Single headline for demos, derived from triage tier, engine readiness wording, and open remediation rows.
    """
    tier = (risk_tier or "").strip().title()
    op = (readiness_opinion or "").strip()
    op_l = op.lower()
    n_rem = int(open_remediation_count)

    if not op or op == "—":
        return "Conditionally ready pending remediation"

    if "complete required-control definitions" in op_l:
        return "Not ready"

    if "additional controls must be implemented prior to deployment" in op_l:
        return "Not ready"

    if tier == "High":
        if n_rem > 0 or "additional controls and remediations must be completed" in op_l:
            return "Escalate"
        if "required controls and remediation must be completed" in op_l:
            return "Escalate"
        if "document evidence specifications" in op_l:
            return "Escalate"
        if "required controls specified; evidence review flag set" in op_l:
            return "Conditionally ready pending remediation"
        return "Escalate"

    if n_rem > 0:
        return "Conditionally ready pending remediation"

    if (
        "document evidence specifications" in op_l
        or "additional controls and remediations must be completed" in op_l
        or "required controls and remediation must be completed" in op_l
    ):
        return "Conditionally ready pending remediation"

    if "required controls specified; evidence review flag set" in op_l:
        return "Ready for standard review"

    return "Conditionally ready pending remediation"


def get_risk_tier_rationale_bullets(
    use_case_text: str,
    tags: Sequence[str] | None,
    *,
    regulation_label_count: int,
    business_function: str,
    final_tier: str,
) -> list[str]:
    """
    Three to five bullets explaining triage tier, aligned with `compute_enriched_tier` / base `determine_risk_tier` rules.
    """
    base = determine_risk_tier(use_case_text, list(tags or []))
    t = _tagset(tags)
    text_l = (use_case_text or "").lower()
    bullets: list[str] = [
        f"Baseline sensitivity from **tags and narrative** is **{base}** before enterprise context adjustments."
    ]

    if base == "High":
        tag_hits = sorted(t & _HIGH_TAGS)
        if tag_hits:
            shown = ", ".join(tag_hits[:8])
            bullets.append(f"**High-tier tags** present include: {shown}.")
        frag = _text_hits_fragments(text_l, _HIGH_TEXT_FRAGMENTS)
        if frag:
            bullets.append(
                "**Narrative** matches patterns associated with customer channels, sensitive data, hosted models, or automated actions."
            )
    elif base == "Medium":
        if t & _MEDIUM_TAGS or _text_hits_fragments(text_l, _MEDIUM_TEXT_FRAGMENTS):
            bullets.append(
                "**Copilot**, retrieval, or internal generative patterns justify at least **medium** scrutiny when no high-tier triggers apply."
            )
    else:
        if not (t & _HIGH_TAGS) and not _text_hits_fragments(text_l, _HIGH_TEXT_FRAGMENTS):
            bullets.append("**No** high-sensitivity tag or narrative triggers fired; default posture is **low** unless context bumps apply.")

    rc = int(regulation_label_count)
    if rc >= 6:
        bullets.append(
            f"**{rc}** regulatory / standards selections imply a **broad** control surface and drive a **stronger** minimum tier."
        )
    elif rc >= 4:
        bullets.append(
            f"**{rc}** regulatory / standards selections increase expected oversight and can **raise** the minimum tier."
        )

    high_func = {
        "Underwriting / Risk Decisioning",
        "Clinical Operations",
        "Fraud Detection / Investigations",
        "Executive Decision Support",
        "Legal",
        "Quality Assurance",
    }
    if business_function in high_func:
        bullets.append(
            f"**{business_function}** is classified as a **higher-materiality** business function for AI governance."
        )
    elif business_function in {"Security Operations", "Compliance", "Finance"}:
        bullets.append(
            f"**{business_function}** expects **cross-functional** security and control depth beyond a minimal review."
        )

    bullets.append(f"**Assigned triage tier: {final_tier}** — use this for forum routing alongside the catalog risk view.")

    # Keep 3–5 bullets: drop middle extras if needed, always keep first and last (tier summary)
    if len(bullets) > 5:
        keep_first = bullets[0]
        summary = bullets[-1]
        middle = bullets[1:-1]
        trimmed = middle[:3] if len(middle) > 3 else middle
        bullets = [keep_first, *trimmed, summary]
    if len(bullets) < 3:
        bullets.insert(
            -1,
            "Industry, specialization, and technical intake tags merge with your narrative inside the **existing** assessment engine.",
        )
    return bullets[:5]


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
