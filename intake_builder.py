"""
Compose natural-language use case narratives from structured builder fields.

Used only by the Streamlit UI; does not change the mapping engine.
"""

from __future__ import annotations

from typing import Sequence

USE_CASE_TYPES: tuple[str, ...] = (
    "Chatbot / Assistant",
    "Search / Knowledge Assistant",
    "Summarization",
    "Content Generation",
    "Decision Support",
    "Classification / Review",
    "Agentic Workflow",
    "Recommendations",
    "Monitoring / Detection",
)

PRIMARY_USER_GROUPS: tuple[str, ...] = (
    "Employees",
    "Customers",
    "Analysts",
    "Clinicians",
    "Agents",
    "Operations Teams",
    "Executives",
)

BUILDER_DATA_TYPES: tuple[str, ...] = (
    "Public Data",
    "Internal Business Data",
    "Customer Data",
    "Employee Data",
    "Financial Data",
    "Health Data",
    "Regulated Data",
    "Confidential Documents",
)

MODEL_PATTERNS: tuple[str, ...] = (
    "Internal Model",
    "External LLM",
    "RAG",
    "Rules + LLM",
    "Agent with Tool Use",
)

CAPABILITIES: tuple[str, ...] = (
    "Answer Questions",
    "Summarize Documents",
    "Draft Content",
    "Recommend Actions",
    "Support Decisions",
    "Trigger Workflows",
    "Update Records",
    "Send Communications",
)

HUMAN_REVIEW_OPTIONS: tuple[str, ...] = (
    "Always Required",
    "Sometimes Required",
    "Not Yet Defined",
)


def build_use_case_description(
    industry: str,
    specialization: str,
    business_function: str,
    use_case_type: str,
    primary_user_group: str,
    data_types: Sequence[str],
    model_pattern: str,
    capabilities: Sequence[str],
    human_review_requirement: str,
) -> str:
    """
    Build enterprise-style prose for `map_use_case`, consistent with hand-written intakes.
    """
    ind = (industry or "").strip() or "the stated industry"
    spec = (specialization or "").strip() or "general operations"
    bfn = (business_function or "").strip() or "the business function"
    uct = (use_case_type or "").strip() or "AI-assisted workflow"
    users = (primary_user_group or "").strip() or "defined users"
    mp = (model_pattern or "").strip() or "an AI model integration"
    hr = (human_review_requirement or "").strip() or "under review"

    caps = [c.strip() for c in capabilities if c and str(c).strip()]
    dts = [d.strip() for d in data_types if d and str(d).strip()]

    if len(caps) > 2:
        cap_phrase = ", ".join(caps[:-1]) + f", and {caps[-1]}"
    elif len(caps) == 2:
        cap_phrase = f"{caps[0]} and {caps[1]}"
    elif len(caps) == 1:
        cap_phrase = caps[0]
    else:
        cap_phrase = "core assistance tasks (to be specified)"

    if len(dts) > 2:
        data_phrase = ", ".join(dts[:-1]) + f", and {dts[-1]}"
    elif len(dts) == 2:
        data_phrase = f"{dts[0]} and {dts[1]}"
    elif len(dts) == 1:
        data_phrase = dts[0]
    else:
        data_phrase = "data types to be confirmed"

    parts: list[str] = [
        (
            f"The organization proposes a {uct} for {ind} ({spec}), primarily serving the {bfn} function. "
            f"The primary user community is {users}."
        ),
        f"The intended model pattern is {mp}.",
    ]

    if dts:
        parts.append(f"Relevant categories of data in scope include {data_phrase}.")
    else:
        parts.append("Specific data categories in scope are still being finalized.")

    if caps:
        parts.append(f"Target capabilities include: {cap_phrase}.")
    else:
        parts.append("Specific end-user capabilities are still being scoped.")

    parts.append(
        f"Human review of model outputs or downstream actions is described as: {hr}. "
        "Governance expects alignment between this description and production logging, access controls, and change management."
    )

    return "\n\n".join(parts)
