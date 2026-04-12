"""
Structured technical intake: audience, data types, hosting, pattern, automation, external content.

Maps selections to **ALL_KNOWN_TAGS** and a text block for `map_use_case`. Rule-based only.
"""

from __future__ import annotations

from mapping_engine.taxonomy import ALL_KNOWN_TAGS

# --- Display options (keep stable strings; used as session values and in exports) ---

AUDIENCE_OPTIONS: tuple[str, ...] = (
    "Internal employees only",
    "External customers (self-service digital)",
    "External customers (contact center / assisted)",
    "B2B partners, vendors, or suppliers",
    "Mixed or unclear audience",
)

DATA_TYPE_OPTIONS: tuple[str, ...] = (
    "No structured sensitive personal data in scope",
    "PII (identifiers, contact, account data)",
    "PHI / health information",
    "Financial / payments / transactions",
    "HR / employment / workforce data",
    "Highly regulated or safety-critical data mix",
)

HOSTING_OPTIONS: tuple[str, ...] = (
    "Organization-controlled environment (on-prem or private cloud)",
    "Hyperscaler managed AI (e.g., Azure OpenAI, Bedrock, Vertex)",
    "Third-party SaaS AI product",
    "Hybrid or multiple providers",
    "Unknown / not yet selected",
)

PATTERN_OPTIONS: tuple[str, ...] = (
    "Q&A over internal documents (RAG)",
    "Drafting / copilot over enterprise content",
    "Software or code assistance",
    "Customer-facing chat or assistant",
    "Autonomous agent with tools, APIs, or workflows",
    "Batch scoring, classification, or decision support",
    "Other / hybrid",
)

AUTOMATION_OPTIONS: tuple[str, ...] = (
    "Recommendations only; humans perform all actions",
    "Some approved automated steps (e.g., drafts pending approval)",
    "Can invoke tools, APIs, transactions, or system changes",
    "Unknown / not yet defined",
)

EXTERNAL_CONTENT_OPTIONS: tuple[str, ...] = (
    "Only curated internal or licensed sources",
    "Public web, news, or third-party feeds",
    "User uploads or pasted content of unknown provenance",
    "Both internal and external / untrusted sources",
)


def _known(tags: list[str]) -> list[str]:
    return [t for t in dict.fromkeys(tags) if t in ALL_KNOWN_TAGS]


def tags_from_intake_signals(
    audience: str,
    data_types: list[str],
    hosting: str,
    pattern: str,
    automation: str,
    external_content: str,
) -> list[str]:
    """Derive engine tags from structured technical intake (subset of ALL_KNOWN_TAGS)."""
    tags: list[str] = []

    if audience == "Internal employees only":
        tags.extend(["internal_only"])
    elif audience == "External customers (self-service digital)":
        tags.extend(["customer_facing"])
    elif audience == "External customers (contact center / assisted)":
        tags.extend(["customer_facing", "customer_support_bot"])
    elif audience == "B2B partners, vendors, or suppliers":
        tags.extend(["customer_facing", "pii"])
    elif audience == "Mixed or unclear audience":
        pass  # rely on narrative + other fields; avoid a default bias tag

    for dt in data_types:
        if dt == "No structured sensitive personal data in scope":
            continue
        if dt == "PII (identifiers, contact, account data)":
            tags.append("pii")
        elif dt == "PHI / health information":
            tags.extend(["phi", "healthcare"])
        elif dt == "Financial / payments / transactions":
            tags.append("financial_data")
        elif dt == "HR / employment / workforce data":
            tags.extend(["hr_employment", "pii"])
        elif dt == "Highly regulated or safety-critical data mix":
            tags.extend(["high_stakes", "regulated"])

    if hosting in (
        "Hyperscaler managed AI (e.g., Azure OpenAI, Bedrock, Vertex)",
        "Third-party SaaS AI product",
        "Hybrid or multiple providers",
    ):
        tags.append("third_party_model")

    if pattern == "Q&A over internal documents (RAG)":
        tags.extend(["retrieval", "internal_knowledge"])
    elif pattern == "Drafting / copilot over enterprise content":
        tags.extend(["copilot_pattern", "internal_knowledge"])
    elif pattern == "Software or code assistance":
        tags.extend(["code_generation", "developer_tools"])
    elif pattern == "Customer-facing chat or assistant":
        tags.extend(["customer_facing", "customer_support_bot"])
    elif pattern == "Autonomous agent with tools, APIs, or workflows":
        tags.append("agentic_tools")
    elif pattern == "Batch scoring, classification, or decision support":
        tags.append("high_stakes")

    if automation == "Can invoke tools, APIs, transactions, or system changes":
        tags.append("agentic_tools")

    if external_content == "Public web, news, or third-party feeds":
        tags.extend(["external_content", "untrusted_content"])
    elif external_content == "User uploads or pasted content of unknown provenance":
        tags.append("untrusted_content")
    elif external_content == "Both internal and external / untrusted sources":
        tags.extend(["external_content", "untrusted_content"])

    return _known(tags)


def build_technical_intake_block(
    audience: str,
    data_types: list[str],
    hosting: str,
    pattern: str,
    automation: str,
    external_content: str,
) -> str:
    """Narrative + keyword lines so the matcher and triage text rules see consistent signals."""
    dt_line = ", ".join(data_types) if data_types else "None selected"
    hosting_note = {
        "Hyperscaler managed AI (e.g., Azure OpenAI, Bedrock, Vertex)": (
            "Third-party hosted generative AI APIs in use (e.g., Azure OpenAI, AWS Bedrock, Google Vertex AI)."
        ),
        "Third-party SaaS AI product": "Third-party SaaS AI platform hosts the model or application runtime.",
        "Hybrid or multiple providers": "Multiple hosting or model providers; supply-chain and change-control risk.",
        "Organization-controlled environment (on-prem or private cloud)": (
            "Inference runs in organization-controlled infrastructure (on-premises or private cloud)."
        ),
        "Unknown / not yet selected": "Hosting and model custody not yet finalized.",
    }.get(hosting, hosting)

    auto_note = {
        "Recommendations only; humans perform all actions": (
            "Outputs are advisory; humans execute state changes and transactions."
        ),
        "Some approved automated steps (e.g., drafts pending approval)": (
            "Limited automation with human approval gates on material actions."
        ),
        "Can invoke tools, APIs, transactions, or system changes": (
            "System may perform automated actions via tools, APIs, or workflows (function calling / agentic patterns)."
        ),
        "Unknown / not yet defined": "Automation boundaries not yet defined.",
    }.get(automation, automation)

    lines = [
        "--- Technical & data intake (user-declared; informs tags and assessment text) ---",
        f"Primary audience: {audience}",
        f"Data types in scope: {dt_line}",
        f"Model / hosting: {hosting}",
        f"Hosting detail: {hosting_note}",
        f"Primary interaction pattern: {pattern}",
        f"Automation & actions: {automation}",
        f"Automation detail: {auto_note}",
        f"External / untrusted content: {external_content}",
        "--- End technical intake ---",
    ]
    return "\n".join(lines)


def merge_intake_tags(base: list[str], signal_tags: list[str]) -> list[str]:
    """Deduplicate while preserving order; all values should already be known tags."""
    out: list[str] = []
    seen: set[str] = set()
    for t in list(base) + list(signal_tags):
        if t in ALL_KNOWN_TAGS and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def format_technical_intake_summary(
    audience: str,
    data_types: list[str],
    hosting: str,
    pattern: str,
    automation: str,
    external_content: str,
) -> str:
    dt = "; ".join(data_types) if data_types else "—"
    return (
        f"audience={audience} | data_types={dt} | hosting={hosting} | "
        f"pattern={pattern} | automation={automation} | external_content={external_content}"
    )
