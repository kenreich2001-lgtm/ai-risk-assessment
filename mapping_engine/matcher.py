"""
Infer use-case tags from text, select risks, and score mapping rows.
R-003 (injection) is NOT tied to retrieval alone — see catalog trigger_tags and
untrusted_content / external_content rules below.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import FrozenSet, List, Literal, Sequence, Tuple
from mapping_engine.catalog import EDGES, RISKS, Risk, RiskControlEdge
from mapping_engine.taxonomy import ALL_KNOWN_TAGS, LIKELIHOOD_RANK, SEVERITY_RANK
_RULES: Tuple[Tuple[FrozenSet[str], str], ...] = (
    (
        frozenset(
            {
                "customer support",
                "support chatbot",
                "helpdesk bot",
                "chatbot for customers",
                "customer-facing chat",
                "customer-facing chatbot",
            }
        ),
        "customer_support_bot",
    ),
    (
        frozenset(
            {
                "customer-facing",
                "customer facing",
                "external user",
                "public website",
                "self-service portal",
                "for customers",
                "b2c",
                "retail bank",
            }
        ),
        "customer_facing",
    ),
    (frozenset({"internal assistant", "internal knowledge", "employee assistant", "sharepoint", "confluence", "company wiki"}), "internal_knowledge"),
    (frozenset({"employee portal", "intranet only", "staff-only", "internal only", "internal-only"}), "internal_only"),
    (frozenset({"financial", "bank", "insurance", "wealth", "pci", "trading", "underwriting", "loan"}), "financial_services"),
    (frozenset({"pii", "personally identifiable", "personal data", "gdpr"}), "pii"),
    (frozenset({"phi", "patient", "ehr", "clinical", "hipaa", "diagnosis"}), "phi"),
    (frozenset({"health", "hospital", "medical", "care plan", "prior authorization"}), "healthcare"),
    (frozenset({"government", "agency", "citizen", "municipal", "federal", "public sector"}), "public_sector"),
    (
        frozenset(
            {
                "hiring",
                "recruit",
                "candidate",
                "performance review",
                "hr ",
                "human resources",
                "workforce",
                "employee policy",
                "policy questions",
                "pto",
                "parental leave",
                "benefits questions",
            }
        ),
        "hr_employment",
    ),
    (frozenset({"high-stakes", "high stakes", "safety-critical", "clinical decision", "credit decision", "legal advice"}), "high_stakes"),
    (frozenset({"regulated", "soc2", "soc 2", "sox", "fedramp", "compliance", "audit", "pci", "baa", "hipaa"}), "regulated"),
    (frozenset({"bias", "fair lending", "eea", "disparate impact", "protected class"}), "bias_sensitive"),
    (
        frozenset(
            {"rag", "retrieval", "vector database", "vector index", "grounding", "knowledge base", "enterprise documents"}
        ),
        "retrieval",
    ),
    (
        frozenset(
            {
                "agent",
                "agentic",
                "tools",
                "tool use",
                "plugin",
                "mcp",
                "function calling",
                "create ticket",
                "ticket creation",
                "service ticket",
                "trigger action",
                "orchestrat",
                "workflow",
                "invoke api",
                "call api",
                "rest api",
                "rest apis",
                "api integration",
            }
        ),
        "agentic_tools",
    ),
    (frozenset({"fine-tun", "fine tun", "lora", "peft", "custom weights"}), "fine_tuned"),
    (
        frozenset(
            {
                "openai",
                "anthropic",
                "azure openai",
                "bedrock",
                "vertex",
                "hosted model",
                "hosted llm",
                "third-party model",
                "vendor model",
                "api llm",
            }
        ),
        "third_party_model",
    ),
    (frozenset({"github copilot", "code assist", "developer productivity", "ide assistant"}), "developer_tools"),
    (frozenset({"copilot", "draft email", "writing assistant", "summarize attachments"}), "copilot_pattern"),
    (frozenset({"generate code", "pull request", "unit test", "refactor code"}), "code_generation"),
    # Untrusted / external ingestion (prompt injection surface beyond managed internal corpus)
    (
        frozenset(
            {
                "untrusted",
                "user upload",
                "public internet",
                "internet source",
                "web scrap",
                "web crawl",
                "scrape",
                "malicious document",
                "unknown sender",
                "email attachment",
                "paste from",
                "ticketing system",
                "ticket body",
                "anonymous",
            }
        ),
        "untrusted_content",
    ),
    (
        frozenset(
            {
                "external vendor",
                "third-party feed",
                "third-party pdf",
                "vendor portal",
                "public website content",
                "news feed",
                "external api",
                "data broker",
            }
        ),
        "external_content",
    ),
)
# Explicit high-risk context for priority scoring (consulting-facing rubric).
_HIGH_RISK_PRIORITY_TAGS = frozenset({"customer_facing", "action_execution", "sensitive_data"})
# Tags that indicate confidential or regulated subject matter → derived sensitive_data.
_SENSITIVE_BASE_TAGS = frozenset(
    {"pii", "phi", "financial_data", "financial_services", "healthcare", "hr_employment", "high_stakes"}
)
_CUSTOMER_AUDIENCE_TAGS = frozenset({"customer_facing", "customer_support_bot"})
_INTERNAL_AUDIENCE_TAGS = frozenset({"internal_only", "internal_knowledge"})
_ACTION_FALLBACK_PHRASES = frozenset(
    {
        "agentic",
        "function calling",
        "tool use",
        "invoke api",
        "call api",
        "create ticket",
        "trigger action",
        "mcp",
        "workflow automation",
    }
)
AudienceKind = Literal["customer_facing", "internal", "unknown"]
AutonomyKind = Literal["action_taking", "read_only", "unknown"]
ProvenanceKind = Literal["external_untrusted", "controlled_internal", "mixed", "unknown"]
@dataclass(frozen=True)
class InferenceAxes:
    """Second-layer, rule-based view of the use case (no LLM)."""
    audience: AudienceKind
    autonomy: AutonomyKind
    data_provenance: ProvenanceKind
def _infer_axes(tags: FrozenSet[str], normalized_text: str) -> InferenceAxes:
    """Infer axes from first-layer tags plus a short phrase fallback only for action-taking."""
    tagset = set(tags)
    if tagset & _CUSTOMER_AUDIENCE_TAGS:
        audience: AudienceKind = "customer_facing"
    elif tagset & _INTERNAL_AUDIENCE_TAGS:
        audience = "internal"
    else:
        audience = "unknown"
    if "agentic_tools" in tagset:
        autonomy: AutonomyKind = "action_taking"
    elif any(p in normalized_text for p in _ACTION_FALLBACK_PHRASES):
        autonomy = "action_taking"
    elif any(p in normalized_text for p in ("read-only", "read only", "summarization only", "question answering only")):
        autonomy = "read_only"
    else:
        autonomy = "unknown"
    if tagset & {"untrusted_content", "external_content"}:
        data_provenance: ProvenanceKind = "external_untrusted"
    elif tagset & {"internal_knowledge", "internal_only"} and not (tagset & {"untrusted_content", "external_content", "customer_facing", "customer_support_bot"}):
        data_provenance = "controlled_internal"
    elif tagset & {"customer_facing", "customer_support_bot"} and (tagset & {"untrusted_content", "external_content", "retrieval"}):
        data_provenance = "mixed"
    elif "retrieval" in tagset or "knowledge base" in normalized_text:
        if tagset & {"untrusted_content", "external_content"}:
            data_provenance = "external_untrusted"
        elif tagset & _CUSTOMER_AUDIENCE_TAGS:
            data_provenance = "mixed"
        else:
            data_provenance = "controlled_internal"
    else:
        data_provenance = "unknown"
    return InferenceAxes(audience=audience, autonomy=autonomy, data_provenance=data_provenance)
def _apply_derived_tags(found: set[str], axes: InferenceAxes, normalized_text: str) -> None:
    """Add stable derived tags for scoring and reporting (additive)."""
    if (
        axes.data_provenance in ("external_untrusted", "mixed")
        or found & {"untrusted_content", "external_content"}
        or (axes.audience == "customer_facing" and ("user message" in normalized_text or "end user" in normalized_text or "customer input" in normalized_text))
    ):
        found.add("untrusted_input")
    if axes.autonomy == "action_taking" or "agentic_tools" in found:
        found.add("action_execution")
    if found & _SENSITIVE_BASE_TAGS:
        found.add("sensitive_data")
def mapping_priority_score(risk: Risk, tags: FrozenSet[str], edge_weight: int = 1) -> int:
    """
    Priority on 0–100: weighted sum with severity dominant, then likelihood, breadth,
    explicit high-risk context tags, small trigger overlap, tiny edge tie-break.
    Components are documented so sponsors can trace why a row ranks where it does.
    """
    sev = SEVERITY_RANK[risk.severity]
    lik = LIKELIHOOD_RANK[risk.likelihood]
    # Severity (largest slice): Critical..Low maps to a clear step function (~40 pts max).
    severity_pts = {1: 10, 2: 22, 3: 32, 4: 42}[sev]
    # Likelihood: separate from severity so "High / High" does not explode via multiplication.
    likelihood_pts = {1: 6, 2: 14, 3: 20}[lik]
    # Impact domain breadth: more stakeholder concern areas → slightly higher rank (capped).
    n_dom = len(risk.impact_domain)
    domain_pts = min(12, n_dom * 4)
    # High-risk posture tags requested for transparency (cap so tags never outweigh severity).
    hr_hits = tags & _HIGH_RISK_PRIORITY_TAGS
    high_risk_pts = min(12, 4 * len(hr_hits))
    # Catalog alignment: reward concrete tag↔risk linkage without large discontinuous jumps.
    overlap = len(risk.trigger_tags & tags)
    overlap_pts = min(6, 2 * overlap)
    # Secondary controls for the same risk: modest tie-break only.
    tie_pts = min(2, max(0, edge_weight - 1))
    total = severity_pts + likelihood_pts + domain_pts + high_risk_pts + overlap_pts + tie_pts
    return int(max(0, min(100, total)))
@dataclass(frozen=True)
class MatchResult:
    tags: FrozenSet[str]
    selected_risks: Tuple[Risk, ...]
    edges: Tuple[RiskControlEdge, ...]
def normalize_text(text: str) -> str:
    return " ".join(text.lower().split())
def infer_tags(use_case_text: str, extra_tags: Sequence[str] | None = None) -> FrozenSet[str]:
    t = normalize_text(use_case_text)
    found: set[str] = set()
    for phrases, tag in _RULES:
        if any(p in t for p in phrases):
            found.add(tag)
    if extra_tags:
        for x in extra_tags:
            if x in ALL_KNOWN_TAGS:
                found.add(x)
    if "llm" in t or "large language" in t or "generative ai" in t or "genai" in t:
        found.add("third_party_model")
    if "chatbot" in t and "customer_support_bot" not in found and "customer-facing" in t:
        found.add("customer_support_bot")
    if (
        "assistant" in t
        and "customer-facing" not in t
        and "customer facing" not in t
        and "for customers" not in t
        and ("internal-only" in t or "internal assistant" in t or "employee assistant" in t)
    ):
        found.add("internal_knowledge")
    if "patient" in t or "clinical" in t or "ehr" in t:
        found.update({"healthcare", "phi"})
    if "patient" in t and any(w in t for w in ("communication", "communications", "draft", "message", "discharge")):
        found.add("high_stakes")
    if "ehr" in t or "education sheets" in t or "clinical note" in t:
        found.add("retrieval")
    if "rag" in t or "retrieval" in t or "vector" in t:
        if "financial" in t or "bank" in t or "wealth" in t:
            found.add("financial_services")
    if ("employee" in t or "staff" in t) and any(w in t for w in ("policy", "policies", "pto", "benefits", "hr")):
        found.add("internal_knowledge")
    if "wire" in t or "payment" in t or "kyc" in t:
        found.add("financial_services")
    axes = _infer_axes(frozenset(found), t)
    _apply_derived_tags(found, axes, t)
    return frozenset(found)
def select_risks(tags: FrozenSet[str]) -> Tuple[Risk, ...]:
    if not tags:
        return tuple()
    chosen: List[Risk] = []
    for risk in RISKS:
        if risk.trigger_tags & tags:
            chosen.append(risk)
    if not chosen:
        return tuple(r for r in RISKS if r.id in {"R-001", "R-004", "R-007", "R-009", "R-011", "R-012"})
    return tuple(chosen)
def edges_for_risks(risks: Sequence[Risk]) -> Tuple[RiskControlEdge, ...]:
    risk_ids = {r.id for r in risks}
    selected_edges: Tuple[RiskControlEdge, ...] = tuple(e for e in EDGES if e.risk_id in risk_ids)
    return selected_edges
def match_use_case(use_case_text: str, extra_tags: Sequence[str] | None = None) -> MatchResult:
    tags = infer_tags(use_case_text, extra_tags)
    risks = select_risks(tags)
    edges = edges_for_risks(risks)
    return MatchResult(tags=tags, selected_risks=risks, edges=edges)
