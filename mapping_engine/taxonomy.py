"""
Stable labels for NIST AI RMF (AI 100-1) and Generative AI Profile (AI 600-1) alignment.

Includes shared enumerations for risks and controls used across the catalog and matcher.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Literal

# --- Risk rubric ---
RiskSeverity = Literal["Critical", "High", "Medium", "Low"]
RiskLikelihood = Literal["High", "Medium", "Low"]

# --- Control rubric ---
ControlType = Literal["administrative", "technical", "procedural"]
CoverageKind = Literal["preventive", "detective", "corrective", "compensating"]

SEVERITY_RANK: dict[str, int] = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
LIKELIHOOD_RANK: dict[str, int] = {"High": 3, "Medium": 2, "Low": 1}


@dataclass(frozen=True)
class AIRMFRef:
    function: str
    category_id: str
    category_name: str


@dataclass(frozen=True)
class GAIProfileRef:
    code: str
    name: str
    notes: str = ""


# Primary AI RMF categories
GOVERN_POLICIES = AIRMFRef("Govern", "GOV-1", "Policies, processes, procedures, and governance")
GOVERN_ACCOUNTABILITY = AIRMFRef("Govern", "GOV-2", "Roles, responsibility, and accountability")
MAP_CONTEXT = AIRMFRef("Map", "MAP-1", "Context is established and understood")
MAP_CATEGORIZATION = AIRMFRef("Map", "MAP-2", "Categorization of the AI system")
MAP_IMPACT = AIRMFRef("Map", "MAP-3", "Impacts are characterized")
MEASURE_IDENTIFY = AIRMFRef("Measure", "MSR-1", "Appropriate methods and metrics are identified")
MEASURE_ANALYZE = AIRMFRef("Measure", "MSR-2", "Trustworthiness characteristics are analyzed")
MEASURE_MONITOR = AIRMFRef("Measure", "MSR-3", "Continual monitoring and assessment")
MANAGE_RESPOND = AIRMFRef("Manage", "MNG-1", "Risks are managed and prioritized")
MANAGE_INCIDENT = AIRMFRef("Manage", "MNG-2", "Incident response, recovery, and communication")

# GAI Profile themes
GAI_DATA_SCALE = GAIProfileRef("GAI-DATA", "Broad / heterogeneous data exposure", "Training, tuning, or retrieval corpora")
GAI_STOCHASTIC = GAIProfileRef("GAI-OUT", "Stochastic outputs", "Non-determinism and hallucination paths")
GAI_USER_INFL = GAIProfileRef("GAI-UX", "User-in-the-loop and prompt surface", "Prompt injection, misuse, content policy")
GAI_TRANSPARENCY = GAIProfileRef("GAI-TRANS", "Transparency and explainability limits", "Vendor/black-box model constraints")
GAI_SUPPLY = GAIProfileRef("GAI-SUP", "Third-party model / platform dependence", "API and supply-chain risk")
GAI_AUTOMATION = GAIProfileRef("GAI-AUTO", "Automation and tool use", "Agents, plugins, elevated privileges")


def format_nist_refs(*refs: AIRMFRef) -> str:
    return "; ".join(f"{r.function} ({r.category_id}: {r.category_name})" for r in refs)


def format_gai_refs(*refs: GAIProfileRef) -> str:
    return "; ".join(f"{r.code} — {r.name}" for r in refs)


ALL_KNOWN_TAGS: FrozenSet[str] = frozenset(
    {
        "customer_facing",
        "customer_support_bot",
        "internal_knowledge",
        "internal_only",
        "high_stakes",
        "regulated",
        "pii",
        "phi",
        "financial_data",
        "financial_services",
        "agentic_tools",
        "retrieval",
        "fine_tuned",
        "third_party_model",
        "code_generation",
        "hr_employment",
        "healthcare",
        "public_sector",
        "bias_sensitive",
        "developer_tools",
        "copilot_pattern",
        "untrusted_content",
        "external_content",
    }
)
