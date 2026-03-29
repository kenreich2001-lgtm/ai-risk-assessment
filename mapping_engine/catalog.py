"""Risk and control catalog + risk→control edges."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from mapping_engine.taxonomy import (
    AIRMFRef,
    CoverageKind,
    ControlType,
    GAIProfileRef,
    GAI_AUTOMATION,
    GAI_DATA_SCALE,
    GAI_STOCHASTIC,
    GAI_SUPPLY,
    GAI_TRANSPARENCY,
    GAI_USER_INFL,
    GOVERN_ACCOUNTABILITY,
    GOVERN_POLICIES,
    MANAGE_INCIDENT,
    MANAGE_RESPOND,
    MAP_CATEGORIZATION,
    MAP_CONTEXT,
    MAP_IMPACT,
    MEASURE_ANALYZE,
    MEASURE_IDENTIFY,
    MEASURE_MONITOR,
    RiskLikelihood,
    RiskSeverity,
)


@dataclass(frozen=True)
class Risk:
    id: str
    name: str
    description: str
    nist: Tuple[AIRMFRef, ...]
    gai: Tuple[GAIProfileRef, ...]
    trigger_tags: frozenset[str]
    severity: RiskSeverity
    likelihood: RiskLikelihood
    impact_domain: Tuple[str, ...]
    residual_risk: str


@dataclass(frozen=True)
class Control:
    id: str
    name: str
    description: str
    nist: Tuple[AIRMFRef, ...]
    gai: Tuple[GAIProfileRef, ...]
    control_type: ControlType
    coverage: CoverageKind


@dataclass(frozen=True)
class RiskControlEdge:
    risk_id: str
    control_id: str
    rationale_key: str
    remediation_key: str
    weight: int = 1


RISKS: Tuple[Risk, ...] = (
    Risk(
        id="R-001",
        name="Harmful or unreliable outputs",
        description=(
            "Incorrect, misleading, or unsafe generations—including hallucinations and "
            "overconfident tone—cause bad decisions or user harm in context."
        ),
        nist=(MAP_IMPACT, MEASURE_ANALYZE, MANAGE_RESPOND),
        gai=(GAI_STOCHASTIC, GAI_USER_INFL),
        trigger_tags=frozenset(
            {"customer_facing", "customer_support_bot", "high_stakes", "regulated", "healthcare", "public_sector", "financial_services"}
        ),
        severity="High",
        likelihood="High",
        impact_domain=("Safety", "Reliability", "Legal/Compliance"),
        residual_risk="Tail failures and emergent regressions may still occur after vendor or prompt changes.",
    ),
    Risk(
        id="R-002",
        name="Privacy and confidentiality breach",
        description=(
            "PII/PHI or business secrets leak via model outputs, retrieval corpora, logging, "
            "or vendor processing without adequate boundaries."
        ),
        nist=(MAP_CONTEXT, MAP_CATEGORIZATION, MANAGE_RESPOND),
        gai=(GAI_DATA_SCALE, GAI_USER_INFL),
        trigger_tags=frozenset({"pii", "phi", "financial_data", "regulated", "retrieval", "customer_facing", "internal_knowledge"}),
        severity="High",
        likelihood="Medium",
        impact_domain=("Privacy", "Legal/Compliance"),
        residual_risk="Zero leak guarantee is infeasible; insider abuse or novel exfiltration paths may remain.",
    ),
    Risk(
        id="R-003",
        name="Prompt injection and untrusted content",
        description=(
            "Adversarial instructions in user input or ingested documents override safeguards, "
            "exfiltrate context, or trigger unsafe tool use."
        ),
        nist=(MAP_CONTEXT, MEASURE_MONITOR, MANAGE_INCIDENT),
        gai=(GAI_USER_INFL, GAI_AUTOMATION),
        trigger_tags=frozenset(
            {
                "customer_facing",
                "agentic_tools",
                "third_party_model",
                "customer_support_bot",
                "untrusted_content",
                "external_content",
            }
        ),
        severity="High",
        likelihood="High",
        impact_domain=("Security", "Privacy"),
        residual_risk="Motivated attackers adapt faster than static filters; layered defenses still have seams.",
    ),
    Risk(
        id="R-004",
        name="Third-party model supply-chain exposure",
        description=(
            "Hosted APIs introduce dependency on vendor security, versioning, data retention, "
            "and opaque behavior shifts."
        ),
        nist=(MAP_CATEGORIZATION, GOVERN_ACCOUNTABILITY, MANAGE_RESPOND),
        gai=(GAI_SUPPLY, GAI_TRANSPARENCY),
        trigger_tags=frozenset({"third_party_model"}),
        severity="Medium",
        likelihood="High",
        impact_domain=("Reliability", "Security", "Legal/Compliance"),
        residual_risk="Vendor-side incidents and silent updates remain outside full enterprise control.",
    ),
    Risk(
        id="R-005",
        name="Insufficient human oversight",
        description=(
            "Unclear accountability, missing approvals, or rubber-stamping recommendations in "
            "high-impact contexts (employment, care, finance, public services)."
        ),
        nist=(GOVERN_POLICIES, GOVERN_ACCOUNTABILITY, MAP_IMPACT),
        gai=(GAI_USER_INFL,),
        trigger_tags=frozenset({"high_stakes", "hr_employment", "regulated", "public_sector", "healthcare", "financial_services"}),
        severity="High",
        likelihood="Medium",
        impact_domain=("Legal/Compliance", "Fairness", "Safety"),
        residual_risk="Human reviewers can still err or face pressure to agree with the model.",
    ),
    Risk(
        id="R-006",
        name="Tool/agent over-privilege",
        description=(
            "Model-issued actions (tickets, payments, data writes) exceed least privilege "
            "or bypass segregation of duties."
        ),
        nist=(MAP_CONTEXT, MEASURE_IDENTIFY, MANAGE_RESPOND),
        gai=(GAI_AUTOMATION, GAI_USER_INFL),
        trigger_tags=frozenset({"agentic_tools"}),
        severity="Critical",
        likelihood="Medium",
        impact_domain=("Security", "Reliability", "Legal/Compliance"),
        residual_risk="New tools or emergency break-glass paths can reintroduce excessive scope.",
    ),
    Risk(
        id="R-007",
        name="Evaluation drift and monitoring gaps",
        description=(
            "Quality, safety, and compliance posture erodes as data, prompts, integrations, "
            "or upstream models change without detected regression."
        ),
        nist=(MEASURE_IDENTIFY, MEASURE_ANALYZE, MEASURE_MONITOR),
        gai=(GAI_STOCHASTIC, GAI_SUPPLY),
        trigger_tags=frozenset({"fine_tuned", "third_party_model", "customer_facing", "high_stakes", "financial_services", "healthcare"}),
        severity="Medium",
        likelihood="High",
        impact_domain=("Reliability", "Legal/Compliance"),
        residual_risk="Monitoring cannot exhaustive-cover all user journeys and rare harm scenarios.",
    ),
    Risk(
        id="R-008",
        name="Bias and disparate impact",
        description=(
            "Outputs or ranking behavior systematically disadvantage protected or sensitive groups "
            "in hiring, service, or eligibility contexts."
        ),
        nist=(MAP_IMPACT, MEASURE_ANALYZE, GOVERN_POLICIES),
        gai=(GAI_DATA_SCALE, GAI_STOCHASTIC, GAI_USER_INFL),
        trigger_tags=frozenset({"hr_employment", "bias_sensitive", "customer_facing", "financial_services", "regulated", "public_sector"}),
        severity="High",
        likelihood="Medium",
        impact_domain=("Fairness", "Legal/Compliance", "Reputation"),
        residual_risk="Statistical fairness metrics may not capture all substantive harms or intersectionality.",
    ),
    Risk(
        id="R-009",
        name="Overreliance and automation bias",
        description=(
            "Users treat fluent text as authoritative, skip verification, or under-weight "
            "contradictory evidence—especially in internal assistants and copilots."
        ),
        nist=(MAP_IMPACT, GOVERN_POLICIES, MANAGE_RESPOND),
        gai=(GAI_STOCHASTIC, GAI_USER_INFL),
        trigger_tags=frozenset({"internal_knowledge", "copilot_pattern", "customer_support_bot", "developer_tools", "code_generation"}),
        severity="Medium",
        likelihood="High",
        impact_domain=("Reliability", "Safety", "Legal/Compliance"),
        residual_risk="Behavioral nudges reduce but do not eliminate complacency under time pressure.",
    ),
    Risk(
        id="R-010",
        name="Insecure handling of model outputs",
        description=(
            "Downstream systems render or execute model output unsafely (e.g., injection into "
            "UI, documents, or tickets; secrets echoed into logs)."
        ),
        nist=(MANAGE_RESPOND, MANAGE_INCIDENT, MAP_CONTEXT),
        gai=(GAI_USER_INFL, GAI_AUTOMATION),
        trigger_tags=frozenset({"agentic_tools", "customer_support_bot", "code_generation", "developer_tools", "internal_knowledge"}),
        severity="High",
        likelihood="Medium",
        impact_domain=("Security", "Privacy"),
        residual_risk="Novel downstream integrations may omit sanitization until retrospectively found.",
    ),
    Risk(
        id="R-011",
        name="Model misuse and abuse",
        description=(
            "Scraping, prompt spam, policy violations, jailbreak attempts, or resource exhaustion "
            "against shared AI endpoints."
        ),
        nist=(GOVERN_POLICIES, MEASURE_MONITOR, MANAGE_INCIDENT),
        gai=(GAI_USER_INFL, GAI_SUPPLY),
        trigger_tags=frozenset({"customer_facing", "third_party_model", "customer_support_bot"}),
        severity="Medium",
        likelihood="High",
        impact_domain=("Security", "Reliability", "Reputation"),
        residual_risk="Determined actors evolve evasion; shared models remain attractive targets.",
    ),
    Risk(
        id="R-012",
        name="Weak authentication and authorization",
        description=(
            "Endpoints, admin consoles, or retrieval backends lack robust IAM—allowing data or "
            "capability access beyond user roles."
        ),
        nist=(MAP_CONTEXT, GOVERN_POLICIES, MANAGE_RESPOND),
        gai=(GAI_DATA_SCALE, GAI_USER_INFL),
        trigger_tags=frozenset({"retrieval", "internal_knowledge", "pii", "phi", "financial_data", "agentic_tools"}),
        severity="High",
        likelihood="Medium",
        impact_domain=("Security", "Privacy", "Legal/Compliance"),
        residual_risk="Misconfigured RBAC or service accounts can reopen lateral movement paths.",
    ),
    Risk(
        id="R-013",
        name="Training/tuning/RAG data provenance gaps",
        description=(
            "Unclear origin, license, or quality of corpora—risk of poisoned retrieval, IP "
            "infringement, or toxic/biased source dominance."
        ),
        nist=(MAP_CATEGORIZATION, MAP_CONTEXT, MEASURE_ANALYZE),
        gai=(GAI_DATA_SCALE, GAI_TRANSPARENCY),
        trigger_tags=frozenset({"retrieval", "fine_tuned", "internal_knowledge", "financial_services", "healthcare"}),
        severity="Medium",
        likelihood="Medium",
        impact_domain=("Legal/Compliance", "Reliability", "Fairness"),
        residual_risk="Provenance paperwork can lag reality for rapidly changing document stores.",
    ),
    Risk(
        id="R-014",
        name="Inadequate AI incident response",
        description=(
            "No defined playbooks for model incidents (silent quality collapse, data spill via prompt, "
            "tool mis-invocation)—slow containment and notification."
        ),
        nist=(MANAGE_INCIDENT, GOVERN_POLICIES, MEASURE_MONITOR),
        gai=(GAI_AUTOMATION, GAI_SUPPLY),
        trigger_tags=frozenset({"regulated", "high_stakes", "agentic_tools", "healthcare", "financial_services", "public_sector"}),
        severity="High",
        likelihood="Medium",
        impact_domain=("Legal/Compliance", "Reputation", "Reliability"),
        residual_risk="Tabletop accuracy does not guarantee execution quality during real outages.",
    ),
)

CONTROLS: Tuple[Control, ...] = (
    Control(
        id="C-EVAL",
        name="Task-specific evaluation and red-teaming",
        description="Benchmarks, adversarial suites, regression gates tied to tasks and personas.",
        nist=(MEASURE_IDENTIFY, MEASURE_ANALYZE, MEASURE_MONITOR),
        gai=(GAI_STOCHASTIC, GAI_USER_INFL),
        control_type="technical",
        coverage="detective",
    ),
    Control(
        id="C-HUMAN",
        name="Human-in-the-loop and approval gates",
        description="Defined reviewers, SLAs, segregation of duties, audit trail for overrides.",
        nist=(GOVERN_ACCOUNTABILITY, MAP_IMPACT, MANAGE_RESPOND),
        gai=(GAI_USER_INFL,),
        control_type="procedural",
        coverage="corrective",
    ),
    Control(
        id="C-DATA-GOV",
        name="Data minimization, classification, and lineage",
        description="Data inventory, classification-driven access, retention, vendor DPA alignment.",
        nist=(MAP_CONTEXT, MAP_CATEGORIZATION, GOVERN_POLICIES),
        gai=(GAI_DATA_SCALE,),
        control_type="administrative",
        coverage="preventive",
    ),
    Control(
        id="C-LOG",
        name="Telemetry, audit logs, and traceability",
        description="Trace IDs, policy-aware logging, tamper-evident storage, access monitoring.",
        nist=(MEASURE_MONITOR, MANAGE_INCIDENT, GOVERN_POLICIES),
        gai=(GAI_DATA_SCALE, GAI_USER_INFL),
        control_type="technical",
        coverage="detective",
    ),
    Control(
        id="C-GUARD",
        name="Input/output policy enforcement",
        description="Filters, structured outputs, untrusted-doc isolation, rate limits.",
        nist=(MANAGE_RESPOND, MEASURE_MONITOR),
        gai=(GAI_USER_INFL, GAI_AUTOMATION),
        control_type="technical",
        coverage="preventive",
    ),
    Control(
        id="C-VENDOR",
        name="Vendor and model change management",
        description="Contracts, subprocessors, version pinning, breaking-change testing, exit options.",
        nist=(GOVERN_POLICIES, MANAGE_RESPOND, MAP_CATEGORIZATION),
        gai=(GAI_SUPPLY, GAI_TRANSPARENCY),
        control_type="administrative",
        coverage="compensating",
    ),
    Control(
        id="C-TOOLS",
        name="Least-privilege tool integration",
        description="Scoped credentials, allow-listed actions, confirmations, circuit breakers.",
        nist=(MAP_CONTEXT, MEASURE_IDENTIFY, MANAGE_RESPOND),
        gai=(GAI_AUTOMATION,),
        control_type="technical",
        coverage="preventive",
    ),
    Control(
        id="C-DOC",
        name="System documentation and disclosure",
        description="Model/system cards, limitations, residual risks, stakeholder comms.",
        nist=(MAP_IMPACT, GOVERN_ACCOUNTABILITY, GOVERN_POLICIES),
        gai=(GAI_TRANSPARENCY, GAI_STOCHASTIC),
        control_type="administrative",
        coverage="preventive",
    ),
    Control(
        id="C-FAIR",
        name="Fairness and bias testing program",
        description="Disaggregated metrics, disparity testing, sensitive-use review boards.",
        nist=(MEASURE_ANALYZE, MAP_IMPACT, GOVERN_POLICIES),
        gai=(GAI_DATA_SCALE, GAI_STOCHASTIC),
        control_type="procedural",
        coverage="detective",
    ),
    Control(
        id="C-AUTO-SAFE",
        name="Automation-bias safeguards",
        description="UX friction for high-risk paths, required citations, confidence/uncertainty cues, training.",
        nist=(MAP_IMPACT, GOVERN_POLICIES, MANAGE_RESPOND),
        gai=(GAI_USER_INFL, GAI_STOCHASTIC),
        control_type="procedural",
        coverage="compensating",
    ),
    Control(
        id="C-OUT-SAFE",
        name="Output sanitization and secure rendering",
        description="Encoding/safe templates for downstream UIs, secret scanners, attachment policies.",
        nist=(MANAGE_RESPOND, MAP_CONTEXT),
        gai=(GAI_USER_INFL, GAI_AUTOMATION),
        control_type="technical",
        coverage="preventive",
    ),
    Control(
        id="C-ABUSE",
        name="Abuse prevention and acceptable use",
        description="AUP, throttling, bot detection, anomaly alerts, account action workflows.",
        nist=(GOVERN_POLICIES, MEASURE_MONITOR, MANAGE_INCIDENT),
        gai=(GAI_USER_INFL,),
        control_type="administrative",
        coverage="detective",
    ),
    Control(
        id="C-IAM",
        name="Strong IAM for AI services and data planes",
        description="Federation, RBAC/ABAC, scoped API keys, retrieval tenancy isolation.",
        nist=(MAP_CONTEXT, GOVERN_POLICIES, MANAGE_RESPOND),
        gai=(GAI_DATA_SCALE, GAI_USER_INFL),
        control_type="technical",
        coverage="preventive",
    ),
    Control(
        id="C-PROV",
        name="Corpus provenance and ingestion QA",
        description="Source attestations, license checks, ingestion tests, poison detection sampling.",
        nist=(MAP_CATEGORIZATION, MAP_CONTEXT, MEASURE_ANALYZE),
        gai=(GAI_DATA_SCALE, GAI_TRANSPARENCY),
        control_type="procedural",
        coverage="preventive",
    ),
    Control(
        id="C-IR-AI",
        name="AI-specific incident response",
        description="Runbooks for model rollback, prompt data spill, tool misuse; comms and RCA templates.",
        nist=(MANAGE_INCIDENT, GOVERN_POLICIES, MEASURE_MONITOR),
        gai=(GAI_AUTOMATION, GAI_SUPPLY),
        control_type="procedural",
        coverage="corrective",
    ),
)

EDGES: Tuple[RiskControlEdge, ...] = (
    RiskControlEdge("R-001", "C-EVAL", "unreliable_output", "eval_harness"),
    RiskControlEdge("R-001", "C-HUMAN", "unreliable_output", "human_review"),
    RiskControlEdge("R-001", "C-DOC", "unreliable_output", "document_limits"),
    RiskControlEdge("R-001", "C-GUARD", "unreliable_output", "iop_controls"),
    RiskControlEdge("R-001", "C-AUTO-SAFE", "unreliable_output", "automation_bias"),
    RiskControlEdge("R-002", "C-DATA-GOV", "privacy", "data_minimization"),
    RiskControlEdge("R-002", "C-LOG", "privacy", "logging_privacy"),
    RiskControlEdge("R-002", "C-GUARD", "privacy", "output_controls"),
    RiskControlEdge("R-002", "C-IAM", "privacy", "iam_data_plane"),
    RiskControlEdge("R-003", "C-GUARD", "injection", "untrusted_content"),
    RiskControlEdge("R-003", "C-LOG", "injection", "detection_monitoring"),
    RiskControlEdge("R-003", "C-TOOLS", "injection", "tool_sandbox"),
    RiskControlEdge("R-003", "C-IR-AI", "injection", "ir_injection"),
    RiskControlEdge("R-004", "C-VENDOR", "supply_chain", "vendor_mgmt"),
    RiskControlEdge("R-004", "C-EVAL", "supply_chain", "version_regression"),
    RiskControlEdge("R-004", "C-DOC", "supply_chain", "vendor_disclosure"),
    RiskControlEdge("R-005", "C-HUMAN", "oversight", "governance_roles"),
    RiskControlEdge("R-005", "C-DOC", "oversight", "accountability_docs"),
    RiskControlEdge("R-005", "C-AUTO-SAFE", "oversight", "automation_bias"),
    RiskControlEdge("R-006", "C-TOOLS", "agent_safety", "least_priv_tools"),
    RiskControlEdge("R-006", "C-GUARD", "agent_safety", "action_gates"),
    RiskControlEdge("R-006", "C-HUMAN", "agent_safety", "human_approval"),
    RiskControlEdge("R-006", "C-IR-AI", "agent_safety", "ir_tool_misuse"),
    RiskControlEdge("R-007", "C-EVAL", "monitoring", "continuous_eval"),
    RiskControlEdge("R-007", "C-LOG", "monitoring", "production_metrics"),
    RiskControlEdge("R-007", "C-VENDOR", "monitoring", "vendor_change"),
    RiskControlEdge("R-008", "C-FAIR", "bias", "fairness_program"),
    RiskControlEdge("R-008", "C-HUMAN", "bias", "bias_human_review"),
    RiskControlEdge("R-008", "C-PROV", "bias", "corpus_fairness"),
    RiskControlEdge("R-008", "C-DOC", "bias", "bias_disclosure"),
    RiskControlEdge("R-009", "C-AUTO-SAFE", "automation_bias", "automation_bias"),
    RiskControlEdge("R-009", "C-DOC", "automation_bias", "reliance_training"),
    RiskControlEdge("R-009", "C-EVAL", "automation_bias", "behavioral_eval"),
    RiskControlEdge("R-010", "C-OUT-SAFE", "output_security", "output_pipeline"),
    RiskControlEdge("R-010", "C-LOG", "output_security", "secret_leak_detect"),
    RiskControlEdge("R-010", "C-GUARD", "output_security", "structured_output"),
    RiskControlEdge("R-011", "C-ABUSE", "abuse", "abuse_controls"),
    RiskControlEdge("R-011", "C-GUARD", "abuse", "rate_policy"),
    RiskControlEdge("R-011", "C-IAM", "abuse", "fraud_iam"),
    RiskControlEdge("R-012", "C-IAM", "iam", "iam_full"),
    RiskControlEdge("R-012", "C-DATA-GOV", "iam", "data_gov_iam"),
    RiskControlEdge("R-012", "C-LOG", "iam", "access_anomaly"),
    RiskControlEdge("R-013", "C-PROV", "provenance", "provenance_full"),
    RiskControlEdge("R-013", "C-DATA-GOV", "provenance", "corpus_gov"),
    RiskControlEdge("R-013", "C-EVAL", "provenance", "rag_qa_gold"),
    RiskControlEdge("R-014", "C-IR-AI", "incident", "ir_playbooks"),
    RiskControlEdge("R-014", "C-LOG", "incident", "forensics_ready"),
    RiskControlEdge("R-014", "C-VENDOR", "incident", "vendor_notify"),
)

_CONTROL_BY_ID: Dict[str, Control] = {c.id: c for c in CONTROLS}
_RISK_BY_ID: Dict[str, Risk] = {r.id: r for r in RISKS}


def get_control(control_id: str) -> Control:
    return _CONTROL_BY_ID[control_id]


def get_risk(risk_id: str) -> Risk:
    return _RISK_BY_ID[risk_id]


def edges_for_risk(risk_id: str) -> List[RiskControlEdge]:
    return [e for e in EDGES if e.risk_id == risk_id]
