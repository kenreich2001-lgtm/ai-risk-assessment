"""
Deterministic regulatory overlay, risk governance tags, and remediation enrichment.

This layer sits **above** the existing assessment engine outputs. It does not determine
legal applicability or compliance; it informs prioritization, tagging, and narrative framing.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

# ---------------------------------------------------------------------------
# Industry / specialization overlay (curated, high-level)
# ---------------------------------------------------------------------------

_DEFAULT_GENERIC = {
    "frameworks": ("NIST AI RMF", "NIST AI 600-1 themes (organizational practice)"),
    "regulatory_themes": ("trustworthy AI practices", "human oversight for consequential outputs"),
    "control_emphasis": ("documentation and ownership", "monitoring and incident response"),
}

REGULATORY_OVERLAY: dict[str, dict[str, dict[str, tuple[str, ...]]]] = {
    "Financial Services": {
        "Banking": {
            "frameworks": (
                "SR 11-7 (Federal Reserve model risk management)",
                "OCC Bulletin 2011-12 (model validation)",
                "FFIEC IT examination handbook (risk management expectations)",
                "GLBA",
                "NYDFS Cybersecurity Regulation",
            ),
            "regulatory_themes": (
                "model validation and independent review",
                "fair and transparent customer decisioning",
                "third-party and vendor resilience",
            ),
            "control_emphasis": (
                "challenge and effective review",
                "performance monitoring and drift detection",
                "documentation of model assumptions and limitations",
            ),
        },
        "Insurance": {
            "frameworks": (
                "NAIC Insurance Data Security Model Law (and related NAIC AI governance dialogue)",
                "GLBA",
                "NYDFS Cybersecurity Regulation",
                "state unfair trade practice expectations (high-level)",
            ),
            "regulatory_themes": (
                "governance of predictive models in underwriting and claims",
                "privacy of policyholder and claimant data",
                "explainability for adverse decisions where applicable",
            ),
            "control_emphasis": (
                "documented model inventory and risk tiering",
                "human review for material claim or eligibility outcomes",
                "data lineage for training and decision features",
            ),
        },
        "Payments / Fintech": {
            "frameworks": (
                "GLBA",
                "FTC Safeguards Rule",
                "PCI DSS (where cardholder data is in scope)",
                "consumer protection and UDAAP-oriented supervisory culture",
            ),
            "regulatory_themes": (
                "fraud and abuse detection integrity",
                "safeguards for customer financial data",
                "resilience of customer-impacting systems",
            ),
            "control_emphasis": (
                "strong authentication and session controls",
                "transaction and model-output monitoring",
                "vendor diligence for payment and AI subprocessors",
            ),
        },
        "_default": {
            "frameworks": ("GLBA", "FTC Safeguards Rule", "SOC 2", "NIST AI RMF"),
            "regulatory_themes": ("financial data protection", "model and vendor governance"),
            "control_emphasis": ("access control and logging", "change management"),
        },
    },
    "Healthcare": {
        "Provider": {
            "frameworks": (
                "HIPAA Privacy Rule",
                "HIPAA Security Rule",
                "clinical safety and documentation integrity (organizational expectations)",
            ),
            "regulatory_themes": (
                "PHI minimum necessary and controlled access",
                "auditability of access to clinical systems",
                "patient safety for AI-influenced workflows",
            ),
            "control_emphasis": (
                "role-based access to prompts and outputs",
                "human-in-the-loop for clinical decisions",
                "retention and de-identification policies",
            ),
        },
        "Medical Devices": {
            "frameworks": (
                "FDA medical device cybersecurity guidance",
                "FDA AI/ML-enabled SaMD discussion (predetermined change plans, transparency)",
                "IEC 62304 (software lifecycle)",
                "ISO 13485 (quality management)",
            ),
            "regulatory_themes": (
                "validation and verification of device software behavior",
                "cybersecurity risk management",
                "controlled design changes and traceability",
            ),
            "control_emphasis": (
                "software bill of materials and update governance",
                "safety testing and residual risk documentation",
                "segregation of clinical vs non-clinical environments",
            ),
        },
        "Payer / Insurance": {
            "frameworks": (
                "HIPAA Privacy Rule",
                "HIPAA Security Rule",
                "utilization management and appeals fairness (organizational expectations)",
            ),
            "regulatory_themes": (
                "fairness in utilization and coverage decisions",
                "coordination of PHI across payers and providers",
                "appeals and adverse determination documentation",
            ),
            "control_emphasis": (
                "bias testing on protected cohorts where decisions are automated or assisted",
                "appeals workflows with human sign-off",
                "BAA and subprocessor governance",
            ),
        },
        "_default": {
            "frameworks": ("HIPAA Privacy Rule", "HIPAA Security Rule", "NIST AI RMF"),
            "regulatory_themes": ("PHI protection", "clinical quality and safety alignment"),
            "control_emphasis": ("access reviews", "audit logging", "human oversight"),
        },
    },
    "Technology": {
        "SaaS / Enterprise Software": {
            "frameworks": ("SOC 2", "ISO 27001", "GDPR", "CCPA / CPRA"),
            "regulatory_themes": (
                "tenant isolation and data residency",
                "transparency for automated processing",
                "vendor and subprocessors chain",
            ),
            "control_emphasis": (
                "IAM and logging",
                "secure SDLC for AI features",
                "customer data handling in prompts and training",
            ),
        },
        "_default": {
            "frameworks": ("SOC 2", "ISO 27001", "GDPR"),
            "regulatory_themes": ("security governance", "privacy by design"),
            "control_emphasis": ("access management", "incident response", "vendor risk"),
        },
    },
    "Government / Public Sector": {
        "Benefits Administration": {
            "frameworks": (
                "NIST SP 800-53",
                "FedRAMP (cloud services context)",
                "public-sector privacy, fairness, and recordkeeping expectations",
            ),
            "regulatory_themes": (
                "procedural fairness and equitable access",
                "auditability of eligibility determinations",
                "citizen data minimization",
            ),
            "control_emphasis": (
                "dual control and appeals",
                "configuration management",
                "continuous monitoring and security assessment",
            ),
        },
        "_default": {
            "frameworks": ("NIST SP 800-53", "FedRAMP"),
            "regulatory_themes": ("access control", "auditability", "equity in citizen-facing systems"),
            "control_emphasis": ("authorization boundaries", "logging", "change boards"),
        },
    },
    "Education": {
        "_default": {
            "frameworks": ("FERPA", "COPPA (where minors are in scope)"),
            "regulatory_themes": ("student data confidentiality", "parental consent where applicable"),
            "control_emphasis": ("minimum necessary access", "data sharing agreements"),
        },
    },
    "Retail / E-Commerce": {
        "_default": {
            "frameworks": ("GDPR", "CCPA / CPRA", "PCI DSS (payment context)"),
            "regulatory_themes": (
                "consumer transparency",
                "payment and loyalty data protection",
            ),
            "control_emphasis": ("consent and preference centers", "fraud monitoring"),
        },
    },
    "Life Sciences / Pharma": {
        "_default": {
            "frameworks": ("GxP / CSV", "clinical data integrity expectations", "privacy and safety context"),
            "regulatory_themes": (
                "ALCOA+ data integrity",
                "validated systems for regulated decisions",
                "pharmacovigilance and safety signal handling",
            ),
            "control_emphasis": (
                "electronic records and signatures",
                "audit trails",
                "change control for regulated models",
            ),
        },
    },
    "Manufacturing": {
        "Industrial Operations": {
            "frameworks": (
                "industrial cybersecurity (IEC 62443-oriented practice)",
                "operational resilience expectations",
            ),
            "regulatory_themes": ("safety interlocks", "OT/IT segmentation"),
            "control_emphasis": ("safe state on failure", "privileged remote access reviews"),
        },
        "_default": {
            "frameworks": ("ISO 27001", "operational technology resilience"),
            "regulatory_themes": ("safety and production integrity", "supply chain security"),
            "control_emphasis": ("change management", "vendor access"),
        },
    },
    "Energy / Utilities": {
        "_default": {
            "frameworks": ("NERC CIP (where applicable)", "NIST CSF", "operational resilience"),
            "regulatory_themes": ("grid reliability", "privileged operations"),
            "control_emphasis": ("segmentation", "logging", "emergency procedures"),
        },
    },
}

# Substrings (lowercase) in selected regulation labels -> governance / control themes
REGULATION_THEME_TRIGGERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("hipaa", ("access control", "audit logging", "data protection", "minimum necessary / controlled access")),
    ("glba", ("financial privacy safeguards", "risk-based security program", "vendor oversight")),
    ("pci", ("cardholder data protection", "segmentation", "logging and testing")),
    ("gdpr", ("lawful basis and transparency", "data subject rights", "profiling / automated decision sensitivity")),
    ("ccpa", ("consumer transparency", "opt-out / preference handling", "service provider contracts")),
    ("ftc", ("safeguards program", "risk assessment cadence")),
    ("nydfs", ("cybersecurity program", "periodic penetration testing", "access privileges")),
    ("fedramp", ("continuous monitoring", "security controls baseline", "authorization boundary")),
    ("800-53", ("access control", "auditability", "configuration management", "security assessment")),
    ("nist ai", ("AI risk management lifecycle", "governance and accountability")),
    ("soc 2", ("security governance", "logging", "incident response", "vendor risk")),
    ("iso 27001", ("ISMS", "risk treatment", "access management")),
    ("ferpa", ("student records confidentiality", "directory information rules")),
    ("coppa", ("parental consent", "children’s data minimization")),
    ("sox", ("internal control over financial reporting", "IT general controls")),
    ("gxp", ("validation", "data integrity", "change control")),
    ("fda", ("validation", "software traceability", "cybersecurity", "lifecycle change control")),
    ("nerc", ("CIP standards alignment", "privileged access", "perimeter protection")),
)

# Base tags from catalog risk id (deterministic)
RISK_ID_GOVERNANCE_TAGS: dict[str, tuple[str, ...]] = {
    "R-001": ("Model Risk", "Consumer Harm Risk", "Operational Risk"),
    "R-002": ("Privacy Risk", "Security Risk", "Regulatory Risk"),
    "R-003": ("Security Risk", "Operational Risk", "Third-Party Risk"),
    "R-004": ("Third-Party Risk", "Operational Risk", "Model Risk"),
    "R-005": ("Decisioning Risk", "Regulatory Risk", "Auditability Risk"),
    "R-006": ("Security Risk", "Operational Risk", "Consumer Harm Risk"),
    "R-007": ("Model Risk", "Operational Risk", "Auditability Risk"),
    "R-008": ("Fairness / Bias Risk", "Regulatory Risk", "Decisioning Risk", "Consumer Harm Risk"),
    "R-009": ("Data Quality Risk", "Operational Risk", "Auditability Risk"),
    "R-010": ("Security Risk", "Operational Risk"),
    "R-011": ("Operational Risk", "Security Risk", "Consumer Harm Risk"),
    "R-012": ("Security Risk", "Privacy Risk", "Operational Risk"),
    "R-013": ("Third-Party Risk", "Data Quality Risk", "Consumer Harm Risk"),
    "R-014": ("Operational Risk", "Auditability Risk", "Regulatory Risk"),
}

_KEYWORD_TAG_RULES: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (
        ("hallucinat", "wrong answer", "unsafe", "misleading", "incorrect"),
        ("Model Risk", "Consumer Harm Risk"),
    ),
    (
        ("phi", "hipaa", "patient", "clinical", "ehr"),
        ("Safety Risk", "Privacy Risk", "Regulatory Risk"),
    ),
    (
        ("pii", "personal data", "breach", "leak", "exfil"),
        ("Privacy Risk", "Security Risk"),
    ),
    (
        ("bias", "fair", "disparate", "discriminat", "protected class"),
        ("Fairness / Bias Risk", "Regulatory Risk", "Decisioning Risk"),
    ),
    (
        ("underwrit", "credit", "loan", "eligibility", "adverse action"),
        ("Decisioning Risk", "Regulatory Risk", "Model Risk"),
    ),
    (
        ("vendor", "third party", "subprocessor", "hosted", "openai", "bedrock", "azure openai"),
        ("Third-Party Risk", "Security Risk", "Operational Risk"),
    ),
    (
        ("tool", "function calling", "mcp", "api", "agent"),
        ("Security Risk", "Operational Risk", "Consumer Harm Risk"),
    ),
    (
        ("monitor", "metric", "eval", "drift", "validation"),
        ("Model Risk", "Auditability Risk", "Operational Risk"),
    ),
    (
        ("log", "audit", "trace"),
        ("Auditability Risk", "Security Risk"),
    ),
)


def get_regulatory_overlay(industry: str, specialization: str) -> dict[str, tuple[str, ...]]:
    ind = (industry or "").strip()
    spec = (specialization or "").strip()
    block = REGULATORY_OVERLAY.get(ind, {})
    prof = block.get(spec) or block.get("_default")
    if prof:
        return prof
    return {
        "frameworks": _DEFAULT_GENERIC["frameworks"],
        "regulatory_themes": _DEFAULT_GENERIC["regulatory_themes"],
        "control_emphasis": _DEFAULT_GENERIC["control_emphasis"],
    }


def applicable_regulatory_context_summary(
    industry: str,
    specialization: str,
    selected_regulation_labels: Sequence[str],
) -> str:
    """Single-line summary for exports (not a legal determination)."""
    overlay = get_regulatory_overlay(industry, specialization)
    parts = [f"{ind} / {spec}", "overlay: " + "; ".join(overlay.get("frameworks", ())[:6])]
    if selected_regulation_labels:
        parts.append("selected: " + "; ".join(selected_regulation_labels[:8]))
    return " | ".join(parts)


def themes_for_selected_regulations(selected_regulation_labels: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    blob = " ".join(selected_regulation_labels).lower()
    for needle, themes in REGULATION_THEME_TRIGGERS:
        if needle in blob:
            for t in themes:
                if t not in seen:
                    seen.add(t)
                    out.append(t)
    return out


def _risk_text_blob(risk_row: Mapping[str, Any]) -> str:
    chunks = [
        str(risk_row.get("risk_id", "")),
        str(risk_row.get("risk_name", "")),
        str(risk_row.get("operational_stake", "")),
        str(risk_row.get("failure_mode", "")),
        str(risk_row.get("materiality_rationale", "")),
    ]
    return " ".join(chunks).lower()


def tag_risk(
    risk_row: Mapping[str, Any],
    *,
    industry: str,
    specialization: str,
    business_function: str,
    selected_regulations: Sequence[str],
    derived_tags: Sequence[str],
) -> list[str]:
    rid = str(risk_row.get("risk_id", "")).strip()
    text = _risk_text_blob(risk_row)
    tagset = {str(t).lower() for t in derived_tags}
    tags: list[str] = []
    seen: set[str] = set()

    def add_many(items: Sequence[str]) -> None:
        for x in items:
            if x not in seen:
                seen.add(x)
                tags.append(x)

    add_many(RISK_ID_GOVERNANCE_TAGS.get(rid, ()))

    for keywords, labels in _KEYWORD_TAG_RULES:
        if any(k in text for k in keywords):
            add_many(labels)

    ind_l = (industry or "").lower()
    spec_l = (specialization or "").lower()
    bf = (business_function or "").lower()

    if "health" in ind_l or "clinical" in bf or "phi" in tagset or "healthcare" in tagset:
        if any(k in text for k in ("customer", "patient", "clinical", "care", "wrong", "unsafe")):
            add_many(["Safety Risk", "Consumer Harm Risk"])

    if "financial" in ind_l or "underwrit" in bf or "financial_services" in tagset:
        add_many(["Regulatory Risk", "Decisioning Risk"])

    if selected_regulations:
        add_many(["Regulatory Risk"])

    if "model" in text or "validation" in text:
        add_many(["Model Risk"])

    return tags


def tag_all_material_risks(
    material_risks: Sequence[Mapping[str, Any]],
    *,
    industry: str,
    specialization: str,
    business_function: str,
    selected_regulations: Sequence[str],
    derived_tags: Sequence[str],
) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    enriched: list[dict[str, Any]] = []
    by_id: dict[str, list[str]] = {}
    for row in material_risks:
        r = dict(row)
        tgs = tag_risk(
            row,
            industry=industry,
            specialization=specialization,
            business_function=business_function,
            selected_regulations=selected_regulations,
            derived_tags=derived_tags,
        )
        rid = str(row.get("risk_id", ""))
        by_id[rid] = tgs
        r["governance_risk_tags"] = tgs
        r["governance_risk_tags_display"] = ", ".join(tgs)
        enriched.append(r)
    return enriched, by_id


def risk_domain_why_it_matters(
    risk_row: Mapping[str, Any],
    *,
    industry: str,
    specialization: str,
    tags: Sequence[str],
) -> str:
    """One concise sentence for UI — domain-informed, not legal advice."""
    ind = industry or "this industry"
    spec = specialization or "this specialization"
    rn = str(risk_row.get("risk_name", "this risk")).strip()
    tagset = set(tags)
    if "Safety Risk" in tagset and ("Health" in industry or "Clinical" in (risk_row.get("risk_name") or "")):
        return f"In {ind} ({spec}), {rn} can affect patient safety, care quality, or documentation integrity if outputs are wrong or unreviewed."
    if "Fairness / Bias Risk" in tagset or "Decisioning Risk" in tagset:
        return f"In {ind}, {rn} can create supervisory or customer trust exposure when model-assisted decisions are opaque or unevenly applied."
    if "Privacy Risk" in tagset or "Security Risk" in tagset:
        return f"In {ind} ({spec}), {rn} can amplify data protection and security obligations for sensitive or regulated data flows."
    if "Third-Party Risk" in tagset:
        return f"Hosted models and subprocessors mean {rn} spans your security, data handling, and contractual control expectations."
    if "Model Risk" in tagset:
        return f"{rn} is material to model risk management: validation, monitoring, and change control should keep pace with production use."
    return f"For {ind} ({spec}), {rn} should be tracked with clear ownership, monitoring, and evidence for governance forums."


def assign_remediation_owner(
    governance_tags: Sequence[str],
    *,
    industry: str,
    specialization: str,
) -> str:
    ts = set(governance_tags)
    ind_l = (industry or "").lower()
    spec_l = (specialization or "").lower()
    if "Safety Risk" in ts and ("health" in ind_l or "clinical" in spec_l or "medical" in spec_l):
        return "Clinical Safety"
    if "Fairness / Bias Risk" in ts or "Decisioning Risk" in ts:
        if "financial" in ind_l:
            return "Model Validation"
        return "Compliance"
    if "Privacy Risk" in ts:
        return "Privacy / Legal"
    if "Security Risk" in ts or "Third-Party Risk" in ts:
        return "Information Security"
    if "Model Risk" in ts or "Auditability Risk" in ts:
        return "Model Validation"
    if "Data Quality Risk" in ts:
        return "Engineering"
    return "AI Governance"


def assign_remediation_priority(
    base_priority: str,
    governance_tags: Sequence[str],
) -> str:
    """Elevate deterministically when tags imply higher materiality."""
    ts = set(governance_tags)
    bp = (base_priority or "Medium").strip().title()
    if bp == "High":
        return "High"
    if "Safety Risk" in ts or "Consumer Harm Risk" in ts:
        return "High"
    if "Privacy Risk" in ts and "Security Risk" in ts:
        return "High"
    if "Fairness / Bias Risk" in ts and "Regulatory Risk" in ts:
        return "High"
    if bp == "Low":
        return "Low"
    return "Medium"


def build_regulatory_remediation_rationale(
    governance_tags: Sequence[str],
    regulation_themes: Sequence[str],
    selected_regulations: Sequence[str],
    overlay_frameworks: Sequence[str],
) -> str:
    """Plain governance rationale — not legal advice."""
    tag_part = ", ".join(governance_tags[:5]) if governance_tags else "general governance"
    theme_part = ", ".join(regulation_themes[:4]) if regulation_themes else "baseline control themes"
    reg_part = (
        "; ".join(selected_regulations[:3])
        if selected_regulations
        else "; ".join(overlay_frameworks[:3])
    )
    return (
        f"Remediation emphasis reflects tags ({tag_part}) and supervisory/regulatory expectations considered "
        f"({theme_part}), informed by relevant context including: {reg_part}. "
        "This is design-time guidance—not a determination that each cited framework fully applies."
    )


def regulatory_context_for_display(
    selected_regulations: Sequence[str],
    overlay_frameworks: Sequence[str],
) -> str:
    if selected_regulations:
        return "; ".join(selected_regulations[:10])
    return "; ".join(overlay_frameworks[:8])


def enrich_remediation_gaps(
    gaps: Sequence[Mapping[str, Any]],
    *,
    risk_tags_by_id: Mapping[str, Sequence[str]],
    industry: str,
    specialization: str,
    selected_regulations: Sequence[str],
    regulation_themes: Sequence[str],
    overlay_frameworks: Sequence[str],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for g in gaps:
        row = dict(g)
        related = g.get("related_risks") or []
        merged_tags: list[str] = []
        seen: set[str] = set()
        for rr in related:
            rid = str(rr.get("risk_id", ""))
            for t in risk_tags_by_id.get(rid, ()):
                if t not in seen:
                    seen.add(t)
                    merged_tags.append(t)
        owner = assign_remediation_owner(merged_tags, industry=industry, specialization=specialization)
        priority = assign_remediation_priority(str(g.get("remediation_priority", "Medium")), merged_tags)
        reg_disp = regulatory_context_for_display(selected_regulations, overlay_frameworks)
        rationale = build_regulatory_remediation_rationale(
            merged_tags,
            regulation_themes,
            selected_regulations,
            overlay_frameworks,
        )
        row["governance_risk_tags"] = merged_tags
        row["governance_risk_tags_display"] = ", ".join(merged_tags) if merged_tags else "—"
        row["remediation_owner_suggested"] = owner
        row["remediation_priority_enriched"] = priority
        row["regulatory_context_display"] = reg_disp
        row["enrichment_rationale"] = rationale
        out.append(row)
    return out


def mapping_row_enrichment(
    table: Sequence[Mapping[str, Any]],
    risk_tags_by_id: Mapping[str, Sequence[str]],
    applicable_regulatory_context: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for r in table:
        d = dict(r)
        rid = str(d.get("risk_id", ""))
        tags = risk_tags_by_id.get(rid, [])
        d["governance_risk_tags"] = ", ".join(tags) if tags else ""
        d["applicable_regulatory_context"] = applicable_regulatory_context
        rows.append(d)
    return rows
