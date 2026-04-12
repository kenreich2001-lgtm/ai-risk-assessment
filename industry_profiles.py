"""
Enterprise intake taxonomy: industry, specialization, business function, and regulatory context.

Rule-based only. Feeds **known matcher tags** (subset of ALL_KNOWN_TAGS) and a structured text block
into `map_use_case`. Does **not** determine legal compliance.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from mapping_engine.taxonomy import ALL_KNOWN_TAGS

# ---------------------------------------------------------------------------
# Regulations / standards (labels shown in UI; keys for defaults)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RegulationEntry:
    key: str
    label: str
    """Extra matcher tags implied when this context is selected (subset of ALL_KNOWN_TAGS)."""
    derived_tags: frozenset[str]


REGULATION_ENTRIES: tuple[RegulationEntry, ...] = (
    RegulationEntry("glba", "GLBA", frozenset({"regulated", "financial_services", "pii"})),
    RegulationEntry("ftc_safeguards", "FTC Safeguards Rule", frozenset({"regulated", "pii"})),
    RegulationEntry("nydfs", "NYDFS Cybersecurity Regulation", frozenset({"regulated", "financial_services"})),
    RegulationEntry("pci", "PCI DSS", frozenset({"regulated", "financial_data", "financial_services"})),
    RegulationEntry("sox", "SOX", frozenset({"regulated", "financial_services"})),
    RegulationEntry("hipaa_priv", "HIPAA Privacy Rule", frozenset({"regulated", "phi", "healthcare"})),
    RegulationEntry("hipaa_sec", "HIPAA Security Rule", frozenset({"regulated", "phi", "healthcare"})),
    RegulationEntry("fda_cyber", "FDA medical device cybersecurity guidance", frozenset({"regulated", "healthcare", "high_stakes"})),
    RegulationEntry("gxp", "GxP / CSV (life sciences context)", frozenset({"regulated", "healthcare", "high_stakes"})),
    RegulationEntry("soc2", "SOC 2", frozenset({"regulated", "pii"})),
    RegulationEntry("iso27001", "ISO 27001", frozenset({"regulated"})),
    RegulationEntry("nist_csf", "NIST CSF", frozenset({"regulated"})),
    RegulationEntry("nist_ai_rmf", "NIST AI RMF", frozenset({"regulated"})),
    RegulationEntry("gdpr", "GDPR", frozenset({"regulated", "pii"})),
    RegulationEntry("ccpa", "CCPA / CPRA", frozenset({"regulated", "pii"})),
    RegulationEntry("fedramp", "FedRAMP", frozenset({"regulated", "public_sector"})),
    RegulationEntry("nist_800_53", "NIST 800-53", frozenset({"regulated", "public_sector"})),
    RegulationEntry("public_records", "Public records / privacy context", frozenset({"regulated", "public_sector", "pii"})),
    RegulationEntry("ferpa", "FERPA", frozenset({"regulated", "pii"})),
    RegulationEntry("coppa", "COPPA", frozenset({"regulated", "pii"})),
    RegulationEntry("platform_privacy", "Platform privacy / content governance context", frozenset({"regulated", "pii", "customer_facing"})),
    RegulationEntry("nerc_cip", "NERC CIP", frozenset({"regulated", "high_stakes"})),
    RegulationEntry("ot_resilience", "Operational resilience / industrial cybersecurity context", frozenset({"regulated", "high_stakes"})),
    RegulationEntry("privilege", "Confidentiality / privilege context (legal)", frozenset({"regulated", "pii"})),
    RegulationEntry("employment_privacy", "Employment data privacy context", frozenset({"regulated", "hr_employment", "pii"})),
)

REGULATIONS_BY_KEY: dict[str, RegulationEntry] = {r.key: r for r in REGULATION_ENTRIES}
ALL_REGULATION_LABELS: tuple[str, ...] = tuple(sorted(r.label for r in REGULATION_ENTRIES))
LABEL_TO_KEY: dict[str, str] = {r.label: r.key for r in REGULATION_ENTRIES}


def _filter_known(tags: Iterable[str]) -> list[str]:
    return [t for t in dict.fromkeys(tags) if t in ALL_KNOWN_TAGS]


@dataclass(frozen=True)
class SpecializationProfile:
    default_regulation_keys: tuple[str, ...]
    derived_tags: tuple[str, ...]
    risk_emphasis: tuple[str, ...]
    control_emphasis: tuple[str, ...]


def _sp(
    regs: tuple[str, ...],
    tags: tuple[str, ...],
    risks: tuple[str, ...],
    controls: tuple[str, ...],
) -> SpecializationProfile:
    return SpecializationProfile(regs, tags, risks, controls)


# Industry -> specialization -> profile
SPECIALIZATION_PROFILES: dict[str, dict[str, SpecializationProfile]] = {
    "Financial Services": {
        "Banking": _sp(
            ("glba", "ftc_safeguards", "pci", "soc2"),
            ("financial_services", "regulated", "pii", "financial_data"),
            (
                "customer financial data exposure",
                "fraud and unauthorized transactions",
                "fairness in customer-facing decisions",
                "traceability of model-influenced outcomes",
            ),
            ("strong access control and logging", "third-party model change control", "human review for adverse actions"),
        ),
        "Insurance": _sp(
            ("glba", "ftc_safeguards", "soc2"),
            ("financial_services", "regulated", "pii", "high_stakes"),
            ("claims and eligibility decisions", "PHI in health lines", "bias in pricing or triage"),
            ("document decision rationale", "segregation of duties on model updates"),
        ),
        "Asset / Wealth Management": _sp(
            ("glba", "ftc_safeguards", "sox", "soc2"),
            ("financial_services", "regulated", "pii", "high_stakes"),
            ("investment suitability and disclosures", "data leakage across clients"),
            ("advisory oversight", "audit trail for recommendations"),
        ),
        "Payments / Fintech": _sp(
            ("pci", "glba", "soc2", "gdpr"),
            ("financial_services", "regulated", "financial_data", "agentic_tools"),
            ("payment fraud", "API abuse", "cross-border data"),
            ("least-privilege tool scopes", "real-time fraud monitoring"),
        ),
        "Capital Markets": _sp(
            ("sox", "glba", "soc2", "nist_csf"),
            ("financial_services", "regulated", "high_stakes", "internal_knowledge"),
            ("market integrity and communications", "insider information handling"),
            ("retention and surveillance alignment", "model validation for trading-adjacent use"),
        ),
    },
    "Healthcare": {
        "Provider": _sp(
            ("hipaa_priv", "hipaa_sec", "soc2"),
            ("healthcare", "phi", "regulated", "high_stakes"),
            ("PHI exposure", "unsafe clinical suggestions", "documentation integrity"),
            ("minimum necessary access", "human-in-loop for clinical paths", "auditability"),
        ),
        "Payer / Insurance": _sp(
            ("hipaa_priv", "hipaa_sec", "glba"),
            ("healthcare", "phi", "regulated", "financial_services"),
            ("eligibility and benefits decisions", "coordination of care data"),
            ("appeals and adverse determination review", "BAA and subprocessors"),
        ),
        "Medical Devices": _sp(
            ("fda_cyber", "hipaa_sec", "iso27001"),
            ("healthcare", "regulated", "high_stakes"),
            ("safety-critical software behavior", "field update integrity"),
            ("validation evidence", "secure SDLC", "incident response"),
        ),
        "Digital Health": _sp(
            ("hipaa_priv", "gdpr", "ccpa"),
            ("healthcare", "phi", "pii", "regulated", "customer_facing"),
            ("consumer health data misuse", "consent and transparency"),
            ("data minimization", "clear escalation to clinicians"),
        ),
        "Healthcare Operations": _sp(
            ("hipaa_priv", "hipaa_sec", "soc2"),
            ("healthcare", "phi", "internal_knowledge", "regulated"),
            ("operational errors affecting patients", "workforce-facing AI"),
            ("role-based access to prompts and outputs", "training on PHI boundaries"),
        ),
    },
    "Technology": {
        "SaaS / Enterprise Software": _sp(
            ("soc2", "iso27001", "gdpr"),
            ("pii", "regulated", "customer_facing", "retrieval"),
            ("tenant isolation", "hallucinated answers in support", "admin abuse paths"),
            ("strong IAM", "logging and DLP", "evaluations per tenant tier"),
        ),
        "Consumer Tech": _sp(
            ("ccpa", "gdpr", "platform_privacy"),
            ("customer_facing", "pii", "regulated"),
            ("profiling and transparency", "minor safety where applicable"),
            ("consent flows", "abuse detection on public endpoints"),
        ),
        "Cloud / Infrastructure": _sp(
            ("soc2", "iso27001", "nist_csf"),
            ("regulated", "internal_knowledge", "high_stakes"),
            ("misconfiguration and blast radius", "shared responsibility clarity"),
            ("change management", "privileged access reviews"),
        ),
        "Cybersecurity": _sp(
            ("nist_csf", "iso27001", "nist_800_53"),
            ("regulated", "internal_knowledge", "high_stakes"),
            ("false negatives on threats", "leakage of sensitive telemetry"),
            ("human validation of autonomous responses", "immutable audit logs"),
        ),
        "AI / ML Platform": _sp(
            ("nist_ai_rmf", "soc2", "gdpr"),
            ("regulated", "third_party_model", "customer_facing"),
            ("model supply chain", "customer data in training or logging"),
            ("model cards", "customer data segregation", "incident playbooks"),
        ),
    },
    "Retail / E-Commerce": {
        "Online Marketplace": _sp(
            ("ccpa", "gdpr", "pci"),
            ("customer_facing", "pii", "financial_data", "regulated"),
            ("seller and buyer data commingling", "fraud in listings and payouts"),
            ("marketplace policy enforcement", "payment fraud analytics"),
        ),
        "Direct-to-Consumer": _sp(
            ("ccpa", "gdpr", "ftc_safeguards"),
            ("customer_facing", "pii", "regulated", "bias_sensitive"),
            ("personalization privacy", "marketing claims accuracy"),
            ("preference centers", "marketing human review"),
        ),
        "Omnichannel Retail": _sp(
            ("pci", "ccpa", "soc2"),
            ("customer_facing", "pii", "financial_data"),
            ("loyalty and purchase history exposure", "returns fraud"),
            ("POS and e-com consistent controls", "PII in support bots"),
        ),
        "Payments / Checkout": _sp(
            ("pci", "glba", "soc2"),
            ("financial_data", "regulated", "customer_facing"),
            ("cardholder data handling", "checkout manipulation"),
            ("tokenization", "fraud scoring transparency"),
        ),
        "Customer Support Operations": _sp(
            ("ccpa", "soc2"),
            ("customer_support_bot", "customer_facing", "pii"),
            ("wrong answers acted on by staff", "credential or order data in chat"),
            ("HITL for refunds and account changes", "redaction in logs"),
        ),
    },
    "Manufacturing": {
        "Industrial Operations": _sp(
            ("ot_resilience", "iso27001"),
            ("high_stakes", "regulated", "internal_knowledge"),
            ("safety interlocks", "OT/IT convergence"),
            ("change control", "physical safety review gates"),
        ),
        "Supply Chain": _sp(
            ("iso27001", "nist_csf"),
            ("internal_knowledge", "retrieval", "regulated"),
            ("counterfeit or wrong specs propagated", "vendor document trust"),
            ("provenance of retrieved specs", "supplier risk reviews"),
        ),
        "Quality / Compliance": _sp(
            ("gxp", "iso27001"),
            ("regulated", "high_stakes", "internal_knowledge"),
            ("audit trail integrity", "non-conformance handling"),
            ("electronic records controls", "segregation of duties"),
        ),
        "Robotics / Automation": _sp(
            ("ot_resilience", "iso27001"),
            ("agentic_tools", "high_stakes", "regulated"),
            ("unsafe automated motion or commands", "human override"),
            ("simulation and kill-switch testing", "least-privilege automation"),
        ),
        "Product Engineering": _sp(
            ("iso27001", "soc2"),
            ("developer_tools", "code_generation", "internal_knowledge"),
            ("IP leakage", "unsafe generated code in builds"),
            ("secure coding checks", "license scanning"),
        ),
    },
    "Energy / Utilities": {
        "Power / Utilities": _sp(
            ("nerc_cip", "ot_resilience"),
            ("regulated", "high_stakes", "public_sector"),
            ("grid reliability", "privileged operations access"),
            ("NERC-aligned logging", "emergency operating procedures"),
        ),
        "Oil / Gas": _sp(
            ("ot_resilience", "iso27001"),
            ("high_stakes", "regulated"),
            ("field operations safety", "environmental reporting integrity"),
            ("hazardous operations review", "change boards"),
        ),
        "Renewables": _sp(
            ("ot_resilience", "nist_csf"),
            ("high_stakes", "regulated"),
            ("forecast and dispatch errors", "SCADA exposure"),
            ("segmentation", "vendor remote access"),
        ),
        "Grid Operations": _sp(
            ("nerc_cip", "nist_800_53"),
            ("high_stakes", "regulated", "public_sector"),
            ("real-time control decisions", "shared situational data"),
            ("dual control", "time-bound elevated access"),
        ),
        "Field Services": _sp(
            ("ot_resilience",),
            ("internal_knowledge", "customer_facing", "pii"),
            ("customer site data on devices", "unsafe work instructions"),
            ("offline policy enforcement", "PII minimization on mobile"),
        ),
    },
    "Telecommunications": {
        "Network Operations": _sp(
            ("nist_csf", "iso27001"),
            ("high_stakes", "regulated", "internal_knowledge"),
            ("service outage decisions", "config drift"),
            ("peer review for automated changes", "rollback drills"),
        ),
        "Customer Service": _sp(
            ("ccpa", "soc2"),
            ("customer_support_bot", "customer_facing", "pii"),
            ("account takeover assistance", "billing disputes"),
            ("step-up auth", "transcript retention policy"),
        ),
        "Billing / Revenue Management": _sp(
            ("pci", "sox", "soc2"),
            ("financial_data", "regulated", "pii"),
            ("revenue recognition errors", "refund abuse"),
            ("financial controls", "anomaly detection review"),
        ),
        "Infrastructure Planning": _sp(
            ("nist_800_53", "iso27001"),
            ("regulated", "internal_knowledge"),
            ("capital project data sensitivity", "coverage maps"),
            ("need-to-know on network designs", "third-party NDA alignment"),
        ),
    },
    "Media / Entertainment": {
        "Content Platforms": _sp(
            ("gdpr", "ccpa", "platform_privacy"),
            ("customer_facing", "pii", "regulated"),
            ("recommendation fairness", "harmful content amplification"),
            ("moderation workflows", "appeals transparency"),
        ),
        "Advertising / AdTech": _sp(
            ("gdpr", "ccpa", "platform_privacy"),
            ("pii", "regulated", "customer_facing", "bias_sensitive"),
            ("profiling and consent", "competitive data misuse"),
            ("consent strings", "audience modeling review"),
        ),
        "Publishing": _sp(
            ("ccpa", "gdpr"),
            ("pii", "internal_knowledge"),
            ("IP and licensing errors", "defamation risk in generated copy"),
            ("legal pre-publication for sensitive topics", "rights metadata"),
        ),
        "Streaming Services": _sp(
            ("gdpr", "ccpa"),
            ("customer_facing", "pii", "regulated"),
            ("kids content where COPPA applies", "personalization transparency"),
            ("age assurance", "recommendation audits"),
        ),
    },
    "Education": {
        "K-12": _sp(
            ("ferpa", "coppa", "gdpr"),
            ("pii", "regulated", "high_stakes"),
            ("student data mishandling", "safeguarding"),
            ("parental consent flows", "minimum necessary in prompts"),
        ),
        "Higher Education": _sp(
            ("ferpa", "gdpr"),
            ("pii", "regulated", "internal_knowledge"),
            ("research data and FERPA overlap", "grading integrity"),
            ("IRB alignment where research", "access to student systems"),
        ),
        "EdTech Platform": _sp(
            ("ferpa", "coppa", "soc2"),
            ("pii", "customer_facing", "regulated"),
            ("multi-tenant student data", "model training on user content"),
            ("tenant isolation", "DPA with schools"),
        ),
        "Student Services": _sp(
            ("ferpa",),
            ("pii", "hr_employment", "regulated"),
            ("financial aid and discipline sensitivity", "bias in routing"),
            ("human appeal paths", "restricted logging"),
        ),
    },
    "Government / Public Sector": {
        "Citizen Services": _sp(
            ("fedramp", "nist_800_53", "public_records"),
            ("public_sector", "regulated", "pii", "customer_facing"),
            ("procedural fairness", "explainability to citizens", "recordkeeping"),
            ("human review for benefits decisions", "accessibility"),
        ),
        "Benefits Administration": _sp(
            ("fedramp", "nist_800_53", "public_records"),
            ("public_sector", "regulated", "pii", "high_stakes"),
            ("incorrect eligibility", "sensitive citizen data"),
            ("dual control", "appeals and overrides"),
        ),
        "Public Safety": _sp(
            ("nist_800_53", "fedramp"),
            ("public_sector", "high_stakes", "regulated"),
            ("wrong situational guidance", "surveillance ethics"),
            ("chain of custody for evidence AI", "bias testing"),
        ),
        "Defense Support": _sp(
            ("nist_800_53", "fedramp"),
            ("public_sector", "regulated", "high_stakes"),
            ("classified spillage", "supply chain"),
            ("air-gapped workflows where required", "classification labels in prompts"),
        ),
        "Regulatory Administration": _sp(
            ("public_records", "nist_800_53"),
            ("public_sector", "regulated", "pii", "high_stakes"),
            ("due process and consistency", "privileged enforcement data"),
            ("audit trails", "legal review of automated notices"),
        ),
    },
    "Real Estate": {
        "Property Management": _sp(
            ("glba", "ccpa", "ftc_safeguards"),
            ("pii", "financial_data", "regulated"),
            ("tenant financial data", "fair housing risk"),
            ("fair housing testing", "secure payment handling"),
        ),
        "Brokerage": _sp(
            ("glba", "ccpa"),
            ("pii", "financial_services", "regulated"),
            ("misrepresentation in listings", "KYC data"),
            ("disclosure review", "advertising compliance"),
        ),
        "Lending / Mortgage": _sp(
            ("glba", "pci", "sox"),
            ("financial_services", "regulated", "pii", "high_stakes"),
            ("ECOA/fair lending exposure", "fraud"),
            ("adverse action notices", "model risk management"),
        ),
        "Tenant Operations": _sp(
            ("ccpa",),
            ("pii", "customer_facing"),
            ("access control to units", "noise and safety tickets"),
            ("after-hours escalation", "vendor access"),
        ),
    },
    "Transportation / Logistics": {
        "Fleet Operations": _sp(
            ("iso27001",),
            ("internal_knowledge", "high_stakes", "customer_facing"),
            ("route safety", "driver PII"),
            ("telematics data minimization", "human dispatch override"),
        ),
        "Shipping / Logistics": _sp(
            ("iso27001", "gdpr"),
            ("retrieval", "customer_facing", "pii"),
            ("customs data accuracy", "delay misinformation"),
            ("cross-border data maps", "SLA monitoring"),
        ),
        "Route Optimization": _sp(
            (),
            ("internal_knowledge", "high_stakes"),
            ("inequitable service areas", "safety of suggested routes"),
            ("fairness checks", "human validation on edge cases"),
        ),
        "Warehouse Operations": _sp(
            ("iso27001",),
            ("internal_knowledge", "agentic_tools"),
            ("inventory errors", "robotic pick safety"),
            ("inventory reconciliation", "safety interlocks"),
        ),
    },
    "Professional Services": {
        "Consulting": _sp(
            ("soc2", "iso27001"),
            ("internal_knowledge", "pii", "regulated"),
            ("client confidential data in prompts", "conflicts"),
            ("client data segregation", "engagement firewalling"),
        ),
        "Legal Services": _sp(
            ("privilege", "soc2"),
            ("pii", "regulated", "high_stakes"),
            ("privilege waiver risk", "wrong legal guidance"),
            ("ethical walls", "human attorney review"),
        ),
        "Accounting / Audit": _sp(
            ("sox", "soc2"),
            ("financial_services", "regulated", "pii"),
            ("material misstatements", "independence"),
            ("workpaper integrity", "partner review"),
        ),
        "HR / Recruiting": _sp(
            ("employment_privacy", "gdpr", "ccpa"),
            ("hr_employment", "bias_sensitive", "pii", "regulated"),
            ("hiring bias", "pay equity perceptions"),
            ("structured interviews", "bias testing on cohorts"),
        ),
    },
    "Life Sciences / Pharma": {
        "Drug Development": _sp(
            ("gxp", "fda_cyber", "gdpr"),
            ("regulated", "healthcare", "high_stakes"),
            ("clinical data integrity", "safety signals"),
            ("CSV for GxP systems", "audit trails"),
        ),
        "Clinical Operations": _sp(
            ("gxp", "hipaa_priv", "hipaa_sec"),
            ("healthcare", "phi", "high_stakes", "regulated"),
            ("protocol deviations", "patient safety"),
            ("monitoring and medical review", "source data verification"),
        ),
        "Pharmacovigilance": _sp(
            ("gxp", "fda_cyber"),
            ("healthcare", "high_stakes", "regulated"),
            ("missed adverse events", "signal detection errors"),
            ("case processing QA", "expedited reporting"),
        ),
        "Manufacturing / Quality": _sp(
            ("gxp", "iso27001"),
            ("regulated", "high_stakes"),
            ("batch record integrity", "CAPA traceability"),
            ("electronic signatures", "ALCOA+ principles"),
        ),
        "Commercial Operations": _sp(
            ("gdpr", "ccpa", "ftc_safeguards"),
            ("customer_facing", "pii", "regulated", "healthcare"),
            ("promotional content accuracy", "HCP targeting"),
            ("MLR/medical review", "fair balance"),
        ),
    },
    "General Enterprise / Other": {
        "Internal Productivity": _sp(
            ("soc2",),
            ("internal_knowledge", "internal_only", "copilot_pattern"),
            ("shadow IT integrations", "over-trust of drafts"),
            ("acceptable use", "DLP on pastes"),
        ),
        "Customer Support": _sp(
            ("ccpa", "soc2"),
            ("customer_support_bot", "customer_facing", "pii"),
            ("wrong answers to customers", "credential exposure"),
            ("HITL for sensitive actions", "QA sampling"),
        ),
        "Analytics / Reporting": _sp(
            ("soc2", "gdpr"),
            ("retrieval", "pii", "internal_knowledge"),
            ("re-identification", "misleading dashboards"),
            ("row-level security", "definition of metrics"),
        ),
        "Knowledge Management": _sp(
            ("iso27001",),
            ("retrieval", "internal_knowledge"),
            ("stale or wrong policies", "over-sharing"),
            ("content freshness SLAs", "access reviews"),
        ),
        "Back Office Operations": _sp(
            ("soc2", "sox"),
            ("internal_knowledge", "pii", "regulated"),
            ("payment and vendor errors", "fraud"),
            ("SOX controls where applicable", "segregation of duties"),
        ),
    },
}


INDUSTRIES: tuple[str, ...] = tuple(sorted(SPECIALIZATION_PROFILES.keys()))


# Business function -> (derived tags, risk emphasis bullets)
BUSINESS_FUNCTION_META: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "Customer Support": (("customer_support_bot", "customer_facing", "pii"), ("wrong guidance acted on quickly", "credential phishing in chat")),
    "Sales": (("customer_facing", "pii"), ("misquoted pricing or terms", "pipeline data leakage")),
    "Marketing": (("customer_facing", "pii", "bias_sensitive"), ("profiling concerns", "misleading generated claims")),
    "Underwriting / Risk Decisioning": (("financial_services", "high_stakes", "bias_sensitive", "regulated"), ("adverse decisions", "fair lending exposure", "model explainability")),
    "Claims / Case Management": (("pii", "high_stakes", "regulated"), ("case errors", "fraudulent claims assistance")),
    "Finance": (("financial_data", "regulated", "pii"), ("mis-postings", "SOX-relevant spreadsheets")),
    "Compliance": (("regulated", "internal_knowledge"), ("missed obligations", "over-automation of judgments")),
    "Legal": (("pii", "regulated", "high_stakes"), ("privilege and confidentiality", "incorrect legal summaries")),
    "HR / Recruiting": (("hr_employment", "bias_sensitive", "pii", "regulated"), ("hiring bias", "pay equity")),
    "IT / Service Desk": (("internal_knowledge", "pii"), ("credential resets abuse", "runbook errors")),
    "Security Operations": (("high_stakes", "regulated", "internal_knowledge"), ("false negatives", "over-blocking")),
    "Engineering / Product Development": (("developer_tools", "code_generation", "internal_knowledge"), ("IP leakage", "unsafe generated code")),
    "Clinical Operations": (("healthcare", "phi", "high_stakes", "regulated"), ("patient harm", "documentation integrity")),
    "Research / R&D": (("internal_knowledge", "high_stakes"), ("data leakage", "unvalidated conclusions")),
    "Supply Chain / Procurement": (("retrieval", "internal_knowledge"), ("vendor fraud", "spec errors")),
    "Operations": (("internal_knowledge", "agentic_tools"), ("process automation errors", "manual override gaps")),
    "Quality Assurance": (("regulated", "high_stakes", "internal_knowledge"), ("test escape", "audit trail gaps")),
    "Fraud Detection / Investigations": (("financial_services", "high_stakes", "pii", "regulated"), ("false positives/negatives", "sensitive investigations data")),
    "Knowledge Management": (("retrieval", "internal_knowledge"), ("stale answers", "over-sharing")),
    "Executive Decision Support": (("high_stakes", "internal_knowledge", "regulated"), ("strategic misinformation", "material non-public data")),
}

BUSINESS_FUNCTIONS: tuple[str, ...] = tuple(sorted(BUSINESS_FUNCTION_META.keys()))


def get_specializations(industry: str) -> list[str]:
    return sorted(SPECIALIZATION_PROFILES.get(industry, {}).keys())


def get_specialization_profile(industry: str, specialization: str) -> SpecializationProfile | None:
    return SPECIALIZATION_PROFILES.get(industry, {}).get(specialization)


def get_default_regulations(industry: str, specialization: str) -> list[str]:
    prof = get_specialization_profile(industry, specialization)
    if not prof:
        return []
    return [REGULATIONS_BY_KEY[k].label for k in prof.default_regulation_keys if k in REGULATIONS_BY_KEY]


def tags_from_regulation_labels(labels: Sequence[str]) -> list[str]:
    out: list[str] = []
    for lab in labels:
        key = LABEL_TO_KEY.get(lab)
        if key and key in REGULATIONS_BY_KEY:
            out.extend(REGULATIONS_BY_KEY[key].derived_tags)
    return _filter_known(out)


def get_derived_industry_tags(industry: str, specialization: str) -> list[str]:
    prof = get_specialization_profile(industry, specialization)
    if not prof:
        return []
    return _filter_known(prof.derived_tags)


def get_derived_function_tags(business_function: str) -> list[str]:
    meta = BUSINESS_FUNCTION_META.get(business_function)
    if not meta:
        return []
    return _filter_known(meta[0])


def get_combined_context_tags(
    industry: str,
    specialization: str,
    business_function: str,
    selected_regulations: Sequence[str],
    user_extra_tags: Sequence[str] | None,
) -> list[str]:
    merged: list[str] = []
    merged.extend(get_derived_industry_tags(industry, specialization))
    merged.extend(get_derived_function_tags(business_function))
    merged.extend(tags_from_regulation_labels(selected_regulations))
    if user_extra_tags:
        merged.extend(user_extra_tags)
    return _filter_known(merged)


def determine_contextual_risk_emphasis(
    industry: str,
    specialization: str,
    business_function: str,
    selected_regulations: Sequence[str],
) -> list[str]:
    prof = get_specialization_profile(industry, specialization)
    items: list[str] = []
    if prof:
        items.extend(prof.risk_emphasis)
    fm = BUSINESS_FUNCTION_META.get(business_function)
    if fm:
        items.extend(fm[1])
    if selected_regulations:
        items.append(f"Regulatory context considered ({len(selected_regulations)} item(s)) elevates documentation and review expectations.")
    # dedupe preserve order
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out[:12]


def determine_control_emphasis(
    industry: str,
    specialization: str,
    business_function: str,
) -> list[str]:
    prof = get_specialization_profile(industry, specialization)
    items: list[str] = []
    if prof:
        items.extend(prof.control_emphasis)
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out[:10]


def build_domain_rationale(
    industry: str,
    specialization: str,
    business_function: str,
    selected_regulations: Sequence[str],
) -> str:
    regs = ", ".join(selected_regulations) if selected_regulations else "None selected beyond profile defaults you cleared."
    risks = determine_contextual_risk_emphasis(industry, specialization, business_function, selected_regulations)
    risk_blob = "; ".join(risks[:5])
    return (
        f"Industry **{industry}** / **{specialization}** with business function **{business_function}** frames typical "
        f"failure modes around: {risk_blob}. "
        f"Regulatory / standards context selected for this intake: {regs}. "
        "This context informs tag emphasis, triage, and reviewer focus—it does **not** determine legal compliance."
    )


def build_context_enrichment_block(
    industry: str,
    specialization: str,
    business_function: str,
    selected_regulations: Sequence[str],
) -> str:
    """Prepended to user narrative so the matcher can pick up domain keywords."""
    regs = "; ".join(selected_regulations) if selected_regulations else "None explicitly selected"
    emphasis = determine_contextual_risk_emphasis(industry, specialization, business_function, selected_regulations)
    ctrl = determine_control_emphasis(industry, specialization, business_function)
    return (
        "--- Structured governance context (for assessment; not a legal determination) ---\n"
        f"Industry: {industry}\n"
        f"Specialization: {specialization}\n"
        f"Business function: {business_function}\n"
        f"Regulatory / standards context considered: {regs}\n"
        f"Domain risk emphasis (illustrative): {'; '.join(emphasis[:6])}\n"
        f"Control emphasis notes (illustrative): {'; '.join(ctrl[:5])}\n"
        "--- End structured context ---"
    )


def compute_enriched_tier(
    use_case_text: str,
    final_assessment_tags: Sequence[str],
    *,
    regulation_label_count: int,
    business_function: str,
) -> str:
    """Apply transparent bumps on top of base `determine_risk_tier`."""
    from governance_workflow import determine_risk_tier

    base = determine_risk_tier(use_case_text, list(final_assessment_tags))
    rank = {"Low": 0, "Medium": 1, "High": 2}
    r = rank[base]

    if regulation_label_count >= 4:
        r = max(r, 1)
    if regulation_label_count >= 6:
        r = max(r, 2)

    high_func = {
        "Underwriting / Risk Decisioning",
        "Clinical Operations",
        "Fraud Detection / Investigations",
        "Executive Decision Support",
        "Legal",
        "Quality Assurance",
    }
    if business_function in high_func:
        r = max(r, 2)

    if business_function in {"Security Operations", "Compliance", "Finance"}:
        r = max(r, 1)

    inv = {0: "Low", 1: "Medium", 2: "High"}
    return inv[r]
