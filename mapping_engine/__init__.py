"""AI use case risk assessment and control mapping — public API: `map_use_case`.

This tool performs an AI use case risk assessment. For a given use case, it identifies and ranks the most
material risks, maps those risks to relevant controls aligned to NIST AI RMF and AI 600-1, and defines the
remediation actions required to address control gaps and prepare the use case for validation or audit.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Sequence

from mapping_engine.audit_report import generate_audit_report
from mapping_engine.catalog import CONTROLS, Risk, get_control
from mapping_engine.nist_control_mapping import CONTROL_TO_NIST
from mapping_engine.framework_alignment import compute_row_framework_alignment, row_mapping_strength
from mapping_engine.matcher import mapping_priority_score, match_use_case
from mapping_engine.rationale import build_rationale
from mapping_engine.remediation import RemediationDetail, build_remediation, format_remediation_deliverable
from mapping_engine.taxonomy import format_gai_refs, format_nist_refs


@dataclass(frozen=True)
class MappedRow:
    priority_score: int
    mapping_strength: str
    risk_id: str
    risk_name: str
    risk_description: str
    risk_severity: str
    risk_likelihood: str
    impact_domain: str
    risk_catalog_residual: str
    risk_nist_ai_rmf: str
    risk_generative_ai_profile: str
    control_id: str
    control_name: str
    control_type: str
    control_coverage: str
    control_nist_ai_rmf: str
    control_generative_ai_profile: str
    primary_nist_ai_rmf_function: str
    primary_nist_ai_rmf_categories: str
    nist_ai_rmf_explicit_mapping: str
    primary_nist_ai_600_1_themes: str
    framework_mapping_rationale: str
    mapping_rationale: str
    remediation_gap: str
    remediation_action: str
    remediation_artifact: str
    remediation_verification: str
    remediation_residual_risk: str
    remediation_client_narrative: str
    remediation_priority: str
    remediation_owner: str
    remediation_timeline: str
    remediation_evidence_expectation: str


MAPPING_TABLE_SCHEMA: tuple[str, ...] = tuple(MappedRow.__dataclass_fields__.keys())

# Keys returned on `map_use_case(...)[\"audit_report\"]` (risk & control assessment payload).
AUDIT_REPORT_SCHEMA: tuple[str, ...] = (
    "executive_summary",
    "overall_risk_level",
    "use_case_summary",
    "most_material_risks",
    "required_controls",
    "gaps_and_remediation",
    "required_remediation_actions",
    "evidence_for_audit_readiness",
    "audit_readiness_conclusion",
    "diagnostics",
)


def map_use_case(
    use_case_text: str,
    extra_tags: Sequence[str] | None = None,
    *,
    audit_evidence_confirmed: bool = False,
) -> Dict[str, Any]:
    m = match_use_case(use_case_text, extra_tags)
    summary = use_case_text.strip()[:500]
    by_risk: Dict[str, List[Any]] = {}
    for e in m.edges:
        by_risk.setdefault(e.risk_id, []).append(e)

    rows: List[MappedRow] = []
    for risk in m.selected_risks:
        for edge in by_risk.get(risk.id, []):
            ctrl = get_control(edge.control_id)
            prio = mapping_priority_score(risk, m.tags, edge.weight)
            rem: RemediationDetail = build_remediation(risk, ctrl, edge.remediation_key, m.tags, prio)
            strength = row_mapping_strength(edge.remediation_key)
            fw = compute_row_framework_alignment(risk, ctrl, edge.rationale_key, edge.remediation_key)
            rows.append(
                MappedRow(
                    priority_score=prio,
                    mapping_strength=strength,
                    risk_id=risk.id,
                    risk_name=risk.name,
                    risk_description=risk.description,
                    risk_severity=risk.severity,
                    risk_likelihood=risk.likelihood,
                    impact_domain=", ".join(risk.impact_domain),
                    risk_catalog_residual=risk.residual_risk,
                    risk_nist_ai_rmf=format_nist_refs(*risk.nist),
                    risk_generative_ai_profile=format_gai_refs(*risk.gai),
                    control_id=ctrl.id,
                    control_name=ctrl.name,
                    control_type=ctrl.control_type,
                    control_coverage=ctrl.coverage,
                    control_nist_ai_rmf=format_nist_refs(*ctrl.nist),
                    control_generative_ai_profile=format_gai_refs(*ctrl.gai),
                    primary_nist_ai_rmf_function=fw.primary_nist_ai_rmf_function,
                    primary_nist_ai_rmf_categories=fw.primary_nist_ai_rmf_categories,
                    nist_ai_rmf_explicit_mapping=fw.nist_ai_rmf_explicit_mapping,
                    primary_nist_ai_600_1_themes=fw.primary_nist_ai_600_1_themes,
                    framework_mapping_rationale=fw.framework_mapping_rationale,
                    mapping_rationale=build_rationale(
                        risk,
                        ctrl,
                        edge.rationale_key,
                        summary,
                        m.tags,
                        fw,
                    ),
                    remediation_gap=rem.gap,
                    remediation_action=rem.action,
                    remediation_artifact=rem.artifact,
                    remediation_verification=rem.verification,
                    remediation_residual_risk=rem.residual_risk,
                    remediation_client_narrative=format_remediation_deliverable(rem, edge.remediation_key),
                    remediation_priority=rem.remediation_priority,
                    remediation_owner=rem.remediation_owner,
                    remediation_timeline=rem.remediation_timeline,
                    remediation_evidence_expectation=rem.remediation_evidence_expectation,
                )
            )

    rows.sort(key=lambda r: (-r.priority_score, r.risk_id, r.control_id))

    out: Dict[str, Any] = {
        "use_case_text": use_case_text.strip(),
        "audit_evidence_confirmed": audit_evidence_confirmed,
        "executive_summary": "",
        "tags": sorted(m.tags),
        "risks": [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity,
                "likelihood": r.likelihood,
                "impact_domain": ", ".join(r.impact_domain),
                "residual_risk": r.residual_risk,
                "nist_ai_rmf": format_nist_refs(*r.nist),
                "generative_ai_profile": format_gai_refs(*r.gai),
            }
            for r in m.selected_risks
        ],
        "mapping_table": [asdict(row) for row in rows],
    }
    out["audit_report"] = generate_audit_report(out)
    out["executive_summary"] = (out["audit_report"] or {}).get("executive_summary", "")

    if __debug__ and out["mapping_table"]:
        assert set(out["mapping_table"][0]) == set(MAPPING_TABLE_SCHEMA)
        assert {c.id for c in CONTROLS} == set(CONTROL_TO_NIST.keys())
    if __debug__ and out.get("audit_report"):
        assert tuple(out["audit_report"].keys()) == AUDIT_REPORT_SCHEMA
    return out


__all__ = [
    "map_use_case",
    "MappedRow",
    "MAPPING_TABLE_SCHEMA",
    "AUDIT_REPORT_SCHEMA",
    "CONTROL_TO_NIST",
    "RemediationDetail",
    "format_remediation_deliverable",
    "generate_audit_report",
]
