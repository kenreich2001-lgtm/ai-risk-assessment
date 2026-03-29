"""Risk-to-control mapping — public API: map_use_case."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Sequence, Tuple

from mapping_engine.catalog import Risk, get_control
from mapping_engine.matcher import mapping_priority_score, match_use_case
from mapping_engine.rationale import build_rationale
from mapping_engine.remediation import RemediationDetail, build_remediation, format_remediation_deliverable
from mapping_engine.taxonomy import format_gai_refs, format_nist_refs


@dataclass(frozen=True)
class MappedRow:
    priority_score: int
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
    mapping_rationale: str
    remediation_gap: str
    remediation_action: str
    remediation_artifact: str
    remediation_verification: str
    remediation_residual_risk: str
    remediation_client_narrative: str


MAPPING_TABLE_SCHEMA: tuple[str, ...] = tuple(MappedRow.__dataclass_fields__.keys())


def map_use_case(use_case_text: str, extra_tags: Sequence[str] | None = None) -> Dict[str, Any]:
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
            rem: RemediationDetail = build_remediation(risk, ctrl, edge.remediation_key, m.tags)
            rows.append(
                MappedRow(
                    priority_score=prio,
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
                    mapping_rationale=build_rationale(risk, ctrl, edge.rationale_key, summary, m.tags),
                    remediation_gap=rem.gap,
                    remediation_action=rem.action,
                    remediation_artifact=rem.artifact,
                    remediation_verification=rem.verification,
                    remediation_residual_risk=rem.residual_risk,
                    remediation_client_narrative=format_remediation_deliverable(rem),
                )
            )

    rows.sort(key=lambda r: (-r.priority_score, r.risk_id, r.control_id))

    def _executive_summary(
        table: List[MappedRow],
        tag_list: List[str],
        risks_sel: Tuple[Risk, ...],
    ) -> str:
        """5–7 sentences; deterministic from scores, risks, and tags (no LLM)."""
        if not table:
            return (
                "Posture is **indeterminate** for mapping priority because no risk–control rows were produced. "
                "Broaden the use-case description or validated tags, then re-run the mapper. "
                "Absent catalog matches, the tool does not infer a ranked control backlog."
            )

        peak = max(row.priority_score for row in table)
        # Posture from peak row score (0–100): conservative bands for sponsor briefing.
        if peak >= 82:
            posture_lbl = "elevated to **critical**"
        elif peak >= 66:
            posture_lbl = "**high**"
        elif peak >= 45:
            posture_lbl = "**moderate**"
        else:
            posture_lbl = "**low-to-moderate**"

        best_by_risk: Dict[str, int] = {}
        for row in table:
            best_by_risk[row.risk_id] = max(best_by_risk.get(row.risk_id, 0), row.priority_score)
        ordered_risks = sorted(best_by_risk.keys(), key=lambda rid: -best_by_risk[rid])[:3]
        risk_meta = {r.id: r for r in risks_sel}
        driver_bits: List[str] = []
        for rid in ordered_risks:
            rcat = risk_meta.get(rid)
            nm = rcat.name if rcat else rid
            sev = rcat.severity if rcat else ""
            lik = rcat.likelihood if rcat else ""
            driver_bits.append(f"{rid} ({nm}; {sev} / {lik}) at peak score {best_by_risk[rid]}")

        tagset = frozenset(tag_list)
        focus: List[str] = []
        if tagset & {"agentic_tools", "action_execution"}:
            focus.append("action/tool guardrails and least-privilege execution")
        if tagset & {"customer_facing", "customer_support_bot", "untrusted_input", "untrusted_content", "external_content"}:
            focus.append("customer-channel hardening and untrusted-input handling")
        if tagset & {"retrieval", "internal_knowledge"}:
            focus.append("retrieval/IAM boundaries and corpus governance")
        if tagset & {"third_party_model"}:
            focus.append("vendor posture, monitoring, and contractual control")
        if tagset & {"pii", "phi", "sensitive_data", "financial_data", "financial_services", "healthcare", "hr_employment"}:
            focus.append("data minimization, logging, and privacy-sensitive QA")
        if not focus:
            focus.append("cross-cutting governance, evaluation, and production monitoring")
        seen_f: set[str] = set()
        focus_unique = [x for x in focus if not (x in seen_f or seen_f.add(x))]

        s1 = (
            f"Overall mapped priority posture is {posture_lbl} (peak mapping score {peak}/100 on the current catalog weighting)."
        )
        s2 = "Primary drivers, by peak score per risk, are: " + "; ".join(driver_bits) + "."
        s3 = "Recommended near-term emphasis: " + "; ".join(focus_unique[:4]) + "."
        s4 = (
            "These judgments reflect inferred tags and catalog severity/likelihood only; "
            "they should be validated against your actual data flows, tool inventory, and regulatory perimeter."
        )
        s5 = (
            "Residual exposure remains where vendor behavior, emergent prompts, or organizational exceptions sit outside the modeled controls."
        )
        return " ".join([s1, s2, s3, s4, s5])

    exec_summary = _executive_summary(rows, sorted(m.tags), m.selected_risks)

    out: Dict[str, Any] = {
        "executive_summary": exec_summary,
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
    if __debug__ and out["mapping_table"]:
        assert set(out["mapping_table"][0]) == set(MAPPING_TABLE_SCHEMA)
    return out


__all__ = ["map_use_case", "MappedRow", "MAPPING_TABLE_SCHEMA", "RemediationDetail", "format_remediation_deliverable"]
