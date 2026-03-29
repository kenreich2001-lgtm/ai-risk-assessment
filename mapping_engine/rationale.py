"""Enterprise-oriented mapping rationales (NIST AI RMF + Generative AI Profile framing)."""

from __future__ import annotations

from mapping_engine.catalog import Control, Risk


def _coverage_sentence(coverage: str, control_type: str) -> str:
    role = {
        "preventive": "**Preventive**: reduces probability of the failure mode before harm materializes.",
        "detective": "**Detective**: surfaces misuse, drift, and anomalies early enough to intervene.",
        "corrective": "**Corrective**: contains damage and restores an acceptable operating state after a trigger.",
        "compensating": "**Compensating**: supplemental assurance where primary technical controls are incomplete (typical with vendor-hosted models).",
    }.get(coverage, coverage)
    hint = {
        "administrative": "governance, contracts, and assigned accountability.",
        "technical": "enforcement in software, platforms, and infrastructure.",
        "procedural": "operating discipline, checkpoints, and supervised workflows.",
    }.get(control_type, "mixed administrative and technical measures.")
    return f"{role} Implemented as a **{control_type}** control — {hint}"


def _overlap_nist(risk: Risk, control: Control) -> str:
    r_ids = {x.category_id for x in risk.nist}
    shared = [f"{x.function} ({x.category_id})" for x in control.nist if x.category_id in r_ids]
    if shared:
        return "NIST AI RMF alignment concentrates on " + "; ".join(shared[:3]) + "."
    return (
        "NIST mapping is complementary: the control emphasizes "
        + ", ".join(f"{x.function} ({x.category_id})" for x in control.nist[:2])
        + " while the risk stresses different MAP/MEASURE/MANAGE threads."
    )


def _mechanism_line(risk: Risk, rationale_key: str) -> str:
    """How loss occurs — keyed for variety; risk.id refines high-stakes rows."""
    head = rationale_key.split("_")[0] if "_" in rationale_key else rationale_key
    by_key = {
        "unreliable": (
            f"In this design, **{risk.name}** propagates through plausible-sounding outputs that are not verified "
            f"against authoritative sources before decisions or customer-facing replies ship."
        ),
        "privacy": (
            f"**{risk.name}** materializes when embeddings, logging, or completion paths retain or echo "
            f"regulated or confidential material beyond the intended consumer or retention boundary."
        ),
        "injection": (
            f"**{risk.name}** arises when instruction-bearing content (prompts, tickets, uploaded files) "
            f"is interpreted as trusted context, shifting model behavior or tool arguments."
        ),
        "supply": (
            f"**{risk.name}** tracks vendor release, routing, and data-handling changes that the enterprise "
            f"does not fully observe until downstream behavior or audits diverge."
        ),
        "oversight": (
            f"**{risk.name}** appears when approvals, role clarity, or escalation paths do not match "
            f"the actual autonomy of the model in frontline workflows."
        ),
        "agent": (
            f"**{risk.name}** compounds when natural-language intent is mapped to APIs or transactions "
            f"without hard limits on scope, confirmation, or rollback."
        ),
        "monitoring": (
            f"**{risk.name}** develops quietly as prompts, corpora, or integrations shift while KPIs "
            f"still reflect launch baselines."
        ),
        "bias": (
            f"**{risk.name}** persists when retrieval or base-model skew produces systematically "
            f"different treatment for cohorts in scope for fairness or eligibility review."
        ),
        "automation": (
            f"**{risk.name}** grows when users substitute model text for verification because fluency "
            f"reads as diligence under time pressure."
        ),
        "output": (
            f"**{risk.name}** emerges when downstream components treat model strings like trusted data "
            f"for rendering, execution, or persistence."
        ),
        "abuse": (
            f"**{risk.name}** scales with exposed endpoints: volume, policy-testing traffic, or "
            f"resource consumption the service was not sized to absorb."
        ),
        "iam": (
            f"**{risk.name}** occurs when AI-facing routes skip the same segregation of duties and "
            f"token scopes expected of the core application tier."
        ),
        "provenance": (
            f"**{risk.name}** reflects unclear chain-of-custody for documents or weights that feed "
            f"retrieval and tuning decisions."
        ),
        "incident": (
            f"**{risk.name}** widens when model- or tool-related events lack owners, severity rubrics, "
            f"and communication paths tested before production stress."
        ),
    }
    line = by_key.get(rationale_key, by_key.get(head, ""))
    if line:
        return line
    return (
        f"Given **{risk.name}**, the practical failure path is that controls upstream of the model "
        f"do not constrain the combinations of data, prompts, and tools that can run in production."
    )


def _risk_specific_mechanism_addon(risk: Risk, rationale_key: str) -> str:
    if risk.id == "R-006" and "agent" in rationale_key:
        return " Tooling expands blast radius: a single bad argument bundle can touch multiple backends."
    if risk.id == "R-012":
        return " Retrieval indexes and admin surfaces are frequent weak links in otherwise strong apps."
    if risk.id == "R-003":
        return " Mixed trust zones (user text plus internal snippets) increase privilege confusion for the model."
    if risk.id == "R-008":
        return " Employment and eligibility contexts amplify legal exposure per decision record."
    if risk.id == "R-005":
        return " The cost of a missed human checkpoint rises with regulated or safety-critical subject matter."
    return ""


def build_rationale(
    risk: Risk,
    control: Control,
    rationale_key: str,
    use_case_summary: str,
    tags: frozenset[str],
) -> str:
    tag_line = ", ".join(sorted(tags)) if tags else "unspecified generative-AI deployment context"
    narrative = ""
    if use_case_summary.strip():
        narrative = (
            f"The stated use case ({use_case_summary.strip()[:280]}{'…' if len(use_case_summary.strip()) > 280 else ''}) "
            f"sits in a context tagged: {tag_line}. "
        )
    else:
        narrative = f"Inferred operating context (tags: {tag_line}) "

    relevance = (
        f"{narrative}"
        f"**{risk.name}** warrants attention because {risk.description.rstrip('.')}. "
        f"The mapping prioritizes this row where those conditions intersect with the controls catalog."
    )

    mechanism_core = _mechanism_line(risk, rationale_key)
    addon = _risk_specific_mechanism_addon(risk, rationale_key)
    mechanism = mechanism_core + (f" {addon}" if addon else "")

    control_fit = (
        f"**{control.name}** fits because {_overlap_nist(risk, control)} "
        f"{control.description.rstrip('.')}. {_coverage_sentence(control.coverage, control.control_type)}"
    )

    residual = (
        f"{risk.residual_risk} **{control.name}** does not remove model stochasticity or hostile creativity; "
        f"it tightens governance and evidence around decisions the model influences."
    )

    sections = (
        f"1. **Relevance to this use case**\n\n{relevance}\n\n"
        f"2. **Mechanism**\n\n{mechanism}\n\n"
        f"3. **Control fit**\n\n{control_fit}\n\n"
        f"4. **Residual risk / limitation**\n\n{residual}"
    )
    return sections
