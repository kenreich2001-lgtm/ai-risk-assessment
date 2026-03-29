"""Risk and control assessment over `map_use_case` results — design and coverage view, not a compliance attestation."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, List, Sequence, Tuple

from mapping_engine.catalog import get_control
from mapping_engine.nist_control_mapping import format_secondary_ai_rmf, get_control_framework_mapping

# Operational / customer-regulatory stake + what failure looks like on stage (consulting voice).
_TOP_RISK_NARRATIVE: Dict[str, Tuple[str, str]] = {
    "R-001": (
        "Customers and frontline staff execute on the assistant’s wording—so wrong tone, facts, or safety gaps convert straight into churn, complaints, and supervisory attention.",
        "Call transcripts and tickets show confident-but-wrong guidance; executives learn from social media or a regulator letter, not from an internal dashboard first.",
    ),
    "R-002": (
        "PII, PHI, or contractual secrets in prompts, logs, embeddings, or vendor subprocessors create breach notification, contract, and licensing exposure overnight.",
        "Forensic review finds full prompts or transcripts in the wrong index; a customer or DP regulator asks how their record entered model training or logging.",
    ),
    "R-003": (
        "Malicious or careless content in chats, tickets, or retrieved docs becomes executable intent—security and fraud teams care because the blast radius is the whole connected stack.",
        "An attacker seeds a help-article paragraph; the assistant follows it into credential helpers, sideways data reads, or ticket workflows you thought were guarded.",
    ),
    "R-004": (
        "You operate without a bill of materials for model routing, refusal behavior, and retention—operations and legal lose the thread when behavior changes in production.",
        "SLAs slip after an opaque vendor rollout; logs show different refusal rates but no change ticket on your side explaining customer impact.",
    ),
    "R-005": (
        "Regulators and unions expect a named human when eligibility, care, or pay decisions lean on software—ambiguous RACI is litigation discovery gold.",
        "An audit asks who approved an adverse decision; the trail stops at “model suggested.”",
    ),
    "R-006": (
        "Every integrated API is a potential teller window—finance and IAM peers need proof scopes, approvals, and rollbacks match money-movement reality.",
        "A single prompt sequence opens refunds, account changes, or ticket escalations at scale before anyone in ops notices the pattern.",
    ),
    "R-007": (
        "Governance forums assume yesterday’s metrics still describe live traffic; boards hear green dashboards while customers hit regressions.",
        "Support quality drops for two sprints; nobody pages until a viral post compares answers week-over-week.",
    ),
    "R-008": (
        "Fair-lending and employment rules bite when model-assisted rationales skew by cohort—reputation and class actions scale faster than model retraining.",
        "Disparate outcomes appear in a sampling exercise; legal demands the prompt and corpus trail for a challenged decision.",
    ),
    "R-009": (
        "Internal efficiency wins evaporate when staff paste AI prose into systems of record without verification—your CMDB and CRM quietly become fiction.",
        "Audit pulls a runbook paragraph written by the assistant; it omits a required safety check that humans no longer read.",
    ),
    "R-010": (
        "Untrusted model strings crossing into tickets, browsers, and exports become classic injection and secrecy problems—appsec owns the breach narrative.",
        "Credentials render in a ticket preview; a phishing pattern rides a generated HTML block into a browser the team trusted as “internal only.”",
    ),
    "R-011": (
        "Public endpoints are both a cost center and an abuse magnet—FinOps and trust-and-safety escalations land together.",
        "Budget alerts fire while scraped prompts train a competitor; your abuse queue cannot tie sessions to real customers.",
    ),
    "R-012": (
        "Weak AuthZ on RAG and admin planes negates fine-grained app permissions—expect cross-tenant findings if pen-test or a regulator maps data flows.",
        "Support user A’s retrieval session surfaces snippets tagged to customer B; the ticket closes but the access log tells a different story.",
    ),
    "R-013": (
        "Procurement and IP counsel care about corpus lineage; bad sources poison customer answers and renewals.",
        "Legal flags an unlicensed doc in the index after a customer cites an impossible policy “quote” the model invented from a stale PDF.",
    ),
    "R-014": (
        "Incident timelines drive regulatory and customer trust—an AI severity-1 without owners looks like negligence under scrutiny.",
        "A model outage or spill lands in Slack threads instead of a declared incident; notification clocks never start.",
    ),
}

_RESIDUAL_STILL_BEHAVIOR: Dict[str, str] = {
    "R-001": "generate misleading customer-facing answers that drive refunds, rework, or regulatory complaints",
    "R-002": "leak sensitive account or health data through prompts, logging, embeddings, or hosted inference",
    "R-003": "fall for adversarial prompts or poisoned external content and misuse tools or context windows",
    "R-004": "change effective behavior when the third-party stack updates routing, filters, or retention without your release gate",
    "R-005": "leave high-stakes decisions without a defensible human owner in the audit trail",
    "R-006": "trigger unintended account or ticket actions through over-broad tools",
    "R-007": "operate outside tested quality bands while monitoring and eval cycles catch up",
    "R-008": "disproportionately disadvantage protected classes in service or eligibility outcomes",
    "R-009": "plant wrong structured fields into CRM, ticketing, or knowledge bases staff treat as authoritative",
    "R-010": "inject unsafe content into rendered channels where downstream systems assume trust",
    "R-011": "absorb abuse or scraping that spikes cost and erodes customer trust on public paths",
    "R-012": "cross tenant or role boundaries in retrieval and admin calls tied to the assistant",
    "R-013": "cite poisoned, stale, or unlicensed sources as if authoritative for customers",
    "R-014": "mishandle a severe AI incident because playbooks, owners, or forensics are immature",
}


def _english_join_phrases(parts: List[str]) -> str:
    p = [x.strip() for x in parts if x and x.strip()]
    if not p:
        return ""
    if len(p) == 1:
        return p[0]
    if len(p) == 2:
        return f"{p[0]} and {p[1]}"
    return f"{', '.join(p[:-1])}, and {p[-1]}"


def _overall_risk_level(most_material: List[Dict[str, Any]]) -> str:
    """Aggregate label from catalog severities and peak scores only (no new scoring rules)."""
    if not most_material:
        return "MEDIUM"
    peak_max = max(int(m.get("peak_priority_score") or 0) for m in most_material)
    sev_rank = {"Critical": 3, "High": 3, "Medium": 2, "Low": 1}
    worst = max(sev_rank.get(str(m.get("severity", "")).strip(), 0) for m in most_material)
    if worst >= 3:
        return "HIGH"
    if worst == 2:
        return "HIGH" if peak_max >= 70 else "MEDIUM"
    if worst == 1:
        return "MEDIUM" if peak_max >= 50 else "LOW"
    return "HIGH" if peak_max >= 65 else ("MEDIUM" if peak_max >= 35 else "LOW")


def _residual_why_controls_incomplete(top_ids: Sequence[str], tagset: set[str]) -> str:
    t = set(top_ids)
    has_tools = bool(t & {"R-006", "R-012"}) or bool(tagset & {"agentic_tools", "action_execution"})
    has_untrusted = bool(t & {"R-003", "R-013", "R-002"}) or bool(
        tagset
        & {
            "untrusted_input",
            "untrusted_content",
            "external_content",
            "retrieval",
            "customer_facing",
            "customer_support_bot",
        }
    )
    has_output = bool(t & {"R-001", "R-009"})
    has_monitor_gap = bool(t & {"R-007"})
    third_party = bool(t & {"R-004"}) or bool(tagset & {"third_party_model"})

    if has_tools and has_untrusted:
        return (
            "Real-time tool execution plus adversarial prompts and unreviewed external content mean **preventive rules alone are insufficient**; "
            "**monitoring, testing, and incident playbooks must** cover novel instruction-and-action sequences."
        )
    if has_tools:
        return (
            "**Tooling executes in real time** ahead of manual review; **least-privilege scopes, automated blocks, and synchronous approvals must** "
            "cover prompt paths outside documented workflows."
        )
    if has_untrusted:
        return (
            "User-supplied and retrieved text **introduce instruction patterns outside training-time filters**; **injection and exfiltration defenses must** "
            "be **retested continuously** as content and models change."
        )
    if has_output and third_party:
        return (
            "Third-party model routing **changes completion behavior independently of your release gate**; **evaluation gates and vendor change control must** "
            "stay aligned to customer-facing quality and safety."
        )
    if has_monitor_gap or third_party:
        return (
            "**Monitoring and governance forums must** track corpus, prompt, and hosted-behavior drift; **periodic review is mandatory** so regressions surface on a defined cadence."
        )
    if has_output:
        return (
            "**Novel customer phrasing produces plausible wrong answers** that pass coarse checks; **human or automated review layers must** sit on outbound paths."
        )
    if t & {"R-002"} or tagset & {"pii", "phi", "sensitive_data", "financial_data", "financial_services"}:
        return (
            "**Sensitive data propagates through** logging, replay, and embedding side paths; **data-classification, retention, and access policies must** span every system that touches the assistant."
        )
    return (
        "**New prompt-and-context combinations outpace** modeled test cases; **continuous red-teaming and control updates must** close gaps as traffic evolves."
    )


def _specific_residual_statement(
    top_risk_ids: Sequence[str],
    risk_meta: Dict[str, Dict[str, Any]],
    tags: List[str],
) -> str:
    ids = [rid for rid in top_risk_ids[:3] if rid in risk_meta]
    if not ids:
        return "**Material risks are not identified** in this pass; **expand the use-case input** before treating residual exposure as complete."

    tagset = set(tags or [])
    labels = [str(risk_meta[rid].get("name", rid)).strip() for rid in ids]
    behaviors = [_RESIDUAL_STILL_BEHAVIOR.get(rid, "").strip() for rid in ids]
    behaviors = [b for b in behaviors if b]
    if not behaviors:
        _, fail = _TOP_RISK_NARRATIVE.get(ids[0], ("", ""))
        behaviors = [fail or "produce harm through model outputs or connected functions"]

    focus = behaviors[:2] if len(behaviors) >= 2 else behaviors
    beh_text = focus[0] if len(focus) == 1 else f"{focus[0]} or {focus[1]}"

    theme_text = _english_join_phrases(labels)
    s1 = f"For **{theme_text}**, **failure modes in scope include** **{beh_text}**."
    s2 = _residual_why_controls_incomplete(ids, tagset)
    return f"{s1} {s2}"


_MATERIAL_RISK_LIMIT = 5
_MAX_PRIMARY_PER_RISK = 3
_MAX_SUPPORTING_PER_RISK = 2


def _evidence_is_generic_or_weak(evid: str) -> bool:
    """True when expectation text is too thin for review-ready specificity."""
    e = (evid or "").strip()
    if len(e) < 55:
        return True
    blob = e.lower()
    if (
        "configuration exports; change tickets" in blob
        and "access reviews, eval reports, blocked-action logs" in blob
    ):
        return True
    return False


def _control_status_reason(
    status: str,
    ctrl_name: str,
    risk_names: List[str],
    tagset: set[str],
    rids: List[str],
) -> str:
    rn = _english_join_phrases(risk_names)
    low = (ctrl_name or "").lower()

    if status == "missing":
        return (
            f"{rn} is material for this use case, but **no control** was identified as a **direct mitigator** in this assessment—"
            f"**agent or tooling actions**, **injection paths**, and **customer-impacting outputs** therefore lack a clear control anchor in the required set."
        )

    if status == "partial":
        if "iam" in low or "access" in low or "identity" in low:
            core = "**The design must** extend IAM and retrieval boundaries so **every** AI-initiated tool and data-plane call for this use case sits inside an explicit access rule set"
        elif "monitor" in low or "metric" in low or "telemet" in low or "dashboard" in low:
            core = "**Telemetry is required** as **primary** coverage—not **secondary**—for **real-time** tool-abuse and drift tied to each priority risk"
        elif "approval" in low or "human" in low or "loop" in low:
            core = "**Human approval must** be the **lead** mitigator on **every** priority risk’s customer-affecting path; **step-up approval must** bind the **live** tool-execution path"
        elif "policy" in low or "input" in low or "output" in low or "enforce" in low:
            core = "**Input/output policy enforcement must** be the **lead** mitigation for **each** affected risk, with **runtime** I/O rules specified—not optional overlays"
        elif "incident" in low or "response" in low:
            core = "**AI- and tool-specific** incident playbooks and forensics **must** be **primary** for **each** priority risk where response is listed"
        elif "eval" in low or "red" in low:
            core = "**Evaluation and red-teaming must** be the **lead** control for **each** peak risk, with **release-gate** evidence defined in the design"
        else:
            core = "This control is **supporting** for at least one priority risk; **the design must** name **where primary runtime enforcement** sits for that risk"

        behavior = _behavior_threads_for_readiness(tagset, rids)
        return f"{core}, particularly where {behavior} intersects {rn}."

    # present
    if "tool" in low or "sandbox" in low or "privilege" in low:
        present_core = "scoped for least-privilege tool execution"
    elif "input" in low or "output" in low or "policy" in low:
        present_core = "positioned to enforce I/O boundaries on live traffic"
    elif "approval" in low or "human" in low:
        present_core = "intended to gate customer-affecting actions before irreversible effects"
    elif "monitor" in low or "incident" in low:
        present_core = "intended to detect and respond when model or tool behavior diverges"
    else:
        present_core = "positioned as a **direct** (not ancillary) mitigator for the named risks"

    behavior = _behavior_threads_for_readiness(tagset, rids)
    return (
        f"{ctrl_name} is among the **direct mitigations** for {rn}; it is {present_core} where {behavior} "
        f"drive concern—a substantive control for this slice, not a disclosure-only afterthought."
    )


def _behavior_threads_for_readiness(tagset: set[str], material_ids: List[str]) -> str:
    mid = set(material_ids)
    parts: List[str] = []
    if mid & {"R-006", "R-012"} or tagset & {"agentic_tools", "action_execution"}:
        parts.append("agent-initiated tools that change tickets, accounts, or transactions")
    if mid & {"R-003", "R-013"} or tagset & {"untrusted_input", "untrusted_content", "external_content", "retrieval"}:
        parts.append("prompt injection and untrusted or retrieved content")
    if mid & {"R-001", "R-009"} or tagset & {"customer_facing", "customer_support_bot"}:
        parts.append("customer-facing answers that users or staff act on without verification")
    if mid & {"R-002"} or tagset & {"pii", "phi", "sensitive_data", "financial_data"}:
        parts.append("sensitive data in prompts, logs, or embeddings")
    if mid & {"R-004"} or tagset & {"third_party_model"}:
        parts.append("third-party model routing and opaque behavior shifts")
    return _english_join_phrases(parts) if parts else "model behavior and integrations in this scope"


def _build_required_controls(
    table: List[Dict[str, Any]],
    material_risk_ids: List[str],
    risk_by_id: Dict[str, Dict[str, Any]],
    use_case_text: str,
    tags: List[str],
) -> List[Dict[str, Any]]:
    """One row per required control: primary-first, capped per material risk; synthetic rows for unmapped material risks."""
    by_risk: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in table:
        by_risk[row["risk_id"]].append(row)

    tagset = set(tags or [])

    # (control_id or "") -> {"risk_ids": set, "rows": list of chosen representative rows per (risk,control)}
    buckets: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"risk_ids": set(), "pairs": []})

    for rid in material_risk_ids:
        rows_r = sorted(by_risk.get(rid, []), key=lambda x: (-int(x.get("priority_score") or 0), x["control_id"]))
        prim = [r for r in rows_r if r.get("mapping_strength") == "primary"]
        chosen: List[Dict[str, Any]] = []
        seen_c: set[str] = set()
        if prim:
            for r in prim:
                if r["control_id"] not in seen_c and len(seen_c) < _MAX_PRIMARY_PER_RISK:
                    seen_c.add(r["control_id"])
                    chosen.append(r)
        else:
            sup = [r for r in rows_r if r.get("mapping_strength") == "supporting"]
            for r in sup[:_MAX_SUPPORTING_PER_RISK]:
                if r["control_id"] not in seen_c:
                    seen_c.add(r["control_id"])
                    chosen.append(r)

        if not chosen:
            key = ""
            if key not in buckets:
                buckets[key] = {"risk_ids": set(), "pairs": []}
            buckets[key]["risk_ids"].add(rid)
            continue

        for r in chosen:
            cid = r["control_id"]
            buckets[cid]["risk_ids"].add(rid)
            buckets[cid]["pairs"].append((rid, cid))

    out: List[Dict[str, Any]] = []

    for cid, data in sorted(buckets.items(), key=lambda x: (x[0] == "", x[0])):
        rids = sorted(data["risk_ids"])
        risk_names = [risk_by_id.get(r, {}).get("name", r) for r in rids]

        if cid == "":
            # Missing: no direct control chosen for at least one material risk
            rep_peaks: List[int] = []
            for r in rids:
                rs = by_risk.get(r, [])
                if rs:
                    rep_peaks.append(max(int(x.get("priority_score") or 0) for x in rs))
            peak_hint = max(rep_peaks) if rep_peaks else 0
            out.append(
                {
                    "control_id": "",
                    "required_control": "(No direct mitigation identified for this assessment pass)",
                    "control_objective": "",
                    "primary_ai_rmf_mapping": "",
                    "secondary_ai_rmf_mapping": "",
                    "primary_ai_600_1_risk_theme": "",
                    "required_remediation_action": (
                        "Identify and implement **direct** mitigations from the control library (or document **executive risk acceptance** with compensating measures); "
                        "re-run the assessment with fuller use-case and data-flow detail."
                    ),
                    "related_risks": [{"risk_id": r, "risk_name": risk_by_id.get(r, {}).get("name", r)} for r in rids],
                    "control_status": "missing",
                    "remediation_required": "yes",
                    "evidence_expected": (
                        "Updated use-case and data-flow documentation; risk-register entries naming mitigations; signed risk-acceptance where applicable; "
                        "and artifacts that prove compensating controls where mitigations are deferred."
                    ),
                    "remediation_priority": "High" if peak_hint >= 60 else "Medium",
                    "remediation_owner": "AI governance / security engineering",
                    "remediation_timeline": "0–30 days" if peak_hint >= 60 else "30–60 days",
                    "control_status_reason": _control_status_reason("missing", "", risk_names, tagset, rids),
                }
            )
            continue

        # Per-risk: is there a primary link to cid?
        all_primary = True
        any_link = False
        candidate_rows: List[Dict[str, Any]] = []
        for rid in rids:
            pair_rows = [r for r in by_risk.get(rid, []) if r["control_id"] == cid]
            if not pair_rows:
                all_primary = False
                continue
            any_link = True
            has_prim = any(r.get("mapping_strength") == "primary" for r in pair_rows)
            if not has_prim:
                all_primary = False
            candidate_rows.append(max(pair_rows, key=lambda r: (-int(r.get("priority_score") or 0), 1 if r.get("mapping_strength") == "primary" else 0)))

        rep = max(
            [r for r in table if r["control_id"] == cid and r["risk_id"] in rids],
            key=lambda r: (1 if r.get("mapping_strength") == "primary" else 0, int(r.get("priority_score") or 0)),
            default=candidate_rows[0] if candidate_rows else {},
        )

        if not any_link:
            status = "missing"
        elif all_primary:
            status = "present"
        else:
            status = "partial"

        rem_req = "yes" if status != "present" else "no"
        ctrl_obj = get_control(cid)
        cf = get_control_framework_mapping(cid)
        ctrl_nm = ctrl_obj.name
        status_reason = _control_status_reason(status, ctrl_nm, risk_names, tagset, rids)

        evid = (rep.get("remediation_evidence_expectation") or "").strip()
        if not evid:
            evid = (
                "Configuration exports; change tickets; and tests of effectiveness appropriate to this control family "
                "(access reviews, eval reports, blocked-action logs, or runbooks as applicable)."
            )

        rem_act = (rep.get("remediation_action") or "").strip() or (
            "Operate control to standard with owned evidence and periodic retest."
        )

        out.append(
            {
                "control_id": cid,
                "required_control": ctrl_obj.name,
                "control_objective": ctrl_obj.description,
                "primary_ai_rmf_mapping": cf.primary_ai_rmf_mapping,
                "secondary_ai_rmf_mapping": format_secondary_ai_rmf(cf.secondary_ai_rmf_mapping),
                "primary_ai_600_1_risk_theme": cf.primary_ai_600_1_risk_theme,
                "required_remediation_action": rem_act,
                "related_risks": [{"risk_id": r, "risk_name": risk_by_id.get(r, {}).get("name", r)} for r in rids],
                "control_status": status,
                "remediation_required": rem_req,
                "evidence_expected": evid,
                "remediation_priority": rep.get("remediation_priority") or "Medium",
                "remediation_owner": rep.get("remediation_owner") or "Cross-functional lead",
                "remediation_timeline": rep.get("remediation_timeline") or "30–60 days",
                "control_status_reason": status_reason,
            }
        )

    # Sort: missing first, then partial, then present; then by name
    rank = {"missing": 0, "partial": 1, "present": 2}
    out.sort(key=lambda x: (rank.get(x["control_status"], 9), x["required_control"]))
    return out


def _risk_name_line(risk_by_id: Dict[str, Dict[str, Any]], material_risk_ids: List[str]) -> str:
    bits = [f"{risk_by_id.get(rid, {}).get('name', rid)} ({rid})" for rid in material_risk_ids[:5]]
    return "; ".join(bits) if bits else "priority risks in scope"


def _evidence_artifact_examples() -> str:
    return (
        "**When controls are implemented**, validation or audit would typically expect artifact types such as **application and security logs**, "
        "**IAM and policy configurations**, **model and prompt evaluation reports**, **blocked-action or abuse telemetry**, and "
        "**incident-response artifacts** (playbooks, tabletops, post-incident reviews)—**tie specific artifacts to each control row** in the required-control table."
    )


def _readiness_opinion_and_rationale(
    required_controls: List[Dict[str, Any]],
    mapping_result: Dict[str, Any],
    tags: List[str],
    material_risk_ids: List[str],
    risk_by_id: Dict[str, Dict[str, Any]],
    use_case_clip: str,
) -> Tuple[str, str]:
    """Same branching as historical readiness logic; narrative is design-time requirements only."""
    tagset = set(tags or [])
    behavior = _behavior_threads_for_readiness(tagset, material_risk_ids)
    risk_line = _risk_name_line(risk_by_id, material_risk_ids)
    ctrl_names = [r["required_control"] for r in required_controls if r.get("control_id")]
    ctrl_line = _english_join_phrases(ctrl_names[:6]) if ctrl_names else "*(no control names)*"

    if not required_controls:
        return (
            "Complete required-control definitions for this use case",
            f"**Implementation requirement:** no required-control rows were generated for «{use_case_clip or 'this scope'}». **Expand** the use-case description and **re-run** the assessment so **named direct mitigations** exist for **{risk_line}**.\n\n"
            f"{_evidence_artifact_examples()}",
        )

    has_missing = any(r["control_status"] == "missing" for r in required_controls)
    has_partial = any(r["control_status"] == "partial" for r in required_controls)
    rem_yes = any(r.get("remediation_required") == "yes" for r in required_controls)
    evid_empty = any(not (r.get("evidence_expected") or "").strip() for r in required_controls)
    evid_weak = any(_evidence_is_generic_or_weak(r.get("evidence_expected", "")) for r in required_controls)

    if has_missing:
        return (
            "Additional controls must be implemented prior to deployment",
            f"**Use-case risk threads:** {behavior}. **{risk_line}** drive materiality.\n\n"
            f"**At least one priority behavior lacks a named direct mitigation** in the required-control set. **Add explicit mitigations** for **tool-driven actions**, **injection paths**, and **customer-impacting outputs** **before deployment**.\n\n"
            f"{_evidence_artifact_examples()}",
        )

    if evid_empty:
        return (
            "Document evidence specifications per required control",
            f"**{risk_line}** are **in scope** with **{behavior}**.\n\n"
            f"**Named mitigations** include **{ctrl_line}**. **Every** required control **must** list **evidence specifications** (artifact types for future validation or audit) so implementation and test plans are traceable.\n\n"
            f"{_evidence_artifact_examples()}",
        )

    if has_partial or rem_yes or evid_weak:
        frag = []
        if has_partial:
            frag.append(
                "**partial mappings must** be elevated to **full direct mitigations** for tool and I/O paths on each priority risk"
            )
        if rem_yes:
            frag.append("**open remediation rows must** be **closed in the design record** before deployment")
        if evid_weak:
            frag.append(
                "**evidence specifications must** name concrete artifacts (logs, configurations, evaluation cycles)—**not** generic placeholders"
            )
        return (
            "Additional controls and remediations must be completed prior to deployment",
            f"**Required controls** address **{behavior}** and prioritize **{risk_line}**.\n\n"
            f"**Mitigations named:** **{ctrl_line}**. **Prior to deployment:** {'; '.join(frag)}.\n\n"
            f"{_evidence_artifact_examples()}",
        )

    all_present = all(r["control_status"] == "present" for r in required_controls)
    all_rem_no = all(r.get("remediation_required") == "no" for r in required_controls)
    if not (all_present and all_rem_no):
        return (
            "Additional controls must be implemented prior to deployment",
            f"**{risk_line}** with **{behavior}** **require** a **complete** required-control design.\n\n"
            f"**Every** mitigation **must** be **fully specified** (not partial) and **open remediation items must** be **resolved in the design record** **before deployment**.\n\n"
            f"{_evidence_artifact_examples()}",
        )

    evidence_attested = bool(mapping_result.get("audit_evidence_confirmed"))
    if not evidence_attested:
        return (
            "Required controls and remediation must be completed prior to deployment",
            f"**Required mitigations** for **{behavior}** include **{ctrl_line}**, mapped to **{risk_line}**.\n\n"
            f"**Prior to deployment**, **complete** **all required remediation actions** in this assessment and **finish** **evidence specifications** per control row.\n\n"
            f"**`audit_evidence_confirmed`** is an **optional program flag**: set it **only after** **independent review of real implementation evidence** (this engine does **not** perform that review).\n\n"
            f"{_evidence_artifact_examples()}",
        )

    return (
        "Required controls specified; evidence review flag set",
        f"**Required mitigations** **{ctrl_line}** **address** **{behavior}** for **{risk_line}** in this design pass.\n\n"
        f"**`audit_evidence_confirmed` is set** to record that **implementation evidence was reviewed outside this tool**; **the required-control and remediation tables remain the design record**.\n\n"
        f"**Ongoing change control** for **tool scopes**, **access rules**, and **model or data updates** **is mandatory**.\n\n"
        f"{_evidence_artifact_examples()}",
    )


# Executive-summary “why this matters” copy per catalog risk id (business tone; selection logic unchanged).
_BUSINESS_WHY_BY_RISK: Dict[str, str] = {
    "R-001": (
        "This use case **puts AI-generated answers in front of customers or staff** who may act on them. "
        "**This can result in** wrong advice, unsafe guidance, or false confidence. "
        "**Impact** includes **customer** complaints and churn, bad decisions, and **regulatory** attention where disclosures or advice are wrong."
    ),
    "R-002": (
        "This use case **handles sensitive information** in prompts, search, or logs. "
        "**This can result in** personal or confidential **data** showing up where it should not, or being kept too long. "
        "**Impact** includes breach response cost, broken customer trust, and legal or contract exposure."
    ),
    "R-003": (
        "This use case **lets users or outside content steer** what the model does, including any connected actions. "
        "**This can result in** hidden instructions, **data** leaks, or misuse of tools. "
        "**Impact** includes fraud, security incidents, and harm to **customers** and the business."
    ),
    "R-004": (
        "This use case **relies on third-party models or services** you do not fully control. "
        "**This can result in** silent changes to answers, refusals, or handling of **data**. "
        "**Impact** includes inconsistent **customer** experience and gaps when vendors change behavior."
    ),
    "R-005": (
        "This use case **supports outcomes that affect people** (for example eligibility, pay, or care). "
        "**This can result in** unclear accountability when something goes wrong. "
        "**Impact** includes legal and **regulatory** scrutiny over who decided what, and harm to affected individuals."
    ),
    "R-006": (
        "This use case **allows the system to take real actions**—such as updating tickets, accounts, or transactions—through tools, not just answering questions. "
        "**This can result in** wrong or unauthorized changes if access is too broad or approvals are missing. "
        "**Impact** includes **customer** harm, direct **financial** loss, fines, and reputational damage."
    ),
    "R-007": (
        "This use case **depends on model behavior staying good** while prompts, **data**, and models change. "
        "**This can result in** slow drift in quality before leadership sees it. "
        "**Impact** includes **customer** dissatisfaction and silent growth of errors and incidents."
    ),
    "R-008": (
        "This use case **can steer outcomes across groups of customers or employees**. "
        "**This can result in** unfair treatment that shows up in service or decisions. "
        "**Impact** includes legal risk, reputational harm, and real harm to **customers** and staff."
    ),
    "R-009": (
        "This use case **lets AI fill in fields** that staff or downstream systems treat as true. "
        "**This can result in** bad **data** in CRM, tickets, or knowledge bases. "
        "**Impact** includes wrong **customer** handling, rework, and operational cleanup cost."
    ),
    "R-010": (
        "This use case **shows model output inside apps or channels** that assume content is safe. "
        "**This can result in** unsafe or manipulative content reaching users or systems. "
        "**Impact** includes security incidents and **customer** exposure."
    ),
    "R-011": (
        "This use case **exposes an AI endpoint** to broad or public use. "
        "**This can result in** abuse, scraping, or runaway usage. "
        "**Impact** includes **money** lost to compute and abuse, plus trust and stability problems."
    ),
    "R-012": (
        "This use case **connects the assistant to sensitive data and admin paths**. "
        "**This can result in** people seeing information outside their role or tenant. "
        "**Impact** includes **data** leakage, fraud risk, and **regulatory** findings."
    ),
    "R-013": (
        "This use case **bases answers on documents and sources** the model does not own. "
        "**This can result in** wrong, outdated, or unlicensed information presented as fact. "
        "**Impact** includes **customer** harm, legal and IP issues, and bad business decisions."
    ),
    "R-014": (
        "This use case **needs a crisp response when AI causes or worsens an incident**. "
        "**This can result in** slow, improvised handling if roles and playbooks are unclear. "
        "**Impact** includes missed **regulatory** clocks and lasting **customer** trust damage."
    ),
}


def _executive_why_business(risk_id: str, risk_by_id: Dict[str, Dict[str, Any]]) -> str:
    if risk_id in _BUSINESS_WHY_BY_RISK:
        return _BUSINESS_WHY_BY_RISK[risk_id]
    meta = risk_by_id.get(risk_id, {})
    name = meta.get("name", risk_id)
    impact = (meta.get("impact_domain") or "").strip()
    tail = f" Key impact areas: {impact}." if impact else ""
    return (
        f"This use case **surfaces {name}** as the leading concern from how the workload was described. "
        f"**This can result in** harm to **customers**, **money**, or **data** if not managed.{tail}"
    )


def _required_controls_bullets(names: List[str]) -> str:
    if not names:
        return "- *(none identified in this assessment)*"
    return "\n".join(f"- {n.strip()}" for n in names if n and str(n).strip())


def _risk_first_executive_summary(
    top_risk: Dict[str, Any] | None,
    required_control_names: List[str],
    overall_risk_level: str,
    use_case_clip: str,
    risk_by_id: Dict[str, Dict[str, Any]],
    tags: List[str],
) -> str:
    _ = tags  # signature stable for callers; top risk id drives “why” text
    if not top_risk:
        return (
            "**Most material risk:** **Not determined** — describe the use case in more detail so risks can be ranked.\n\n"
            f"**Overall risk level:** **{overall_risk_level}** (provisional until the use case is clear).\n\n"
            "**Why this matters:** With almost no context, we cannot yet explain what the system does, what could go wrong, or who is affected.\n\n"
            "**Required controls — these must be implemented:**\n"
            "- *(not identified — re-run with a fuller use-case description)*"
        )
    rn = top_risk.get("risk_name", top_risk.get("risk_id", ""))
    rid = str(top_risk.get("risk_id", ""))
    why = _executive_why_business(rid, risk_by_id)
    bullets = _required_controls_bullets(required_control_names)

    return "\n\n".join(
        [
            f"**Most material risk:** **{rn}** ({rid}).",
            f"**Overall risk level:** **{overall_risk_level}**",
            f"**Why this matters:** {why}",
            f"**Required controls — these must be implemented:**\n{bullets}",
        ]
    )


def generate_audit_report(mapping_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Required-controls-centric risk and control assessment artifact. Alignment language only — never claims compliance.
    """
    table: List[Dict[str, Any]] = list(mapping_result.get("mapping_table") or [])
    risks: List[Dict[str, Any]] = list(mapping_result.get("risks") or [])
    tags: List[str] = list(mapping_result.get("tags") or [])
    use_case_text = (mapping_result.get("use_case_text") or "").strip()

    risk_by_id = {r["id"]: r for r in risks}

    peak_by_risk: Dict[str, int] = {}
    for row in table:
        rid = row["risk_id"]
        peak_by_risk[rid] = max(peak_by_risk.get(rid, 0), int(row.get("priority_score") or 0))

    material_risk_ids = sorted(peak_by_risk.keys(), key=lambda i: -peak_by_risk[i])[:_MATERIAL_RISK_LIMIT]
    if not material_risk_ids and risks:
        _sev = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        material_risk_ids = [
            str(r["id"])
            for r in sorted(
                risks,
                key=lambda x: (_sev.get(str(x.get("severity", "")), 9), str(x.get("id", ""))),
            )
        ][:3]

    # B. Most material risks
    most_material: List[Dict[str, Any]] = []
    top_for_residual: List[str] = []
    for rid in material_risk_ids:
        meta = risk_by_id.get(rid, {})
        biz, fail = _TOP_RISK_NARRATIVE.get(rid, ("", ""))
        stake = biz or (meta.get("description") or "")[:400]
        failure = fail or "Operational or regulatory fallout from unmitigated exposure in live channels."
        most_material.append(
            {
                "risk_id": rid,
                "risk_name": meta.get("name", rid),
                "severity": meta.get("severity", ""),
                "likelihood": meta.get("likelihood", ""),
                "peak_priority_score": peak_by_risk.get(rid, 0),
                "operational_stake": stake,
                "failure_mode": failure,
                "materiality_rationale": f"{stake[:280]}…" if len(stake) > 280 else stake,
            }
        )
        top_for_residual.append(rid)

    overall_risk_level = _overall_risk_level(most_material)

    required_controls = _build_required_controls(
        table,
        material_risk_ids,
        risk_by_id,
        use_case_text or mapping_result.get("use_case_description") or "",
        tags,
    )

    opinion, opinion_rationale = _readiness_opinion_and_rationale(
        required_controls,
        mapping_result,
        tags,
        material_risk_ids,
        risk_by_id,
        use_case_text[:160] if use_case_text else "",
    )

    # D. Gaps — rows needing remediation or non-present status
    gaps_and_remediation: List[Dict[str, Any]] = []
    for rc in required_controls:
        if rc["control_status"] == "present" and rc.get("remediation_required") == "no":
            continue
        gaps_and_remediation.append(
            {
                "control_id": rc["control_id"],
                "required_control": rc["required_control"],
                "control_status": rc["control_status"],
                "related_risks": rc["related_risks"],
                "remediation_action": rc.get("required_remediation_action", ""),
                "remediation_priority": rc.get("remediation_priority", "Medium"),
                "remediation_owner": rc.get("remediation_owner", ""),
                "remediation_timeline": rc.get("remediation_timeline", ""),
                "evidence_expected": rc.get("evidence_expected", ""),
            }
        )

    required_remediation_actions: List[Dict[str, Any]] = []
    for g in gaps_and_remediation:
        rr = g.get("related_risks") or []
        rsn = ", ".join(f"{x.get('risk_name', x.get('risk_id', ''))} ({x.get('risk_id', '')})" for x in rr) if rr else "—"
        required_remediation_actions.append(
            {
                "control_id": g["control_id"],
                "required_control": g["required_control"],
                "control_status": g["control_status"],
                "related_risks": rsn,
                "remediation_action": g.get("remediation_action", ""),
                "remediation_priority": g.get("remediation_priority", "Medium"),
            }
        )

    # E. Evidence — dedupe
    ev_lines: List[str] = []
    seen_ev: set[str] = set()
    for rc in required_controls:
        e = (rc.get("evidence_expected") or "").strip()
        if e and e not in seen_ev:
            seen_ev.add(e)
            ev_lines.append(e)

    ev_body = (
        "\n".join(f"• {x}" for x in ev_lines)
        if ev_lines
        else "• **Define** concrete **evidence specifications** in **each** required-control row."
    )
    evidence_block = (
        "**Evidence artifacts for future validation or audit (specify per control after implementation):**\n\n" + ev_body
    )

    residual_statement = _specific_residual_statement(top_for_residual[:3], risk_by_id, tags)

    # Executive summary inputs
    top_risk_dict: Dict[str, Any] | None = most_material[0] if most_material else None
    req_names = [r["required_control"] for r in required_controls if r.get("control_id")]
    if not req_names:
        req_names = [r["required_control"] for r in required_controls]

    exec_summary = _risk_first_executive_summary(
        top_risk_dict,
        req_names[:8],
        overall_risk_level,
        use_case_text[:120] or "this scope",
        risk_by_id,
        tags,
    )

    # A. Use case summary (narrative, not row counts)
    use_case_summary = (
        f"**Scope:** {(use_case_text[:600] + '…') if len(use_case_text) > 600 else (use_case_text or '*(describe use case in mapper input)*')} "
        f"\n\n**Inferred tags:** {', '.join(tags) if tags else '—'}. "
        f"**Priority risks in view:** {', '.join(r['risk_name'] for r in most_material) or '—'}."
    )

    total_rows = len(table)
    denom = total_rows if total_rows else 1
    fn_counts = Counter((row.get("primary_nist_ai_rmf_function") or "Unspecified") for row in table)
    framework_alignment: Dict[str, Dict[str, Any]] = {
        fn: {
            "mapped_control_rows": fn_counts.get(fn, 0),
            "pct_of_rows": round(100.0 * fn_counts.get(fn, 0) / denom, 1),
        }
        for fn in ("Govern", "Map", "Measure", "Manage")
    }

    return {
        "executive_summary": exec_summary,
        "overall_risk_level": overall_risk_level,
        "use_case_summary": use_case_summary,
        "most_material_risks": most_material,
        "required_controls": required_controls,
        "gaps_and_remediation": gaps_and_remediation,
        "required_remediation_actions": required_remediation_actions,
        "evidence_for_audit_readiness": evidence_block,
        "audit_readiness_conclusion": {
            "readiness_opinion": opinion,
            "rationale": opinion_rationale,
            "residual_note": residual_statement,
        },
        "diagnostics": {
            "framework_alignment": framework_alignment,
            "mapping_row_count": total_rows,
            "material_risk_ids": material_risk_ids,
        },
    }


__all__ = ["generate_audit_report"]
