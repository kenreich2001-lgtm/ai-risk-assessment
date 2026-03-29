"""Enterprise-oriented mapping rationales — concise, varied, with explicit NIST AI RMF and AI 600-1 framing."""

from __future__ import annotations

import hashlib

from mapping_engine.catalog import Control, Risk
from mapping_engine.framework_alignment import RowFrameworkAlignment


def _variant_seed(risk_id: str, control_id: str) -> int:
    return int(hashlib.sha256(f"{risk_id}:{control_id}".encode()).hexdigest()[:8], 16)


def _tag_bits(tags: frozenset[str]) -> str:
    return ", ".join(sorted(tags)) if tags else "general deployment"


def _relevance_short(
    risk: Risk,
    tags: frozenset[str],
    use_case_summary: str,
    variant: int,
    control_id: str,
) -> str:
    t = _tag_bits(tags)
    uc = use_case_summary.strip()
    one_line = risk.description.split(".")[0] + "." if risk.description else risk.name
    pick = (variant + _variant_seed(risk.id, control_id)) % 8

    if uc:
        clip = uc[:120] + ("…" if len(uc) > 120 else "")
        openers = [
            f"**{risk.name}** sits in the control scope because {one_line} Narrative «{clip}» with [{t}] keeps that risk testable.",
            f"Stated context «{clip}» intersects **{risk.name}**: {one_line} Tags [{t}] narrow the failure scenarios reviewers should trace.",
            f"For [{t}], **{risk.name}** is the credible harm vector—{one_line}—given how the work is described.",
            f"Operational story: {one_line} That is why **{risk.name}** must be evidenced while tags read [{t}] and «{clip}» holds.",
            f"**Customer/regulator view:** {one_line} Here, **{risk.name}** is live risk under [{t}] and «{clip}».",
            f"«{clip}» is not generic Q&A: with [{t}], **{risk.name}** materializes as {one_line}",
            f"Scope line «{clip}» plus [{t}] forces **{risk.name}** into assessment—{one_line}",
            f"Because [{t}] touches production paths, **{risk.name}** warrants controls: {one_line} («{clip}»).",
        ]
    else:
        openers = [
            f"**{risk.name}** is a defensible inclusion: {one_line} Inferred [{t}] carries real integration and data contact.",
            f"Inferred tags [{t}] pull **{risk.name}** forward—{one_line}",
            f"Reviewers will ask how **{risk.name}** is mitigated; {one_line} Context [{t}] supplies the plausible paths.",
            f"**{risk.name}** ({one_line}) remains material whenever [{t}] describes this deployment.",
            f"Catalog logic under [{t}] highlights **{risk.name}**: {one_line}",
            f"Even without a long prose scope, [{t}] implies **{risk.name}**—{one_line}",
            f"**Operational stake:** {one_line} Tags [{t}] anchor **{risk.name}** to concrete telemetry and assets.",
            f"**{risk.name}**: {one_line} [{t}] is the bridge from theory to monitored behavior.",
        ]
    return openers[pick % len(openers)]


def _mechanism_tight(risk: Risk, rationale_key: str, risk_id: str) -> str:
    head = rationale_key.split("_")[0] if "_" in rationale_key else rationale_key
    table: dict[str, str] = {
        "unreliable": "Bad answers read authoritative before anyone checks sources.",
        "privacy": "Logging, retrieval, and completions widen who can see sensitive content.",
        "injection": "Hostile text in prompts or files steers the model or tool arguments.",
        "supply": "Vendor routing, retention, and versions move faster than your visibility.",
        "oversight": "Actual autonomy outruns who is accountable or who must approve.",
        "agent": "Language maps straight to API calls without tight scope or rollback.",
        "monitoring": "Drift in prompts, data, or integrations slips past stale KPIs.",
        "bias": "Corpora steer materially different outcomes for regulated cohorts.",
        "automation": "Fluency substitutes for verification under deadline pressure.",
        "output": "Downstream systems execute or store model strings as if trusted.",
        "abuse": "Exposed endpoints see volume and probing you did not size for.",
        "iam": "AI routes skip token scope and segregation you require elsewhere.",
        "provenance": "Source, license, and lineage for RAG/tuning are unclear or stale.",
        "incident": "No exercised owners or playbooks when model/tool events occur.",
    }
    base = table.get(rationale_key, table.get(head, ""))
    if not base:
        base = "Gaps upstream let risky prompt/tool/data combinations reach production."

    addons = {
        "R-003": " Mixed-trust inputs sharpen injection blast radius.",
        "R-006": " Tool breadth multiplies backend reach from one bad bundle.",
        "R-012": " Indexes and admin planes often lag app IAM maturity.",
        "R-008": " HR/eligibility raises legal leverage per stored decision.",
        "R-005": " Missing a checkpoint hurts most when stakes are regulated.",
    }
    return base + (f" {addons[risk_id]}" if risk_id in addons else "")


def _control_hook(control: Control, coverage: str, ctype: str) -> str:
    cov = {
        "preventive": "blocks failures early",
        "detective": "surfaces abuse and drift",
        "corrective": "limits fallout after triggers",
        "compensating": "backs primary controls where vendors are opaque",
    }.get(coverage, "addresses residual exposure")
    return f"**{control.name}** ({ctype}, {cov}) {control.description.split('.')[0].lower()}."


def build_rationale(
    risk: Risk,
    control: Control,
    rationale_key: str,
    use_case_summary: str,
    tags: frozenset[str],
    fw: RowFrameworkAlignment,
) -> str:
    v = _variant_seed(risk.id, control.id)

    relevance = _relevance_short(risk, tags, use_case_summary, v, control.id)
    mechanism = _mechanism_tight(risk, rationale_key, risk.id)
    control_fit = _control_hook(control, control.coverage, control.control_type)

    n_idx = (v // 3) % 3
    nist_opts = [
        (
            f"**NIST AI RMF (AI 100-1):** {fw.nist_ai_rmf_explicit_mapping}. "
            f"Lead function **{fw.primary_nist_ai_rmf_function}**; full subcategories **{fw.primary_nist_ai_rmf_categories}**. "
            f"{control.name} gives auditable traction on that thread for this failure mode."
        ),
        (
            f"**NIST AI RMF (AI 100-1):** {fw.nist_ai_rmf_explicit_mapping}. "
            f"This row clusters under **{fw.primary_nist_ai_rmf_function}** with **{fw.primary_nist_ai_rmf_categories}**—"
            f"{control.name} is the operational lever that makes the intent testable."
        ),
        (
            f"**NIST AI RMF (AI 100-1):** {fw.nist_ai_rmf_explicit_mapping}. "
            f"**{fw.primary_nist_ai_rmf_function}** frames the duty; **{fw.primary_nist_ai_rmf_categories}** name the work. "
            f"{control.name} is the concrete mitigator paired to **{risk.name}**."
        ),
    ]
    nist_block = nist_opts[n_idx]

    g_idx = (v // 5) % 3
    gai_opts = [
        (
            f"**NIST AI 600-1 Generative AI Profile:** Themes **{fw.primary_nist_ai_600_1_themes}** describe how generation, "
            f"data paths, and optional tool use intersect—{control.name} is the chosen counterweight in this pairing."
        ),
        (
            f"**NIST AI 600-1:** **{fw.primary_nist_ai_600_1_themes}** bound the GenAI profile issues; "
            f"testing and operations should verify {control.name} under those theme stresses, not generic IT smoke tests."
        ),
        (
            f"**NIST AI 600-1 Generative AI Profile:** **{fw.primary_nist_ai_600_1_themes}** flag where profile hazards concentrate; "
            f"pair that view with evidence that {control.name} operates in live traffic."
        ),
    ]
    gai_block = gai_opts[g_idx]

    r_idx = (v // 11) % 3
    res_tail = [
        f"Exceptions, shadow prompts, and supplier-side edits can still bypass {control.name} until monitors and tests catch up.",
        f"{control.name} narrows exposure; it does not erase **{risk.name}** when workflows or models shift outside the last review cycle.",
        f"Watch for drift: new tools, corpora, or model versions can reopen **{risk.name}** even with {control.name} on paper.",
    ]
    residual = f"**Residual concern:** {risk.residual_risk} {res_tail[r_idx]}"

    return (
        f"1. **Why it matters in this use case**\n{relevance}\n\n"
        f"2. **How it manifests**\n{mechanism}\n\n"
        f"3. **Why this control**\n{control_fit}\n\n"
        f"4. **Row mapping — NIST AI RMF**\n{nist_block}\n\n"
        f"5. **Row mapping — NIST AI 600-1**\n{gai_block}\n\n"
        f"6. **Framework note**\n{fw.framework_mapping_rationale}\n\n"
        f"7. {residual}"
    )
