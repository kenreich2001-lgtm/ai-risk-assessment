"""
Streamlit UI for the AI use case risk assessment and control mapping engine (`map_use_case`).

Run from this directory: streamlit run app.py
"""

from __future__ import annotations

import html
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mapping_engine import map_use_case

from governance_workflow import (
    DEFAULT_ASSESSMENT_STATUS,
    build_triage_rationale,
    classify_use_case_category,
    determine_review_path,
    determine_risk_tier,
    format_assessment_timestamp,
    generate_use_case_id,
    governance_export_row,
)

# Enterprise positioning (product copy — concise, no hype)
TOOL_SUBTITLE = (
    "Assess proposed AI use cases for governance review: surface material risks, map required controls "
    "to NIST AI RMF and NIST AI 600-1, and document remediation expected before validation, deployment, or audit."
)

TOOL_PURPOSE = (
    "Use this workspace to record an intake, run the assessment engine, and produce a structured draft suitable "
    "for governance, security, and model-risk forums. Outputs are design-time expectations—not proof of implementation."
)

INTAKE_INSTRUCTIONS = (
    "**Before you submit:** complete each intake row that applies (left: what to capture, right: your answers). "
    "Optional sidebar tags refine context. The **governance triage** layer (category, tier, review path) uses "
    "rule-based logic on your text and tags; **material risks and controls** come from the assessment engine below."
)

RESULTS_SCOPE_NOTE = (
    "**Draft assessment:** expected controls and remediation prior to go-live. "
    "Does not attest that controls are implemented or that independent evidence has been reviewed."
)

OPTIONAL_TAGS_GUIDANCE = """
Use this when something important might **not** be obvious from the description, or you want to **emphasize** a dimension.

**Format:** comma-separated, **lowercase**, words joined with **underscores** (must match the engine’s tag names).

**Examples:**  
`agentic_tools`, `pii`, `phi`, `financial_services`, `healthcare`, `customer_facing`, `customer_support_bot`, `internal_only`, `internal_knowledge`, `third_party_model`, `retrieval`, `regulated`, `high_stakes`, `hr_employment`, `public_sector`, `bias_sensitive`, `fine_tuned`, `code_generation`, `developer_tools`, `copilot_pattern`

If you are unsure of a tag name, **spell out the same idea in the use case fields**—the tool also infers many tags from keywords (e.g. “refunds via API” helps surface tool-use risks).
"""

# (key, title, description, placeholder, how_to_obtain_markdown)
USE_CASE_FIELDS: list[tuple[str, str, str, str, str]] = [
    (
        "what_it_does",
        "What it does",
        "The AI’s role: what it produces or helps with (e.g. draft replies, summarize tickets, generate code, answer policy questions).",
        "e.g. Suggests replies and next steps for support agents in the chat console.",
        """**Who to ask:** Product owner, AI/feature sponsor, or the manager of the team using the tool.

**Where to look:** Project charter, PRFAQ, internal wiki, user-story backlog, demo recording, or training deck.

**What to request:** A short “allowed behaviors” list—what the assistant may suggest, draft, or automate vs what is out of scope.""",
    ),
    (
        "business_function",
        "Business function",
        "Who uses it and the job to be done—why the business is deploying this (efficiency, quality, scale, compliance support, etc.).",
        "e.g. Tier-1 and tier-2 support agents handling retail customer questions.",
        """**Who to ask:** Business sponsor, operations lead, or program manager for the rollout.

**Where to look:** OKRs, business case, capacity model, or support/ops KPI deck.

**What to request:** Primary user roles, rough volume (e.g. cases per day), and the outcome you are optimizing (handle time, quality, compliance checks).""",
    ),
    (
        "core_systems",
        "Core systems & connections",
        "Which systems of record or platforms it touches: CRM, ticketing, EHR, core banking, payments, IAM, data warehouse, internal APIs, etc.",
        "e.g. Salesforce case object, ServiceNow incidents, internal customer profile API.",
        """**Who to ask:** Solution architect, integration engineer, or application owner for each system named in the pilot.

**Where to look:** Architecture diagram, integration catalog, API portal, CMDB, or change tickets for new endpoints.

**What to request:** System names, environments (prod/non-prod), and whether the AI reads only, writes, or both.""",
    ),
    (
        "data_involved",
        "Data involved",
        "Types of data in prompts, responses, or logs: PII, PHI, payment/financial, secrets, or only low-sensitivity internal content.",
        "e.g. Account numbers, order history, and free-text customer messages (PII).",
        """**Who to ask:** Data owner, privacy office, security GRC, or the team that signed the vendor DPA.

**Where to look:** Data-classification policy, data inventory, ROPA/dataset register, or prior DPIA.

**What to request:** Categories only (e.g. customer PII, PHI, cardholder data)—exact field lists can come later.""",
    ),
    (
        "actions_tools",
        "Actions & tools",
        "Whether it can trigger real-world effects: APIs, tools, workflows (refunds, ticket updates, email sends) vs read-only Q&A.",
        "e.g. Can create tickets and request refunds via approved APIs; human confirms some actions.",
        """**Who to ask:** Engineer who implemented tools/MCP/plugins, or the author of the workflow automation.

**Where to look:** API specs, OpenAPI/Swagger, integration tests, feature flags, or threat-model appendix.

**What to request:** A list of callable actions, required approvals, and whether execution is synchronous with the user session.""",
    ),
    (
        "audience",
        "Who sees the output",
        "End users: external customers / public site vs employees only / partners. Authentication and channel (web, phone assist, Slack, etc.).",
        "e.g. Authenticated agents only; not shown directly to customers.",
        """**Who to ask:** Product manager, identity/IAM lead, or customer-trust contact.

**Where to look:** Auth design doc, journey map, URL allowlists, or launch communications.

**What to request:** Customer-facing vs internal-only, login method (SSO, guest, API key), and which channels (web, mobile, Slack, phone assist).""",
    ),
    (
        "model_hosting",
        "Model & hosting",
        "Vendor or stack: OpenAI, Azure OpenAI, Bedrock, Vertex, Anthropic, self-hosted; plus RAG, document search, or web if used.",
        "e.g. Azure OpenAI; answers grounded on internal Confluence + PDF runbooks.",
        """**Who to ask:** ML/platform engineer, cloud FinOps, or vendor management for the AI contract.

**Where to look:** Azure/AWS/GCP console project names, vendor order form, enterprise agreement, or architecture decision record (ADR).

**What to request:** Vendor + region, deployment model (hosted API vs VPC), and whether retrieval/RAG indexes exist and who owns them.""",
    ),
    (
        "regulatory",
        "Regulatory & stakes",
        "Industry or decision stakes if relevant: regulated environment, healthcare, financial services, HR/employment, public sector, safety- or credit-related outcomes.",
        "e.g. Retail banking; not used for credit decisions in this phase.",
        """**Who to ask:** Compliance, legal, or industry program office (e.g. HIPAA, financial crime, employment law).

**Where to look:** Regulatory mapping docs, risk register, internal “high-risk AI” checklist, or audit findings.

**What to request:** Industry and whether outputs influence eligibility, credit, care, hiring, or safety-critical operations—even if “not in this phase.”""",
    ),
]

ADDITIONAL_NOTES_SOURCING = """**If scope is still fuzzy:** Schedule a 30-minute triad with **product**, **engineering**, and **security / risk**.

**Useful artifacts:** Phased roadmap, “out of scope for pilot” bullets, or a single workflow diagram from trigger to tool call.

**Good enough for now:** A honest “unknown—follow up with X team” note is better than leaving the whole assessment blank."""


def _compose_use_case_text(rows: list[tuple[str, str]], notes: str) -> str:
    chunks: list[str] = []
    for title, text in rows:
        t = (text or "").strip()
        if t:
            chunks.append(f"{title}:\n{t}")
    n = (notes or "").strip()
    if n:
        chunks.append(f"Additional notes:\n{n}")
    return "\n\n".join(chunks)


def _intake_fields_still_empty() -> list[tuple[str, str]]:
    """Field titles and sourcing guidance where the user has not entered text yet."""
    missing: list[tuple[str, str]] = []
    for key, title, _desc, _ph, how in USE_CASE_FIELDS:
        raw = st.session_state.get(f"uc_{key}")
        if not (str(raw or "").strip()):
            missing.append((title, how))
    return missing


def _inject_styles() -> None:
    st.markdown(
        """
        <style>
            header[data-testid="stHeader"] { background: transparent; }
            .main .block-container {
                padding-top: 1.25rem;
                padding-bottom: 3rem;
                max-width: 1180px;
            }
            div[data-testid="stSidebar"] {
                background: linear-gradient(185deg, #f8fafc 0%, #eef2ff 55%, #f1f5f9 100%);
                border-right: 1px solid #e2e8f0;
            }
            div[data-testid="stSidebar"] .stMarkdown h3 {
                font-size: 1.05rem;
                font-weight: 600;
                color: #0f172a;
                margin-bottom: 0.75rem;
            }
            .tag-pill {
                display: inline-block;
                padding: 0.2rem 0.65rem;
                margin: 0.15rem 0.35rem 0.15rem 0;
                border-radius: 999px;
                background: #e0e7ff;
                color: #312e81;
                font-size: 0.8125rem;
                font-weight: 500;
                border: 1px solid #c7d2fe;
            }
            .hero-wrap {
                background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 42%, #1d4ed8 100%);
                border-radius: 14px;
                padding: 1.5rem 1.75rem 1.6rem;
                margin-bottom: 1.75rem;
                box-shadow: 0 12px 40px -12px rgba(15, 23, 42, 0.45);
            }
            .hero-wrap h1 {
                color: #f8fafc !important;
                font-size: 1.65rem !important;
                font-weight: 700 !important;
                letter-spacing: -0.03em;
                margin: 0 0 0.35rem 0 !important;
                border: none !important;
                padding: 0 !important;
            }
            .hero-sub {
                color: rgba(248, 250, 252, 0.88);
                font-size: 0.98rem;
                line-height: 1.5;
                margin: 0;
            }
            .section-label {
                font-size: 0.72rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.08em;
                color: #64748b;
                margin: 0 0 0.35rem 0;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _hero() -> None:
    st.markdown(
        f"""
        <div class="hero-wrap">
            <h1>AI use case governance assessment</h1>
            <p class="hero-sub">{html.escape(TOOL_SUBTITLE)}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _tags_pills(tags: list[str]) -> None:
    if not tags:
        st.caption("No tags inferred for this run.")
        return
    inner = "".join(f'<span class="tag-pill">{html.escape(t)}</span>' for t in tags)
    st.markdown(inner, unsafe_allow_html=True)


DETAIL_VIEW_COLS = [
    "priority_score",
    "mapping_strength",
    "risk_id",
    "risk_name",
    "control_id",
    "control_name",
    "nist_ai_rmf_explicit_mapping",
    "primary_nist_ai_rmf_function",
    "primary_nist_ai_rmf_categories",
    "primary_nist_ai_600_1_themes",
    "framework_mapping_rationale",
    "remediation_priority",
    "remediation_owner",
    "remediation_timeline",
    "remediation_evidence_expectation",
]

REQUIRED_CONTROL_COLS = [
    "control_id",
    "required_control",
    "control_objective",
    "primary_ai_rmf_mapping",
    "secondary_ai_rmf_mapping",
    "primary_ai_600_1_risk_theme",
    "required_remediation_action",
    "control_status",
    "control_status_reason",
    "remediation_required",
    "related_risks",
    "evidence_expected",
]

REMEDIATION_ACTION_COLS = [
    "required_control",
    "control_status",
    "related_risks",
    "remediation_action",
    "remediation_priority",
]


def _rc_column_config(df: pd.DataFrame) -> dict:
    cfg: dict = {}
    if "priority_score" in df.columns:
        cfg["priority_score"] = st.column_config.ProgressColumn(
            "Score",
            help="Relative mapping priority (0–100 scale).",
            format="%d",
            min_value=0,
            max_value=100,
        )
    if "control_objective" in df.columns:
        cfg["control_objective"] = st.column_config.TextColumn("Objective", width="large")
    if "required_remediation_action" in df.columns:
        cfg["required_remediation_action"] = st.column_config.TextColumn("Remediation", width="large")
    if "control_status_reason" in df.columns:
        cfg["control_status_reason"] = st.column_config.TextColumn("Status rationale", width="medium")
    if "evidence_expected" in df.columns:
        cfg["evidence_expected"] = st.column_config.TextColumn("Evidence", width="medium")
    return cfg


st.set_page_config(
    page_title="AI use case governance assessment",
    layout="wide",
    initial_sidebar_state="expanded",
    page_icon="🛡️",
)

_inject_styles()

with st.sidebar:
    st.markdown("### Governance intake")
    st.caption(
        "Complete the **use case intake** in the main workspace (left: what to collect, right: your answers), "
        "then submit for **governance triage** and control mapping."
    )
    with st.expander("Optional tags — when and how", expanded=False):
        st.markdown(OPTIONAL_TAGS_GUIDANCE)

    extra_raw = st.text_input(
        "Optional extra tags",
        placeholder="e.g. agentic_tools, pii, third_party_model, financial_services",
        help="Comma-separated official tag names. Merged with tags inferred from your intake answers.",
    )
    st.caption("Merged with tags inferred from intake text.")
    run = st.button("Assess use case for governance review", type="primary", use_container_width=True)

with st.sidebar:
    st.divider()
    st.markdown(
        "<span style='font-size:0.8rem;color:#64748b;'>Control-to-framework alignment uses a curated map in the assessment engine (not ad-hoc keyword inference at runtime).</span>",
        unsafe_allow_html=True,
    )

_hero()
st.markdown(f"<p style='color:#475569;font-size:1rem;margin:0 0 0.75rem 0;'>{html.escape(TOOL_PURPOSE)}</p>", unsafe_allow_html=True)

st.markdown('<p class="section-label">Governance intake — use case record</p>', unsafe_allow_html=True)
st.markdown(INTAKE_INSTRUCTIONS)
st.caption(
    "Each row: **left** = information to collect, **right** = your entry. Use **Missing this info?** for sourcing tips."
)

with st.expander("Open all sourcing recommendations (print-friendly)", expanded=False):
    st.caption("Same tips as the **Missing this info?** button on each row—useful for workshops or email to stakeholders.")
    for _key, title, _desc, _ph, how in USE_CASE_FIELDS:
        st.markdown(f"##### {title}")
        st.markdown(how)
        st.divider()
    st.markdown("##### Additional notes")
    st.markdown(ADDITIONAL_NOTES_SOURCING)

intake_rows: list[tuple[str, str]] = []
for key, title, desc, ph, how in USE_CASE_FIELDS:
    c_label, c_entry = st.columns([0.34, 0.66], gap="medium")
    with c_label:
        st.markdown(f"**{title}**")
        st.caption(desc)
        with st.popover("Missing this info?"):
            st.markdown(how)
    with c_entry:
        val = st.text_area(
            title,
            placeholder=ph,
            key=f"uc_{key}",
            label_visibility="collapsed",
            height=100,
        )
        intake_rows.append((title, val))

st.markdown("**Additional notes** *(optional)*")
st.caption("Other context: pilot scope, phased rollout, exclusions, or edge cases.")
with st.popover("Tips for this section"):
    st.markdown(ADDITIONAL_NOTES_SOURCING)
notes_val = st.text_area(
    "Additional notes",
    key="uc_notes",
    label_visibility="collapsed",
    height=88,
    placeholder="e.g. Phase 1 is read-only; tool integrations planned for phase 2…",
)

use_case = _compose_use_case_text(intake_rows, notes_val)

with st.expander("Why we ask for these fields", expanded=False):
    st.markdown(
        "The engine reads your answers as **one combined use case** to infer tags, select catalog risks, and map controls. "
        "**Business function**, **core systems**, **data**, **tools/actions**, and **audience** are the strongest drivers. "
        "Plain language is fine—**specifics** beat buzzwords."
    )

if not run:
    st.info(
        "Complete at least one **intake** row above, add **optional tags** in the sidebar if needed, "
        "then click **Assess use case for governance review**."
    )
elif not (use_case or "").strip():
    st.warning("Please enter at least one answer in the use case intake form before running the assessment.")
else:
    now = datetime.now(timezone.utc)
    assessment_id = generate_use_case_id(now)
    assessment_ts = format_assessment_timestamp(now)

    with st.spinner("Running governance assessment (risk selection, control mapping, remediation)…"):
        result = map_use_case(use_case, [x.strip() for x in extra_raw.split(",") if x.strip()] or None)
    ar = result.get("audit_report") or {}
    conc = ar.get("audit_readiness_conclusion") or {}

    tags_list = list(result.get("tags") or [])
    overall = ar.get("overall_risk_level") or ""
    # Rule-based governance triage (explainable; separate from catalog risk scoring).
    category = classify_use_case_category(use_case, tags_list)
    risk_tier = determine_risk_tier(use_case, tags_list)
    review_path = determine_review_path(risk_tier)
    triage_rationale = build_triage_rationale(
        use_case,
        tags_list,
        risk_tier=risk_tier,
        category=category,
    )
    gov_row = governance_export_row(
        use_case_id=assessment_id,
        assessment_timestamp=assessment_ts,
        assessment_status=DEFAULT_ASSESSMENT_STATUS,
        use_case_category=category,
        risk_tier=risk_tier,
        recommended_review_path=review_path,
        triage_rationale=triage_rationale,
    )

    st.success("Assessment complete. Draft governance record generated below.")
    st.caption(RESULTS_SCOPE_NOTE)

    # --- 1 · Assessment metadata (at-a-glance strip) ---
    st.subheader("1 · Assessment metadata")
    with st.container(border=True):
        st.caption("Reference identifiers and routing for this draft assessment.")
        a1, a2, a3 = st.columns(3)
        a1.metric("Use case ID", assessment_id)
        a2.metric("Timestamp (UTC)", assessment_ts)
        a3.metric("Status", DEFAULT_ASSESSMENT_STATUS)
        b1, b2 = st.columns([1, 2])
        b1.metric("Risk tier (triage)", risk_tier)
        b2.markdown(f"**Recommended review path**  \n{review_path}")

    # --- 2 · Governance triage summary ---
    st.subheader("2 · Governance triage summary")
    with st.container(border=True):
        st.caption(
            "Rule-based classification from intake text and tags. "
            "Catalog **overall risk** from the engine may differ; both are shown in the use case summary."
        )
        st.metric("Use case category", category)
        with st.expander("Triage rationale (rule-based, for reviewers)", expanded=False):
            st.write(triage_rationale)

    mm = ar.get("most_material_risks") or []
    rc_rows = ar.get("required_controls") or []
    rem_rows = ar.get("required_remediation_actions") or []
    table = result.get("mapping_table") or []

    # --- 3 · Use case summary ---
    st.subheader("3 · Use case summary")
    with st.container(border=True):
        clip = (use_case[:400] + "…") if len(use_case) > 400 else use_case
        st.markdown("**Submitted intake (excerpt)**")
        st.markdown(clip or "—")
        with st.expander("Full submitted intake", expanded=False):
            st.text(use_case or "—")
        st.markdown("**Context tags**")
        _tags_pills(tags_list)
        st.caption("Inferred from intake text plus any optional tags you added in the sidebar.")
        c_eng, c_tri = st.columns(2)
        with c_eng:
            st.metric("Catalog overall risk (engine)", (overall or "—").strip().upper())
        with c_tri:
            st.metric("Governance risk tier (rules)", risk_tier)
        st.caption(
            "The **engine** score drives material risks and controls below. **Triage tier** routes governance reviews."
        )
        es = (result.get("executive_summary") or "").strip()
        if es:
            with st.expander("Executive narrative (assessment engine)", expanded=False):
                st.markdown(es)

    still_empty = _intake_fields_still_empty()
    if still_empty:
        with st.expander(
            f"Intake follow-up: {len(still_empty)} field(s) left blank — optional sourcing",
            expanded=False,
        ):
            st.caption(
                "The assessment ran on available information. Completing these fields later tightens control coverage."
            )
            for title, how in still_empty:
                st.markdown(f"**{title}**")
                st.markdown(how)
                st.divider()

    # --- 4 · Material risks identified ---
    st.subheader("4 · Material risks identified")
    r1, r2, r3, r4 = st.columns(4)
    r1.metric("Material risks", len(mm))
    r2.metric("Required controls", len(rc_rows))
    r3.metric("Open remediation rows", len(rem_rows))
    r4.metric("Risk–control mappings", len(table))
    if mm:
        st.dataframe(pd.DataFrame(mm), use_container_width=True, hide_index=True)
    else:
        st.caption("No material risks listed for this pass.")

    # --- 5 · Required controls before deployment ---
    st.subheader("5 · Required controls before deployment")
    if rc_rows:
        rcdf = pd.DataFrame(rc_rows)
        rccols = [c for c in REQUIRED_CONTROL_COLS if c in rcdf.columns]
        st.dataframe(
            rcdf[rccols],
            use_container_width=True,
            hide_index=True,
            column_config=_rc_column_config(rcdf),
        )
    else:
        st.caption("No required-control rows for this run.")

    # --- 6 · Required remediation before validation ---
    st.subheader("6 · Required remediation before validation")
    if rem_rows:
        remdf = pd.DataFrame(rem_rows)
        remcols = [c for c in REMEDIATION_ACTION_COLS if c in remdf.columns]
        st.dataframe(
            remdf[remcols],
            use_container_width=True,
            hide_index=True,
            column_config={
                "remediation_action": st.column_config.TextColumn("Action", width="large"),
                "related_risks": st.column_config.TextColumn("Related risks", width="medium"),
            }
            if all(c in remdf.columns for c in ("remediation_action", "related_risks"))
            else {},
        )
    else:
        st.caption("No open remediation rows for this pass.")

    # --- 7 · Audit / review notes ---
    st.subheader("7 · Audit & review notes")
    with st.container(border=True):
        opinion = conc.get("readiness_opinion") or "—"
        st.markdown("**Readiness posture (design-time)**")
        st.markdown(f"**{opinion}**")
        if conc.get("rationale"):
            with st.expander("Review rationale", expanded=False):
                st.markdown(conc["rationale"])
        if conc.get("residual_note"):
            with st.expander("Residual exposure note", expanded=False):
                st.markdown(conc["residual_note"])
        st.markdown("**Evidence expectations (engine)**")
        st.markdown(ar.get("evidence_for_audit_readiness") or "—")

    # --- 8 · Downloadable detail ---
    st.subheader("8 · Downloadable detail & technical appendix")
    gov_summary_df = pd.DataFrame([gov_row])
    d1, d2 = st.columns([1, 2])
    with d1:
        st.download_button(
            "Download governance summary (CSV)",
            gov_summary_df.to_csv(index=False),
            f"{assessment_id}_governance_summary.csv",
            "text/csv",
            use_container_width=True,
        )
    with d2:
        st.caption(
            "Columns: use_case_id, assessment_timestamp, assessment_status, use_case_category, "
            "risk_tier, recommended_review_path, triage_rationale."
        )

    with st.expander("Engine use case narrative (reference)", expanded=False):
        st.markdown(ar.get("use_case_summary") or "—")

    with st.expander("Full assessment record (legacy sections A–F + diagnostics)", expanded=False):
        st.markdown("##### A. Use case summary")
        st.markdown(ar.get("use_case_summary") or "—")
        st.markdown("##### B. Most material risks")
        if mm:
            st.dataframe(pd.DataFrame(mm), use_container_width=True, hide_index=True)
        else:
            st.caption("—")
        st.markdown("##### C. Required controls")
        if rc_rows:
            st.dataframe(pd.DataFrame(rc_rows), use_container_width=True, hide_index=True)
        else:
            st.caption("—")
        st.markdown("##### D. Remediation actions")
        if rem_rows:
            st.dataframe(pd.DataFrame(rem_rows), use_container_width=True, hide_index=True)
        else:
            st.caption("None for this pass.")
        st.markdown("##### E. Evidence for audit readiness")
        st.markdown(ar.get("evidence_for_audit_readiness") or "—")
        st.markdown("##### F. Readiness (combined)")
        st.markdown(f"**{conc.get('readiness_opinion', '—')}** — {conc.get('rationale', '')}")
        diag = ar.get("diagnostics") or {}
        if diag:
            st.divider()
            st.caption("Diagnostics")
            st.json(
                {
                    "mapping_row_count": diag.get("mapping_row_count"),
                    "material_risk_ids": diag.get("material_risk_ids"),
                    "framework_alignment": diag.get("framework_alignment"),
                }
            )

    if not table:
        st.caption("No risk–control mapping rows.")
    else:
        df = pd.DataFrame(table)
        for k, v in gov_row.items():
            df[k] = v
        cols_present = [c for c in DETAIL_VIEW_COLS if c in df.columns]

        t1, t2 = st.tabs(["Top mappings by priority", "Primary-strength mappings"])
        with t1:
            top5 = df.nlargest(min(5, len(df)), "priority_score")
            dc: dict = {}
            if "priority_score" in top5.columns:
                dc["priority_score"] = st.column_config.ProgressColumn(
                    "Score", format="%d", min_value=0, max_value=100
                )
            st.dataframe(top5[cols_present], use_container_width=True, hide_index=True, column_config=dc)
        with t2:
            prim = df[df["mapping_strength"] == "primary"] if "mapping_strength" in df.columns else df
            st.caption(f"{len(prim)} row(s) with primary mapping strength.")
            st.dataframe(prim[cols_present], use_container_width=True, hide_index=True)

        dl_col1, dl_col2 = st.columns([1, 2])
        with dl_col1:
            csv_full = df.to_csv(index=False)
            st.download_button(
                "Download full mapping table (CSV)",
                csv_full,
                f"{assessment_id}_mapping_table.csv",
                "text/csv",
                use_container_width=True,
            )
        with dl_col2:
            st.caption(
                "Engine mapping columns unchanged; seven governance fields repeated on each row for filtering in Excel."
            )

        with st.expander("Full mapping table (all columns)", expanded=False):
            st.dataframe(df, use_container_width=True, hide_index=True)

    st.divider()
    st.caption("Draft governance assessment — not an implementation or compliance attestation.")
