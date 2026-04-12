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
    format_assessment_timestamp,
    generate_use_case_id,
    get_launch_recommendation,
    get_required_reviewers,
    get_risk_tier_rationale_bullets,
    governance_export_row,
)
from industry_profiles import (
    ALL_REGULATION_LABELS,
    BUSINESS_FUNCTIONS,
    INDUSTRIES,
    build_context_enrichment_block,
    build_domain_rationale,
    compute_enriched_tier,
    determine_contextual_risk_emphasis,
    determine_control_emphasis,
    get_combined_context_tags,
    get_default_regulations,
    get_specializations,
)
from intake_builder import (
    BUILDER_DATA_TYPES,
    CAPABILITIES,
    HUMAN_REVIEW_OPTIONS,
    MODEL_PATTERNS,
    PRIMARY_USER_GROUPS,
    USE_CASE_TYPES,
    build_use_case_description,
)
from intake_signals import (
    AUDIENCE_OPTIONS,
    AUTOMATION_OPTIONS,
    DATA_TYPE_OPTIONS,
    EXTERNAL_CONTENT_OPTIONS,
    HOSTING_OPTIONS,
    PATTERN_OPTIONS,
    build_technical_intake_block,
    format_technical_intake_summary,
    merge_intake_tags,
    tags_from_intake_signals,
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
    "**Before you submit:** choose an **Assessment Setup Mode** (sample template, structured builder, or free text), then set "
    "**industry**, **specialization**, **business function**, and **data / hosting / audience** "
    "(these add engine tags and a short technical block). Adjust **regulatory context** when specialization changes. "
    "Optional sidebar tags still merge with derived tags. "
    "This is **not** a legal compliance determination."
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

If you are unsure of a tag name, **spell out the same idea in the use case description**—the engine also infers tags from keywords.
"""

GENERAL_USE_CASE_TIPS = """**Strong descriptions mention:** data types (PII/PHI/financial), **customer vs internal** audience, **tools/APIs** that change records or money, and **hosting** (e.g. Azure OpenAI)."""

SAMPLE_USE_CASE_PLACEHOLDER = "Select a sample template..."

# Optional "regulations" lists use exact labels from ALL_REGULATION_LABELS.
SAMPLE_USE_CASES: dict[str, dict] = {
    "Consumer bank underwriting assistant": {
        "industry": "Financial Services",
        "specialization": "Banking",
        "business_function": "Underwriting / Risk Decisioning",
        "regulations": [
            "FTC Safeguards Rule",
            "GLBA",
            "NIST AI RMF",
            "PCI DSS",
            "SOC 2",
        ],
        "description": (
            "Hosted LLM assists underwriters by summarizing credit files, extracting employment and income signals, "
            "and drafting adverse-action explanations. Uses Azure OpenAI; prompts may include PII, credit attributes, "
            "and co-applicant data. A human underwriter must approve any decision communicated to the applicant."
        ),
    },
    "Insurance claims triage copilot": {
        "industry": "Financial Services",
        "specialization": "Insurance",
        "business_function": "Claims / Case Management",
        "regulations": [
            "FTC Safeguards Rule",
            "GLBA",
            "HIPAA Privacy Rule",
            "HIPAA Security Rule",
            "SOC 2",
        ],
        "description": (
            "Copilot triages first notice of loss: suggests reserves, flags fraud indicators, and drafts adjuster notes "
            "from FNOL text and images. May reference PHI for health lines. Third-party hosted model with retrieval over "
            "claims history; no automatic payouts—staff confirms outcomes."
        ),
    },
    "Clinical documentation assistant": {
        "industry": "Healthcare",
        "specialization": "Provider",
        "business_function": "Clinical Operations",
        "regulations": [
            "HIPAA Privacy Rule",
            "HIPAA Security Rule",
            "NIST AI RMF",
            "SOC 2",
        ],
        "description": (
            "Ambient documentation assistant drafts SOAP-style notes from clinician–patient encounters. "
            "PHI in prompts and outputs; integrated with EHR. Clinicians review and sign every note; model is hosted "
            "in our cloud tenant with BAA-covered subprocessors."
        ),
    },
    "Customer support chatbot": {
        "industry": "Retail / E-Commerce",
        "specialization": "Customer Support Operations",
        "business_function": "Customer Support",
        "regulations": ["CCPA / CPRA", "PCI DSS", "SOC 2"],
        "description": (
            "Customer-facing chatbot answers order status, returns, and loyalty questions using retrieval over policies "
            "and order APIs. Hosted LLM; may surface PII when customers authenticate. Human handoff for refunds and "
            "account security changes."
        ),
    },
    "Employee HR knowledge assistant": {
        "industry": "Professional Services",
        "specialization": "HR / Recruiting",
        "business_function": "Knowledge Management",
        "regulations": ["CCPA / CPRA", "Employment data privacy context", "GDPR", "SOC 2"],
        "description": (
            "Internal assistant answers employees’ questions on benefits, leave, and workplace policies using Confluence "
            "and the HRIS handbook. Internal-only; responses include PII only when the employee asks about their own record. "
            "No hiring decisions; no automated actions against HR systems."
        ),
    },
    "Payment fraud monitoring copilot": {
        "industry": "Financial Services",
        "specialization": "Payments / Fintech",
        "business_function": "Fraud Detection / Investigations",
        "regulations": ["FTC Safeguards Rule", "GLBA", "PCI DSS", "SOC 2"],
        "description": (
            "Analyst-facing copilot summarizes transaction and device signals, suggests investigation steps, and drafts "
            "case narratives. Uses an external LLM in our VPC; prompts may include customer identifiers and payment metadata. "
            "No automated account closure; investigators confirm escalations."
        ),
    },
    "Engineering secure code copilot": {
        "industry": "Technology",
        "specialization": "SaaS / Enterprise Software",
        "business_function": "Engineering / Product Development",
        "regulations": ["GDPR", "NIST AI RMF", "SOC 2"],
        "description": (
            "IDE-integrated copilot suggests code and tests from internal repos and docs. Internal developers only; "
            "may surface API keys or customer config if mis-pasted. Hosted third-party model with enterprise agreement; "
            "human review required before merge to protected branches."
        ),
    },
    "Regulatory policy Q&A assistant": {
        "industry": "Financial Services",
        "specialization": "Banking",
        "business_function": "Compliance",
        "regulations": [
            "FTC Safeguards Rule",
            "GLBA",
            "NIST AI RMF",
            "SOC 2",
            "SOX",
        ],
        "description": (
            "RAG assistant answers compliance officers’ questions over internal policies, regulatory memos, and exam "
            "guidance. Internal use; outputs are advisory with mandatory human verification before supervisory or board "
            "reporting. Retrieval over SharePoint and the policy library."
        ),
    },
}


def _apply_sample_use_case() -> None:
    choice = st.session_state.get("gov_sample_use_case")
    if not choice or choice == SAMPLE_USE_CASE_PLACEHOLDER:
        return
    row = SAMPLE_USE_CASES.get(choice)
    if not row:
        return
    ind = row["industry"]
    spec = row["specialization"]
    st.session_state["gov_industry"] = ind
    st.session_state["gov_specialization"] = spec
    st.session_state["gov_business_function"] = row["business_function"]
    st.session_state["gov_use_case_desc"] = row["description"]
    st.session_state["_reg_ctx"] = (ind, spec)
    reg_list = row.get("regulations")
    if reg_list:
        allowed = frozenset(ALL_REGULATION_LABELS)
        st.session_state["regs_selected"] = [x for x in reg_list if x in allowed]
    else:
        st.session_state["regs_selected"] = get_default_regulations(ind, spec)


def _inject_styles() -> None:
    st.markdown(
        r"""
        <style>
            @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:ital,wght@0,400;0,500;0,600;0,700;1,400&family=IBM+Plex+Serif:wght@500;600&display=swap');

            :root {
                --gov-font-sans: "IBM Plex Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                --gov-font-display: "IBM Plex Serif", Georgia, "Times New Roman", serif;
                --gov-ink: #0f172a;
                --gov-ink-muted: #334155;
                --gov-border: #e2e8f0;
                --gov-surface: #f8fafc;
            }

            html, body, input, textarea, button, select {
                font-family: var(--gov-font-sans);
            }

            .stApp {
                font-family: var(--gov-font-sans);
                -webkit-font-smoothing: antialiased;
                -moz-osx-font-smoothing: grayscale;
            }

            header[data-testid="stHeader"] {
                background: linear-gradient(180deg, #ffffff 0%, rgba(255,255,255,0.92) 100%);
                border-bottom: 1px solid var(--gov-border);
            }

            .main .block-container {
                padding-top: 1.5rem;
                padding-bottom: 3.5rem;
                padding-left: 2rem;
                padding-right: 2rem;
                max-width: 1200px;
            }

            /* Streamlit headings & prose */
            .main h1, .main h2, .main h3 {
                font-family: var(--gov-font-sans);
                font-weight: 600;
                letter-spacing: -0.02em;
                color: var(--gov-ink);
            }
            .main h2 {
                font-size: 1.2rem;
                margin-top: 0.25rem;
                margin-bottom: 0.5rem;
                padding-bottom: 0.35rem;
                border-bottom: 1px solid var(--gov-border);
            }
            .main h3 {
                font-size: 1.05rem;
            }
            /* Main prose — darker for readability on white */
            div[data-testid="stMarkdownContainer"] p,
            div[data-testid="stMarkdownContainer"] li {
                font-size: 0.9375rem;
                line-height: 1.6;
                color: var(--gov-ink-muted);
            }
            div[data-testid="stCaption"] {
                font-size: 0.8125rem !important;
                line-height: 1.5 !important;
                color: #475569 !important;
            }

            /* Alerts (success / info / warning): force dark text — global muted gray was hurting contrast */
            div[data-testid="stAlert"] {
                border-radius: 10px !important;
                border: 1px solid #cbd5e1 !important;
                background-color: #f8fafc !important;
            }
            div[data-testid="stAlert"] p,
            div[data-testid="stAlert"] li,
            div[data-testid="stAlert"] div[data-testid="stMarkdownContainer"] p,
            div[data-testid="stAlert"] div[data-testid="stMarkdownContainer"] li {
                color: #0f172a !important;
                font-size: 0.9375rem !important;
                line-height: 1.55 !important;
                font-weight: 500 !important;
            }

            /* Metrics */
            [data-testid="stMetricValue"] {
                font-family: var(--gov-font-sans) !important;
                font-size: 1.25rem !important;
                font-weight: 600 !important;
                letter-spacing: -0.02em !important;
                color: #0f172a !important;
            }
            [data-testid="stMetricLabel"] label {
                font-size: 0.7rem !important;
                font-weight: 600 !important;
                text-transform: uppercase;
                letter-spacing: 0.06em !important;
                color: #475569 !important;
            }

            /* Sidebar */
            div[data-testid="stSidebar"] {
                background: linear-gradient(195deg, #f8fafc 0%, #f1f5f9 45%, #eef2ff 100%);
                border-right: 1px solid var(--gov-border);
            }
            div[data-testid="stSidebar"] .stMarkdown h3 {
                font-family: var(--gov-font-sans);
                font-size: 1rem;
                font-weight: 600;
                color: var(--gov-ink);
                margin-bottom: 0.65rem;
                letter-spacing: -0.01em;
            }
            div[data-testid="stSidebar"] p,
            div[data-testid="stSidebar"] span,
            div[data-testid="stSidebar"] label {
                font-size: 0.875rem;
                line-height: 1.5;
                color: #1e293b !important;
            }

            /* Form controls */
            .stTextArea textarea, .stTextInput input {
                font-size: 0.9375rem !important;
                line-height: 1.5 !important;
                border-radius: 8px !important;
            }
            div[data-testid="stVerticalBlock"] > div[data-baseweb] {
                border-radius: 8px;
            }

            /* Dataframes */
            div[data-testid="stDataFrame"] {
                font-size: 0.8125rem !important;
            }

            /* Primary button */
            .stButton > button[kind="primary"] {
                font-weight: 600 !important;
                letter-spacing: 0.02em;
                border-radius: 8px !important;
                padding: 0.5rem 1rem !important;
            }

            .tag-pill {
                display: inline-block;
                padding: 0.25rem 0.7rem;
                margin: 0.15rem 0.35rem 0.15rem 0;
                border-radius: 999px;
                background: linear-gradient(180deg, #eef2ff 0%, #e0e7ff 100%);
                color: #3730a3;
                font-family: var(--gov-font-sans);
                font-size: 0.8125rem;
                font-weight: 500;
                border: 1px solid #c7d2fe;
                letter-spacing: 0.01em;
            }
            /* Hero: dark slate only (no bright blue) so all copy stays high-contrast */
            .hero-wrap {
                background: linear-gradient(165deg, #1e293b 0%, #0f172a 55%, #020617 100%);
                border-radius: 16px;
                padding: 1.75rem 2rem 1.85rem;
                margin-bottom: 1.75rem;
                border: 1px solid #334155;
                box-shadow: 0 12px 32px -8px rgba(15, 23, 42, 0.45);
            }
            .hero-wrap h1 {
                font-family: var(--gov-font-display);
                color: #ffffff !important;
                font-size: 1.75rem !important;
                font-weight: 600 !important;
                letter-spacing: -0.025em;
                line-height: 1.25;
                margin: 0 0 0.5rem 0 !important;
                border: none !important;
                padding: 0 !important;
                text-shadow: 0 1px 2px rgba(0, 0, 0, 0.35);
            }
            .hero-sub {
                font-family: var(--gov-font-sans);
                color: #e2e8f0 !important;
                font-size: 1.0625rem;
                font-weight: 400;
                line-height: 1.6;
                margin: 0;
                max-width: 52rem;
                text-shadow: 0 1px 2px rgba(0, 0, 0, 0.25);
            }
            .section-label {
                font-family: var(--gov-font-sans);
                font-size: 0.6875rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.1em;
                color: #475569;
                margin: 0 0 0.4rem 0;
            }

            /* Bordered Streamlit containers (results cards) */
            div[data-testid="stVerticalBlockBorderWrapper"] {
                border-radius: 12px !important;
                border-color: var(--gov-border) !important;
                box-shadow: 0 1px 3px rgba(15, 23, 42, 0.06);
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
        "Set **enterprise context** in the main workspace, choose **template**, **builder**, or **free text**, then submit. "
        "Optional tags here merge with **derived context tags** from industry and regulations."
    )
    with st.expander("Optional tags — when and how", expanded=False):
        st.markdown(OPTIONAL_TAGS_GUIDANCE)

    extra_raw = st.text_input(
        "Optional extra tags",
        placeholder="e.g. agentic_tools, pii, third_party_model, financial_services",
        help="Comma-separated official tag names. Merged with derived context tags and text-inferred tags.",
    )
    st.caption("Merged with derived context and use case text.")
    run = st.button("Assess use case for governance review", type="primary", use_container_width=True)

with st.sidebar:
    st.divider()
    st.markdown(
        "<span style='font-size:0.8rem;color:#64748b;'>Control-to-framework alignment uses a curated map in the assessment engine (not ad-hoc keyword inference at runtime).</span>",
        unsafe_allow_html=True,
    )

_hero()
st.markdown(f"<p style='color:#475569;font-size:1rem;margin:0 0 0.75rem 0;'>{html.escape(TOOL_PURPOSE)}</p>", unsafe_allow_html=True)

st.markdown('<p class="section-label">Governance intake — enterprise context</p>', unsafe_allow_html=True)
st.markdown(INTAKE_INSTRUCTIONS)

setup_mode = st.radio(
    "Assessment Setup Mode",
    options=("Sample Template", "Build Custom Use Case", "Free-Text Use Case"),
    horizontal=True,
    key="gov_setup_mode",
    help="Sample templates load realistic demos; the builder composes prose from structured fields; free text is unconstrained.",
)

if setup_mode == "Sample Template":
    st.selectbox(
        "Load Sample Template",
        options=[SAMPLE_USE_CASE_PLACEHOLDER, *SAMPLE_USE_CASES.keys()],
        key="gov_sample_use_case",
        on_change=_apply_sample_use_case,
        help="Prefills industry, specialization, business function, regulatory context (where defined), and narrative.",
    )
    st.caption("Templates set the fields below—you can edit anything before assessing.")

with st.expander("Tips for the use case description", expanded=False):
    st.markdown(GENERAL_USE_CASE_TIPS)

st.subheader("Structured context")
c_ind, c_spec = st.columns(2)
with c_ind:
    industry = st.selectbox("Industry", INDUSTRIES, key="gov_industry")
with c_spec:
    specialization = st.selectbox(
        "Specialization / sub-industry",
        get_specializations(industry),
        key="gov_specialization",
    )

business_function = st.selectbox(
    "Business function",
    BUSINESS_FUNCTIONS,
    key="gov_business_function",
)

st.subheader("Data, hosting & behavior")
st.caption(
    "Selections map to **known assessment tags** (e.g., customer_facing, pii, third_party_model, agentic_tools) "
    "and add keywords the engine reads with your narrative. Align with your description when possible."
)
bh_left, bh_right = st.columns(2)
with bh_left:
    audience = st.selectbox("Primary audience", AUDIENCE_OPTIONS, key="gov_audience")
    hosting = st.selectbox("Model / hosting", HOSTING_OPTIONS, key="gov_hosting")
    pattern = st.selectbox("Primary interaction pattern", PATTERN_OPTIONS, key="gov_pattern")
with bh_right:
    data_types = st.multiselect(
        "Data types in scope",
        options=list(DATA_TYPE_OPTIONS),
        default=[],
        key="gov_data_types",
        help="Select all that apply.",
    )
    automation = st.selectbox("Automation & system actions", AUTOMATION_OPTIONS, key="gov_automation")
    external_content = st.selectbox(
        "External or untrusted content",
        EXTERNAL_CONTENT_OPTIONS,
        key="gov_external",
    )

_ctx = (industry, specialization)
if st.session_state.get("_reg_ctx") != _ctx:
    st.session_state["_reg_ctx"] = _ctx
    st.session_state["regs_selected"] = get_default_regulations(industry, specialization)

regs_selected: list[str] = st.multiselect(
    "Relevant regulatory context (informs prioritization; not a compliance determination)",
    options=list(ALL_REGULATION_LABELS),
    default=st.session_state.get("regs_selected", []),
    key="regs_selected",
    help="Defaults update when industry or specialization changes. You may add or remove items.",
)

user_tags_sidebar = [x.strip() for x in extra_raw.split(",") if x.strip()]

signal_tags = tags_from_intake_signals(
    audience,
    data_types,
    hosting,
    pattern,
    automation,
    external_content,
)
derived_for_engine = merge_intake_tags(
    get_combined_context_tags(
        industry,
        specialization,
        business_function,
        regs_selected,
        user_tags_sidebar,
    ),
    signal_tags,
)
technical_intake_summary = format_technical_intake_summary(
    audience,
    data_types,
    hosting,
    pattern,
    automation,
    external_content,
)

if setup_mode == "Build Custom Use Case":
    st.subheader("Structured use case builder")
    st.caption(
        "Compose a narrative from structured choices. **Industry**, **specialization**, and **business function** above "
        "are included in the generated text. Align **Data, hosting & behavior** with the builder for consistent tags."
    )
    b_left, b_right = st.columns(2)
    with b_left:
        builder_use_case_type = st.selectbox("Use Case Type", USE_CASE_TYPES, key="gov_builder_uc_type")
        builder_primary_users = st.selectbox("Primary User Group", PRIMARY_USER_GROUPS, key="gov_builder_primary_users")
        builder_model_pattern = st.selectbox("Model Pattern", MODEL_PATTERNS, key="gov_builder_model_pattern")
        builder_human_review = st.selectbox(
            "Human Review Requirement",
            HUMAN_REVIEW_OPTIONS,
            key="gov_builder_human_review",
        )
    with b_right:
        builder_data_types_uc = st.multiselect(
            "Data Types Used",
            options=list(BUILDER_DATA_TYPES),
            default=[],
            key="gov_builder_data_types_uc",
        )
        builder_capabilities = st.multiselect(
            "Capabilities",
            options=list(CAPABILITIES),
            default=[],
            key="gov_builder_capabilities",
        )

    builder_narrative = build_use_case_description(
        industry,
        specialization,
        business_function,
        builder_use_case_type,
        builder_primary_users,
        list(builder_data_types_uc),
        builder_model_pattern,
        list(builder_capabilities),
        builder_human_review,
    )
    narrative_plain = builder_narrative.strip()

    with st.container(border=True):
        st.markdown("##### Generated use case preview")
        st.caption("This prose is submitted with structured context and technical intake—same path as a typed narrative.")
        st.code(builder_narrative, language=None)

else:
    st.subheader("Use case narrative")
    if setup_mode == "Sample Template":
        st.caption("Edit the narrative after loading a template, or write your own.")
    else:
        st.caption("Free-text entry: structured fields above still add tags and the technical block sent to the engine.")

    user_desc = st.text_area(
        "Describe the AI use case for governance review",
        height=170,
        key="gov_use_case_desc",
        placeholder=(
            "Example: Hosted LLM copilot for service agents with read/write to CRM; may suggest refunds; "
            "chats can contain account numbers and order history…"
        ),
    )
    narrative_plain = user_desc.strip()

with st.container(border=True):
    st.markdown("**Derived context preview** (what will shape tags and reviewer emphasis)")
    st.caption(
        "These tags are merged with text-inferred tags inside the **existing** assessment engine—no change to core mapping logic."
    )
    p1, p2 = st.columns(2)
    with p1:
        st.markdown(f"**Industry:** {industry}  \n**Specialization:** {specialization}  \n**Business function:** {business_function}")
        st.markdown("**Audience / hosting / pattern**")
        st.caption(f"{audience} · {hosting} · {pattern}")
        st.markdown("**Data types**")
        st.caption(", ".join(data_types) if data_types else "—")
        st.markdown("**Automation · external content**")
        st.caption(f"{automation} · {external_content}")
        st.markdown("**Regulations / standards selected**")
        if regs_selected:
            st.write(", ".join(regs_selected))
        else:
            st.caption("None (narrow scope)")
    with p2:
        st.markdown("**Combined context tags** (industry + regulations + technical intake + sidebar)")
        _tags_pills(derived_for_engine)
    emph = determine_contextual_risk_emphasis(industry, specialization, business_function, regs_selected)
    st.markdown("**Domain risk emphasis (illustrative)**")
    for line in emph[:6]:
        st.caption(f"• {line}")
    ctrl_e = determine_control_emphasis(industry, specialization, business_function)
    with st.expander("Control emphasis notes (illustrative)", expanded=False):
        for line in ctrl_e:
            st.caption(f"• {line}")

enrichment_block = build_context_enrichment_block(industry, specialization, business_function, regs_selected)
tech_block = build_technical_intake_block(
    audience,
    data_types,
    hosting,
    pattern,
    automation,
    external_content,
)
use_case_full = f"{enrichment_block}\n\n{tech_block}\n\n{narrative_plain}".strip()

if not run:
    st.info(
        "Choose a setup mode, complete **industry**, **specialization**, **business function**, **data/hosting/audience**, "
        "and **regulatory context**, add a use case via **template**, **builder**, or **free text**, optionally add sidebar **tags**, "
        "then click **Assess use case for governance review**."
    )
elif not narrative_plain:
    st.warning(
        "Add a use case narrative (**free text** or **sample template**) or complete the **structured builder** before running the assessment."
    )
else:
    now = datetime.now(timezone.utc)
    assessment_id = generate_use_case_id(now)
    assessment_ts = format_assessment_timestamp(now)

    extra_tags_arg = derived_for_engine if derived_for_engine else None

    with st.spinner("Running governance assessment (risk selection, control mapping, remediation)…"):
        result = map_use_case(use_case_full, extra_tags_arg)

    ar = result.get("audit_report") or {}
    conc = ar.get("audit_readiness_conclusion") or {}

    tags_list = list(result.get("tags") or [])
    overall = ar.get("overall_risk_level") or ""
    category = classify_use_case_category(use_case_full, tags_list)
    risk_tier = compute_enriched_tier(
        use_case_full,
        tags_list,
        regulation_label_count=len(regs_selected),
        business_function=business_function,
    )
    review_path = determine_review_path(risk_tier)
    domain_rationale_md = build_domain_rationale(industry, specialization, business_function, regs_selected)
    triage_rationale = build_triage_rationale(
        use_case_full,
        tags_list,
        risk_tier=risk_tier,
        category=category,
        domain_context=domain_rationale_md.replace("**", ""),
    )
    gov_row = governance_export_row(
        use_case_id=assessment_id,
        assessment_timestamp=assessment_ts,
        assessment_status=DEFAULT_ASSESSMENT_STATUS,
        use_case_category=category,
        risk_tier=risk_tier,
        recommended_review_path=review_path,
        triage_rationale=triage_rationale,
        industry=industry,
        specialization=specialization,
        business_function=business_function,
        selected_regulations="; ".join(regs_selected),
        derived_context_tags=", ".join(derived_for_engine),
        technical_intake_summary=technical_intake_summary,
    )

    st.success("Assessment complete. Draft governance record generated below.")
    st.caption(RESULTS_SCOPE_NOTE)

    mm = ar.get("most_material_risks") or []
    rc_rows = ar.get("required_controls") or []
    rem_rows = ar.get("required_remediation_actions") or []
    table = result.get("mapping_table") or []

    tier_rationale_bullets = get_risk_tier_rationale_bullets(
        use_case_full,
        tags_list,
        regulation_label_count=len(regs_selected),
        business_function=business_function,
        final_tier=risk_tier,
    )
    required_reviewers = get_required_reviewers(
        risk_tier=risk_tier,
        business_function=business_function,
        regulation_labels=regs_selected,
        tags=tags_list,
    )
    launch_recommendation = get_launch_recommendation(
        risk_tier=risk_tier,
        readiness_opinion=str(conc.get("readiness_opinion") or ""),
        open_remediation_count=len(rem_rows),
    )

    # --- 1 · Assessment metadata (at-a-glance strip) ---
    st.subheader("1 · Assessment metadata")
    with st.container(border=True):
        st.caption("Reference identifiers and routing for this draft assessment.")
        a1, a2, a3 = st.columns(3)
        a1.metric("Use case ID", assessment_id)
        a2.metric("Timestamp (UTC)", assessment_ts)
        a3.metric("Status", DEFAULT_ASSESSMENT_STATUS)
        b1, b2, b3 = st.columns(3)
        b1.metric("Risk tier (triage)", risk_tier)
        b2.markdown(f"**Recommended review path**  \n{review_path}")
        b3.markdown(f"**Launch recommendation (demo)**  \n{html.escape(launch_recommendation)}")

    # --- 2 · Governance triage summary ---
    st.subheader("2 · Governance triage summary")
    with st.container(border=True):
        st.caption(
            "Structured intake plus rule-based tiering (transparent bumps for regulation count and certain business functions). "
            "Catalog **overall risk** from the engine may differ; both appear under the use case summary."
        )
        st.markdown("##### Risk tier rationale")
        for line in tier_rationale_bullets:
            st.markdown(f"- {line}")
        st.divider()
        st.markdown("##### Required reviewers")
        st.caption("Illustrative roster from tier, tags, and regulatory context—adjust to your operating model.")
        st.markdown(
            "\n".join(f"- **{html.escape(r)}**" for r in required_reviewers),
            unsafe_allow_html=True,
        )
        st.divider()
        st.markdown("##### Launch recommendation")
        if launch_recommendation == "Ready for standard review":
            st.success(launch_recommendation)
        elif launch_recommendation == "Not ready":
            st.error(launch_recommendation)
        elif launch_recommendation == "Escalate":
            st.warning(launch_recommendation)
        else:
            st.info(launch_recommendation)
        st.divider()
        g1, g2, g3 = st.columns(3)
        g1.metric("Use case ID", assessment_id)
        g2.metric("Timestamp (UTC)", assessment_ts)
        g3.metric("Status", DEFAULT_ASSESSMENT_STATUS)
        st.markdown(f"**Industry:** {industry}  \n**Specialization:** {specialization}  \n**Business function:** {business_function}")
        st.markdown("**Relevant regulatory context considered**")
        if regs_selected:
            st.write(", ".join(regs_selected))
        else:
            st.caption("None selected for this run.")
        st.markdown("**Combined context tags** (enterprise + technical intake + sidebar extras, sent as `extra_tags`)")
        _tags_pills(derived_for_engine)
        with st.expander("Technical & data intake (submitted)", expanded=False):
            st.markdown(f"- **Audience:** {audience}")
            st.markdown(f"- **Data types:** {', '.join(data_types) if data_types else '—'}")
            st.markdown(f"- **Hosting:** {hosting}")
            st.markdown(f"- **Pattern:** {pattern}")
            st.markdown(f"- **Automation:** {automation}")
            st.markdown(f"- **External content:** {external_content}")
            st.caption(technical_intake_summary)
        st.metric("Risk tier (triage)", risk_tier)
        st.markdown(f"**Recommended review path**  \n{review_path}")
        st.metric("Use case category", category)
        with st.expander("Triage rationale (rule-based, for reviewers)", expanded=False):
            st.write(triage_rationale)

    # --- 3 · Regulatory context summary ---
    st.subheader("3 · Regulatory context summary")
    with st.container(border=True):
        st.info(
            "This assessment uses selected industry and regulatory context to inform **risk prioritization**, **control emphasis**, "
            "and **remediation guidance**. It does **not** determine legal compliance or full regulatory applicability."
        )
        if regs_selected:
            st.markdown("**Context items you selected**")
            for lab in regs_selected:
                st.caption(f"• {lab}")
        else:
            st.caption("No regulatory or standards context items selected—scope is intentionally narrow or TBD.")
        st.markdown("**Why this context matters (plain language)**")
        st.markdown(domain_rationale_md)

    # --- 4 · Use case summary ---
    st.subheader("4 · Use case summary")
    with st.container(border=True):
        desc_clip = (narrative_plain[:400] + "…") if len(narrative_plain) > 400 else narrative_plain
        st.markdown("**Use case narrative (excerpt)**")
        st.markdown(desc_clip or "—")
        with st.expander("Full text sent to the engine (structured context + narrative)", expanded=False):
            st.text(use_case_full or "—")
        st.markdown("**Assessment tags (structured context + inferred + optional sidebar)**")
        _tags_pills(tags_list)
        st.caption(
            "Tags merge **derived** context, **optional sidebar** tags, and **text-inferred** signals inside the existing engine."
        )
        c_eng, c_tri = st.columns(2)
        with c_eng:
            st.metric("Catalog overall risk (engine)", (overall or "—").strip().upper())
        with c_tri:
            st.metric("Governance risk tier (triage)", risk_tier)
        st.caption(
            "The **engine** drives material risks and controls below. **Triage tier** routes governance forums."
        )
        es = (result.get("executive_summary") or "").strip()
        if es:
            with st.expander("Executive narrative (assessment engine)", expanded=False):
                st.markdown(es)

    # --- 5 · Material risks identified ---
    st.subheader("5 · Material risks identified")
    r1, r2, r3, r4 = st.columns(4)
    r1.metric("Material risks", len(mm))
    r2.metric("Required controls", len(rc_rows))
    r3.metric("Open remediation rows", len(rem_rows))
    r4.metric("Risk–control mappings", len(table))
    if mm:
        st.dataframe(pd.DataFrame(mm), use_container_width=True, hide_index=True)
    else:
        st.caption("No material risks listed for this pass.")

    # --- 6 · Required controls before deployment ---
    st.subheader("6 · Required controls before deployment")
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

    # --- 7 · Required remediation before validation ---
    st.subheader("7 · Required remediation before validation")
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

    # --- 8 · Audit / review notes ---
    st.subheader("8 · Audit & review notes")
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

    # --- 9 · Downloadable detail ---
    st.subheader("9 · Downloadable detail & technical appendix")
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
            "Columns include use_case_id, timestamp, status, industry, specialization, business_function, "
            "selected_regulations, derived_context_tags, technical_intake_summary, category, risk_tier, review path, triage_rationale."
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
