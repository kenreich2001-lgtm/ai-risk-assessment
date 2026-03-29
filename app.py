"""
Streamlit UI for the AI use case risk assessment and control mapping engine (`map_use_case`).

Run from this directory: streamlit run app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mapping_engine import map_use_case

TOOL_SUBTITLE = (
    "AI Risk Assessment: Rank risks, identify required controls, and define remediation actions for a given use case."
)

TOOL_PURPOSE = (
    "This tool performs an AI use case risk assessment. For a given use case, it identifies and ranks the most "
    "material risks, maps those risks to relevant controls aligned to NIST AI RMF and AI 600-1, and defines the "
    "remediation actions required to address control gaps and prepare the use case for validation or audit."
)

RESULTS_SCOPE_NOTE = (
    "This assessment defines the risk level for the use case and the controls required for safe deployment. "
    "It does not determine whether those controls are currently implemented."
)

RISK_LEVEL_EMOJI = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}


def _risk_level_line(level: str) -> str:
    key = (level or "").strip().upper()
    icon = RISK_LEVEL_EMOJI.get(key, "⚪")
    return f"{icon} **Overall risk level:** **{key or '—'}**"


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

st.set_page_config(page_title="AI use case risk assessment", layout="wide")
st.title("AI use case risk assessment")
st.caption(TOOL_SUBTITLE)
st.markdown(TOOL_PURPOSE)

use_case = st.text_area("Use case description", height=180, placeholder="Describe the GenAI/system context…")
extra_raw = st.text_input("Optional extra tags (comma-separated)", "")

if st.button("Map use case", type="primary"):
    extras = [x.strip() for x in extra_raw.split(",") if x.strip()]
    result = map_use_case(use_case, extras if extras else None)
    ar = result.get("audit_report") or {}
    conc = ar.get("audit_readiness_conclusion") or {}

    st.markdown(_risk_level_line(ar.get("overall_risk_level") or ""))
    st.info(RESULTS_SCOPE_NOTE)

    st.subheader("Risk Assessment Summary")
    st.info(result.get("executive_summary", ""))

    st.subheader("Required controls for this use case")
    rc_rows = ar.get("required_controls") or []
    if rc_rows:
        rcdf = pd.DataFrame(rc_rows)
        rccols = [c for c in REQUIRED_CONTROL_COLS if c in rcdf.columns]
        st.dataframe(rcdf[rccols], use_container_width=True, hide_index=True)
    else:
        st.caption("No required-control rows derived for this run.")

    st.subheader("Required remediation actions before deployment")
    rem_rows = ar.get("required_remediation_actions") or []
    if rem_rows:
        remdf = pd.DataFrame(rem_rows)
        remcols = [c for c in REMEDIATION_ACTION_COLS if c in remdf.columns]
        st.dataframe(remdf[remcols], use_container_width=True, hide_index=True)
    else:
        st.caption("None—no open remediation rows on required controls for this pass.")

    st.subheader("Required Controls & Remediation")
    st.markdown(f"**Implementation requirement:** **{conc.get('readiness_opinion', '—')}**")
    if conc.get("rationale"):
        st.write(conc["rationale"])
    if conc.get("residual_note"):
        st.caption("Residual risk note")
        st.write(conc["residual_note"])

    st.caption("Design-time risk and required-controls assessment—**not** an implementation attestation.")

    st.subheader("Inferred tags")
    st.write(", ".join(result.get("tags", [])) or "(none)")

    with st.expander("AI Risk & Control Assessment (sections A–F)", expanded=False):
        st.markdown("#### A. Use case summary")
        st.markdown(ar.get("use_case_summary") or "—")

        st.markdown("#### B. Most material risks")
        mm = ar.get("most_material_risks") or []
        if mm:
            st.dataframe(pd.DataFrame(mm), use_container_width=True, hide_index=True)
        else:
            st.caption("—")

        st.markdown("#### C. Required controls for this use case")
        if rc_rows:
            st.dataframe(pd.DataFrame(rc_rows), use_container_width=True, hide_index=True)
        else:
            st.caption("—")

        st.markdown("#### D. Required remediation actions before deployment")
        if rem_rows:
            st.dataframe(pd.DataFrame(rem_rows), use_container_width=True, hide_index=True)
        else:
            st.caption("None for this pass.")

        st.markdown("#### E. Evidence artifacts for future validation or audit")
        st.markdown(ar.get("evidence_for_audit_readiness") or "—")

        st.markdown("#### F. Required Controls & Remediation")
        st.markdown(
            f"**Implementation requirement:** **{conc.get('readiness_opinion', '—')}** — {conc.get('rationale', '')}"
        )

        diag = ar.get("diagnostics") or {}
        if diag:
            st.markdown("---\n**Diagnostics (secondary)**")
            st.json(
                {
                    "mapping_row_count": diag.get("mapping_row_count"),
                    "material_risk_ids": diag.get("material_risk_ids"),
                    "framework_alignment": diag.get("framework_alignment"),
                }
            )

    table = result.get("mapping_table", [])
    if not table:
        st.caption("No mapping rows.")
    else:
        df = pd.DataFrame(table)
        cols_present = [c for c in DETAIL_VIEW_COLS if c in df.columns]

        st.subheader("Supporting detail: top 5 by priority score")
        top5 = df.nlargest(min(5, len(df)), "priority_score")
        st.dataframe(top5[cols_present], use_container_width=True, hide_index=True)

        st.subheader("Supporting detail: primary mappings")
        prim = df[df["mapping_strength"] == "primary"] if "mapping_strength" in df.columns else df
        st.caption(f"{len(prim)} row(s) marked primary.")
        st.dataframe(prim[cols_present], use_container_width=True, hide_index=True)

        csv = df.to_csv(index=False)
        st.download_button("Download full mapping table (CSV)", csv, "mapping_table.csv", "text/csv")

        with st.expander("Full mapping table (all columns)", expanded=False):
            st.dataframe(df, use_container_width=True, hide_index=True)
