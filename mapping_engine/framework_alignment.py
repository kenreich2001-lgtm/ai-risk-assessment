"""Per-row NIST AI RMF and AI 600-1 alignment for mapping-table rows.

NIST AI RMF **outcomes** and the **primary AI 600-1 risk theme** for each control come **only**
from the curated table in ``nist_control_mapping.CONTROL_FRAMEWORK_MAP``. Nothing in this module
**infers** those strings at runtime from risk text or keyword overlap.
"""

from __future__ import annotations

from dataclasses import dataclass

from mapping_engine.catalog import Control, Risk
from mapping_engine.nist_control_mapping import (
    ControlFrameworkMapping,
    format_curated_rmf_mapping_line,
    get_control_framework_mapping,
)

_SUPPORTING_REMEDIATION_KEYS: frozenset[str] = frozenset(
    {
        "document_limits",
        "accountability_docs",
        "vendor_disclosure",
        "bias_disclosure",
        "reliance_training",
        "governance_roles",
        "vendor_notify",
        "behavioral_eval",
    }
)


def row_mapping_strength(remediation_key: str) -> str:
    return "supporting" if remediation_key in _SUPPORTING_REMEDIATION_KEYS else "primary"


@dataclass(frozen=True)
class RowFrameworkAlignment:
    primary_nist_ai_rmf_function: str
    primary_nist_ai_rmf_categories: str
    nist_ai_rmf_explicit_mapping: str
    primary_nist_ai_600_1_themes: str
    framework_mapping_rationale: str


def _rmf_function_token(primary_outcome: str) -> str:
    return (primary_outcome.split()[0] if primary_outcome else "Manage").capitalize()


def _gai_code_from_theme(theme_str: str) -> str:
    if "—" in theme_str:
        return theme_str.split("—", 1)[0].strip()
    return theme_str.split()[0] if theme_str else "GAI-OUT"


_GAI_ROLE: dict[str, str] = {
    "GAI-UX": "the prompt and misuse surface the model exposes to users and upstream content",
    "GAI-AUTO": "automation that turns model output into tool calls and side effects",
    "GAI-DATA": "scale and heterogeneity of data in corpora used for tuning or retrieval",
    "GAI-OUT": "stochastic outputs that can mislead without independent verification",
    "GAI-TRANS": "limited transparency into vendor-hosted behavior and change",
    "GAI-SUP": "third-party model and API dependence",
}


def _consulting_framework_rationale_curated(
    risk: Risk,
    control: Control,
    cf: ControlFrameworkMapping,
    supporting_track: bool,
) -> str:
    primary_outcome = cf.primary_ai_rmf_mapping
    fn = _rmf_function_token(primary_outcome)
    ctrl_lower = control.name.lower()
    risk_lower = risk.name.lower()
    c = control.coverage
    theme_str = cf.primary_ai_600_1_risk_theme
    gcode = _gai_code_from_theme(theme_str)
    role0 = _GAI_ROLE.get(gcode, "generative-AI-specific exposure in this design")

    if fn == "Govern":
        s1 = (
            f"This mapping aligns to **{primary_outcome}** because **{ctrl_lower}** fixes ownership, policy, "
            f"or accountability for how the AI system is run—before issues show up in production metrics."
        )
    elif fn == "Map":
        s1 = (
            f"This mapping aligns to **{primary_outcome}** because **{ctrl_lower}** clarifies context and impacts "
            f"so **{risk_lower}** is not handled with an incomplete picture of the use case."
        )
    elif fn == "Measure":
        if c == "detective":
            s1 = (
                f"This mapping aligns to **{primary_outcome}** because **{ctrl_lower}** is built to observe misuse, drift, "
                f"or guardrail breaches—so failures surface while they are still containable."
            )
        else:
            s1 = (
                f"This mapping aligns to **{primary_outcome}** because **{ctrl_lower}** produces repeatable signals "
                f"and analysis that make **{risk_lower}** diagnosable rather than anecdotal."
            )
    else:
        if c == "preventive":
            s1 = (
                f"This mapping aligns to **{primary_outcome}** because **{ctrl_lower}** enforces preventive constraints "
                f"on generation, disclosure, or tool use—not merely documents intent."
            )
        elif c == "detective":
            s1 = (
                f"This mapping aligns to **{primary_outcome}** with detective posture: **{ctrl_lower}** detects and escalates "
                f"unsafe behavior so **{risk_lower}** is interrupted before impact accumulates."
            )
        elif c == "corrective":
            s1 = (
                f"This mapping aligns to **{primary_outcome}** on corrective lines—**{ctrl_lower}** limits blast radius "
                f"and restores control after triggers tied to **{risk_lower}**."
            )
        else:
            s1 = (
                f"This mapping aligns to **{primary_outcome}** because **{ctrl_lower}** supplies compensating assurance "
                f"where primary technical prevention is incomplete for **{risk_lower}**."
            )

    s2 = (
        f"Without it, safeguards stay paper-deep: **{risk_lower}** reaches customers, logs, or integrated systems "
        f"with less friction and weaker traceability."
    )
    s3 = (
        f"NIST AI 600-1 profile alignment for this row is **{theme_str}** ({role0}); "
        f"**{ctrl_lower}** is how this pairing addresses **{risk_lower}** in practice."
    )

    out = f"{s1} {s2} {s3}"
    if supporting_track:
        out += " **Supporting** row: disclosure, governance, or training weight—not the sole runtime gate."
    return out


def compute_row_framework_alignment(
    risk: Risk,
    control: Control,
    rationale_key: str,
    remediation_key: str,
) -> RowFrameworkAlignment:
    _ = rationale_key
    cf = get_control_framework_mapping(control.id)
    mapping_line = format_curated_rmf_mapping_line(cf)
    primary_fn = _rmf_function_token(cf.primary_ai_rmf_mapping)
    parts = [cf.primary_ai_rmf_mapping, *cf.secondary_ai_rmf_mapping]
    categories_str = "; ".join(parts)

    supporting = remediation_key in _SUPPORTING_REMEDIATION_KEYS
    expl = _consulting_framework_rationale_curated(risk, control, cf, supporting)

    return RowFrameworkAlignment(
        primary_nist_ai_rmf_function=primary_fn,
        primary_nist_ai_rmf_categories=categories_str,
        nist_ai_rmf_explicit_mapping=mapping_line,
        primary_nist_ai_600_1_themes=cf.primary_ai_600_1_risk_theme,
        framework_mapping_rationale=f"{mapping_line}\n\n{expl}",
    )
