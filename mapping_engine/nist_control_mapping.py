"""
Centralized, curated control → NIST AI RMF / AI 600-1 mapping.

**Mappings are maintained only in** ``CONTROL_FRAMEWORK_MAP``. They are **not** inferred at
runtime from keywords, risk text, or risk–control intersections. Every catalog control id
must have exactly one row.

Outcome-style AI RMF references (e.g. ``MAP 3.5``, ``MEASURE 2.7``) are **curated labels**
for traceability; each control has **one** primary and **at most two** secondary mappings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass(frozen=True)
class ControlFrameworkMapping:
    """Explicit framework fields for a catalog control (table-only)."""

    primary_ai_rmf_mapping: str
    secondary_ai_rmf_mapping: Tuple[str, ...]  # length 0–2
    primary_ai_600_1_risk_theme: str


# Conservative: one primary + up to two secondary RMF outcomes per control.
CONTROL_FRAMEWORK_MAP: Dict[str, ControlFrameworkMapping] = {
    "C-EVAL": ControlFrameworkMapping(
        "MEASURE 2.7",
        ("MEASURE 2.10",),
        "GAI-OUT — Stochastic outputs",
    ),
    "C-HUMAN": ControlFrameworkMapping(
        "MANAGE 3.1",
        ("MAP 3.5",),
        "GAI-UX — User-in-the-loop and prompt surface",
    ),
    "C-DATA-GOV": ControlFrameworkMapping(
        "MAP 3.5",
        ("MEASURE 2.10",),
        "GAI-DATA — Broad / heterogeneous data exposure",
    ),
    "C-LOG": ControlFrameworkMapping(
        "MEASURE 2.11",
        ("MANAGE 4.1",),
        "GAI-DATA — Broad / heterogeneous data exposure",
    ),
    "C-GUARD": ControlFrameworkMapping(
        "MANAGE 3.1",
        ("MEASURE 2.7",),
        "GAI-UX — User-in-the-loop and prompt surface",
    ),
    "C-VENDOR": ControlFrameworkMapping(
        "MANAGE 3.1",
        ("MEASURE 2.10",),
        "GAI-SUP — Third-party model / platform dependence",
    ),
    "C-TOOLS": ControlFrameworkMapping(
        "MAP 3.5",
        ("MANAGE 3.1",),
        "GAI-AUTO — Automation and tool use",
    ),
    "C-DOC": ControlFrameworkMapping(
        "MAP 3.5",
        ("MANAGE 3.1",),
        "GAI-TRANS — Transparency and explainability limits",
    ),
    "C-FAIR": ControlFrameworkMapping(
        "MEASURE 2.7",
        ("MAP 3.5",),
        "GAI-DATA — Broad / heterogeneous data exposure",
    ),
    "C-AUTO-SAFE": ControlFrameworkMapping(
        "MANAGE 3.1",
        ("MAP 3.5",),
        "GAI-UX — User-in-the-loop and prompt surface",
    ),
    "C-OUT-SAFE": ControlFrameworkMapping(
        "MANAGE 4.1",
        ("MANAGE 3.1",),
        "GAI-UX — User-in-the-loop and prompt surface",
    ),
    "C-ABUSE": ControlFrameworkMapping(
        "MEASURE 2.11",
        ("MANAGE 3.1",),
        "GAI-UX — User-in-the-loop and prompt surface",
    ),
    "C-IAM": ControlFrameworkMapping(
        "MAP 3.5",
        ("MANAGE 3.1",),
        "GAI-DATA — Broad / heterogeneous data exposure",
    ),
    "C-PROV": ControlFrameworkMapping(
        "MAP 3.5",
        ("MEASURE 2.10",),
        "GAI-DATA — Broad / heterogeneous data exposure",
    ),
    "C-IR-AI": ControlFrameworkMapping(
        "MANAGE 4.1",
        ("MEASURE 2.11",),
        "GAI-AUTO — Automation and tool use",
    ),
}


def get_control_framework_mapping(control_id: str) -> ControlFrameworkMapping:
    m = CONTROL_FRAMEWORK_MAP.get(control_id)
    if m is None:
        raise KeyError(f"CONTROL_FRAMEWORK_MAP missing control id {control_id!r}; add an explicit mapping.")
    return m


def format_secondary_ai_rmf(secondary: Tuple[str, ...]) -> str:
    return "; ".join(secondary) if secondary else ""


def format_curated_rmf_mapping_line(cf: ControlFrameworkMapping) -> str:
    parts = [cf.primary_ai_rmf_mapping]
    parts.extend(cf.secondary_ai_rmf_mapping)
    return "Mapped to: NIST AI RMF – " + ", ".join(parts)


# Back-compat alias for tests / imports expecting the old name
CONTROL_TO_NIST = CONTROL_FRAMEWORK_MAP
