# AI Risk Assessment Tool

## What this does

This tool performs a risk assessment for AI use cases. It identifies the most material risks, maps required controls aligned to NIST AI RMF / AI 600-1, and defines remediation actions needed before deployment.

Output is **design-time** guidance for validation or audit; it does not confirm that controls are already implemented.

## Example use case

Customer support chatbot with:

- CRM integrations  
- PII access  
- agentic tool execution  

## Example input

Customer support AI assistant connected to CRM that can update tickets and process refunds.

## Example output

- **Risk level:** HIGH  
- **Top risks:** Tool over-privilege, prompt injection, harmful outputs  
- **Required controls:** IAM, HITL approvals, logging, evaluation  
- **Remediation:** Restrict tool scopes, add approval gates, implement monitoring  

(Exact risk and control names come from the built-in catalog for each run.)

## How to run

From the `project` directory:

```bash
streamlit run app.py
```

Requires Python 3.10+ and dependencies such as `streamlit` and `pandas` (install as needed for your environment).

---

## Programmatic API

```python
from mapping_engine import map_use_case

result = map_use_case(
    "Your use case description…",
    extra_tags=["customer_facing", "agentic_tools"],  # optional
    audit_evidence_confirmed=False,
)
```

| Key on `result` | Contents |
|-----------------|----------|
| `tags` | Inferred and merged tags |
| `risks` | Selected catalog risks |
| `mapping_table` | Risk–control rows (`MappedRow` / `MAPPING_TABLE_SCHEMA`) |
| `audit_report` | Overall level, executive summary, required controls, gaps, remediation (`AUDIT_REPORT_SCHEMA`) |
| `executive_summary` | Short narrative |

`audit_report["required_controls"]` includes **`required_control`**, **`control_objective`**, **`primary_ai_rmf_mapping`**, **`secondary_ai_rmf_mapping`**, **`primary_ai_600_1_risk_theme`**, **`required_remediation_action`**, plus status, related risks, and evidence fields.

## Framework mapping (curated)

Per-control NIST AI RMF outcomes and primary AI 600-1 risk theme are maintained only in **`mapping_engine/nist_control_mapping.py`** (`CONTROL_FRAMEWORK_MAP`). They are not inferred at runtime from free text. `CONTROL_TO_NIST` aliases that map for compatibility.

## Package layout

| Module | Role |
|--------|------|
| `catalog.py` | Risks, controls, edges |
| `matcher.py` | Tag inference, risk selection, scoring |
| `nist_control_mapping.py` | Curated control → RMF / 600-1 table |
| `framework_alignment.py` | Row-level alignment from the table |
| `rationale.py` | Mapping rationales |
| `remediation.py` | Remediation text and metadata |
| `audit_report.py` | `generate_audit_report` |
| `__init__.py` | `map_use_case`, `MappedRow`, schemas |
