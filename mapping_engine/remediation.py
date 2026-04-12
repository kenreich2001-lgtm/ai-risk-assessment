"""Remediation playbooks — gap, action, artifact, verification, residual."""

from __future__ import annotations

from dataclasses import dataclass

from mapping_engine.catalog import Control, Risk


@dataclass(frozen=True)
class RemediationDetail:
    gap: str
    action: str
    artifact: str
    verification: str
    residual_risk: str
    remediation_evidence_expectation: str = ""
    remediation_priority: str = "Medium"
    remediation_owner: str = "Cross-functional lead"
    remediation_timeline: str = "30–60 days"


def _d(gap: str, action: str, artifact: str, verification: str, residual: str) -> RemediationDetail:
    return RemediationDetail(
        gap=gap,
        action=action,
        artifact=artifact,
        verification=verification,
        residual_risk=residual,
        remediation_evidence_expectation="",
    )


_PLAYBOOKS: dict[str, RemediationDetail] = {
    "eval_harness": _d(
        "No task-grounded evaluation tied to releases.",
        "Gold scenarios per intent; automate regression on model/prompt/tool changes; gate production.",
        "Eval charter; CI reports; signed release record.",
        "Last N releases include eval deltas; failures block deploy.",
        "Tail regressions may still slip through until production signal.",
    ),
    "human_review": _d(
        "No reviewer, SLA, or audit trail for high-impact outputs.",
        "Approval matrix; train reviewers; log overrides and rationale.",
        "RACI; training logs; sampled attestations.",
        "Audit sample: high-risk cases have approver within SLA.",
        "Review fatigue can weaken quality.",
    ),
    "document_limits": _d(
        "Users lack clear intended use and limitations.",
        "In-product disclosures; manager talking points on residual risk.",
        "Versioned disclosure text; acknowledgments where needed.",
        "Surveys/tickets show improved awareness of limits.",
        "Users may still skim disclosures.",
    ),
    "iop_controls": _d(
        "No machine enforcement for unsafe or overconfident outputs.",
        "Structured outputs; refusal policies; citation rules; UX de-biasing certainty.",
        "Policy config; change control; transcripts.",
        "Red-team shows blocks on forbidden classes.",
        "Novel phrasings may evade filters temporarily.",
    ),
    "automation_bias": _d(
        "Staff treat fluent AI output as fact.",
        "Attestations, citations, 'draft' banners; training on automation bias.",
        "Training logs; UX screenshots; worksheets.",
        "Studies show more verification behaviors post-change.",
        "Time pressure erodes adherence.",
    ),
    "reliance_training": _d(
        "Enablement ignores safe reliance patterns.",
        "Modules on verification, escalation, and failure examples.",
        "LMS completion; knowledge checks.",
        "Drills show correct escalations.",
        "Decay without refreshers.",
    ),
    "behavioral_eval": _d(
        "Metrics miss human-AI interaction failures.",
        "Task studies; behavioral KPIs (override rate, time-on-source).",
        "Protocol; findings memo; backlog.",
        "Post-remediation study shows movement toward safer patterns.",
        "Samples may not cover all personas.",
    ),
    "data_minimization": _d(
        "Over-retention of sensitive data in prompts/logs/corpora.",
        "Classify fields; redact logs; tighten retention; segregate environments.",
        "Data-flow diagram; retention schedule; DPA updates.",
        "Log sampling; retention job receipts.",
        "Legacy pipelines may reintroduce sprawl.",
    ),
    "logging_privacy": _d(
        "Telemetry creates unmanaged PHI/PII stores.",
        "Hash/redact; restrict roles; DPIA updates.",
        "Schema register; access reviews; sign-off.",
        "Privacy review: no full prompts in open indices.",
        "Vendor logging may differ from internal standard.",
    ),
    "output_controls": _d(
        "Sensitive attributes leak to consumers.",
        "Schema validation; allow-lists; alerts on violations.",
        "Policy-as-code; monitoring snapshots.",
        "Synthetic forbidden-content tests block appropriately.",
        "Multilingual/obfuscated evasion possible.",
    ),
    "iam_data_plane": _d(
        "Retrieval/inference lacks RBAC/tenant boundaries.",
        "Subject tokens end-to-end; per-tenant indexes; SoD.",
        "IAM arch note; pen-test scope.",
        "AuthZ tests pass; cross-tenant attempts logged denied.",
        "Misconfigured SPs remain a risk.",
    ),
    "untrusted_content": _d(
        "Untrusted text treated as instructions.",
        "Isolate parsing; strip hidden instructions; provenance; high-risk secondary checks.",
        "Threat model; hardening checklist; pipeline diagram.",
        "Injection suite: containment in staging; no tool exfiltration in red team.",
        "Novel carriers may bypass parsers.",
    ),
    "detection_monitoring": _d(
        "SOC lacks AI-relevant detections.",
        "Alerts for tool abuse, prompt spikes, policy blocks; tiered response.",
        "Use cases; tuning history; drill AARs.",
        "Tabletop meets MTTD/MTTR targets.",
        "Low-and-slow abuse may evade thresholds.",
    ),
    "tool_sandbox": _d(
        "Tools expose broad capabilities without validation.",
        "Narrow scopes; JSON-schema args; ephemeral creds; deny destructive defaults.",
        "Manifests; fuzzing results.",
        "Adversarial args fail safe; no lateral movement.",
        "Shadow tools bypass manifest.",
    ),
    "ir_injection": _d(
        "IR assumes classic exploits only.",
        "AI IR annex: key revoke, prompt snapshot, vendor case, notice triggers.",
        "Templates; forensic list; RACI.",
        "Tabletop with legal/comms sign-off.",
        "Cross-border notice timing still judgmental.",
    ),
    "ir_tool_misuse": _d(
        "No rollback for bad tool actions.",
        "Compensating transactions; idempotent APIs; rollback scripts.",
        "Tagged incidents; RTO proof from game day.",
        "Rollback within RTO in exercise.",
        "Some physical-world effects irreversible.",
    ),
    "vendor_mgmt": _d(
        "Informal vendor commitments on logging/subprocessors/change notice.",
        "Contract schedules; SLAs; audit rights; residency options.",
        "Executed DPA; vendor risk register; QBRs.",
        "Spot-check subprocessors and terms.",
        "Vendor disputes delay remediation.",
    ),
    "version_regression": _d(
        "Silent model upgrades degrade behavior.",
        "Pin versions; canary; auto-rollback; changelog gate.",
        "Canary metrics; promotion approvals.",
        "Last upgrades have green canaries pre-full rollout.",
        "Canary slice may miss tail queries.",
    ),
    "vendor_disclosure": _d(
        "Stakeholders lack consolidated vendor/limitation view.",
        "Disclosure pack for exec/legal; versioned repo.",
        "Quarterly attestation vs production config.",
        "Exceptions documented.",
        "Opaque supplier documentation gaps remain.",
    ),
    "vendor_notify": _d(
        "Unclear vendor-incident notification path.",
        "Severity mapping; SLAs; crisis comms crosswalk.",
        "Templates pre-cleared by legal.",
        "Timed tabletop for vendor outage.",
        "Novel incidents need legal judgment.",
    ),
    "vendor_change": _d(
        "Teams learn of vendor changes from users.",
        "Advisory subscriptions; CI diffs; error/refusal by model ID.",
        "Workbook; monthly delta minutes.",
        "Drill detects injected regression in one business day.",
        "Invisible A/B at vendor still possible.",
    ),
    "governance_roles": _d(
        "Implicit RACI across product/security/legal.",
        "Publish RACI; CAB for material changes; committee escalation.",
        "Charter; decision log; risk register links.",
        "Sample changes have complete chain in 90 days.",
        "Deadline pressure bypass culture.",
    ),
    "accountability_docs": _d(
        "Evidence scattered or unversioned.",
        "Central evidence store; map to SOC/ISO narrative.",
        "Index; retention; access control.",
        "Sampled incident fully traceable.",
        "Poor metadata hurts investigations.",
    ),
    "least_priv_tools": _d(
        "Agent credentials exceed least privilege.",
        "Tight OAuth scopes; short-lived tokens; reviews; deny lists.",
        "Inventory; pen-test closure.",
        "Privilege-escalation sims blocked.",
        "Break-glass needs compensating monitoring.",
    ),
    "action_gates": _d(
        "Irreversible actions from single model suggestion.",
        "Step-up/dual control/preview-diff; rate limits on side effects.",
        "Policy matrix; automated abuse tests.",
        "Tests block without confirmation; SIEM on bypass.",
        "Exec risk acceptance for exceptions.",
    ),
    "human_approval": _d(
        "No maker-checker on sensitive actions.",
        "Dual control; evidence bundle; approver identity.",
        "IdP groups; audit queries.",
        "Zero SoD violations in sample window.",
        "Social engineering of approvers.",
    ),
    "continuous_eval": _d(
        "No periodic eval of misuse and safety drift.",
        "Quarterly eval + sampling; vendor delta tracking.",
        "Roadmap; trends; remediated tickets.",
        "Exec review shows trend or accepted residual.",
        "Rare demographics/languages under-covered.",
    ),
    "production_metrics": _d(
        "No AI SLOs (refusals, tool errors, cost).",
        "Dashboard + paging + runbooks.",
        "Links; on-call config; postmortems.",
        "Weekly ops review without silent threshold edits.",
        "Blind spots until incidents add signals.",
    ),
    "forensics_ready": _d(
        "Forensics lacks trace IDs, tool args, model version.",
        "Trace standard; immutable logs; legal hold alignment.",
        "Standard + mock investigation under target time.",
        "Mock completes using standard logs only.",
        "Privacy limits some fields—document explicitly.",
    ),
    "fairness_program": _d(
        "No disparate-impact testing approach.",
        "Lawful proxy strategy; metrics; thresholds; escalation.",
        "Plan; results; legal memo.",
        "Independent QA reproduces results.",
        "Small samples limit power.",
    ),
    "bias_human_review": _d(
        "Reviewers lack stereotype/steering guidance.",
        "Rubric; calibration; SME escalation.",
        "Logs; disagreement analysis.",
        "Improved inter-rater reliability on gold sets.",
        "Human bias persists—dual review on highest stakes.",
    ),
    "corpus_fairness": _d(
        "Corpus skew dominates narratives.",
        "Source audit; diversify authorities; ingest filters.",
        "Manifest; inclusion criteria; sign-off.",
        "Sensitive-Q spot checks improve post-change.",
        "Historical doc bias remains partly.",
    ),
    "bias_disclosure": _d(
        "Stakeholders uninformed on fairness limits.",
        "Disclosure appendix; legal-aligned customer messaging.",
        "Sign-off; staff training.",
        "Messaging consistent in spot checks.",
        "Liability vs precision tradeoffs ongoing.",
    ),
    "output_pipeline": _d(
        "Model text hits HTML/tickets without sanitization.",
        "Contextual escaping; CSP; secret scan outbound.",
        "Secure coding std; SAST/DAST; ticketed exceptions.",
        "Injection battery passes staging.",
        "New connectors may skip sanitization.",
    ),
    "secret_leak_detect": _d(
        "No detection for secrets in model→ticket/log paths.",
        "Outbound secret scanner; redact/page.",
        "Config; tuning; redacted examples.",
        "Fake secrets caught at acceptable FP rate.",
        "Novel encodings evade briefly.",
    ),
    "structured_output": _d(
        "Free text to structured writers without validation.",
        "JSON/schema server-side validation; retry policy.",
        "Registry; fuzz results.",
        "Malformed never reaches writers unvalidated.",
        "Edge schemas need human mapping.",
    ),
    "abuse_controls": _d(
        "No enforceable AUP or enforcement for abuse rings.",
        "AUP; throttle; progressive enforcement.",
        "Versioned AUP; playbook; samples.",
        "Simulated abuse actioned within SLA safely.",
        "False positives need appeals.",
    ),
    "rate_policy": _d(
        "Bursts exhaust budget / enable probing.",
        "Per-tenant/user quotas; adaptive throttle; finance alerts.",
        "Config; burn scenarios; runbook.",
        "Load test shows graceful degradation.",
        "Distributed attacks need edge/WAF.",
    ),
    "fraud_iam": _d(
        "Weak signup lifecycle for high-value AI access.",
        "MFA; device signals where lawful; velocity checks.",
        "Fraud assessment; SOC integration.",
        "Synthetic ring contained; acceptable FP.",
        "Privacy limits some signals.",
    ),
    "iam_full": _d(
        "AI gateway/admin APIs below enterprise auth bar.",
        "SSO/MFA; vault secrets; SCIM groups.",
        "Hardening checklist; access review artifacts.",
        "Pen-test: no unauth admin paths.",
        "Shadow vendor admin UIs.",
    ),
    "data_gov_iam": _d(
        "AI bypasses classification gates.",
        "Auto-classify sources; block unclassified prod RAG.",
        "Exception register with expiry.",
        "Audit: no orphan unclassified corpora.",
        "Mis-labeling at source propagates.",
    ),
    "access_anomaly": _d(
        "No detection of odd retrieval/tool patterns.",
        "Baseline; geo/role anomalies; insider-program tie-in.",
        "Rules; tuning log; joint SOC review.",
        "Purple-team validates alert + runbook.",
        "Baseline drift causes fatigue.",
    ),
    "provenance_full": _d(
        "No authoritative corpus registry (license, lineage, owner).",
        "Registry with owner, license, refresh, scans, retirement.",
        "Exports; legal sign-off; per-version changelog.",
        "Spot audit: hashes match registry.",
        "Legacy shares resist registration.",
    ),
    "corpus_gov": _d(
        "Ingestion skips governance for speed.",
        "Mandatory tickets for sources; PII checks; denylists.",
        "Template; SLA metrics.",
        "Monthly: 100% new sources ticketed.",
        "Emergency ingest needs 48h post-review.",
    ),
    "rag_qa_gold": _d(
        "No curated Q/A to catch grounding regression.",
        "Gold sets; nightly eval; SME ownership.",
        "Version control; alert on corpus change.",
        "Synthetic perturbation triggers alert.",
        "Gold decays as rules change.",
    ),
    "ir_playbooks": _d(
        "No AI-tailored incident playbooks.",
        "Decision trees for spill, collapse, tool damage; training.",
        "Approved PDF; annual refresh.",
        "Graded tabletop with tracked gaps.",
        "Novel modalities outpace first playbook.",
    ),
}


# What reviewers/auditors typically expect to see evidenced for each remediation playbook.
_REMEDIATION_EVIDENCE_EXPECTATION: dict[str, str] = {
    "eval_harness": "Task-grounded evaluation charters; versioned gold scenarios; CI/regression reports; release sign-offs tying scores to model/prompt/tool versions.",
    "human_review": "Approval RACI; sampled tickets with approver identity and timestamps; override logs with rationale; SLA metrics.",
    "document_limits": "Versioned in-product disclosure text; knowledge-base articles; optional user acknowledgments where policy requires them.",
    "iop_controls": "Policy-as-code exports; refusal/block configuration snapshots; red-team or synthetic violation test results; change tickets for policy edits.",
    "automation_bias": "Training completion logs; UX screenshots showing “draft”/uncertainty cues; post-training attestation or quiz results.",
    "reliance_training": "LMS completion records; knowledge-check scores; refreshed curriculum tied to model or workflow changes.",
    "behavioral_eval": "Human study protocol; behavioral KPI definitions; findings memo; backlog items linked to remediation owners.",
    "data_minimization": "Data-flow diagrams; field classification; retention schedules; DPA excerpts; log sampling showing redaction effectiveness.",
    "logging_privacy": "Telemetry schema register; DPIA or privacy review sign-off; role-based access reviews for log stores.",
    "output_controls": "Schema/allow-list configuration; monitoring snapshots; synthetic tests demonstrating blocked sensitive-attribute patterns.",
    "iam_data_plane": "RBAC policy exports; per-tenant index manifests; authorization test results; pen-test or AuthZ regression evidence.",
    "untrusted_content": "Prompt/document pipeline diagrams; parser hardening checklist; staged injection test reports with containment proof.",
    "detection_monitoring": "SIEM/SOAR use cases; tuning history; blocked tool-execution or abuse logs; tabletop after-action notes with MTTD/MTTR.",
    "tool_sandbox": "Tool manifests with scoped OAuth; JSON-schema validation proofs; fuzz/adversarial arg test results; deny-default evidence.",
    "ir_injection": "AI incident annex to IR plan; forensic evidence checklist; legal/comms pre-cleared templates; tabletop sign-in sheet.",
    "ir_tool_misuse": "Rollback/compensation playbooks; tagged incident tickets; game-day results showing RTO for reversing bad tool actions.",
    "vendor_mgmt": "Executed DPA/schedules; subprocessor registers; vendor risk assessments; QBR minutes; sampled contract control tests.",
    "version_regression": "Pinned model/version config; canary dashboards; promotion approvals; changelog gates tied to production deploys.",
    "vendor_disclosure": "Versioned disclosure packs; quarterly attestation vs production routing; exception register with owners.",
    "vendor_notify": "Severity-to-SLA matrix; crisis-comms runbooks; timed drill outcomes for vendor-notice scenarios.",
    "vendor_change": "Vendor advisory subscription logs; CI diffs on behavior; monthly operational review minutes on model deltas.",
    "governance_roles": "Published RACI; CAB or governance committee minutes; decision logs with risk-register links.",
    "accountability_docs": "Central evidence index; retention and access-control policy; sampled investigation showing end-to-end traceability.",
    "least_priv_tools": "Token scope inventories; short-lived credential configs; periodic privilege review; pen-test closure for tool paths.",
    "action_gates": "Dual-control or step-up policy matrix; rate-limit configs; automated tests proving blocks without confirmation; SIEM rules on bypass.",
    "human_approval": "Maker-checker IdP group mappings; audit queries showing no SoD violations in sample window; approval bundle samples.",
    "continuous_eval": "Quarterly eval reports with trend charts; vendor change trackers; executive risk-acceptance minutes where residual is accepted.",
    "production_metrics": "Live dashboards; on-call/runbook links; paging history; postmortems for threshold breaches without silent edits.",
    "forensics_ready": "Trace ID standard; immutable log architecture diagram; mock investigation write-up completed within target time under legal hold rules.",
    "fairness_program": "Testing plan; lawful-proxy methodology memo; results with thresholds; independent QA reproduction notes.",
    "bias_human_review": "Reviewer rubrics; calibration exercises; inter-rater reliability reports on gold sets.",
    "corpus_fairness": "Source manifest with inclusion criteria; legal sign-off on sensitive corpora; pre/post spot-check results.",
    "bias_disclosure": "Legal-reviewed fairness limitations; training records; messaging consistency spot checks.",
    "output_pipeline": "Secure coding standard; SAST/DAST reports; CSP configuration; injection-battery results from staging.",
    "secret_leak_detect": "Outbound scanner configuration; tuning log; redacted examples of detected secrets; FP review notes.",
    "structured_output": "JSON/schema registry; server-side validation code links; fuzz test evidence showing rejects before writers.",
    "abuse_controls": "Versioned AUP; enforcement playbook; sampled abuse cases closed within SLA with appeals trail.",
    "rate_policy": "Quota/throttle configuration; finance burn scenarios; load-test report showing graceful degradation.",
    "fraud_iam": "MFA/device policy; fraud assessment; SOC integration samples; synthetic ring containment test results.",
    "iam_full": "SSO/MFA config exports; vault/secret rotation evidence; access review; pen-test report (no unauth admin).",
    "data_gov_iam": "Classification metadata on sources; exception register with expiry; audit showing no unclassified prod RAG corpora.",
    "access_anomaly": "Baseline documentation; detection rules with tuning log; purple-team validation of alert + response playbook.",
    "provenance_full": "Corpus registry exports; legal license files; hash/lineage spot audits matching production indexes.",
    "corpus_gov": "Mandatory source tickets; PII checks; monthly metrics proving new sources are governed before ingest.",
    "rag_qa_gold": "Version-controlled gold Q/A sets; nightly eval logs; alerts tied to corpus or prompt changes.",
    "ir_playbooks": "Approved AI playbooks; annual refresh record; graded tabletop with gap tracker and owners.",
}


def _evidence_expectation_for_key(remediation_key: str) -> str:
    if remediation_key in _REMEDIATION_EVIDENCE_EXPECTATION:
        return _REMEDIATION_EVIDENCE_EXPECTATION[remediation_key]
    return (
        "Change-management approvals; configuration or policy exports; and independent tests of effectiveness "
        "(e.g., samples, logs, or access reviews) appropriate to the control family and deployment."
    )


_REMEDIATION_OWNER: dict[str, str] = {
    "eval_harness": "AI engineering / ML platform",
    "human_review": "Risk owner / operations",
    "document_limits": "Product / legal",
    "iop_controls": "AI engineering / security",
    "automation_bias": "Change enablement / HR (if workforce)",
    "reliance_training": "Change enablement / L&D",
    "behavioral_eval": "AI engineering / research",
    "data_minimization": "Data governance / privacy",
    "logging_privacy": "Privacy engineering / security",
    "output_controls": "AI engineering / application security",
    "iam_data_plane": "Security / identity",
    "untrusted_content": "Application security / AI engineering",
    "detection_monitoring": "Security operations / AI engineering",
    "tool_sandbox": "AI engineering / platform security",
    "ir_injection": "Security / incident response",
    "ir_tool_misuse": "Security / incident response",
    "vendor_mgmt": "Third-party risk / procurement",
    "version_regression": "AI engineering / SRE",
    "vendor_disclosure": "Legal / risk",
    "vendor_notify": "Legal / crisis communications",
    "vendor_change": "SRE / vendor management",
    "governance_roles": "AI governance / enterprise risk",
    "accountability_docs": "AI governance / compliance",
    "least_priv_tools": "Platform security / AI engineering",
    "action_gates": "AI engineering / product",
    "human_approval": "Operations / risk owner",
    "continuous_eval": "AI engineering / model risk",
    "production_metrics": "SRE / AI ops",
    "forensics_ready": "Security / forensics",
    "fairness_program": "Responsible AI / legal",
    "bias_human_review": "HR / responsible AI",
    "corpus_fairness": "Data governance / responsible AI",
    "bias_disclosure": "Legal / product",
    "output_pipeline": "Application security",
    "secret_leak_detect": "Security engineering",
    "structured_output": "AI engineering",
    "abuse_controls": "Security / product trust",
    "rate_policy": "Platform / FinOps",
    "fraud_iam": "Security / fraud",
    "iam_full": "Security / identity",
    "data_gov_iam": "Data governance / security",
    "access_anomaly": "Security operations",
    "provenance_full": "Data governance / legal",
    "corpus_gov": "Data governance",
    "rag_qa_gold": "AI engineering / quality",
    "ir_playbooks": "Incident response / legal",
}


def _planning_fields(priority_score: int, risk_severity: str, remediation_key: str) -> tuple[str, str, str]:
    sev = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(risk_severity, 2)
    if priority_score >= 72 or (priority_score >= 56 and sev >= 3):
        prio, timeline = "High", "0–30 days"
    elif priority_score >= 46 or sev >= 3:
        prio, timeline = "Medium", "30–60 days"
    else:
        prio, timeline = "Low", "60–90 days"
    owner = _REMEDIATION_OWNER.get(remediation_key, "AI program / security engineering")
    return prio, owner, timeline


def build_remediation(
    risk: Risk,
    control: Control,
    remediation_key: str,
    tags: frozenset[str],
    priority_score: int = 0,
) -> RemediationDetail:
    tag_prefix = f"Context tags: {', '.join(sorted(tags))}. " if tags else ""
    base = _PLAYBOOKS.get(
        remediation_key,
        _d(
            f"No playbook for `{remediation_key}` vs {control.name}.",
            f"Implement {control.name} to enterprise standard with owners and milestones.",
            "Plan; evidence index; risk register update.",
            "Readiness review samples operating effectiveness.",
            risk.residual_risk,
        ),
    )
    pr, owner, timeline = _planning_fields(priority_score, risk.severity, remediation_key)
    evidence_x = _evidence_expectation_for_key(remediation_key)
    return RemediationDetail(
        gap=tag_prefix + base.gap,
        action=base.action,
        artifact=base.artifact,
        verification=base.verification,
        residual_risk=base.residual_risk + " " + risk.residual_risk,
        remediation_evidence_expectation=evidence_x,
        remediation_priority=pr,
        remediation_owner=owner,
        remediation_timeline=timeline,
    )


_EVIDENCE_CLASS: dict[str, str] = {
    "eval_harness": "Produces **evaluation evidence** (AI RMF Measure — analysis and metrics) suitable for release gates.",
    "human_review": "Supports **governance artifact** and **accountability** records under Govern / Manage.",
    "document_limits": "Documentation pack evidences Map / Govern transparency to users and approvers.",
    "iop_controls": "Technical guardrails yield **monitoring evidence** and configuration baselines for Measure.",
    "detection_monitoring": "Runbooks and detections align to **monitoring evidence** and incident-oriented Measure.",
    "continuous_eval": "Trend reports are core **evaluation evidence** for sustained trustworthiness.",
    "production_metrics": "Dashboards and SLO breaches constitute **monitoring evidence** for operations and audit.",
    "ir_playbooks": "Tabletop outputs support **incident response playbook** maturity under Manage.",
    "ir_injection": "AI-shaped **incident response playbook** annex with legal/comms alignment.",
    "ir_tool_misuse": "**Incident response** and rollback evidence for tool-mediated harm.",
    "forensics_ready": "**Monitoring / forensics evidence** chain for traceability and legal hold.",
    "vendor_mgmt": "**Governance artifact** (contracts, DPAs) under third-party Map / Govern.",
    "provenance_full": "**Data lineage evidence** and registry exports for corpus accountability.",
    "rag_qa_gold": "**Evaluation evidence** tied to grounding regression for retrieval paths.",
    "fairness_program": "Disparate-impact testing memo as **evaluation evidence** under MAP impact characterization.",
}


def format_remediation_deliverable(d: RemediationDetail, remediation_key: str = "") -> str:
    hint = _EVIDENCE_CLASS.get(remediation_key, "").strip()
    frame = f"**Framework-oriented evidence:** {hint}\n\n" if hint else ""
    return (
        "### Remediation recommendation\n\n"
        f"{frame}"
        "**Executive summary:** Close the gap with owned milestones, evidence, and a test of effectiveness—"
        "then record accepted residual risk.\n\n"
        "| Workstream element | Detail |\n|---|---|\n"
        f"| **Priority** | {d.remediation_priority} ({d.remediation_timeline}) |\n"
        f"| **Suggested owner** | {d.remediation_owner} |\n"
        f"| **Gap** | {d.gap} |\n"
        f"| **Remediation actions** | {d.action} |\n"
        f"| **Artifacts / evidence** | {d.artifact} |\n"
        f"| **Verification (test of effectiveness)** | {d.verification} |\n"
        f"| **Evidence expectation (audit/review)** | {d.remediation_evidence_expectation or '—'} |\n"
        f"| **Residual risk** | {d.residual_risk} |\n"
    )
