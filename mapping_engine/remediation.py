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


def _d(gap: str, action: str, artifact: str, verification: str, residual: str) -> RemediationDetail:
    return RemediationDetail(gap=gap, action=action, artifact=artifact, verification=verification, residual_risk=residual)


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


def build_remediation(
    risk: Risk,
    control: Control,
    remediation_key: str,
    tags: frozenset[str],
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
    return RemediationDetail(
        gap=tag_prefix + base.gap,
        action=base.action,
        artifact=base.artifact,
        verification=base.verification,
        residual_risk=base.residual_risk + " " + risk.residual_risk,
    )


def format_remediation_deliverable(d: RemediationDetail) -> str:
    return (
        "### Remediation recommendation\n\n"
        "**Executive summary:** Close the gap with owned milestones, evidence, and a test of effectiveness—"
        "then record accepted residual risk.\n\n"
        "| Workstream element | Detail |\n|---|---|\n"
        f"| **Gap** | {d.gap} |\n"
        f"| **Remediation actions** | {d.action} |\n"
        f"| **Artifacts / evidence** | {d.artifact} |\n"
        f"| **Verification (test of effectiveness)** | {d.verification} |\n"
        f"| **Residual risk** | {d.residual_risk} |\n"
    )
