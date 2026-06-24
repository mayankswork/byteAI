# byteAI


### Agent Identity & Authorization System

**I can assign cryptographic identities to each agent, so that all agent actions are authenticated and traceable.** - This means you are moving away from relying on easily stolen passwords or API keys and instead giving each agent a unique, verifiable digital signature (often using public-key infrastructure like Ed25519 keys). This allows the system to prove "who" an agent is and "what" it is allowed to do, establishing a "Zero Trust" environment where every action is authenticated and traceable.


### blast radius containment for compromised agents

<img width="640" height="640" alt="image" src="https://github.com/user-attachments/assets/55609a40-749a-4245-92e2-f81d014a50aa" />

**State isolation between agents**. 
Agents sharing memory or a shared scratchpad is a lateral movement vector. Each agent should have its own isolated working context. Cross-agent communication should go through the orchestrator, not shared state.

**Revocation on anomaly**. 
The audit log should do more than record — it should feed an anomaly detector watching for things like: unusual tool call patterns, prompt content that looks like injection, attempts to access out-of-scope resources, or output volume spikes. On detection, the orchestrator revokes the agent's tokens and moves it to read-only isolation before deciding whether to terminate it.

**Human escalation for irreversible actions**. 
Any action that can't be undone (deleting data, sending emails, making payments, pushing to production) should require explicit human approval or at minimum a confirmation checkpoint — even if the agent claims the orchestrator authorized it. Compromised orchestrators are a real threat model too.

### What happens when an agent is flagged as compromised mid-run?

When an agent is flagged mid-run, you're dealing with a live incident — the agent may still be executing, holding locks, or mid-way through a multi-step action.

Here's how a well-designed system handles it: The response protocol has two distinct phases: the immediate reaction in the first few seconds, and the post-incident investigation. Here's how each phase works, and the key decisions involved.

<img width="640" height="822" alt="image" src="https://github.com/user-attachments/assets/97200c21-1917-400e-acfc-add7543c28cf" />

The key decisions in detail

**Revocation must be synchronous, not eventual.**
The very first action — before any assessment — is cutting the agent's credentials. An async revocation that takes seconds is too slow if the agent is still making tool calls. This means your permission gate needs a live token validation path (check against a revocation list, not just a signed JWT) so the gate can enforce the revocation immediately.

**In-flight action triage is the hardest part.**
The agent may have been mid-way through a multi-step write when it was flagged. You need to know: did it already commit? Is there a compensating transaction available? Was data sent externally? The answers determine whether you're in a "contain and monitor" posture or a "notify affected parties" posture. This is why idempotent, reversible tool design matters so much — it turns a potential disaster into a recoverable incident.

**Isolate vs. terminate is a confidence question.**
If the anomaly detection fired with low confidence (unusual pattern, not a definitive attack signal), isolation is better — you preserve the agent's state for forensics and can restart it if the flag was a false positive. If the confidence is high, or if the agent has already exfiltrated something or executed an irreversible action, terminate immediately and focus entirely on damage assessment.

**The forensic snapshot is your post-mortem material.**
Before you wipe anything, capture: the full prompt/context window the agent was operating with, the sequence of tool calls and their outputs, any external responses it received, and the specific input that triggered the anomaly. Prompt injection attacks in particular leave a clear artifact — the injected instruction will be visible in the captured context.

**Policy update closes the loop.** 
The incident only ends when you've answered: how did this happen, and what changes to permission scope, anomaly detection thresholds, or input sanitization would have caught it earlier or reduced the blast radius?


### What anomaly signals should trigger a compromised-agent flag?

Good anomaly detection is about catching behavioral drift — the difference between what an agent is supposed to do and what it's actually doing. 
Here are the signal categories, roughly ordered from easiest to implement to most sophisticated.

<img width="640" height="872" alt="image" src="https://github.com/user-attachments/assets/e7b62565-13d5-470b-8f93-f90151bc707e" />

### Ways to detect anomaly :

1. implement rate limiting and scope checking on agent tool calls
2. detect prompt injection in agent inputs at runtime
* Layer 1 — Structural: separate instructions from content - so that prompt is separate than the code
* Layer 2 — Lexical: pattern matching on known attack phrases
* Layer 3 — Model-based: a separate inspector LLM : a cheap llm which just detects this before the actual llm call.
* Layer 4 — Behavioral: intent comparison : even if injection slips through input scanning, you can catch it by comparing what the agent was asked to do with what it's about to do. Check the agent's pending tool calls against its original task description before execution.
Example : an agent tasked to "summarise this document" that's now trying to call a mail-sending tool.



### Investigate automatic credential revocation mechanisms

The key idea is simple: detect compromise → immediately cut off access → contain damage → recover safely
The challenge is doing this fast, reliably, and without breaking legitimate workflows.

Mechanism 1 — Short-lived tokens + Redis revocation list :
This is the foundation. Agents should never hold long-lived credentials — they receive a scoped JWT at spawn time with a short TTL (5–15 minutes). The permission gate validates every tool call against this token and against a Redis revocation set.

Mechanism 2 — Per-agent database roles :
Instead of sharing a service account across agents, give each agent its own ephemeral PostgreSQL role at spawn time. Revoking access is then a single DROP ROLE — it kills all active sessions and prevents new connections instantly.

Mechanism 3 — HashiCorp Vault dynamic credentials : 
The key advantage here is that Vault can propagate revocation to the provider (AWS, GCP, etc.) immediately — the credential stops working at the source, not just inside your system.

Sample code:

```
import asyncio

class RevocationController:
    def __init__(self, token_store, db_manager, vault_manager, audit_log):
        self.tokens = token_store
        self.db = db_manager
        self.vault = vault_manager
        self.audit = audit_log

    async def revoke_agent(self, agent_id: str, reason: str, severity: str) -> dict:
        start = time.monotonic()

        # Fire all revocation paths concurrently — don't serialize
        results = await asyncio.gather(
            self._revoke_tokens(agent_id),
            self._revoke_db(agent_id),
            self._revoke_vault(agent_id),
            return_exceptions=True   # don't let one failure block others
        )

        elapsed_ms = (time.monotonic() - start) * 1000

        outcome = {
            "agent_id": agent_id,
            "reason": reason,
            "severity": severity,
            "elapsed_ms": round(elapsed_ms, 1),
            "token_revocation": "ok" if not isinstance(results[0], Exception) else str(results[0]),
            "db_revocation":    "ok" if not isinstance(results[1], Exception) else str(results[1]),
            "vault_revocation": "ok" if not isinstance(results[2], Exception) else str(results[2]),
        }

        await self.audit.record("REVOCATION", outcome)
        return outcome

    async def _revoke_tokens(self, agent_id):
        self.tokens.revoke_all_for_agent(agent_id)

    async def _revoke_db(self, agent_id):
        await self.db.revoke(agent_id)

    async def _revoke_vault(self, agent_id):
        await self.vault.revoke(agent_id)
```

### What is lateral movement.
Lateral movement is the set of techniques an attacker uses to move from one compromised system to another within a network, after gaining an initial foothold.

Instead of attacking directly from the outside, the attacker "lands" on a low-value system (e.g., a compromised user workstation or an AI agent), then pivots across the network to find higher-value targets (e.g., databases, domain controllers, or sensitive AI model repositories).

### Analyze lateral movement prevention strategies.

Lateral movement is what turns a single compromised agent into a system-wide breach. The attacker's goal is to use the foothold in Agent B to reach Agent A's data, the orchestrator's credentials, or resources the compromised agent was never supposed to touch. 
**Prevention is about making each agent a dead end.**

<img width="640" height="600" alt="image" src="https://github.com/user-attachments/assets/4fb7bfb3-dadf-40c4-8e7e-6548f7b1e57f" />

1. Enforce orchestrator-mediated communication : The single most effective structural control: agents must never communicate directly with each other. All inter-agent messaging goes through the orchestrator, which validates, logs, and rate-limits every exchange. A compromised agent that can only talk to the orchestrator has no path to contaminate its peers — it's already in a dead end.

2. Private, non-shared memory : Agents should not share a db, Shared scratchpads and shared vector stores are lateral movement highways. If Agent A and Agent B can both write to the same memory space, a compromised Agent B can poison Agent A's context simply by writing malicious content that Agent A will later read and act on.

3. Network namespace isolation 👍 
At the infrastructure level, each agent runs in its own network namespace with an explicit egress allowlist. An agent that can only reach its permitted tool endpoints cannot make unexpected outbound connections — even if it's been injected with instructions to call attacker.com. The network layer enforces what the permission gate enforces at the application layer: defense in depth.

4. Ephemeral, agent-scoped filesystems
Agents should not have access to a persistent shared filesystem. Each agent gets an ephemeral scratch volume that is destroyed when the agent terminates. This prevents a compromised agent from leaving behind poisoned files that a future agent run will pick up, and prevents cross-agent file-based communication that bypasses your logging.
Secrets in particular should never be written to disk at all — they should be injected at runtime via environment variables from the secret manager and exist only in memory.

5. Blast radius pre-planning
The goal is that the answer to "worst case reach" for any single agent is: only its own explicitly granted resources, nothing else.

### Study damage assessment and forensics capabilities.

Damage assessment is the structured process of answering: **what did the compromised agent actually do, to what, and what is the downstream impact?**

It happens in parallel with containment — you don't wait for revocation to complete before starting the assessment.

<img width="640" height="680" alt="image" src="https://github.com/user-attachments/assets/cdf63b55-3b38-4b0d-af8a-e444159c687e" />

### Phase 1 — Evidence collection
Start collecting immediately, before any cleanup. The instinct to remediate first is wrong — remediation destroys evidence. Preserve first, fix second.

If you don't have the context snapshot — if you didn't take one at detection time — this is the most critical gap in your forensic posture. It's the evidence you most need and the evidence that disappears fastest. Capturing it should be the first automated action on detection, before even token revocation.

The four sources you need are the :
1. audit log (every tool call the agent made, with timestamps and parameters)
2. the context snapshot captured at flag time (this is where the injection payload lives — you need it to understand what the agent was instructed to do)
3. network flow logs (what IP addresses did the agent's namespace connect to, and how much data was transferred)
4. resource access logs from your database, object store, and secrets manager (what was read, what was written, what was queried).

### Phase 2 — Action reconstruction

With evidence in hand, build a chronological timeline. The key questions are:

**When did compromise begin?** The injection might have arrived well before anomaly detection fired. Look for the first tool call that doesn't fit the original task description — that's your approximate compromise time. Everything between that timestamp and revocation is suspect.

**Which actions were legitimate vs attacker-directed?** Compare the task the agent was spawned with against its actual action sequence. Actions that align with the original task are likely legitimate. Actions that diverge — especially novel destinations, out-of-scope tools, or unusual parameter shapes — are attacker-directed. The attacker typically lets the agent complete enough legitimate work to avoid early detection, so you'll often see a clean early phase followed by a divergence point.

**Was data accessed or actually exfiltrated?** This is the most consequential distinction. Accessed means the agent read something it shouldn't have. Exfiltrated means it successfully transmitted that data externally. The difference determines your notification obligations. Check your network logs for outbound connections to novel destinations, and cross-reference the volume of data transferred against what you know was read. A 200-byte outbound connection after reading a 50KB database table is suspicious but not conclusive. A 50KB outbound connection to an unknown endpoint shortly after a database read is exfiltration until proven otherwise.

### Phase 3 — Impact classification

Three tiers, each with different response playbooks:

**Contained** means the agent was flagged and stopped before any data left the system and before any malicious writes were committed. The blast radius is entirely internal. You still need to audit what was read and why, but there's no external notification obligation and no downstream data integrity question. Root cause analysis and policy update are the priorities.

**Data accessed** means sensitive data was read by the compromised agent, but you have no confirmed evidence it was transmitted externally. This is an ambiguous, uncomfortable state — you can't prove exfiltration didn't happen, especially if your network logging has gaps. Treat it conservatively: assume potential exposure and make notification decisions based on the sensitivity of the data accessed, not on the absence of confirmed exfiltration evidence.

**Data exfiltrated** means confirmed outbound transfer of sensitive data. This triggers your breach response playbook in full: legal review, regulatory notification timelines, affected user communication, and potentially public disclosure depending on jurisdiction and data type.

### Phase 4 — Notification and remediation

Notification decisions depend entirely on Phase 3 classification and the nature of the data involved.

For any data involving personal information, your regulatory obligations under GDPR, HIPAA, or equivalent frameworks set hard timelines regardless of how the breach happened — an AI agent being the vector doesn't change your obligations. GDPR's 72-hour supervisory authority notification clock starts from when you became aware of a breach, not when it was contained.

For data remediation, the main questions are: were any writes committed that need to be rolled back? If the agent wrote to a database under attacker direction, those rows need to be identified and quarantined before being trusted by downstream systems. A compromised agent that wrote records, sent emails, or pushed to external systems may have caused downstream effects that persist long after the agent itself is terminated. Trace every write the agent made and verify its legitimacy individually.

The final output of a complete damage assessment is a written incident record that answers: what happened, when, what data was affected, what the confirmed impact was, what notifications were made, and what architectural changes prevent recurrence. That last part — recurrence prevention — is what closes the loop back to your permission gate, anomaly detection, and blast radius containment architecture.


### Research recovery and remediation workflows.

Recovery and remediation is about returning the system to a verified-clean state — not just stopping the attack, but undoing its effects and hardening against recurrence.

It has three distinct tracks that run in parallel: data remediation, system restoration, and architectural hardening.

<img width="640" height="760" alt="image" src="https://github.com/user-attachments/assets/998ca40a-ae72-4021-8026-0733cbdbcf0c" />

**Track 1 — Data remediation**

**Identifying tainted writes** is the first and hardest step. If your audit log records agent ID and timestamp on every database write, you can query all writes made by the compromised agent between the estimated compromise time and revocation. If you don't have that level of write attribution, you're doing archaeology — comparing pre-incident snapshots against current state to find unexpected differences.
The output of this step is a quarantine list: specific rows, files, messages, or records that were created or modified under attacker direction. Quarantine means moving them to an isolated table or storage location — never deleting yet, because they're evidence and you may need them to understand the full attack scope.

**Restoring clean state** then has two options depending on what you found. If the tainted writes are small and well-bounded, surgical remediation works — remove the quarantined records and replay any legitimate writes from the audit log that were co-mingled with attacker-directed ones. If the blast was wider and you can't cleanly separate legitimate from tainted, point-in-time restore from a pre-incident snapshot is safer, accepting the loss of some legitimate work as the price of a known-clean state.

**Notifying downstream** is often overlooked. Any system that consumed, cached, or acted on data written by the compromised agent needs to know that data may be tainted. This includes read caches, derived datasets, queues that consumed the agent's outputs, and any external systems the agent sent data to via API calls. Each of those represents a potential propagation path for the attacker's effects.

**Track 2 — System restoration**

**Never restore the compromised agent from its own image**. Rebuild from a verified base image — the same source your CI/CD pipeline would use for a fresh deployment. The assumption is that the agent's runtime environment may be untrustworthy after compromise.
Fresh credentials are mandatory. Every secret the agent held — database passwords, API keys, tokens — must be treated as potentially leaked and replaced, even if your analysis suggests they weren't actually exfiltrated. The cost of rotating credentials is far lower than the cost of discovering post-incident that the attacker retained a working secret.

**Canary rollout** is the right re-entry pattern. Restore the agent to a staging environment first, run it against representative workloads, and verify its behaviour matches baseline. Then reintroduce it to production with a small traffic slice — say, 5% — with anomaly detection sensitivity temporarily elevated. Widen traffic gradually as confidence builds. This gives you a recovery abort path if something unexpected emerges in production before full rollout.

**Track 3 — Architectural hardening**

Every incident is a free penetration test. The attacker showed you exactly which gap they used — the job now is to close it and close adjacent gaps they could have used.

**Tighten grants** by auditing what permissions the compromised agent actually needed vs what it held. Over-permissioning is almost always discovered in post-incident review. This is the moment where it's easiest to get organisational alignment on removing permissions — the risk is vivid and recent.

**Update detectors** using the actual attack artifacts. The specific injection patterns used, the anomalous tool call sequences, the encoded payloads — all of these become new detection signatures. Your anomaly detector should emerge from every incident with higher precision than it had going in.

**Hardening the input pipeline** means specifically addressing the vector the attacker used. If the compromise was via a document the agent read, that document type now gets an additional inspection step. If it was via an API response, that API's outputs get sanitised before entering the agent context. Close the specific door, then audit adjacent doors.

**Red team retesting** is the verification step for this track. Before you declare the hardening complete, have someone specifically attempt to reproduce the attack that succeeded, plus variations of it. If it fails, the fix holds. If a variation still works, you have more to do. This is the only way to avoid the false confidence of having written a fix without confirming it actually works.

**The verification gate**

All three tracks must independently sign off before the system returns to production. The gate exists because the tracks affect each other — a system restored with clean infrastructure but tainted data is still compromised, and clean data in a system with unpatched attack vectors is still vulnerable. You need all three simultaneously.

The sign-off criteria should be explicit: data team confirms clean state verified, engineering confirms fresh image and credentials deployed and smoke-tested, security confirms hardening implemented and retest passed. Written sign-off, timestamped, stored in the incident record.
