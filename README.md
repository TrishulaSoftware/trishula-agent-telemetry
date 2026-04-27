# Trishula Agent Telemetry

**Deterministic observability for AI agent systems. Merkle-chained audit trails. Anomaly detection. Zero dependencies.**

[![CI](https://github.com/TrishulaSoftware/trishula-agent-telemetry/actions/workflows/ci.yml/badge.svg)](https://github.com/TrishulaSoftware/trishula-agent-telemetry/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests: 44/44](https://img.shields.io/badge/tests-44%2F44-brightgreen.svg)]()
[![SQA v5 ASCENDED](https://img.shields.io/badge/SQA-v5_ASCENDED-gold.svg)]()
[![Zero Dependencies](https://img.shields.io/badge/deps-zero-blue.svg)]()

---

## The Problem

**When your AI agent breaks production, you can't explain why.**

| Stat | Source | Date |
|:--|:--|:--|
| **43%** of AI-generated code needs manual debugging in production | Lightrun | Apr 2026 |
| **54%** of incident resolution relies on "tribal knowledge" | Lightrun | Apr 2026 |
| **5%** of AI model requests failing in production | Datadog | Apr 2026 |
| **65%** of organizations had AI agent security incidents | Cloud Security Alliance | Apr 2026 |
| Meta AI agent exposed restricted data via hallucination | Foresiet | Apr 2026 |

Existing observability tools (LangSmith, Arize Phoenix, Langfuse) are cloud-hosted platforms optimized for LLM monitoring. They track latency, cost, and token usage. **But they don't provide:**

1. **Tamper-evident audit trails** — If an agent's logs can be modified, they're useless for forensics
2. **Anomaly detection** — Error storms and infinite loops go undetected until production crashes
3. **Decision provenance** — You can't reconstruct exactly what inputs and reasoning led to a specific action

### Competitive Analysis

| Feature | Trishula Telemetry | LangSmith | Arize Phoenix | Langfuse |
|:--|:--|:--|:--|:--|
| Merkle chain audit | ✅ SHA-256 | ❌ | ❌ | ❌ |
| Anomaly detection | ✅ Built-in | ❌ | ⚠️ Drift only | ❌ |
| Decision provenance | ✅ Full trace | ⚠️ | ⚠️ | ⚠️ |
| Air-gapped operation | ✅ | ❌ Cloud | ⚠️ Self-host | ⚠️ Self-host |
| Zero dependencies | ✅ | ❌ | ❌ | ❌ |
| Chain verification | ✅ `verify_chain()` | ❌ | ❌ | ❌ |

**Nobody else provides cryptographic chain-of-custody for agent actions.**

---

## What It Does

### Session-Based Agent Tracing

```python
from agent_telemetry import AgentTracer

tracer = AgentTracer(storage_dir="./traces")
session = tracer.start_session("deploy_v2", agent_name="architect")

# Record every agent decision
session.record_decision("validate_config", {"file": "config.yml"}, "VALID", 2.1)
session.record_tool_call("git_push", {"repo": "main"}, {"status": "success"}, 150.0)
session.record_observation("env_scan", {"os": "linux", "cpu_count": 88})
session.record_error("deploy", "Connection refused", {"target": "prod-3"})

# Finalize and verify
report = tracer.end_session("deploy_v2")
print(report.chain_valid)       # True — no tampering
print(report.attestation_hash)  # SHA-256 of full trace
print(report.anomalies)         # [] — no anomalies detected
```

### Automatic Anomaly Detection

The library detects two critical anomaly types:

| Anomaly | Trigger | Severity |
|:--|:--|:--|
| **ERROR_STORM** | 3+ consecutive errors | HIGH |
| **REPETITION_LOOP** | 10 identical events in a row | CRITICAL |

### Merkle Chain Integrity

Every event is linked to the previous via SHA-256 hash chain:

```
GENESIS → Event 1 → Event 2 → ... → Event N
  ↑          ↑          ↑              ↑
SHA-256   prev_hash  prev_hash     prev_hash
```

`session.verify_chain()` validates the entire chain in O(n). Any tampering — insertions, deletions, modifications — is instantly detected.

---

## Proof It Works: 44 Tests

```
CATEGORY 1: TRACER INITIALIZATION ............ 3/3 PASS
CATEGORY 2: SESSION MANAGEMENT ............... 5/5 PASS
CATEGORY 3: EVENT RECORDING .................. 12/12 PASS
CATEGORY 4: MERKLE CHAIN INTEGRITY ........... 3/3 PASS
CATEGORY 5: ANOMALY DETECTION ................ 4/4 PASS
CATEGORY 6: SESSION FINALIZATION ............. 17/17 PASS

TOTAL: 44/44 PASSED | VERDICT: SQA_v5_ASCENDED EXCEEDED
```

```bash
python test_telemetry.py
```

---

## SQA v5 ASCENDED Compliance

| SQA Pillar | Implementation | Evidence |
|:--|:--|:--|
| **Pillar 1: MC/DC** | Each event type (decision, tool_call, observation, error) independently tested. Each anomaly trigger independently verified. | 12 event + 4 anomaly tests |
| **Pillar 2: Bit-Perfect** | SHA-256 Merkle chain with `verify_chain()`. Attestation hash of full session. Persisted to JSON with exact byte representation. | 3 chain + persistence tests |
| **Pillar 3: Adversarial** | Error storms detected automatically. Infinite loops (10 identical events) flagged as CRITICAL. Normal sessions verified anomaly-free. | 4 anomaly tests |
| **Pillar 4: Zero-Leak** | No agent secrets in trace output. Context hashed (truncated to 16 chars). No external telemetry. | Architecture review |

---

## Installation

```bash
git clone https://github.com/TrishulaSoftware/trishula-agent-telemetry.git
cd trishula-agent-telemetry
python test_telemetry.py  # Verify 44/44
```

## License

MIT
