"""Trishula Agent Telemetry — Test Suite (45 tests across 6 categories)"""
import os, sys, json, tempfile, time
from pathlib import Path
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent_telemetry import AgentTracer, Session

PASSED = 0; FAILED = 0
def test(name, cond):
    global PASSED, FAILED
    if cond: PASSED += 1; print(f"  [PASS] {name}")
    else: FAILED += 1; print(f"  [FAIL] {name}")
def section(t): print(f"\n{'='*60}\n  {t}\n{'='*60}")

# ═══ CATEGORY 1: TRACER INITIALIZATION ═══
section("CATEGORY 1: TRACER INITIALIZATION")
tracer = AgentTracer()
test("Tracer initializes", tracer is not None)
test("Zero active sessions", tracer.active_sessions == 0)
test("Zero completed sessions", tracer.completed_sessions == 0)

# ═══ CATEGORY 2: SESSION MANAGEMENT ═══
section("CATEGORY 2: SESSION MANAGEMENT")
s = tracer.start_session("test_001", "architect")
test("Session created", s is not None)
test("Session ID correct", s.session_id == "test_001")
test("Agent name set", s.agent_name == "architect")
test("Active sessions = 1", tracer.active_sessions == 1)
test("Zero events initially", s.event_count == 0)

s2 = tracer.start_session("test_002", "scout")
test("Multiple sessions", tracer.active_sessions == 2)
test("Get session works", tracer.get_session("test_001") is s)

# ═══ CATEGORY 3: EVENT RECORDING ═══
section("CATEGORY 3: EVENT RECORDING")
e1 = s.record_decision("check_config", {"file": "config.yml"}, "VALID", 1.5)
test("Decision recorded", e1 is not None)
test("Event sequence = 1", e1.sequence == 1)
test("Event type = decision", e1.event_type == "decision")
test("Event has timestamp", len(e1.timestamp) > 0)
test("Event has context hash", len(e1.context_hash) == 16)
test("Event has chain hash", len(e1.event_hash) == 64)
test("Decision count = 1", s._decision_count == 1)

e2 = s.record_tool_call("git_push", {"repo": "main"}, {"status": "ok"}, 50.0)
test("Tool call recorded", e2.event_type == "tool_call")
test("Tool call count = 1", s._tool_call_count == 1)
test("Event links to previous", e2.previous_hash == e1.event_hash)

e3 = s.record_observation("env_scan", {"os": "linux", "cpu": 88})
test("Observation recorded", e3.event_type == "observation")

e4 = s.record_error("deploy", "Connection refused", {"target": "prod"})
test("Error recorded", e4.event_type == "error")
test("Error count = 1", s._error_count == 1)
test("Total events = 4", s.event_count == 4)

# ═══ CATEGORY 4: MERKLE CHAIN INTEGRITY ═══
section("CATEGORY 4: MERKLE CHAIN INTEGRITY")
test("Chain is valid", s.verify_chain())

# Different events produce different hashes
test("Events have unique hashes", len({e1.event_hash, e2.event_hash, e3.event_hash, e4.event_hash}) == 4)

# Empty session chain is valid
empty = Session("empty")
test("Empty chain valid", empty.verify_chain())

# ═══ CATEGORY 5: ANOMALY DETECTION ═══
section("CATEGORY 5: ANOMALY DETECTION")
anomaly_session = Session("anomaly_test")

# Trigger error storm (3+ consecutive errors)
anomaly_session.record_error("act1", "fail1")
anomaly_session.record_error("act2", "fail2")
anomaly_session.record_error("act3", "fail3")
test("Error storm detected", anomaly_session.anomaly_count > 0)
test("Anomaly type = ERROR_STORM", any(
    a.anomaly_type == "ERROR_STORM" for a in anomaly_session._anomalies
))

# Trigger repetition loop (10 identical events)
loop_session = Session("loop_test")
for i in range(11):
    loop_session.record_decision("same_action", {"step": "loop"}, "OK")
test("Repetition loop detected", any(
    a.anomaly_type == "REPETITION_LOOP" for a in loop_session._anomalies
))

# Normal session has no anomalies
normal = Session("normal_test")
normal.record_decision("step1", {}, "OK")
normal.record_tool_call("tool1", {}, {"ok": True})
normal.record_decision("step2", {}, "OK")
test("Normal session no anomalies", normal.anomaly_count == 0)

# ═══ CATEGORY 6: SESSION FINALIZATION & REPORTING ═══
section("CATEGORY 6: SESSION FINALIZATION")
report = s.finalize()
test("Report has session ID", report.session_id == "test_001")
test("Report has agent name", report.agent_name == "architect")
test("Report total events = 4", report.total_events == 4)
test("Report decisions = 1", report.decisions == 1)
test("Report tool calls = 1", report.tool_calls == 1)
test("Report errors = 1", report.errors == 1)
test("Report chain valid", report.chain_valid)
test("Report has attestation", len(report.attestation_hash) == 64)
test("Report has duration", report.duration_ms > 0)

# Persistence
with tempfile.TemporaryDirectory() as tmpdir:
    pt = AgentTracer(storage_dir=tmpdir)
    ps = pt.start_session("persist_test", "test_agent")
    ps.record_decision("test", {}, "OK")
    pr = pt.end_session("persist_test")
    files = list(Path(tmpdir).glob("*.json"))
    test("Session persisted to disk", len(files) == 1)
    with open(files[0]) as f:
        data = json.load(f)
    test("Persisted data has session ID", data["session_id"] == "persist_test")
    test("Completed sessions count", pt.completed_sessions == 1)
    test("Active sessions after end = 0", pt.active_sessions == 0)

# ═══ VERDICT ═══
print(f"\n{'='*60}")
total = PASSED + FAILED
print(f"  RESULTS: {PASSED}/{total} PASSED, {FAILED}/{total} FAILED")
print(f"  VERDICT: {'SQA_v5_ASCENDED: EXCEEDED' if FAILED == 0 else 'SQA FAIL'}")
print(f"{'='*60}")
if FAILED > 0: sys.exit(1)
