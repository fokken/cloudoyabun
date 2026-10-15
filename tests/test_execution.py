import json
import os
import signal
import subprocess
import sys

import pytest

from cloudoyabun import execution
from cloudoyabun.execution import Redactor, execute


@pytest.mark.parametrize("split", range(1, 19))
def test_stream_redaction_handles_any_boundary(split):
    text = "prefix-supersecret-suffix"
    redactor = Redactor(["supersecret"])
    result = redactor.feed(text[:split]) + redactor.feed(text[split:]) + redactor.feed("", final=True)
    assert result == "prefix-[REDACTED]-suffix"


def test_logs_separate_streams_and_exit_outcome(service, assessment):
    run = execute(service.db, assessment["id"], "test", [sys.executable, "-c", "import sys; print('hello'); print('diagnostic',file=sys.stderr)"])
    assert run["status"] == "succeeded" and run["exit_code"] == 0
    events = service.events(run["id"])
    assert [e["seq"] for e in events] == list(range(1, len(events) + 1))
    assert any(e["source"] == "stdout" and "hello" in e["details"]["text"] for e in events)
    assert any(e["source"] == "stderr" and "diagnostic" in e["details"]["text"] for e in events)
    assert events[-1]["type"] == "run_completed"


def test_secrets_not_persisted_or_emitted(service, assessment, monkeypatch):
    monkeypatch.setenv("TEST_SECRET", "private-value-123")
    seen = []
    script = "import os,sys,time; s=os.environ['TEST_SECRET']; sys.stdout.write(s[:5]); sys.stdout.flush(); time.sleep(.05); print(s[5:])"
    run = execute(service.db, assessment["id"], "test", [sys.executable, "-c", script], callback=seen.append)
    assert "private-value-123" not in json.dumps(service.events(run["id"]))
    assert "private-value-123" not in json.dumps(seen)
    assert "[REDACTED]" in json.dumps(seen)


def test_failure_retries_and_partial_output(service, assessment):
    run = execute(service.db, assessment["id"], "test", [sys.executable, "-c", "print('before failure'); raise SystemExit(7)"], retries=1)
    assert run["status"] == "failed" and run["exit_code"] == 7
    events = service.events(run["id"])
    assert len([e for e in events if e["type"] == "process_started"]) == 2
    assert len([e for e in events if e["type"] == "output"]) == 2
    assert any(e["type"] == "retry_scheduled" for e in events)


def test_timeout_terminates_process_and_retains_output(service, assessment):
    run = execute(service.db, assessment["id"], "test", [sys.executable, "-c", "import time; print('started',flush=True); time.sleep(20)"], timeout=.2)
    assert run["status"] == "timed-out"
    events = service.events(run["id"])
    assert any(e["type"] == "timeout" for e in events)
    assert any("started" in e["details"].get("text", "") for e in events)


def test_launch_failure_is_logged(service, assessment):
    run = execute(service.db, assessment["id"], "test", ["/does-not-exist/cloudoyabun"])
    assert run["status"] == "failed" and run["exit_code"] is None
    assert any(e["type"] == "launch_failed" for e in service.events(run["id"]))


def test_high_volume_output_has_explicit_truncation(service, assessment, monkeypatch):
    monkeypatch.setattr(execution, "MAX_OUTPUT_BYTES", 5000)
    run = execute(service.db, assessment["id"], "test", [sys.executable, "-c", "print('x' * 100000)"])
    events = service.events(run["id"])
    assert run["status"] == "succeeded"
    assert sum(len(e["details"].get("text", "").encode()) for e in events) <= 5000
    assert sum(e["type"] == "output_truncated" for e in events) == 1


@pytest.mark.parametrize("cancel_signal", [signal.SIGINT, signal.SIGTERM])
def test_cli_cancellation_records_final_outcome(service, assessment, cancel_signal):
    proc = subprocess.Popen([sys.executable, "-m", "cloudoyabun", "--db", str(service.db.path), "run", "--assessment", assessment["id"], "--tool", "test", "--", sys.executable, "-c", "import time; print('ready',flush=True); time.sleep(30)"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        for line in proc.stderr:
            event = json.loads(line)
            if event["type"] == "output":
                break
        proc.send_signal(cancel_signal)
        stdout, stderr = proc.communicate(timeout=5)
        run = json.loads(stdout)
        assert run["status"] == "cancelled" and proc.returncode == 1
        assert any(e["type"] == "cancellation_requested" for e in service.events(run["id"]))
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
