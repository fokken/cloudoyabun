"""Local subprocess runner with durable, bounded, redacted output events."""

import codecs
import os
import re
import selectors
import signal
import subprocess
import time
from pathlib import Path

from .db import now, uid
from .events import Journal
from .service import Service

MAX_OUTPUT_BYTES = 5 * 1024 * 1024


class Redactor:
    def __init__(self, secrets=()):
        self.secrets = sorted(set(s for s in secrets if s), key=len, reverse=True)
        self.width = max(map(len, self.secrets), default=1)
        self.pending = ""

    def text(self, value):
        for secret in self.secrets:
            value = value.replace(secret, "[REDACTED]")
        return value

    def feed(self, text, final=False):
        self.pending += text
        output, index = [], 0
        stop = len(self.pending) if final else max(0, len(self.pending) - self.width + 1)
        while index < stop:
            match = next((s for s in self.secrets if self.pending.startswith(s, index)), None)
            if match:
                output.append("[REDACTED]")
                index += len(match)
            else:
                output.append(self.pending[index])
                index += 1
        self.pending = self.pending[index:]
        return "".join(output)


def sensitive_values(command, env, redact_env):
    secrets = []
    pattern = re.compile(r"secret|token|password|passwd|keypass|jwt|api[_-]?key|access[_-]?key", re.I)
    for name, value in env.items():
        if pattern.search(name) or name in redact_env:
            secrets.append(value)
    for index, arg in enumerate(command):
        if arg.startswith("-") and pattern.search(arg.split("=", 1)[0]):
            if "=" in arg:
                secrets.append(arg.split("=", 1)[1])
            elif index + 1 < len(command):
                secrets.append(command[index + 1])
    return secrets


def execute(db, assessment_id, tool, command, *, timeout=300, retries=0, redact_env=(), callback=None, cwd=None,
            success_codes=(0,), run_metadata=None, postprocess=None):
    """Run an explicitly supplied argument array. Never invokes a shell.

    This generic runner does not infer tool-specific success exit codes or
    import output automatically. It is the substrate for execution adapters.
    """
    if os.name != "posix":
        raise ValueError("The initial execution runner requires a POSIX host")
    service = Service(db)
    service.assessment(assessment_id)
    if not command or timeout <= 0 or retries not in range(4):
        raise ValueError("Supply a command, positive timeout, and 0–3 retries")
    env = os.environ.copy()
    secrets = sensitive_values(command, env, redact_env)
    redactor = Redactor(secrets)
    run_id = uid()
    import json
    with db.connect() as con:
        con.execute("INSERT INTO runs (id,assessment_id,tool,kind,status,started_at,command,worker_pid) VALUES (?,?,?,'execution','running',?,?,?)",
                    (run_id, assessment_id, tool, now(), json.dumps([redactor.text(a) for a in command]), os.getpid()))
    journal = Journal(db, run_id, callback)
    journal.emit("run_started", {"command": [redactor.text(a) for a in command], "cwd": redactor.text(str(Path(cwd or '.').resolve())),
                                 "timeout_seconds": timeout, "max_retries": retries,
                                 "output_limit_bytes": MAX_OUTPUT_BYTES, "tool_version": "unverified",
                                 "adapter": "generic-posix-v1", **(run_metadata or {})})
    journal.emit("credentials_configured", {"redaction_values": len(redactor.secrets)}, step="validation")
    output_bytes, truncated = 0, False
    status, exit_code = "failed", None
    process = None
    streams = {}
    try:
        for attempt in range(1, retries + 2):
            exit_code = None
            streams = {}
            try:
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           stdin=subprocess.DEVNULL, cwd=cwd, env=env, start_new_session=True)
            except OSError as exc:
                journal.emit("launch_failed", {"error": redactor.text(str(exc))}, attempt=attempt, level="error")
                status = "failed"
            else:
                journal.emit("process_started", {"pid": process.pid}, attempt=attempt)
                streams = {}
                started, exit_seen = time.monotonic(), None
                status = "succeeded"
                with selectors.DefaultSelector() as selector:
                    for pipe, source in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                        os.set_blocking(pipe.fileno(), False)
                        streams[pipe] = (source, codecs.getincrementaldecoder("utf-8")("replace"), Redactor(secrets))
                        selector.register(pipe, selectors.EVENT_READ)

                    def persist(source, text):
                        nonlocal output_bytes, truncated
                        if not text:
                            return
                        size = len(text.encode("utf-8"))
                        if output_bytes + size > MAX_OUTPUT_BYTES:
                            if not truncated:
                                journal.emit("output_truncated", {"limit_bytes": MAX_OUTPUT_BYTES}, level="warning", attempt=attempt)
                                truncated = True
                            return
                        output_bytes += size
                        journal.emit("output", {"text": text}, source=source, level="output", attempt=attempt)

                    while selector.get_map() or process.poll() is None:
                        if time.monotonic() - started > timeout and status != "timed-out":
                            status = "timed-out"
                            journal.emit("timeout", {"seconds": timeout}, level="error", attempt=attempt)
                            terminate(process, journal, attempt)
                        for key, _ in selector.select(timeout=0.1):
                            pipe = key.fileobj
                            source, decoder, stream_redactor = streams[pipe]
                            try:
                                chunk = os.read(pipe.fileno(), 4096)
                            except BlockingIOError:
                                continue
                            if chunk:
                                persist(source, stream_redactor.feed(decoder.decode(chunk)))
                            else:
                                persist(source, stream_redactor.feed(decoder.decode(b"", final=True), final=True))
                                selector.unregister(pipe)
                                pipe.close()
                        if process.poll() is not None:
                            exit_seen = exit_seen or time.monotonic()
                            if selector.get_map() and time.monotonic() - exit_seen > 1:
                                journal.emit("descendant_streams_closed", {"reason": "parent exited; descendants kept output open"}, level="warning", attempt=attempt)
                                terminate(process, journal, attempt)
                                for key in list(selector.get_map().values()):
                                    source, decoder, stream_redactor = streams[key.fileobj]
                                    persist(source, stream_redactor.feed(decoder.decode(b"", final=True), final=True))
                                    selector.unregister(key.fileobj)
                                    key.fileobj.close()
                    exit_code = process.wait()
                    if status != "timed-out":
                        status = "succeeded" if exit_code in success_codes else "failed"
                    journal.emit("process_exited", {"exit_code": exit_code, "status": status}, attempt=attempt)
            if status == "succeeded" or attempt > retries:
                break
            journal.emit("retry_scheduled", {"next_attempt": attempt + 1, "delay_seconds": 1, "reason": status}, attempt=attempt)
            time.sleep(1)
    except KeyboardInterrupt:
        status = "cancelled"
        journal.emit("cancellation_requested", {}, level="warning")
        if process:
            terminate(process, journal)
            exit_code = process.wait()
            # Flush already-produced output, including the redactor's retained
            # suffix, before closing pipes after cancellation.
            for pipe, (source, decoder, stream_redactor) in streams.items():
                if pipe.closed:
                    continue
                while True:
                    try:
                        chunk = os.read(pipe.fileno(), 4096)
                    except BlockingIOError:
                        break
                    if not chunk:
                        break
                    persist(source, stream_redactor.feed(decoder.decode(chunk)))
                persist(source, stream_redactor.feed(decoder.decode(b"", final=True), final=True))
    except Exception:
        status = "interrupted"
        raise
    finally:
        if process:
            if process.poll() is None:
                terminate(process, journal)
                exit_code = process.wait()
            for pipe in (process.stdout, process.stderr):
                if pipe and not pipe.closed:
                    pipe.close()
        if postprocess:
            try:
                collected_status = postprocess(run_id, journal, status)
                if status == "succeeded" and collected_status != "succeeded":
                    status = collected_status
            except Exception as exc:
                journal.emit("collection_failed", {"error": redactor.text(str(exc))}, step="collection", level="error")
                if status == "succeeded":
                    status = "failed"
        service.finish_run(run_id, status, exit_code)
        journal.emit("run_completed", {"status": status, "exit_code": exit_code, "output_bytes": output_bytes})
    return service.run(run_id)


def terminate(process, journal, attempt=1):
    journal.emit("termination_requested", {"pid": process.pid, "signal": "SIGTERM"}, attempt=attempt, level="warning")
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        pass
    # The parent may exit while a descendant remains; kill the entire group.
    try:
        os.killpg(process.pid, signal.SIGKILL)
        journal.emit("termination_escalated", {"pid": process.pid, "signal": "SIGKILL"}, attempt=attempt, level="warning")
    except ProcessLookupError:
        pass
