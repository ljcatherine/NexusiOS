"""Private, restart-resumable state for bounded Nexus orchestration runs."""
from __future__ import annotations

import json
import fcntl
import hashlib
import logging
import os
import queue
import re
import sqlite3
import stat
import threading
import time
import uuid
from pathlib import Path


TERMINAL = ("completed", "failed", "cancelled")
MAX_ACTIVE_RUNS = 8
MAX_RETAINED_RUNS = 100
MAX_RUN_EVENTS = 100
MAX_SUBMISSION_IDS = 100_000
SUBMISSION_ID = re.compile(r"^[0-9a-f]{32}$")
PRINCIPAL_ID = re.compile(r"^[0-9a-f]{64}$")
WORKSPACE_ID = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
logger = logging.getLogger("nexus_orchestrator.runs")


class SubmissionConflict(Exception):
    """A submission ID is already bound to another request."""


class SubmissionExpired(Exception):
    """The run was pruned, but its ID must never start it again."""


class RunStore:
    """SQLite store whose directory and database are owner-only."""

    def __init__(self, directory: str | Path, legacy_owner: str | None = None):
        if legacy_owner is not None and not PRINCIPAL_ID.fullmatch(legacy_owner):
            raise ValueError("invalid legacy owner ID")
        self.directory = Path(directory).expanduser()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._check_private(self.directory, directory=True)
        lock_fd = os.open(self.directory / 'orchestrator.lock',
                          os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        self._instance_lock = os.fdopen(lock_fd, 'r+b')
        try:
            info = os.fstat(self._instance_lock.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                    stat.S_IMODE(info.st_mode) & 0o077):
                raise PermissionError('orchestrator lock must be an owner-only regular file')
            fcntl.flock(self._instance_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self._instance_lock.close()
            raise
        try:
            self._initialize_store(legacy_owner)
        except BaseException:
            if hasattr(self, "db"):
                self.db.close()
            self._instance_lock.close()
            raise

    def _initialize_store(self, legacy_owner: str | None) -> None:
        self.path = self.directory / "agent-runs.sqlite3"
        if not self.path.exists():
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.close(fd)
        self._check_private(self.path, directory=False)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, timeout=5, isolation_level=None,
                                  check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS runs (
            id TEXT PRIMARY KEY, status TEXT NOT NULL, created REAL NOT NULL,
            updated REAL NOT NULL, phase TEXT NOT NULL, request TEXT NOT NULL,
            result TEXT, error TEXT, cancel_requested INTEGER NOT NULL DEFAULT 0,
            children TEXT NOT NULL, events TEXT NOT NULL DEFAULT '[]', owner TEXT
        )""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS submission_ids (
            id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, owner TEXT
        )""")
        self.db.execute("CREATE TABLE IF NOT EXISTS safety_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(runs)")}
        if "events" not in columns:
            self.db.execute("ALTER TABLE runs ADD COLUMN events TEXT NOT NULL DEFAULT '[]'")
        if "owner" not in columns:
            self.db.execute("ALTER TABLE runs ADD COLUMN owner TEXT")
        submission_columns = {row[1] for row in self.db.execute("PRAGMA table_info(submission_ids)")}
        if "owner" not in submission_columns:
            self.db.execute("ALTER TABLE submission_ids ADD COLUMN owner TEXT")
        if legacy_owner:
            with self.lock:
                self.db.execute("BEGIN IMMEDIATE")
                try:
                    self.db.execute("UPDATE runs SET owner=? WHERE owner IS NULL", (legacy_owner,))
                    self.db.execute("UPDATE submission_ids SET owner=? WHERE owner IS NULL", (legacy_owner,))
                    self.db.execute("COMMIT")
                except BaseException:
                    self.db.execute("ROLLBACK")
                    raise
        # Legacy runs are read-only; proposal runs require a saved safe boundary. An interrupted
        # proposal run must never replay its original request after it starts.
        with self.lock:
            interrupted = self.db.execute("SELECT id FROM runs WHERE status IN ('running','queued','cancelling')").fetchall()
            for (run_id,) in interrupted:
                self.interrupt_for_restart(run_id)

    @staticmethod
    def _check_private(path: Path, *, directory: bool) -> None:
        info = path.lstat()
        expected_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if (not expected_type or info.st_uid != os.geteuid() or
                stat.S_IMODE(info.st_mode) & 0o077):
            raise PermissionError("orchestrator run state must be an owner-only file and directory")

    def create(self, payload: dict, roles: list[str], owner: str | None = None) -> dict:
        record, _ = self.create_or_get(payload, roles, owner=owner)
        return record

    def create_or_get(self, payload: dict, roles: list[str],
                      submission_id: str | None = None, owner: str | None = None) -> tuple[dict, bool]:
        now = time.time()
        if submission_id is not None and not SUBMISSION_ID.fullmatch(submission_id):
            raise ValueError("invalid submission ID")
        if owner is not None and not PRINCIPAL_ID.fullmatch(owner):
            raise ValueError("invalid owner ID")
        run_id = submission_id or uuid.uuid4().hex
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        children = [{"id": uuid.uuid4().hex, "role": role, "status": "queued"} for role in roles]
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                if submission_id is not None:
                    prior = self.db.execute("SELECT request_digest,owner FROM submission_ids WHERE id=?",
                                            (submission_id,)).fetchone()
                    if prior:
                        if prior[0] != digest or prior[1] != owner:
                            raise SubmissionConflict("submission ID belongs to a different request")
                        record = self.get(run_id) if owner is None else self.get_owned(run_id, owner)
                        if record is None:
                            if self.get(run_id) is not None:
                                raise SubmissionConflict("submission ID belongs to another owner")
                            raise SubmissionExpired("submission result is no longer retained")
                        self.db.execute("COMMIT")
                        return record, False
                    if self.db.execute("SELECT 1 FROM runs WHERE id=?", (run_id,)).fetchone():
                        raise SubmissionConflict("submission ID already belongs to another run")
                    count = self.db.execute("SELECT COUNT(*) FROM submission_ids").fetchone()[0]
                    if count >= MAX_SUBMISSION_IDS:
                        raise OverflowError("submission history capacity reached")
                active = self.db.execute("SELECT COUNT(*) FROM runs WHERE status NOT IN ('completed','failed','cancelled')").fetchone()[0]
                if active >= MAX_ACTIVE_RUNS:
                    raise OverflowError("too many queued or running agent tasks")
                if submission_id is not None:
                    self.db.execute("INSERT INTO submission_ids(id,request_digest,owner) VALUES(?,?,?)",
                                    (submission_id, digest, owner))
                initial_events = [{"at": now, "phase": "queued", "status": "queued"}]
                self.db.execute("INSERT INTO runs(id,status,created,updated,phase,request,children,events,owner) "
                                "VALUES(?,?,?,?,?,?,?,?,?)", (run_id, "queued", now, now, "queued",
                                json.dumps(payload, separators=(",", ":")),
                                json.dumps(children, separators=(",", ":")),
                                json.dumps(initial_events, separators=(",", ":")), owner))
                self.db.execute("DELETE FROM runs WHERE id IN (SELECT id FROM runs "
                                "WHERE status IN ('completed','failed','cancelled') ORDER BY updated DESC "
                                "LIMIT -1 OFFSET ?)", (MAX_RETAINED_RUNS,))
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
        return self.get(run_id), True

    def get(self, run_id: str) -> dict | None:
        with self.lock:
            row = self.db.execute("SELECT id,status,created,updated,phase,result,error,cancel_requested,children,events "
                                  "FROM runs WHERE id=?", (run_id,)).fetchone()
        return self._decode(row) if row else None

    def get_owned(self, run_id: str, owner: str) -> dict | None:
        with self.lock:
            row = self.db.execute("SELECT id,status,created,updated,phase,result,error,cancel_requested,children,events,request "
                                  "FROM runs WHERE id=? AND owner=?", (run_id, owner)).fetchone()
        if not row:
            return None
        result = self._decode(row)
        result["approval_id"] = None
        result["approval_kind"] = None
        checkpoint = None
        with self.lock:
            if self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='approval_checkpoints'").fetchone():
                checkpoint = self.db.execute(
                    'SELECT snapshot,checksum,approval_id,digest FROM approval_checkpoints '
                    'WHERE run_id=? AND owner=? ORDER BY step DESC LIMIT 1', (run_id, owner)).fetchone()
        result["workspace_identity"] = None
        try:
            request = json.loads(row[10])
            result["workspace_required"] = not isinstance(request, dict) or request.get("workspace") is not None
            workspace = request.get("workspace") if isinstance(request, dict) else None
            if (isinstance(workspace, dict) and workspace.get("host") in ("debian", "nixos") and
                    isinstance(workspace.get("workspace_id"), str) and
                    WORKSPACE_ID.fullmatch(workspace["workspace_id"])):
                result["workspace_identity"] = {"host": workspace["host"], "id": workspace["workspace_id"]}
            # Only expose the review route for the original owned and checksum-
            # verified pending checkpoint. An unknown/altered action must not
            # silently fall back to a patch or command approval screen.
            if (result['status'] == 'waiting_for_approval' and checkpoint is not None and
                    isinstance(request, dict) and request.get('allow_proposals') is True and
                    isinstance(checkpoint[2], str) and SUBMISSION_ID.fullmatch(checkpoint[2]) and
                    isinstance(checkpoint[3], str) and PRINCIPAL_ID.fullmatch(checkpoint[3]) and
                    hashlib.sha256(checkpoint[0].encode()).hexdigest() == checkpoint[1]):
                state = json.loads(checkpoint[0])
                action = state.get('action') if isinstance(state, dict) else None
                name = action.get('action') if isinstance(action, dict) else None
                kind = {'propose_patch': 'patch', 'propose_command': 'command'}.get(name)
                if kind is not None and state.get('workspace') == workspace:
                    # Verify that the approval actually exists in its own
                    # typed review table. Do not trust a checkpoint action to
                    # reinterpret a patch approval as command authority.
                    with self.lock:
                        if kind == 'command':
                            saved = self.db.execute(
                                'SELECT digest,origin FROM command_approvals WHERE id=? AND owner=?',
                                (checkpoint[2], owner)).fetchone()
                            valid_review = saved == (checkpoint[3], 'agent')
                        else:
                            saved = self.db.execute(
                                'SELECT a.digest,o.origin FROM approvals a JOIN approval_origins o '
                                'ON a.id=o.approval_id AND a.owner=o.owner '
                                'WHERE a.id=? AND a.owner=?', (checkpoint[2], owner)).fetchone()
                            valid_review = saved == (checkpoint[3], 'agent')
                    if valid_review:
                        result['approval_id'] = checkpoint[2]
                        result['approval_kind'] = kind
        except (ValueError, TypeError):
            # Corrupt history must never downgrade the permission requirement.
            result["workspace_required"] = True
        return result

    def request(self, run_id: str) -> str | None:
        with self.lock:
            row = self.db.execute("SELECT request FROM runs WHERE id=?", (run_id,)).fetchone()
        return row[0] if row else None

    def execution_request(self, run_id: str) -> tuple[str, str] | None:
        with self.lock:
            row = self.db.execute("SELECT owner,request FROM runs WHERE id=?", (run_id,)).fetchone()
        if not row or not isinstance(row[0], str) or not PRINCIPAL_ID.fullmatch(row[0]):
            return None
        return row[0], row[1]

    def list(self, limit: int = 30, owner: str | None = None) -> list[dict]:
        with self.lock:
            if owner is None:
                rows = self.db.execute("SELECT id,status,created,updated,phase,result,error,cancel_requested,children,events "
                                       "FROM runs ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
            else:
                rows = self.db.execute("SELECT id,status,created,updated,phase,result,error,cancel_requested,children,events "
                                       "FROM runs WHERE owner=? ORDER BY created DESC LIMIT ?", (owner, limit)).fetchall()
        result = []
        for row in rows:
            record = self._decode(row)
            record.pop("result", None)
            result.append(record)
        return result

    @staticmethod
    def _decode(row) -> dict:
        return {"id": row[0], "status": row[1], "created_at": row[2], "updated_at": row[3],
                "phase": row[4], "result": json.loads(row[5]) if row[5] else None,
                "error": row[6], "cancel_requested": bool(row[7]), "subagents": json.loads(row[8]),
                "events": json.loads(row[9])}

    @staticmethod
    def _append_event(events: list, event: dict) -> list:
        # Activity contains state metadata only, never prompts, file contents,
        # tool results, or upstream exception text.
        safe = {"at": time.time(), "phase": str(event.get("phase", "running"))[:120]}
        status = event.get("status")
        if status in ("queued", "running", "waiting_for_approval", "cancelling", "completed", "failed", "cancelled"):
            safe["status"] = status
        index = event.get("subagent_index")
        if type(index) is int and 0 <= index < 3:
            safe["subagent_index"] = index
            child_status = event.get("subagent_status")
            if child_status in ("queued", "running", "waiting_for_approval", "cancelling", "completed", "failed", "cancelled"):
                safe["subagent_status"] = child_status
        return (events + [safe])[-MAX_RUN_EVENTS:]

    def queued_ids(self) -> list[str]:
        with self.lock:
            return [row[0] for row in self.db.execute(
                "SELECT id FROM runs WHERE status='queued' AND owner IS NOT NULL ORDER BY created").fetchall()]

    def active_count(self) -> int:
        with self.lock:
            count = self.db.execute("SELECT COUNT(*) FROM runs WHERE status NOT IN "
                                    "('completed','failed','cancelled','waiting_for_approval')").fetchone()[0]
            return max(count, 1) if self.inference_quarantined() else count

    def inference_quarantined(self) -> bool:
        with self.lock:
            return self.db.execute("SELECT 1 FROM safety_state WHERE key='inference_unknown'").fetchone() is not None

    def quarantine_inference(self) -> None:
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO safety_state(key,value) VALUES('inference_unknown','1')")

    def clear_inference_quarantine(self) -> None:
        with self.lock:
            self.db.execute("DELETE FROM safety_state WHERE key='inference_unknown'")

    def update(self, run_id: str, *, status: str | None = None, phase: str | None = None,
               result=None, error: str | None = None, cancel_requested: bool | None = None,
               children: list | None = None, activity: dict | None = None) -> None:
        fields, values = [], []
        for name, value in (("status", status), ("phase", phase),
                            ("result", json.dumps(result, separators=(",", ":")) if result is not None else None),
                            ("error", error), ("cancel_requested", int(cancel_requested) if cancel_requested is not None else None),
                            ("children", json.dumps(children, separators=(",", ":")) if children is not None else None)):
            if value is not None:
                fields.append(name + "=?")
                values.append(value)
        if not fields:
            return
        updated = time.time()
        with self.lock:
            row = self.db.execute("SELECT events,phase,status FROM runs WHERE id=?", (run_id,)).fetchone()
            if row is None:
                return
            next_phase = phase if phase is not None else row[1]
            next_status = status if status is not None else row[2]
            details = {"phase": next_phase, "status": next_status, **(activity or {})}
            event = self._append_event(json.loads(row[0]), details)
            fields.append("events=?")
            values.append(json.dumps(event, separators=(",", ":")))
            fields.append("updated=?")
            values.extend((updated, run_id))
            self.db.execute("UPDATE runs SET " + ",".join(fields) + " WHERE id=?", values)

    def report_progress(self, run_id: str, event: dict) -> None:
        with self.lock:
            row = self.db.execute("SELECT status,cancel_requested,children,events FROM runs WHERE id=?",
                                  (run_id,)).fetchone()
            if not row or row[0] in TERMINAL:
                return
            children = json.loads(row[2])
            index = event.get("subagent_index")
            if type(index) is int and 0 <= index < len(children):
                # Never erase a concurrent cancellation with a late progress event.
                prior = children[index]["status"]
                requested = event.get("subagent_status", "running")
                if prior not in ("cancelled", "cancelling") or requested == "cancelled":
                    children[index]["status"] = requested
                event = {**event, "subagent_status": children[index]["status"]}
            status = "cancelling" if row[1] else "running"
            phase = str(event.get("phase", "running"))[:120]
            events = self._append_event(json.loads(row[3]), {**event, "status": status})
            self.db.execute("UPDATE runs SET status=?,phase=?,children=?,events=?,updated=? WHERE id=?",
                            (status, phase, json.dumps(children, separators=(",", ":")),
                             json.dumps(events, separators=(",", ":")), time.time(), run_id))

    def finish_success(self, run_id: str, result: dict) -> None:
        # Serialize the final decision with request_cancel: a cancellation
        # recorded first must never publish a completed result.
        with self.lock:
            record = self.get(run_id)
            if not record or record["status"] in TERMINAL:
                return
            if record["cancel_requested"]:
                self.update(run_id, status="cancelled", phase="cancelled at safe inference boundary")
            elif any(child.get("status") == "cancelling" for child in record["subagents"]):
                # A late child cancellation raced its completion. Its output may
                # already have influenced the parent; do not publish that result.
                children = [{**child, "status": "cancelled"} if child.get("status") == "cancelling"
                            else child for child in record["subagents"]]
                self.update(run_id, status="failed", phase="subagent cancellation raced completion",
                            error="A subagent was cancelled during completion. Retry the task.",
                            children=children)
            else:
                self.update(run_id, status="completed", phase="completed", result=result)

    def interrupt_for_restart(self, run_id: str) -> None:
        # Serialize shutdown with user cancellation. Work is read-only and can
        # be replayed, but a user's cancellation must survive a restart.
        with self.lock:
            record = self.get(run_id)
            if not record or record["status"] in TERMINAL:
                return
            if record["cancel_requested"]:
                self.update(run_id, status="cancelled", phase="cancelled during shutdown")
                return
            request = json.loads(self.request(run_id))
            if request.get('allow_proposals') is True:
                has_table = self.db.execute("SELECT 1 FROM sqlite_master WHERE name='approval_checkpoints'").fetchone()
                checkpoint = has_table and self.db.execute('SELECT 1 FROM approval_checkpoints WHERE run_id=?', (run_id,)).fetchone()
                if checkpoint:
                    self.update(run_id, status='waiting_for_approval', phase='recovering saved patch checkpoint')
                elif record['status'] != 'queued':
                    self.update(run_id, status='failed', phase='interrupted before patch checkpoint',
                                error='The interrupted proposal run cannot be replayed safely.')
                return
            children = [{**child, "status": ("cancelled" if child.get("status") in
                        ("cancelled", "cancelling") else "queued")}
                        for child in record["subagents"]]
            self.update(run_id, status="queued", phase="waiting for restart", children=children)

    def transition_active(self, run_id: str, status: str, phase: str) -> bool:
        with self.lock:
            record = self.get(run_id)
            if not record or record["status"] in TERMINAL or record["cancel_requested"]:
                return False
            if record["status"] != status or record["phase"] != phase:
                self.update(run_id, status=status, phase=phase)
            return True

    def request_cancel(self, run_id: str, child_id: str | None = None, *, owner: str | None = None) -> dict | None:
        with self.lock:
            record = self.get(run_id) if owner is None else self.get_owned(run_id, owner)
            if record is None or record["status"] in TERMINAL:
                return record
            if child_id is None:
                if record["status"] in ("queued", "waiting_for_approval"):
                    self.update(run_id, status="cancelled", phase="cancelled before start", cancel_requested=True)
                else:
                    self.update(run_id, status="cancelling", phase="cancellation requested", cancel_requested=True)
            else:
                children = record["subagents"]
                selected_index = next((index for index, item in enumerate(children)
                                       if item["id"] == child_id), None)
                if selected_index is None:
                    return None
                selected = children[selected_index]
                if selected["status"] == "queued":
                    selected["status"] = "cancelled"
                elif selected["status"] == "running":
                    selected["status"] = "cancelling"
                self.update(run_id, children=children, phase="subagent cancellation requested",
                            activity={"subagent_index": selected_index,
                                      "subagent_status": selected["status"]})
            return self.get(run_id)

    def close(self) -> None:
        with self.lock:
            try:
                self.db.close()
            finally:
                self._instance_lock.close()


class RunJobs:
    """Single-worker queue: logical subagents never overlap PS5 inference."""

    def __init__(self, controller, directory: str | Path):
        self.controller = controller
        self.store = RunStore(directory, getattr(controller, "legacy_run_owner", None))
        from approval_checkpoints import ApprovalCheckpoints
        self.checkpoints = ApprovalCheckpoints(self.store, controller)
        self.controller.inference_started = self.store.quarantine_inference
        self.controller.inference_finished = self.store.clear_inference_quarantine
        self.queue: queue.Queue[str] = queue.Queue(maxsize=MAX_ACTIVE_RUNS)
        self.stopping = threading.Event()
        for run_id in self.store.queued_ids():
            self.queue.put_nowait(run_id)
        self.worker = threading.Thread(target=self._work, name="nexus-agent-runs", daemon=True)
        self.worker.start()

    def submit(self, payload: dict, *, owner: str) -> dict:
        if not isinstance(owner, str) or not PRINCIPAL_ID.fullmatch(owner):
            raise ValueError("verified owner ID required")
        request = dict(payload)
        submission_id = request.pop("submission_id", None)
        if submission_id is not None and (not isinstance(submission_id, str) or
                                          not SUBMISSION_ID.fullmatch(submission_id)):
            raise ValueError("invalid submission ID")
        roles = self.controller.validate_run(request)
        record, created = self.store.create_or_get(request, roles, submission_id, owner)
        if not created:
            return record
        try:
            self.queue.put_nowait(record["id"])
        except queue.Full:
            self.store.update(record["id"], status="failed", phase="queue full",
                              error="The orchestrator queue is full.")
            raise OverflowError("too many queued or running agent tasks")
        return self.store.get(record["id"])

    def cancel(self, run_id: str, child_id: str | None = None, *, owner: str) -> dict | None:
        if not isinstance(owner, str) or not PRINCIPAL_ID.fullmatch(owner):
            raise ValueError("verified owner ID required")
        return self.store.request_cancel(run_id, child_id, owner=owner)

    def active(self) -> int:
        return self.store.active_count()

    def _progress(self, run_id: str, event: dict) -> None:
        self.store.report_progress(run_id, event)

    def _cancelled(self, run_id: str) -> bool:
        record = self.store.get(run_id)
        return record is None or record["cancel_requested"] or self.stopping.is_set()

    def _child_cancelled(self, run_id: str, index: int) -> bool:
        record = self.store.get(run_id)
        return (record is None or index >= len(record["subagents"]) or
                record["subagents"][index]["status"] in ("cancelled", "cancelling"))

    def _work(self) -> None:
        while not self.stopping.is_set():
            try:
                run_id = self.queue.get(timeout=0.2)
            except queue.Empty:
                for ready in self.checkpoints.poll():
                    self.queue.put_nowait(ready)
                continue
            policy_state = None
            try:
                record = self.store.get(run_id)
                if not record or record["status"] in TERMINAL:
                    continue
                if self.store.inference_quarantined():
                    self.store.update(run_id, status="failed", phase="inference state unknown",
                                      error="PS5 inference state requires an operator check.")
                    continue
                if self._cancelled(run_id):
                    if self.stopping.is_set():
                        self.store.interrupt_for_restart(run_id)
                    else:
                        self.store.update(run_id, status="cancelled", phase="cancelled before inference")
                    continue
                acquired = False
                while not self.stopping.is_set():
                    if self._cancelled(run_id):
                        break
                    if self.controller.capacity.acquire(blocking=False):
                        acquired = True
                        break
                    if not self.store.transition_active(run_id, "queued", "waiting for PS5 inference slot"):
                        break
                    self.stopping.wait(0.2)
                if not acquired:
                    if self.stopping.is_set():
                        self.store.interrupt_for_restart(run_id)
                    continue
                try:
                    if self.store.inference_quarantined():
                        self.store.update(run_id, status="failed", phase="inference state unknown",
                                          error="PS5 inference state requires an operator check.")
                        continue
                    switch_deadline = time.monotonic() + 120
                    while self.controller.switch_pending:
                        if self._cancelled(run_id):
                            raise InterruptedError("cancelled")
                        if not self.store.transition_active(run_id, "queued", "waiting for PS5 model switch"):
                            raise InterruptedError("cancelled")
                        try:
                            self.controller.native_status()
                        except Exception as exc:
                            # An unavailable status is ambiguous, never readiness.
                            logger.warning("model switch status unavailable (%s)", type(exc).__name__)
                        if not self.controller.switch_pending:
                            break
                        if time.monotonic() >= switch_deadline:
                            raise RuntimeError("PS5 model switch readiness timed out")
                        self.stopping.wait(2)
                    if not self.store.transition_active(run_id, "running", "starting"):
                        continue
                    execution = self.store.execution_request(run_id)
                    if execution is None:
                        raise RuntimeError("verified task owner is unavailable")
                    owner, encoded = execution
                    request = json.loads(encoded)
                    policy_lock = threading.Lock()
                    policy_state = {"checked": 0.0, "failure": None}
                    def check_cancel_or_policy(force=False):
                        if self._cancelled(run_id):
                            return True
                        with policy_lock:
                            if policy_state["failure"] is not None:
                                return True
                            now = time.monotonic()
                            if not force and now - policy_state["checked"] < 2:
                                return False
                            try:
                                permitted = self.controller.authorize_run(owner, request.get("workspace"))
                                if not permitted:
                                    policy_state["failure"] = "authorization revoked"
                            except Exception:
                                policy_state["failure"] = "authorization unavailable"
                            policy_state["checked"] = now
                            return policy_state["failure"] is not None
                    if check_cancel_or_policy(force=True):
                        raise InterruptedError("cancelled or unauthorized")
                    for attempt in range(3):
                        try:
                            proposal_args = {}
                            if request.get('allow_proposals') is True:
                                checkpoint = self.checkpoints.latest(run_id, owner)
                                if checkpoint is not None:
                                    checkpoint = self.checkpoints.reconcile(run_id, owner)
                                    if checkpoint is None:
                                        from approval_checkpoints import WaitingForApproval
                                        self.store.update(run_id, status='waiting_for_approval', phase='waiting for patch execution receipt')
                                        raise WaitingForApproval()
                                proposal_args = dict(checkpoint=checkpoint,
                                    proposal_checkpoint=lambda state: self.checkpoints.suspend(run_id, owner, state))
                            result = self.controller.run(
                                request, **proposal_args,
                                progress=lambda event: self._progress(run_id, event),
                                cancelled=check_cancel_or_policy,
                                child_cancelled=lambda index: self._child_cancelled(run_id, index))
                            break
                        except InterruptedError:
                            raise
                        except Exception as exc:
                            # Only legacy read-only requests may replay from the
                            # beginning. Proposal runs recover saved tool boundaries.
                            if (request.get("allow_proposals") is True or getattr(exc, "inference_ambiguous", False) or
                                    getattr(exc, "status", None) not in (502, 503) or attempt == 2):
                                raise
                            if check_cancel_or_policy():
                                raise InterruptedError("cancelled")
                            self._progress(run_id, {"phase": "retrying unavailable upstream"})
                            if self.stopping.wait(2 ** attempt) or check_cancel_or_policy():
                                raise InterruptedError("cancelled")
                    if check_cancel_or_policy(force=True):
                        raise InterruptedError("cancelled or unauthorized")
                    if self.stopping.is_set():
                        self.store.interrupt_for_restart(run_id)
                    else:
                        self.store.finish_success(run_id, result)
                except InterruptedError:
                    if self.stopping.is_set():
                        self.store.interrupt_for_restart(run_id)
                    elif policy_state is not None and policy_state["failure"] is not None:
                        self.store.update(run_id, status="failed", phase=policy_state["failure"],
                                          error="Task authorization was revoked or could not be verified.")
                    else:
                        self.store.update(run_id, status="cancelled", phase="cancelled at safe inference boundary")
                except Exception as exc:
                    from approval_checkpoints import WaitingForApproval
                    if isinstance(exc, WaitingForApproval):
                        continue
                    # Do not persist arbitrary upstream or filesystem exception text.
                    logger.error("agent run failed (%s)", type(exc).__name__)
                    if getattr(exc, "inference_ambiguous", False):
                        self.store.quarantine_inference()
                    if self.stopping.is_set():
                        self.store.interrupt_for_restart(run_id)
                    else:
                        status = getattr(exc, "status", None)
                        if status == 413:
                            phase, message = "context limit exceeded", "The task exceeded the active context budget."
                        elif status in (502, 503):
                            phase, message = "upstream unavailable", "An upstream service is unavailable."
                        else:
                            phase, message = "failed", "The agent run failed. Check the service health and retry."
                        self.store.update(run_id, status="failed", phase=phase, error=message)
                finally:
                    self.controller.capacity.release()
            finally:
                self.queue.task_done()

    def close(self) -> None:
        self.stopping.set()
        self.worker.join(timeout=2)
        if not self.worker.is_alive():
            self.checkpoints.close()
            self.store.close()
