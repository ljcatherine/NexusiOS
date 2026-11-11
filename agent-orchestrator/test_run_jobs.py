import json
import importlib.util
import os
import pathlib
import sqlite3
import stat
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import BoundedSemaphore

from run_jobs import RunJobs, RunStore, SubmissionConflict, SubmissionExpired

spec = importlib.util.spec_from_file_location('agent_server', pathlib.Path(__file__).with_name('server.py'))
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)
TOKEN = 'z' * 40
OWNER_ID = 'a' * 64


class ControlledController:
    def __init__(self):
        self.capacity = BoundedSemaphore(1)
        self.switch_pending = None
        self.started = threading.Event()
        self.release = threading.Event()
        self.inference_calls = 0

    def authorize_run(self, principal, workspace):
        return True

    def validate_run(self, payload):
        return ["analyzer"] if payload.get("subagents") else []

    def run(self, payload, *, progress, cancelled, child_cancelled):
        self.inference_calls += 1
        progress({"phase": "subagent analyzer", "subagent_index": 0,
                  "subagent_status": "running"})
        self.started.set()
        self.release.wait(timeout=2)
        agents = []
        if child_cancelled(0):
            progress({"phase": "subagent cancelled", "subagent_index": 0,
                      "subagent_status": "cancelled"})
        else:
            agents = [{"role": "analyzer", "output": "read-only analysis"}]
            progress({"phase": "subagent complete", "subagent_index": 0,
                      "subagent_status": "completed"})
        if cancelled():
            raise InterruptedError("cancelled")
        return {"response": "done", "subagents": agents}


class RunJobsTests(unittest.TestCase):
    def test_running_task_stops_when_authorization_is_revoked(self):
        class RevocableController(ControlledController):
            def __init__(self):
                super().__init__()
                self.allowed = threading.Event()
                self.allowed.set()
                self.seen = []
            def authorize_run(self, principal, workspace):
                self.seen.append((principal, workspace))
                return self.allowed.is_set()
            def run(self, payload, *, progress, cancelled, child_cancelled):
                self.started.set()
                while not cancelled():
                    time.sleep(0.02)
                raise InterruptedError('policy or cancellation')
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            controller = RevocableController()
            jobs = RunJobs(controller, root)
            try:
                workspace = {'host': 'debian', 'workspace_id': 'code', 'path': ''}
                run = jobs.submit({'prompt': 'task', 'workspace': workspace}, owner=OWNER_ID)
                self.assertTrue(controller.started.wait(timeout=1))
                controller.allowed.clear()
                failed = self.wait_for(jobs.store, run['id'], lambda item: item['status'] == 'failed', timeout=5)
                self.assertEqual(failed['phase'], 'authorization revoked')
                self.assertIsNone(failed['result'])
                self.assertEqual(controller.seen[0], (OWNER_ID, workspace))
            finally:
                jobs.close()

    def test_unavailable_policy_check_prevents_task_start(self):
        class UnavailableController(ControlledController):
            def authorize_run(self, principal, workspace):
                raise OSError('private detail')
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            controller = UnavailableController()
            jobs = RunJobs(controller, root)
            try:
                run = jobs.submit({'prompt': 'task'}, owner=OWNER_ID)
                failed = self.wait_for(jobs.store, run['id'], lambda item: item['status'] == 'failed')
                self.assertEqual(failed['phase'], 'authorization unavailable')
                self.assertEqual(controller.inference_calls, 0)
                self.assertNotIn('private detail', failed['error'])
            finally:
                jobs.close()

    def test_workspace_identity_comes_from_saved_request_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            store = RunStore(root)
            try:
                run = store.create({'prompt': 'task', 'workspace': {'host': 'nixos',
                                   'workspace_id': 'code', 'path': 'private/file'}}, [], owner=OWNER_ID)
                record = store.get_owned(run['id'], OWNER_ID)
                self.assertEqual(record['workspace_identity'], {'host': 'nixos', 'id': 'code'})
                self.assertTrue(record['workspace_required'])
                store.db.execute('UPDATE runs SET request=? WHERE id=?', ('{"workspace":{"host":"bad"}}', run['id']))
                corrupt = store.get_owned(run['id'], OWNER_ID)
                self.assertTrue(corrupt['workspace_required'])
                self.assertIsNone(corrupt['workspace_identity'])
                store.db.execute('UPDATE runs SET request=? WHERE id=?', ('{', run['id']))
                self.assertTrue(store.get_owned(run['id'], OWNER_ID)['workspace_required'])
                self.assertIsNone(store.get_owned(run['id'], OWNER_ID)['workspace_identity'])
            finally:
                store.close()

    def test_guard_is_rechecked_after_waiting_for_inference_slot(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            controller = ControlledController()
            controller.capacity.acquire()
            jobs = RunJobs(controller, root)
            held = True
            try:
                run = jobs.submit({'prompt': 'wait'}, owner=OWNER_ID)
                self.wait_for(jobs.store, run['id'], lambda item: item['phase'] == 'waiting for PS5 inference slot')
                jobs.store.quarantine_inference()
                controller.capacity.release()
                held = False
                denied = self.wait_for(jobs.store, run['id'], lambda item: item['status'] == 'failed')
                self.assertEqual(denied['phase'], 'inference state unknown')
                self.assertEqual(controller.inference_calls, 0)
            finally:
                if held:
                    controller.capacity.release()
                jobs.close()

    def test_ambiguous_inference_failure_is_not_retried(self):
        class AmbiguousController(ControlledController):
            def __init__(self):
                super().__init__()
                self.attempts = 0
            def run(self, payload, *, progress, cancelled, child_cancelled):
                self.attempts += 1
                raise api.InferenceStateUnknown(502, 'stream failed')
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            controller = AmbiguousController()
            jobs = RunJobs(controller, root)
            try:
                run = jobs.submit({'prompt': 'ambiguous'}, owner=OWNER_ID)
                self.wait_for(jobs.store, run['id'], lambda item: item['status'] == 'failed')
                self.assertEqual(controller.attempts, 1)
                self.assertEqual(jobs.active(), 1)
                next_run = jobs.submit({'prompt': 'must not start'}, owner=OWNER_ID)
                denied = self.wait_for(jobs.store, next_run['id'], lambda item: item['status'] == 'failed')
                self.assertEqual(denied['phase'], 'inference state unknown')
                self.assertEqual(controller.attempts, 1)
            finally:
                jobs.close()
            store = RunStore(root)
            self.assertTrue(store.inference_quarantined())
            self.assertEqual(store.active_count(), 1)
            store.clear_inference_quarantine()
            self.assertEqual(store.active_count(), 0)
            store.close()

    def test_cancellation_stops_upstream_retry(self):
        class UnavailableController(ControlledController):
            def __init__(self):
                super().__init__()
                self.attempts = 0
            def run(self, payload, *, progress, cancelled, child_cancelled):
                self.attempts += 1
                raise api.AgentError(503, 'unavailable')
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            controller = UnavailableController()
            jobs = RunJobs(controller, root)
            try:
                run = jobs.submit({'prompt': 'cancel retry'}, owner=OWNER_ID)
                self.wait_for(jobs.store, run['id'], lambda item: item['phase'] == 'retrying unavailable upstream')
                jobs.cancel(run['id'], owner=OWNER_ID)
                self.wait_for(jobs.store, run['id'], lambda item: item['status'] == 'cancelled')
                self.assertEqual(controller.attempts, 1)
            finally:
                jobs.close()

    def test_transient_upstream_failure_retries_but_context_error_does_not(self):
        class FailingController(ControlledController):
            def __init__(self, status):
                super().__init__()
                self.status = status
                self.attempts = 0
            def run(self, payload, *, progress, cancelled, child_cancelled):
                self.attempts += 1
                if self.attempts == 1 or self.status == 413:
                    raise api.AgentError(self.status, 'upstream details must stay private')
                return {'response': 'recovered', 'subagents': []}
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            controller = FailingController(503)
            jobs = RunJobs(controller, root)
            try:
                run = jobs.submit({'prompt': 'retry'}, owner=OWNER_ID)
                result = self.wait_for(jobs.store, run['id'], lambda item: item['status'] == 'completed', timeout=4)
                self.assertEqual(controller.attempts, 2)
                self.assertEqual(result['result']['response'], 'recovered')
                self.assertTrue(any(event['phase'] == 'retrying unavailable upstream' for event in result['events']))
            finally:
                jobs.close()
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            controller = FailingController(413)
            jobs = RunJobs(controller, root)
            try:
                run = jobs.submit({'prompt': 'too large'}, owner=OWNER_ID)
                failed = self.wait_for(jobs.store, run['id'], lambda item: item['status'] == 'failed')
                self.assertEqual(controller.attempts, 1)
                self.assertEqual(failed['phase'], 'context limit exceeded')
                self.assertNotIn('upstream details', failed['error'])
            finally:
                jobs.close()

    def test_only_one_store_can_own_a_state_directory(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            first = RunStore(root)
            try:
                with self.assertRaises(BlockingIOError):
                    RunStore(root)
            finally:
                first.close()
            reopened = RunStore(root)
            reopened.close()

    def test_lock_file_rejects_symlinks_and_shared_permissions(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            os.symlink('/dev/null', os.path.join(root, 'orchestrator.lock'))
            with self.assertRaises(OSError):
                RunStore(root)
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            path = os.path.join(root, 'orchestrator.lock')
            with open(path, 'w'):
                pass
            os.chmod(path, 0o644)
            with self.assertRaises(PermissionError):
                RunStore(root)

    def test_run_waits_for_confirmed_model_switch_before_inference(self):
        class SwitchingController(ControlledController):
            def __init__(self):
                super().__init__()
                self.switch_pending = 'model-id'
                self.ready = threading.Event()
                self.checked = threading.Event()
            def native_status(self):
                self.checked.set()
                if self.ready.is_set():
                    self.switch_pending = None
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            controller = SwitchingController()
            controller.release.set()
            jobs = RunJobs(controller, root)
            try:
                run = jobs.submit({'prompt': 'wait for model', 'subagents': 1}, owner=OWNER_ID)
                self.assertTrue(controller.checked.wait(timeout=1))
                self.assertEqual(jobs.store.get(run['id'])['phase'], 'waiting for PS5 model switch')
                self.assertEqual(controller.inference_calls, 0)
                controller.ready.set()
                result = self.wait_for(jobs.store, run['id'], lambda item: item['status'] == 'completed', timeout=4)
                self.assertEqual(result['result']['response'], 'done')
            finally:
                jobs.close()

    def test_cancel_while_waiting_for_model_switch_never_runs_inference(self):
        class SwitchingController(ControlledController):
            def __init__(self):
                super().__init__()
                self.switch_pending = 'model-id'
                self.checked = threading.Event()
            def native_status(self):
                self.checked.set()
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            controller = SwitchingController()
            jobs = RunJobs(controller, root)
            try:
                run = jobs.submit({'prompt': 'cancel', 'subagents': 1}, owner=OWNER_ID)
                self.assertTrue(controller.checked.wait(timeout=1))
                jobs.cancel(run['id'], owner=OWNER_ID)
                self.wait_for(jobs.store, run['id'], lambda item: item['status'] == 'cancelled')
                self.assertEqual(controller.inference_calls, 0)
            finally:
                jobs.close()

    def test_full_queue_does_not_deadlock_worker_waiting_for_capacity(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            controller = ControlledController()
            controller.capacity.acquire()
            controller.release.set()
            jobs = RunJobs(controller, root)
            held = True
            try:
                run = jobs.submit({'prompt': 'wait', 'subagents': 1}, owner=OWNER_ID)
                self.wait_for(jobs.store, run['id'], lambda item: item['phase'] == 'waiting for PS5 inference slot')
                # Stale queue entries can arise from cancellations while the
                # worker is waiting; only the worker can drain these entries.
                for index in range(jobs.queue.maxsize):
                    jobs.queue.put_nowait(f'{index:032x}')
                time.sleep(0.3)
                controller.capacity.release()
                held = False
                result = self.wait_for(jobs.store, run['id'], lambda item: item['status'] == 'completed')
                self.assertEqual(result['result']['response'], 'done')
            finally:
                if held:
                    controller.capacity.release()
                jobs.close()
            self.assertFalse(jobs.worker.is_alive())

    def test_shutdown_requeues_inference_and_restart_resumes(self):
        class InterruptibleController(ControlledController):
            def run(self, payload, *, progress, cancelled, child_cancelled):
                self.started.set()
                while not cancelled():
                    time.sleep(0.01)
                raise InterruptedError('shutdown')

        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            first = InterruptibleController()
            jobs = RunJobs(first, root)
            run = jobs.submit({'prompt': 'resume', 'subagents': 1}, owner=OWNER_ID)
            self.assertTrue(first.started.wait(timeout=1))
            jobs.close()
            self.assertFalse(jobs.worker.is_alive())
            second = ControlledController()
            second.release.set()
            resumed = RunJobs(second, root)
            try:
                record = self.wait_for(resumed.store, run['id'], lambda item: item['status'] == 'completed')
                self.assertEqual(record['result']['response'], 'done')
                self.assertEqual(second.inference_calls, 1)
            finally:
                resumed.close()

    def test_shutdown_preserves_user_cancellation_and_resets_interrupted_children(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            store = RunStore(root)
            run = store.create({'prompt': 'task'}, ['analyzer', 'reviewer'], owner=OWNER_ID)
            store.report_progress(run['id'], {'phase': 'working', 'subagent_index': 0,
                                              'subagent_status': 'completed'})
            store.request_cancel(run['id'], run['subagents'][1]['id'], owner=OWNER_ID)
            store.interrupt_for_restart(run['id'])
            record = store.get(run['id'])
            self.assertEqual([child['status'] for child in record['subagents']], ['queued', 'cancelled'])
            store.request_cancel(run['id'], owner=OWNER_ID)
            store.interrupt_for_restart(run['id'])
            self.assertEqual(store.get(run['id'])['status'], 'cancelled')
            self.assertFalse(store.transition_active(run['id'], 'running', 'starting'))
            self.assertFalse(store.transition_active(run['id'], 'queued', 'waiting'))
            self.assertEqual(store.get(run['id'])['status'], 'cancelled')
            store.close()

    def test_cancel_before_final_commit_wins_and_hides_result(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            store = RunStore(root)
            run = store.create({'prompt': 'task'}, [], owner=OWNER_ID)
            store.update(run['id'], status='running', phase='generating')
            store.request_cancel(run['id'], owner=OWNER_ID)
            store.finish_success(run['id'], {'response': 'must not be published'})
            finished = store.get(run['id'])
            self.assertEqual(finished['status'], 'cancelled')
            self.assertIsNone(finished['result'])
            store.close()

    def test_late_subagent_completion_does_not_override_cancellation(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            store = RunStore(root)
            run = store.create({'prompt': 'task'}, ['analyzer'], owner=OWNER_ID)
            store.report_progress(run['id'], {'phase': 'subagent', 'subagent_index': 0,
                                              'subagent_status': 'running'})
            store.request_cancel(run['id'], run['subagents'][0]['id'], owner=OWNER_ID)
            store.report_progress(run['id'], {'phase': 'late completion', 'subagent_index': 0,
                                              'subagent_status': 'completed'})
            record = store.get(run['id'])
            self.assertEqual(record['subagents'][0]['status'], 'cancelling')
            self.assertEqual(record['events'][-1]['subagent_status'], 'cancelling')
            store.finish_success(run['id'], {'response': 'possibly influenced by cancelled output'})
            record = store.get(run['id'])
            self.assertEqual(record['status'], 'failed')
            self.assertEqual(record['subagents'][0]['status'], 'cancelled')
            self.assertIsNone(record['result'])
            store.close()

    def wait_for(self, store, run_id, predicate, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            record = store.get(run_id)
            if record and predicate(record):
                return record
            time.sleep(0.01)
        self.fail("run did not reach the expected state")

    def test_runs_are_persisted_with_owner_only_permissions(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            store = RunStore(root)
            created = store.create({"prompt": "private task"}, [])
            info = os.stat(store.path)
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(created["status"], "queued")
            store.close()
            reopened = RunStore(root)
            self.assertEqual(reopened.get(created["id"])["status"], "queued")
            self.assertEqual(reopened.request(created["id"]), '{"prompt":"private task"}')
            self.assertEqual(reopened.get(created["id"])["events"][0]["phase"], "queued")
            reopened.close()

    def test_submission_id_recovers_lost_response_without_duplicate_work(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            controller = ControlledController()
            jobs = RunJobs(controller, root)
            request = {"submission_id": "1234567890abcdef1234567890abcdef", "prompt": "same task"}
            try:
                first = jobs.submit(request, owner=OWNER_ID)
                self.assertTrue(controller.started.wait(timeout=1))
                retry = jobs.submit(dict(request), owner=OWNER_ID)
                self.assertEqual(first["id"], retry["id"])
                with self.assertRaises(SubmissionConflict):
                    jobs.submit({**request, "prompt": "different task"}, owner=OWNER_ID)
                controller.release.set()
                self.wait_for(jobs.store, first["id"], lambda row: row["status"] == "completed")
                self.assertEqual(jobs.submit(request, owner=OWNER_ID)["status"], "completed")
                self.assertEqual(controller.inference_calls, 1)
            finally:
                controller.release.set()
                jobs.close()

            reopened = RunStore(root)
            try:
                restored, created = reopened.create_or_get({"prompt": "same task"}, [], request["submission_id"], OWNER_ID)
                self.assertFalse(created)
                self.assertEqual(restored["status"], "completed")
                with reopened.lock:
                    reopened.db.execute("DELETE FROM runs WHERE id=?", (request["submission_id"],))
                with self.assertRaises(SubmissionExpired):
                    reopened.create_or_get({"prompt": "same task"}, [], request["submission_id"], OWNER_ID)
                with self.assertRaises(SubmissionConflict):
                    reopened.create_or_get({"prompt": "different task"}, [], request["submission_id"], OWNER_ID)
            finally:
                reopened.close()

    def test_concurrent_identical_submissions_start_only_one_run(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            controller = ControlledController()
            jobs = RunJobs(controller, root)
            request = {"submission_id": "abcdef0123456789abcdef0123456789", "prompt": "one task"}
            try:
                with ThreadPoolExecutor(max_workers=8) as pool:
                    records = list(pool.map(lambda _: jobs.submit(dict(request), owner=OWNER_ID), range(8)))
                self.assertEqual({record["id"] for record in records}, {request["submission_id"]})
                controller.release.set()
                self.wait_for(jobs.store, request["submission_id"], lambda row: row["status"] == "completed")
                self.assertEqual(controller.inference_calls, 1)
            finally:
                controller.release.set()
                jobs.close()

    def test_legacy_unowned_runs_require_explicit_owner_migration(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            run_id = '1234567890abcdef1234567890abcdef'
            store = RunStore(root)
            store.create_or_get({'prompt': 'legacy'}, [], run_id)
            store.close()
            unowned = RunStore(root)
            self.assertEqual(unowned.queued_ids(), [])
            self.assertIsNone(unowned.get_owned(run_id, OWNER_ID))
            unowned.close()
            migrated = RunStore(root, legacy_owner=OWNER_ID)
            self.assertEqual(migrated.queued_ids(), [run_id])
            self.assertEqual(migrated.get_owned(run_id, OWNER_ID)['status'], 'queued')
            self.assertIsNone(migrated.get_owned(run_id, 'b' * 64))
            record, created = migrated.create_or_get({'prompt': 'legacy'}, [], run_id, OWNER_ID)
            self.assertFalse(created)
            self.assertEqual(record['id'], run_id)
            migrated.close()

    def test_progress_history_is_durable_bounded_and_metadata_only(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            store = RunStore(root)
            run = store.create({"prompt": "do not copy this into events"}, [])
            for index in range(125):
                store.report_progress(run["id"], {
                    "phase": f"step {index}", "subagent_index": 0,
                    "subagent_status": "running", "tool_output": "private file text",
                })
            events = store.get(run["id"])["events"]
            self.assertEqual(len(events), 100)
            self.assertEqual(events[-1]["phase"], "step 124")
            self.assertNotIn("tool_output", events[-1])
            self.assertNotIn("do not copy", json.dumps(events))
            store.close()
            reopened = RunStore(root)
            restored = reopened.get(run["id"])["events"]
            self.assertEqual(restored[:-1], events[1:])
            self.assertEqual(restored[-1]['phase'], 'waiting for restart')
            reopened.close()

    def test_existing_run_database_migrates_to_event_history(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            path = os.path.join(root, "agent-runs.sqlite3")
            db = sqlite3.connect(path)
            db.execute("""CREATE TABLE runs (
                id TEXT PRIMARY KEY, status TEXT NOT NULL, created REAL NOT NULL,
                updated REAL NOT NULL, phase TEXT NOT NULL, request TEXT NOT NULL,
                result TEXT, error TEXT, cancel_requested INTEGER NOT NULL DEFAULT 0,
                children TEXT NOT NULL
            )""")
            db.commit()
            db.close()
            os.chmod(path, 0o600)
            store = RunStore(root)
            self.assertIn("events", {row[1] for row in store.db.execute("PRAGMA table_info(runs)")})
            created = store.create({"prompt": "after migration"}, [])
            self.assertEqual(created["events"][0]["status"], "queued")
            store.close()

    def test_rejects_shared_state_directory_or_database(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o750)
            with self.assertRaises(PermissionError):
                RunStore(root)
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as private:
            os.chmod(root, 0o700)
            os.chmod(private, 0o700)
            link = os.path.join(root, "runs")
            os.symlink(private, link)
            with self.assertRaises(PermissionError):
                RunStore(link)
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            path = os.path.join(root, "agent-runs.sqlite3")
            open(path, "wb").close()
            os.chmod(path, 0o640)
            with self.assertRaises(PermissionError):
                RunStore(root)

    def test_restart_resumes_queued_run_and_subagent_cancellation_isolated(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            controller = ControlledController()
            store = RunStore(root)
            queued = store.create({"prompt": "resume", "subagents": 1}, ["analyzer"], owner=OWNER_ID)
            store.close()

            jobs = RunJobs(controller, root)
            resumed = self.wait_for(jobs.store, queued["id"], lambda row: row["status"] == "running")
            self.assertTrue(controller.started.wait(timeout=1))
            child_id = resumed["subagents"][0]["id"]
            cancelling = jobs.cancel(queued["id"], child_id, owner=OWNER_ID)
            self.assertEqual(cancelling["subagents"][0]["status"], "cancelling")
            self.assertEqual(cancelling["events"][-1]["subagent_status"], "cancelling")
            controller.release.set()
            finished = self.wait_for(jobs.store, queued["id"], lambda row: row["status"] == "completed")
            self.assertEqual(finished["subagents"][0]["status"], "cancelled")
            self.assertEqual(finished["result"]["subagents"], [])
            jobs.close()

    def test_parent_cancel_before_inference_prevents_gpu_call(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            controller = ControlledController()
            controller.capacity.acquire()
            jobs = RunJobs(controller, root)
            capacity_held = True
            try:
                record = jobs.submit({"prompt": "cancel", "subagents": 1}, owner=OWNER_ID)
                cancelled = jobs.cancel(record["id"], owner=OWNER_ID)
                self.assertEqual(cancelled["status"], "cancelled")
                controller.capacity.release()
                capacity_held = False
                time.sleep(0.05)
                self.assertEqual(controller.inference_calls, 0)
            finally:
                if capacity_held:
                    controller.capacity.release()
                controller.release.set()
                jobs.close()

    def test_cancelling_persisted_run_stops_matching_ps5_stream(self):
        class Backend(ThreadingHTTPServer):
            stream_started = threading.Event()
            stream_cancelled = threading.Event()
            conversation_id = None
            deleted_id = None

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def do_POST(self):
                Backend.conversation_id = self.headers.get('X-Conversation-Id')
                self.rfile.read(int(self.headers.get('Content-Length', '0')))
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Transfer-Encoding', 'chunked')
                self.end_headers()
                token = b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n'
                self.wfile.write(f'{len(token):X}\r\n'.encode() + token + b'\r\n')
                self.wfile.flush()
                Backend.stream_started.set()
                Backend.stream_cancelled.wait(timeout=5)
                try:
                    self.wfile.write(b'0\r\n\r\n')
                    self.wfile.flush()
                except OSError:
                    pass
            def do_DELETE(self):
                from urllib.parse import parse_qs, urlsplit
                Backend.deleted_id = parse_qs(urlsplit(self.path).query).get('conv_id', [None])[0]
                Backend.stream_cancelled.set()
                self.send_response(204)
                self.send_header('Content-Length', '0')
                self.end_headers()
            def log_message(self, *_args):
                pass

        class StreamingController(api.Controller):
            def authorize_run(self, principal, workspace):
                return True
            def http_json(self, _base, path, **_kwargs):
                if path == '/props':
                    return {'default_generation_settings': {'n_ctx': 4096}}
                if path == '/chat/completions/input_tokens':
                    return {'input_tokens': 1}
                raise AssertionError(f'unexpected PS5 metadata path: {path}')

        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            backend = Backend(('127.0.0.1', 0), Handler)
            backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
            backend_thread.start()
            controller = StreamingController({
                'NEXUS_ORCHESTRATOR_TOKEN': TOKEN,
                'NEXUS_PS5_CHAT_URL': f'http://127.0.0.1:{backend.server_port}/v1',
                'NEXUS_PS5_MODEL_ID': 'local',
            })
            jobs = RunJobs(controller, root)
            try:
                record = jobs.submit({'prompt': 'stop this run'}, owner=OWNER_ID)
                self.assertTrue(Backend.stream_started.wait(timeout=2))
                self.assertEqual(jobs.cancel(record['id'], owner=OWNER_ID)['status'], 'cancelling')
                finished = self.wait_for(jobs.store, record['id'], lambda item: item['status'] == 'cancelled')
                self.assertIsNone(finished['result'])
                self.assertRegex(Backend.conversation_id or '', r'^[0-9a-f]{32}$')
                self.assertEqual(Backend.deleted_id, Backend.conversation_id)
            finally:
                Backend.stream_cancelled.set()
                jobs.close()
                backend.shutdown()
                backend.server_close()
                backend_thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
