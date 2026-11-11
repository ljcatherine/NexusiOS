"""Durable, single-use approval records. This module performs no workspace writes."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import uuid

from run_jobs import PRINCIPAL_ID, WORKSPACE_ID

HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
SUBMISSION_ID = re.compile(r"^[0-9a-f]{32}$")
MAX_REPLACEMENT_BYTES = 64 * 1024
MAX_APPROVALS = 1024

class ApprovalConflict(ValueError):
    """A saved proposal submission cannot be reused for different contents."""


class ApprovalStore:
    """Uses the run store's owner-only SQLite database and exclusive lock."""

    def __init__(self, runs):
        self.runs = runs
        with runs.lock:
            runs.db.execute("""CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY, owner TEXT NOT NULL, digest TEXT NOT NULL,
                proposal TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL,
                status TEXT NOT NULL, updated REAL NOT NULL
            )""")
            runs.db.execute("""CREATE TABLE IF NOT EXISTS approval_submissions (
                owner TEXT NOT NULL, submission_id TEXT NOT NULL,
                approval_id TEXT NOT NULL, digest TEXT NOT NULL,
                PRIMARY KEY(owner,submission_id)
            )""")
            runs.db.execute("""CREATE TABLE IF NOT EXISTS approval_origins (
                approval_id TEXT PRIMARY KEY, owner TEXT NOT NULL, origin TEXT NOT NULL
            )""")

    @staticmethod
    def _validate(owner: str, proposal: dict) -> str:
        if not isinstance(owner, str) or not PRINCIPAL_ID.fullmatch(owner):
            raise ValueError("invalid approval owner")
        fields = {"host", "workspace_id", "path", "base_sha256", "original", "replacement"}
        if (not isinstance(proposal, dict) or set(proposal) not in (fields, fields | {"workspace_generation"}) or
                ("workspace_generation" in proposal and (not isinstance(proposal["workspace_generation"], str) or
                 not HEX_DIGEST.fullmatch(proposal["workspace_generation"])))):
            raise ValueError("invalid replacement proposal")
        host, root, path = proposal["host"], proposal["workspace_id"], proposal["path"]
        digest, replacement = proposal["base_sha256"], proposal["replacement"]
        original = proposal["original"]
        if (host not in ("debian", "nixos") or not isinstance(root, str) or not WORKSPACE_ID.fullmatch(root) or
                not isinstance(path, str) or not path or len(path.encode("utf-8")) > 512 or
                path.startswith("/") or any(c in path for c in "\\\x00\r\n") or
                len(path.split("/")) > 12 or any(not part or part.startswith(".") or len(part.encode("utf-8")) > 255
                                                   for part in path.split("/")) or
                not isinstance(digest, str) or not HEX_DIGEST.fullmatch(digest) or
                not isinstance(replacement, str) or "\x00" in replacement or
                len(replacement.encode("utf-8")) > MAX_REPLACEMENT_BYTES or
                not isinstance(original, str) or "\x00" in original or
                len(original.encode("utf-8")) > MAX_REPLACEMENT_BYTES or
                hashlib.sha256(original.encode("utf-8")).hexdigest() != digest):
            raise ValueError("invalid replacement proposal")
        return json.dumps(proposal, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def propose(self, owner: str, proposal: dict, *, ttl: int = 900, submission_id: str | None = None,
                origin: str = 'legacy') -> dict:
        if origin not in ('legacy', 'manual', 'agent'):
            raise ValueError('invalid proposal origin')
        if type(ttl) is not int or not 1 <= ttl <= 3600:
            raise ValueError("invalid approval lifetime")
        if submission_id is not None and (not isinstance(submission_id, str) or not SUBMISSION_ID.fullmatch(submission_id)):
            raise ValueError("invalid proposal submission ID")
        canonical = self._validate(owner, proposal)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        now = time.time()
        approval_id = uuid.uuid4().hex
        with self.runs.lock:
            self.runs.db.execute("BEGIN IMMEDIATE")
            try:
                previous = self.runs.db.execute(
                    "SELECT approval_id,digest FROM approval_submissions WHERE owner=? AND submission_id=?",
                    (owner, submission_id)).fetchone() if submission_id is not None else None
                if previous:
                    if not hmac.compare_digest(previous[1], digest):
                        raise ApprovalConflict("proposal submission conflicts with its saved contents")
                    item = self.get(owner, previous[0])
                    if item is None:
                        raise ApprovalConflict("saved proposal is unavailable; it cannot be replayed")
                    if self.origin(owner, item['id']) not in ('legacy', origin):
                        raise ApprovalConflict('proposal origin cannot change')
                    self.runs.db.execute("COMMIT")
                    return item
                count = self.runs.db.execute("SELECT COUNT(*) FROM approvals").fetchone()[0]
                if count >= MAX_APPROVALS:
                    raise OverflowError("approval history capacity reached")
                self.runs.db.execute("INSERT INTO approvals VALUES(?,?,?,?,?,?,?,?)",
                                     (approval_id, owner, digest, canonical, now, now + ttl, "pending", now))
                self.runs.db.execute('INSERT INTO approval_origins VALUES(?,?,?)', (approval_id, owner, origin))
                if submission_id is not None:
                    self.runs.db.execute("INSERT INTO approval_submissions VALUES(?,?,?,?)",
                                         (owner, submission_id, approval_id, digest))
                self.runs.db.execute("COMMIT")
            except BaseException:
                self.runs.db.execute("ROLLBACK")
                raise
        return self.get(owner, approval_id)

    def origin(self, owner: str, approval_id: str) -> str:
        """Missing old provenance never implicitly grants manual execution."""
        if self.get(owner, approval_id) is None:
            raise ApprovalConflict('owned proposal is unavailable')
        with self.runs.lock:
            row = self.runs.db.execute('SELECT owner,origin FROM approval_origins WHERE approval_id=?',
                                      (approval_id,)).fetchone()
        if row is None:
            return 'legacy'
        if row[0] != owner or row[1] not in ('legacy', 'manual', 'agent'):
            raise ApprovalConflict('stored proposal provenance is invalid')
        return row[1]

    def get(self, owner: str, approval_id: str) -> dict | None:
        if not isinstance(owner, str) or not PRINCIPAL_ID.fullmatch(owner):
            raise ValueError("invalid approval owner")
        if not isinstance(approval_id, str) or not SUBMISSION_ID.fullmatch(approval_id):
            return None
        with self.runs.lock:
            row = self.runs.db.execute("SELECT id,digest,proposal,created,expires,status FROM approvals "
                                       "WHERE id=? AND owner=?", (approval_id, owner)).fetchone()
        if row is None:
            return None
        if not hmac.compare_digest(hashlib.sha256(row[2].encode("utf-8")).hexdigest(), row[1]):
            raise ValueError("approval record integrity check failed")
        proposal = json.loads(row[2])
        if self._validate(owner, proposal) != row[2]:
            raise ValueError("approval record is not canonical")
        return {"id": row[0], "digest": row[1], "proposal": proposal,
                "created_at": row[3], "expires_at": row[4], "status": row[5]}

    def get_submission(self, owner: str, submission_id: str) -> dict | None:
        if (not isinstance(owner, str) or not PRINCIPAL_ID.fullmatch(owner) or
                not isinstance(submission_id, str) or not SUBMISSION_ID.fullmatch(submission_id)):
            raise ValueError("invalid proposal identity")
        with self.runs.lock:
            row = self.runs.db.execute("SELECT approval_id,digest FROM approval_submissions WHERE owner=? AND submission_id=?",
                                       (owner, submission_id)).fetchone()
            if row is None:
                return None
            item = self.get(owner, row[0])
            if item is None or not hmac.compare_digest(item["digest"], row[1]):
                raise ApprovalConflict("saved proposal identity is unavailable")
            return item

    def list_scope(self, owner: str, host: str, workspace_id: str) -> list[dict]:
        if not isinstance(owner, str) or not PRINCIPAL_ID.fullmatch(owner):
            raise ValueError("invalid approval owner")
        with self.runs.lock:
            ids = self.runs.db.execute("SELECT id FROM approvals WHERE owner=? ORDER BY created DESC LIMIT ?",
                                       (owner, MAX_APPROVALS)).fetchall()
            items = []
            for (approval_id,) in ids:
                item = self.get(owner, approval_id)
                proposal = item["proposal"]
                if (proposal["host"], proposal["workspace_id"]) != (host, workspace_id):
                    continue
                metadata = {key: value for key, value in item.items() if key != "proposal"}
                metadata.update({"path": proposal["path"], "base_sha256": proposal["base_sha256"]})
                items.append(metadata)
                if len(items) == 100:
                    break
            return items

    def transition(self, owner: str, approval_id: str, digest: str, *, expected: str, target: str) -> bool:
        """Atomically review an exact proposal once, before expiry.

        Execution claims belong exclusively to PatchExecutionStore, which creates
        its operation journal in the same transaction as approval consumption.
        """
        if not isinstance(owner, str) or not PRINCIPAL_ID.fullmatch(owner) or not isinstance(digest, str) or not HEX_DIGEST.fullmatch(digest):
            return False
        if not isinstance(approval_id, str) or not SUBMISSION_ID.fullmatch(approval_id):
            return False
        if (expected, target) not in (("pending", "approved"), ("pending", "rejected")):
            raise ValueError("invalid approval transition")
        now = time.time()
        with self.runs.lock:
            row = self.runs.db.execute("SELECT proposal FROM approvals WHERE id=? AND owner=? AND digest=?",
                                       (approval_id, owner, digest)).fetchone()
            if row is None or not hmac.compare_digest(
                    hashlib.sha256(row[0].encode("utf-8")).hexdigest(), digest):
                return False
            try:
                if self._validate(owner, json.loads(row[0])) != row[0]:
                    return False
            except (ValueError, TypeError, UnicodeError):
                return False
            cursor = self.runs.db.execute("UPDATE approvals SET status=?,updated=? WHERE id=? AND owner=? "
                                          "AND digest=? AND status=? AND expires>?",
                                          (target, now, approval_id, owner, digest, expected, now))
            return cursor.rowcount == 1
