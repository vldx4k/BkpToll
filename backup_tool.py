#!/usr/bin/env python3
"""
backup_tool.py
Automatic backup tool with versioning, sqlite metadata, SHA-256 checks, optional AES-256 encryption,
policies for pruning, restore by version or time, logging, and a simple in-process scheduler.

Requirements:
 - Python 3.10+
 - pip install cryptography pyyaml
"""
import argparse
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

try:
    import yaml
except Exception as e:
    print("Missing dependency 'pyyaml'. Install with: pip install pyyaml")
    raise

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    import base64
except Exception:
    AESGCM = None  # encryption optional

# ----------------------------
# Constants and logging setup
# ----------------------------
APP_NAME = "bkptool"
DEFAULT_DB = "backup_index.sqlite"
DEFAULT_STORE_DIR = "backups_store"
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, f"{APP_NAME}.log")),
        logging.StreamHandler(sys.stdout),
    ],
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(APP_NAME)

# ----------------------------
# Utilities
# ----------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()

def sha256_file(path: Path, block_size: int = 65536) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(block_size), b""):
            h.update(b)
    return h.hexdigest()

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def read_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

# ----------------------------
# Encryption helper (optional)
# ----------------------------
class AESHelper:
    def __init__(self, password: str, salt: bytes = b"bkpsaltv1"):
        if AESGCM is None:
            raise RuntimeError("cryptography library required for encryption")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend(),
        )
        key = kdf.derive(password.encode())
        self._aead = AESGCM(key)

    def encrypt(self, data: bytes, aad: Optional[bytes] = None) -> bytes:
        nonce = os.urandom(12)
        ct = self._aead.encrypt(nonce, data, aad)
        return nonce + ct

    def decrypt(self, blob: bytes, aad: Optional[bytes] = None) -> bytes:
        nonce = blob[:12]
        ct = blob[12:]
        return self._aead.decrypt(nonce, ct, aad)

# ----------------------------
# Database (SQLite) wrapper
# ----------------------------
class IndexDB:
    def __init__(self, path: Path):
        ensure_dir(path.parent)
        self._path = path
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA foreign_keys = ON;")
        self._init_schema()
        self._lock = threading.Lock()

    def _init_schema(self):
        c = self._conn.cursor()
        c.executescript("""
        CREATE TABLE IF NOT EXISTS backups (
            id INTEGER PRIMARY KEY,
            uuid TEXT UNIQUE,
            type TEXT,
            started_at TEXT,
            finished_at TEXT,
            meta_json TEXT
        );
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            backup_id INTEGER,
            path TEXT,
            storage_path TEXT,
            size INTEGER,
            sha256 TEXT,
            mtime REAL,
            author TEXT,
            FOREIGN KEY(backup_id) REFERENCES backups(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
        """)
        c.close()

    @contextmanager
    def transaction(self):
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN")
                yield cur
                cur.execute("COMMIT")
            except Exception:
                cur.execute("ROLLBACK")
                raise
            finally:
                cur.close()

    def insert_backup(self, uuid: str, typ: str, meta: dict) -> int:
        with self.transaction() as cur:
            cur.execute(
                "INSERT INTO backups (uuid, type, started_at, meta_json) VALUES (?, ?, ?, ?)",
                (uuid, typ, now_iso(), json.dumps(meta)),
            )
            return cur.lastrowid

    def finish_backup(self, backup_id: int):
        with self._conn:
            self._conn.execute("UPDATE backups SET finished_at = ? WHERE id = ?", (now_iso(), backup_id))

    def insert_file(self, backup_id: int, path: str, storage_path: str, size: int, sha256: str, mtime: float, author: Optional[str]):
        with self._conn:
            self._conn.execute(
                "INSERT INTO files (backup_id, path, storage_path, size, sha256, mtime, author) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (backup_id, path, storage_path, size, sha256, mtime, author),
            )

    def list_backups(self) -> List[dict]:
        cur = self._conn.cursor()
        cur.execute("SELECT id, uuid, type, started_at, finished_at, meta_json FROM backups ORDER BY started_at DESC")
        rows = cur.fetchall()
        cur.close()
        return [
                {"id": r[0], "uuid": r[1], "type": r[2], "started_at": r[3], "finished_at": r[4], "meta": json.loads(r[5] or "{}")}
            for r in rows
        ]

    def find_backup_by_time(self, t_iso: str) -> Optional[dict]:
        # find latest backup finished_at <= t_iso
        cur = self._conn.cursor()
        cur.execute("SELECT id, uuid, type, started_at, finished_at, meta_json FROM backups WHERE finished_at<=? ORDER BY finished_at DESC LIMIT 1", (t_iso,))
        r = cur.fetchone()
        cur.close()
        if not r:
            return None
        return {"id": r[0], "uuid": r[1], "type": r[2], "started_at": r[3], "finished_at": r[4], "meta": json.loads(r[5] or "{}")}

    def list_files_for_backup(self, backup_id: int) -> List[dict]:
        cur = self._conn.cursor()
        cur.execute("SELECT path, storage_path, size, sha256, mtime, author FROM files WHERE backup_id=?",(backup_id,))
        rows = cur.fetchall()
        cur.close()
        return [
            {"path": r[0], "storage_path": r[1], "size": r[2], "sha256": r[3], "mtime": r[4], "author": r[5]}
            for r in rows
        ]

    def latest_file_entry(self, path: str) -> Optional[dict]:
        cur = self._conn.cursor()
        cur.execute("SELECT files.sha256, files.mtime, backups.id, backups.uuid FROM files JOIN backups ON files.backup_id=backups.id WHERE files.path=? ORDER BY backups.finished_at DESC LIMIT 1", (path,))
        r = cur.fetchone()
        cur.close()
        if not r:
            return None
        return {"sha256": r[0], "mtime": r[1], "backup_id": r[2], "backup_uuid": r[3]}

    def delete_backups(self, backup_ids: List[int]) -> None:
        with self._conn:
            for b in backup_ids:
                self._conn.execute("DELETE FROM backups WHERE id=?", (b,))

# ----------------------------
# Backup storage manager
# ----------------------------
@dataclass
class BackupConfig:
    store_dir: Path
    db_path: Path
    include: List[str]
    exclude: List[str]
    author: Optional[str]
    encryption: Optional[dict]  # {"enabled":bool, "password":str}
    schedule: Optional[dict]  # {"interval_seconds": int}
    retention: Optional[dict]  # {"keep_last": int, "max_age_days": int}
    block_size: int
    temp_dir: Path

    @staticmethod
    def from_dict(d: dict, base_path: Path) -> "BackupConfig":
        return BackupConfig(
            store_dir=base_path.joinpath(d.get("store_dir", DEFAULT_STORE_DIR)),
            db_path=base_path.joinpath(d.get("db_path", DEFAULT_DB)),
            include=d.get("include", ["./"]),
            exclude=d.get("exclude", []),
            author=d.get("author"),
            encryption=d.get("encryption"),
            schedule=d.get("schedule"),
            retention=d.get("retention"),
            block_size=d.get("block_size", 65536),
            temp_dir=base_path.joinpath(d.get("temp_dir", "tmp")),
        )

class BackupTool:
    def __init__(self, cfg: BackupConfig):
        self.cfg = cfg
        ensure_dir(self.cfg.store_dir)
        ensure_dir(self.cfg.temp_dir)
        ensure_dir(Path(LOG_DIR))
        self.db = IndexDB(self.cfg.db_path)
        self._storage_lock = threading.Lock()
        self._aes = None
        if self.cfg.encryption and self.cfg.encryption.get("enabled"):
            pw = self.cfg.encryption.get("password")
            if not pw:
                raise RuntimeError("Encryption enabled but no password provided in config")
            self._aes = AESHelper(pw.encode() if isinstance(pw, str) else pw)

    def _is_excluded(self, path: Path) -> bool:
        s = str(path)
        for p in self.cfg.exclude:
            if s.startswith(p):
                return True
        return False

    def _iter_files(self):
        for root in self.cfg.include:
            root_p = Path(root).expanduser().resolve()
            if not root_p.exists():
                logger.warning("Included path does not exist: %s", root_p)
                continue
            if root_p.is_file():
                yield root_p
            else:
                for dirpath, _, filenames in os.walk(root_p):
                    d = Path(dirpath)
                    for fn in filenames:
                        p = d.joinpath(fn)
                        if not self._is_excluded(p):
                            yield p

    def _copy_file_to_store(self, src: Path, rel_path: str) -> Tuple[str,int]:
        # store under store_dir/<uuid>/<sha256> or store_dir/objects/<sha256>
        sha = sha256_file(src)
        obj_dir = self.cfg.store_dir.joinpath("objects")
        ensure_dir(obj_dir)
        obj_path = obj_dir.joinpath(sha)
        if not obj_path.exists():
            # copy then maybe encrypt
            tmp = self.cfg.temp_dir.joinpath(f"tmp_{os.getpid()}_{int(time.time()*1000)}")
            ensure_dir(tmp.parent)
            try:
                shutil.copy2(src, tmp)
                with tmp.open("rb") as f:
                    data = f.read()
                if self._aes:
                    data = self._aes.encrypt(data)
                with obj_path.open("wb") as out:
                    out.write(data)
            finally:
                try:
                    tmp.unlink()
                except Exception:
                    pass
        return (str(obj_path), src.stat().st_size)

    def perform_full_backup(self) -> dict:
        backup_uuid = f"bk_{int(time.time())}"
        bmeta = {"author": self.cfg.author, "type": "full"}
        bid = self.db.insert_backup(backup_uuid, "full", bmeta)
        logger.info("Starting full backup id=%s", bid)
        try:
            for f in self._iter_files():
                try:
                    storage_path, size = self._copy_file_to_store(f, str(f))
                    sha = sha256_file(f)
                    self.db.insert_file(bid, str(f), storage_path, size, sha, f.stat().st_mtime, self.cfg.author)
                except Exception as e:
                    logger.exception("Error storing file %s: %s", f, e)
            self.db.finish_backup(bid)
            logger.info("Full backup finished id=%s", bid)
            return {"id": bid, "uuid": backup_uuid}
        except Exception:
            # On error, remove partially created backup metadata and physical temp traces
            logger.exception("Backup failed, rolling back metadata id=%s", bid)
            self.db.delete_backups([bid])
            raise

    def _generate_backup_uuid() -> str:
        return "bk_" + uuid.uuid4().hex

    def perform_incremental_backup(self) -> dict:
        bmeta = {"author": self.cfg.author, "type": "incremental"}

        # insert with retry on UNIQUE conflict
        max_retries = 3
        last_exc = None
        for attempt in range(1, max_retries + 1):
            backup_uuid = _generate_backup_uuid()
            try:
                bid = self.db.insert_backup(backup_uuid, "incremental", bmeta)
                break
            except sqlite3.IntegrityError as e:
                last_exc = e
                try:
                    logger.warning("insert_backup IntegrityError, retry %d/%d: %s", attempt, max_retries, e)
                except Exception:
                    pass
                time.sleep(0.05 * attempt)
        else:
            # all retries failed
            raise last_exc

        logger.info("Starting incremental backup id=%s", bid)
        try:
            for f in self._iter_files():
                try:
                    prev = self.db.latest_file_entry(str(f))
                    if prev:
                        mtime = f.stat().st_mtime
                        if abs(prev["mtime"] - mtime) < 0.0001:
                            continue
                        sha = sha256_file(f)
                        if sha == prev["sha256"]:
                            continue
                    storage_path, size = self._copy_file_to_store(f, str(f))
                    sha = sha256_file(f)
                    self.db.insert_file(bid, str(f), storage_path, size, sha, f.stat().st_mtime, self.cfg.author)
                except Exception as e:
                    logger.exception("Error storing file %s: %s", f, e)
            self.db.finish_backup(bid)
            logger.info("Incremental backup finished id=%s", bid)
            return {"id": bid, "uuid": backup_uuid}
        except Exception:
            logger.exception("Incremental backup failed, rolling back metadata id=%s", bid)
            self.db.delete_backups([bid])
            raise

    def list_backups(self) -> List[dict]:
        return self.db.list_backups()

    def restore_file(self, target_path: str, dest: Path, backup_id: Optional[int] = None, as_preview: bool = True) -> bool:
        # find file entry
        if backup_id is None:
            # choose latest
            backups = self.db.list_backups()
            if not backups:
                logger.error("No backups available")
                return False
            backup_id = backups[0]["id"]
        files = self.db.list_files_for_backup(backup_id)
        entry = next((f for f in files if f["path"] == target_path), None)
        if not entry:
            logger.error("File not found in backup id=%s: %s", backup_id, target_path)
            return False
        src = Path(entry["storage_path"])
        if not src.exists():
            logger.error("Stored object missing: %s", src)
            return False
        with src.open("rb") as f:
            data = f.read()
        if self._aes:
            data = self._aes.decrypt(data)
        dest_parent = dest.parent
        ensure_dir(dest_parent)
        out_path = dest if not as_preview else dest_parent.joinpath(dest.name + ".preview")
        with out_path.open("wb") as out:
            out.write(data)
        # verify sha
        got_sha = hashlib.sha256()
        with out_path.open("rb") as f:
            for b in iter(lambda: f.read(65536), b""):
                got_sha.update(b)
        if got_sha.hexdigest() != entry["sha256"]:
            logger.error("SHA mismatch after restore for %s", target_path)
            return False
        logger.info("Restored %s -> %s (preview=%s)", target_path, out_path, as_preview)
        return True

    def restore_by_time(self, target_path: str, dest: Path, t_iso: str, as_preview: bool = True) -> bool:
        b = self.db.find_backup_by_time(t_iso)
        if not b:
            logger.error("No backup found at or before %s", t_iso)
            return False
        return self.restore_file(target_path, dest, backup_id=b["id"], as_preview=as_preview)

    def run_retention_policy(self, preview: bool = True) -> dict:
        # retention: keep_last, max_age_days
        policy = self.cfg.retention or {}
        keep_last = int(policy.get("keep_last", 0))
        max_age = int(policy.get("max_age_days", 0))
        all_b = self.db.list_backups()
        ids_to_delete = []
        if keep_last > 0 and len(all_b) > keep_last:
            ids_to_delete.extend([b["id"] for b in all_b[keep_last:]])
        if max_age > 0:
            cutoff = datetime.now(timezone.utc).astimezone().timestamp() - max_age * 86400
            for b in all_b:
                finished = b.get("finished_at")
                if finished:
                    ts = datetime.fromisoformat(finished).timestamp()
                    if ts < cutoff:
                        if b["id"] not in ids_to_delete:
                            ids_to_delete.append(b["id"])
        # preview mode: list but do not delete
        if preview:
            logger.info("Retention preview - candidates: %s", ids_to_delete)
            return {"preview": True, "candidates": ids_to_delete}
        # physical deletion: delete metadata and corresponding stored objects not referenced by others
        logger.info("Deleting backups: %s", ids_to_delete)
        # collect referenced objects to keep
        keep_objs = set()
        for b in all_b:
            if b["id"] not in ids_to_delete:
                for f in self.db.list_files_for_backup(b["id"]):
                    keep_objs.add(f["sha256"])
        # delete backup metadata
        self.db.delete_backups(ids_to_delete)
        # scan store objects and delete unreferenced
        obj_dir = self.cfg.store_dir.joinpath("objects")
        for obj in obj_dir.iterdir():
            if obj.is_file():
                if obj.name not in keep_objs:
                    try:
                        obj.unlink()
                        logger.info("Removed object %s", obj)
                    except Exception:
                        logger.exception("Failed to remove object %s", obj)
        return {"preview": False, "deleted": ids_to_delete}

    def check_integrity(self, sample: Optional[int] = None) -> dict:
        # sample N files (or all if None), verify stored object hashes match index and file content if decryptable
        results = {"checked": 0, "ok": 0, "failures": []}
        backups = self.db.list_backups()
        for b in backups:
            files = self.db.list_files_for_backup(b["id"])
            for f in files:
                results["checked"] += 1
                obj = Path(f["storage_path"])
                if not obj.exists():
                    results["failures"].append({"file": f["path"], "reason": "missing object", "backup": b["id"]})
                    continue
                try:
                    with obj.open("rb") as fh:
                        data = fh.read()
                    if self._aes:
                        data = self._aes.decrypt(data)
                    h = hashlib.sha256(data).hexdigest()
                    if h != f["sha256"]:
                        results["failures"].append({"file": f["path"], "reason": "sha_mismatch", "backup": b["id"]})
                    else:
                        results["ok"] += 1
                except Exception as e:
                    results["failures"].append({"file": f["path"], "reason": f"error:{e}", "backup": b["id"]})
                if sample and results["checked"] >= sample:
                    return results
        return results

    # Simple in-process scheduler
    def start_scheduler(self):
        if not self.cfg.schedule or not self.cfg.schedule.get("interval_seconds"):
            logger.info("No schedule configured")
            return
        interval = int(self.cfg.schedule["interval_seconds"])
        def loop():
            logger.info("Scheduler started: interval=%s seconds", interval)
            while True:
                try:
                    # do an incremental backup by default
                    self.perform_incremental_backup()
                except Exception:
                    logger.exception("Scheduled backup failed")
                time.sleep(interval)
        t = threading.Thread(target=loop, daemon=True)
        t.start()
        logger.info("Scheduler thread launched")

# ----------------------------
# CLI
# ----------------------------
def load_config(path: Optional[str]) -> BackupConfig:
    base = Path(".").resolve()
    cfg_path = Path(path) if path else base.joinpath("config.yaml")
    if not cfg_path.exists():
        logger.error("Config file not found: %s", cfg_path)
        raise FileNotFoundError(cfg_path)
    d = read_yaml(cfg_path)
    return BackupConfig.from_dict(d, base)

def cli():
    parser = argparse.ArgumentParser(prog="backup_tool", description="Backup tool with versioning")
    parser.add_argument("--config", "-c", help="Path to YAML config", default="config.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("full", help="Run a full backup")
    sub.add_parser("inc", help="Run an incremental backup")
    sub.add_parser("list", help="List backups")
    restore = sub.add_parser("restore", help="Restore a file from backup")
    restore.add_argument("file", help="Path of file as stored in backup (absolute or relative)")
    restore.add_argument("dest", help="Destination path to restore to")
    restore.add_argument("--time", help="ISO time to restore as of (use latest <= time)")

    prune = sub.add_parser("prune", help="Run retention policy (preview by default)")
    prune.add_argument("--apply", action="store_true", help="Apply deletion (not preview)")

    check = sub.add_parser("check", help="Check integrity")
    check.add_argument("--sample", type=int, help="Number of files to sample")

    sub.add_parser("start-scheduler", help="Start built-in scheduler (runs in foreground)")

    args = parser.parse_args()
    cfg = load_config(args.config)
    tool = BackupTool(cfg)

    if args.command == "full":
        res = tool.perform_full_backup()
        print(json.dumps(res))
    elif args.command == "inc":
        res = tool.perform_incremental_backup()
        print(json.dumps(res))
    elif args.command == "list":
        print(json.dumps(tool.list_backups(), indent=2))
    elif args.command == "restore":
        dest = Path(args.dest).expanduser().resolve()
        t = args.time
        if t:
            ok = tool.restore_by_time(args.file, dest, t, as_preview=True)
        else:
            ok = tool.restore_file(args.file, dest, as_preview=True)
        print("ok" if ok else "failed")
    elif args.command == "prune":
        res = tool.run_retention_policy(preview=not args.apply)
        print(json.dumps(res, indent=2))
    elif args.command == "check":
        res = tool.check_integrity(sample=args.sample)
        print(json.dumps(res, indent=2))
    elif args.command == "start-scheduler":
        tool.start_scheduler()
        # run forever
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            logger.info("Scheduler stopped by user")
    else:
        parser.print_help()

if __name__ == "__main__":
    cli()
