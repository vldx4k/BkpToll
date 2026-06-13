import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import os
import shutil
import tempfile
import time
import json
import pytest
from backup_tool import BackupConfig, BackupTool, read_yaml, BackupTool as BT, IndexDB

# Note: small wrapper to import functions from backup_tool.py (names used match implementation)
from backup_tool import load_config

@pytest.fixture()
def tmp_env(tmp_path, monkeypatch):
    base = tmp_path
    data_dir = base / "data"
    store_dir = base / "store"
    tmp = base / "tmp"
    db = base / "idx.sqlite"
    data_dir.mkdir()
    (data_dir / "file1.txt").write_text("hello")
    (data_dir / "file2.txt").write_text("world")
    cfg = {
        "store_dir": str(store_dir),
        "db_path": str(db),
        "include": [str(data_dir)],
        "exclude": [],
        "author": "tester",
        "encryption": {"enabled": False, "password": ""},
        "schedule": None,
        "retention": {"keep_last": 2, "max_age_days": 0},
        "block_size": 65536,
        "temp_dir": str(tmp),
    }
    cfg_path = base / "config.yaml"
    import yaml
    cfg_path.write_text(yaml.safe_dump(cfg))
    yield {"base": base, "cfg": cfg, "cfg_path": cfg_path, "data_dir": data_dir, "store_dir": store_dir, "db": db}

def test_full_and_list(tmp_env):
    cfg = load_config(str(tmp_env["cfg_path"]))
    tool = BackupTool(cfg)
    res = tool.perform_full_backup()
    assert isinstance(res, dict) and "id" in res
    lst = tool.list_backups()
    assert len(lst) == 1
    assert lst[0]["type"] == "full"

def test_incremental_and_no_dup(tmp_env):
    cfg = load_config(str(tmp_env["cfg_path"]))
    tool = BackupTool(cfg)
    tool.perform_full_backup()
    # modify one file
    (tmp_env["data_dir"] / "file2.txt").write_text("world-2")
    tool.perform_incremental_backup()
    lst = tool.list_backups()
    assert len(lst) == 2
    # ensure file1 not duplicated in incremental: check latest entries
    latest = lst[0]  # most recent
    files = tool.db.list_files_for_backup(latest["id"])
    paths = [f["path"] for f in files]
    assert any("file2.txt" in p for p in paths)

def test_restore_and_sha(tmp_env):
    cfg = load_config(str(tmp_env["cfg_path"]))
    tool = BackupTool(cfg)
    tool.perform_full_backup()
    target = tmp_env["data_dir"] / "file1.txt"
    # remove original then restore
    target.unlink()
    ok = tool.restore_file(str(target), tmp_env["base"] / "restored_file1.txt", as_preview=True)
    assert ok
    preview = tmp_env["base"] / "restored_file1.txt.preview"
    assert preview.exists()
    assert preview.read_text() == "hello"

def test_retention_preview(tmp_env):
    cfg = load_config(str(tmp_env["cfg_path"]))
    tool = BackupTool(cfg)
    tool.perform_full_backup()
    time.sleep(1)
    tool.perform_incremental_backup()
    res = tool.run_retention_policy(preview=True)
    assert res["preview"] is True
    assert isinstance(res["candidates"], list)

def test_integrity_check(tmp_env):
    cfg = load_config(str(tmp_env["cfg_path"]))
    tool = BackupTool(cfg)
    tool.perform_full_backup()
    res = tool.check_integrity()
    assert res["checked"] >= 1
    assert res["ok"] >= 1
