"""仓库路径解析。所有路径都相对 KB_ROOT，禁止绝对路径逃逸。"""
from __future__ import annotations

import os
from pathlib import Path

ENV_KB_ROOT = "VULN_ATLAS_KB"
ENV_DB = "VULN_ATLAS_DB"


def repo_root() -> Path:
    """包所在仓库的根目录（vuln_atlas/ 的上一级）。"""
    return Path(__file__).resolve().parent.parent


def kb_root() -> Path:
    """知识库根目录，默认 <repo>/kb，可用 VULN_ATLAS_KB 覆盖。"""
    env = os.environ.get(ENV_KB_ROOT)
    if env:
        return Path(env).expanduser().resolve()
    return repo_root() / "kb"


def db_path() -> Path:
    """index.db 路径，默认 <kb>/index.db，可用 VULN_ATLAS_DB 覆盖。"""
    env = os.environ.get(ENV_DB)
    if env:
        return Path(env).expanduser().resolve()
    return kb_root() / "index.db"


def cards_dir() -> Path:
    return kb_root() / "cards"


def artifacts_dir() -> Path:
    return kb_root() / "artifacts"


def raw_dir() -> Path:
    return kb_root() / "raw"


def manifest_path() -> Path:
    return kb_root() / "manifest.json"


def ensure_dirs() -> None:
    for p in (kb_root(), cards_dir(), artifacts_dir(), raw_dir()):
        p.mkdir(parents=True, exist_ok=True)


def safe_join(base: Path, relative: str) -> Path:
    """把卡内相对路径解析到 base 下，拒绝 `..` 逃逸与符号链接逃逸（§11）。"""
    rel = relative.strip().lstrip("/")
    target = (base / rel).resolve()
    base_r = base.resolve()
    if base_r != target and base_r not in target.parents:
        raise ValueError(f"路径逃逸: {relative}")
    # 逐级检查符号链接
    cur = base_r
    for part in Path(rel).parts:
        cur = cur / part
        if cur.is_symlink():
            raise ValueError(f"符号链接不允许: {relative}")
    return target
