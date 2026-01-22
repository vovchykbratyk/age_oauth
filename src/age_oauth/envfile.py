from __future__ import annotations

import os
from typing import Dict
from pathlib import Path


# check if python-dotenv is there, use internal fallback if not
try:
    from dotenv import load_dotenv as _dotenv_load  # type: ignore
    from dotenv import set_key as _dotenv_set_key   # type: ignore
    _HAVE_DOTENV = True
except Exception:
    _dotenv_load = None
    _dotenv_set_key = None
    _HAVE_DOTENV = False


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and ((s[0] == s[-1]) and s[0] in ("'", '"')):
        return s[1:-1]
    return s


def _quote_env_value(v: str) -> str:
    if v == "" or any(c.isspace() for c in v) or "#" in v:
        return '"' + v.replace('"', '\\"') + '"'
    return v


def _parse_env_file(path: Path) -> Dict[str, str]:
    """
    minimalistic env parser
    """
    data: Dict[str, str] = {}
    if not path.exists():
        return data

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = _strip_quotes(value.strip())
        if key:
            data[key] = value
    return data


def _load_env_fallback(env_path: str) -> Dict[str, str]:
    """
    loads .env to os.environ if we don't have python-dotenv available.
    does NOT clobber existing environment variables.
    """
    p = Path(env_path).expanduser()
    parsed = _parse_env_file(p)

    for k, v in parsed.items():
        os.environ.setdefault(k, v)

    return parsed


def _set_key_fallback(env_path: str, key: str, value: str) -> None:
    """
    minimalistic .env writer
    """
    p = Path(env_path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)

    lines = []
    if p.exists():
        lines = p.read_text(encoding="utf-8").splitlines()

    quoted_val = _quote_env_value(value)
    updated = False
    new_lines = []

    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("#") or "=" not in line:
            new_lines.append(line)
            continue

        existing_key = line.split("=", 1)[0].strip()
        if existing_key == key:
            new_lines.append(f"{key}={quoted_val}")
            updated = True
        else:
            new_lines.append(line)

    if not updated:
        if new_lines and new_lines[-1].strip() != "":
            new_lines.append("")  # nice separation
        new_lines.append(f"{key}={quoted_val}")

    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    tmp.replace(p)


def load_env(env_path: str) -> None:
    """
    loader uses python-dotenv when present, falls back to local functions
    """
    env_path = str(Path(env_path).expanduser())
    if _HAVE_DOTENV and _dotenv_load is not None:
        # default override=False, matches our fallback behavior
        _dotenv_load(dotenv_path=env_path)
    else:
        _load_env_fallback(env_path)


def read_env(env_path: str | Path) -> Dict[str, str]:
    """
    read env file into straight dict without modding os.environ
    (for callers that need vals w/o side effects)
    """
    p = Path(env_path).expanduser()
    return _parse_env_file(p)


def set_env_key(env_path: str, key: str, value: str) -> None:
    """
    setter uses python-dotenv when present, falls back to local functions
    """
    env_path = str(Path(env_path).expanduser())
    if _HAVE_DOTENV and _dotenv_set_key is not None:
        _dotenv_set_key(env_path, key, value)
    else:
        _set_key_fallback(env_path, key, value)