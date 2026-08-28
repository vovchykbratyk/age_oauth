from __future__ import annotations

import os
import time
from typing import Dict
from pathlib import Path


# check if python-dotenv is there, use internal fallback if not
try:
    from dotenv import load_dotenv as _dotenv_load  # type: ignore
    _HAVE_DOTENV = True
except Exception:
    _dotenv_load = None
    _HAVE_DOTENV = False


def _acquire_lock(
    lock_path: Path,
    *,
    timeout_seconds: float = 10.0,
    poll_seconds: float = 0.05,
) -> None:

    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            fd = os.open(
                str(lock_path),
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            )
            try:
                os.write(
                    fd,
                    f"pid={os.getpid()}\n".encode("utf-8"),
                )
            finally:
                os.close(fd)

            return
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Timed out waiting for env file lock: {lock_path}"
                    "if no age-oauth process is using this connection, "
                    "the lock file may be stale and can be deleted"
                )

            time.sleep(poll_seconds)


def _release_lock(lock_path: Path) -> None:
    try:
        lock_path.unlink()
    except FileNotFoundError:
        pass


def _strip_quotes(s: str) -> str:
    s = s.strip()

    if len(s) >= 2 and s[0] == s[-1]:
        if s[0] == '"':
            return (s[1:-1].replace('\\"', '"').replace("\\\\", "\\"))
        if s[0] == "'":
            return s[1:-1]
    return s


def _quote_env_value(v: str) -> str:
    if v == "" or any(c.isspace() for c in v) or "#" in v or '"' in v:
        escaped = v.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

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


def load_env(env_path: str) -> None:
    """
    load vals from an env file into os.environ without overwriting existing
    env variables

    NOTE: prefer parse_env_file() for profile reads without global side effects
    """
    env_path = str(Path(env_path).expanduser())
    if _HAVE_DOTENV and _dotenv_load is not None:
        # default override=False, matches our fallback behavior
        _dotenv_load(dotenv_path=env_path)
    else:
        _load_env_fallback(env_path)


def parse_env_file(env_path: str | Path) -> Dict[str, str]:
    """
    env file into dict (vals w/o side effects)
    """
    p = Path(env_path).expanduser()
    return _parse_env_file(p)


def set_env_key(env_path: str | Path, key: str, value: str) -> None:
    """
    setter wraps batch setter (set_env_keys)
    """
    set_env_keys(env_path, {key: value},)


def set_env_keys(
    env_path: str | Path,
    values: Dict[str, str],
) -> None:
    """
    update one more more keys in an env file

    writers are serialized with a lock to protect the entire transaction
    """
    p = Path(env_path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)

    lock_path = p.with_name(p.name + ".lock")
    _acquire_lock(lock_path)

    try:
        lines = (
            p.read_text(encoding="utf-8").splitlines() if p.exists() else []
        )

        pending = {key: str(value) for key, value in values.items()}

        written: set[str] = set()
        new_lines: list[str] = []

        for line in lines:
            stripped = line.lstrip()

            if stripped.startswith("#") or "=" not in line:
                new_lines.append(line)
                continue

            existing_key = line.split("=", 1)[0].strip()

            if existing_key in pending:
                new_lines.append(
                    f"{existing_key}="
                    f"{_quote_env_value(pending[existing_key])}"
                )
                written.add(existing_key)
            else:
                new_lines.append(line)

        missing_keys = [key for key in pending if key not in written]

        if missing_keys:
            if new_lines and new_lines[-1].strip():
                new_lines.append("")

            for key in missing_keys:
                new_lines.append(f"{key}={_quote_env_value(pending[key])}")

        text = "\n".join(new_lines) + "\n"

        tmp = p.with_name(f"{p.name}.{os.getpid()}.tmp")

        try:
            tmp.write_text(text, encoding="utf-8")
            os.replace(tmp, p)
        finally:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass

    finally:
        _release_lock(lock_path)