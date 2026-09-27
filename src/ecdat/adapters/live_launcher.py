"""Generic external-tool launcher indirection + cross-environment path
translation (DEV-016; docs/open-issues.md OI-009).

Some pinned external tools this project shells out to (semgrep; on this
particular dev machine, also trivy) do not run on native Windows Python --
OI-009: `pip install semgrep` fails on native Windows with semgrep's own
"Semgrep does not support Windows yet, please try again with WSL". The
working fix recorded there is running the *same pinned tool version* inside
this machine's already-present WSL Ubuntu distro, reaching the Windows
checkout through `/mnt/c/...`.

This module makes that a **generic launcher-prefix mechanism**, not a
WSL-specific hack baked into an adapter: any adapter's live `ScanRunner` can
prepend an arbitrary command (`wsl -e`, `ssh host`, a container `exec`, ...)
in front of its pinned argv, resolved from an env var, with no adapter code
ever hardcoding "wsl" as a literal. WSL is simply the one launcher this
project currently has a `PathTranslator` for.

Two independent knobs, both optional and both off by default (a bare tool on
PATH, no translation -- today's Linux/macOS/CI behaviour is unchanged):

* **Launcher prefix** -- `ECDAT_<TOOL>_LAUNCHER` (e.g. `ECDAT_SEMGREP_LAUNCHER`)
  wins over the generic `ECDAT_TOOL_LAUNCHER`. Split with `shlex.split`, so
  `ECDAT_TOOL_LAUNCHER="wsl -e"` becomes `["wsl", "-e"]`, prepended to the
  tool's own argv.
* **Tool binary** -- `ECDAT_<TOOL>_BIN` (e.g. `ECDAT_SEMGREP_BIN`) names the
  binary to invoke *inside* the launched environment (default: the tool's
  bare name, e.g. `"semgrep"`) -- mirrors the existing
  `tls.adapter.ECDAT_OPENSSL_BIN` convention for a single external tool,
  generalised to any tool name.

**Path translation** matters because a launched tool may run in a different
filesystem namespace than this process: an argv path built from
`target.locator` (a Windows path here) must be translated *into* the tool's
own namespace before it is passed, and any path the tool prints back in its
own output must be translated back *out* -- so findings still carry the
Windows-relative paths the harness joins on, never a `/mnt/c/...` path a
Windows-side consumer cannot resolve. `resolve_path_translator` infers `wsl`
translation automatically when the resolved launcher's first token is
literally `wsl`, or it can be forced/disabled per tool with
`ECDAT_<TOOL>_PATH_TRANSLATE` (`wsl` or `identity`) -- kept overridable so a
future non-WSL launcher (say, `ssh` into a Linux box that mounts the same
tree at the same paths) is not forced through WSL's `/mnt/<drive>` rule.
"""
from __future__ import annotations

import os
import shlex
from typing import Protocol


class PathTranslator(Protocol):
    """Translates one path string across the boundary a launcher crosses."""

    def to_tool(self, path: str) -> str:
        """A path in *this* process's namespace -> the path the launched
        tool must be given to reach the same file."""
        ...

    def from_tool(self, path: str) -> str:
        """A path the launched tool printed in its own output -> the
        equivalent path in *this* process's namespace."""
        ...


class IdentityPathTranslator:
    """No launcher, or a launcher that shares this process's filesystem
    namespace (e.g. a plain subprocess on the same machine): paths pass
    through unchanged."""

    def to_tool(self, path: str) -> str:
        return path

    def from_tool(self, path: str) -> str:
        return path


class WslPathTranslator:
    """Windows path <-> WSL path, e.g. `C:\\Atharv's Stack\\ECDAT` <->
    `/mnt/c/Atharv's Stack/ECDAT`.

    Pure string logic -- no `wslpath` subprocess call -- so this is
    exercisable in tests without WSL installed, and so it has no dependency
    on WSL actually being present to translate a path correctly. Handles
    only the one WSL convention this project relies on (`/mnt/<drive>/...`
    for a Windows drive); a WSL-internal-only path (e.g. `/home/user/...`)
    is returned unchanged by `to_tool` since there is no Windows-side
    equivalent to construct, and by `from_tool` since there is nothing to
    translate back.
    """

    def to_tool(self, path: str) -> str:
        posix = path.replace("\\", "/")
        if len(posix) >= 2 and posix[1] == ":" and posix[0].isalpha():
            drive = posix[0].lower()
            rest = posix[2:]
            if rest and not rest.startswith("/"):
                rest = "/" + rest
            return f"/mnt/{drive}{rest}"
        return posix

    def from_tool(self, path: str) -> str:
        if path.startswith("/mnt/") and len(path) >= 7 and path[6] == "/":
            drive = path[5]
            if drive.isalpha():
                rest = path[6:]
                return f"{drive.upper()}:{rest}".replace("/", "\\")
        return path


def _env_tool_key(tool: str) -> str:
    return tool.strip().upper().replace("-", "_")


def resolve_launcher_prefix(tool: str, *, env: dict[str, str] | None = None) -> list[str]:
    """The argv prefix to prepend before `tool`'s own argv.

    `env` is injectable for tests; defaults to the real process environment.
    Empty (no prefix) unless one of the two env vars is set and non-blank.
    """
    environ = env if env is not None else os.environ
    specific = environ.get(f"ECDAT_{_env_tool_key(tool)}_LAUNCHER")
    raw = specific if specific else environ.get("ECDAT_TOOL_LAUNCHER")
    if not raw or not raw.strip():
        return []
    return shlex.split(raw)


def resolve_tool_bin(tool: str, default: str, *, env: dict[str, str] | None = None) -> str:
    """The binary name/path to invoke inside the launched environment --
    `ECDAT_<TOOL>_BIN`, else `default` (the tool's bare name)."""
    environ = env if env is not None else os.environ
    value = environ.get(f"ECDAT_{_env_tool_key(tool)}_BIN")
    return value if value and value.strip() else default


def resolve_path_translator(
    tool: str, launcher_prefix: list[str], *, env: dict[str, str] | None = None
) -> PathTranslator:
    """Which `PathTranslator` to use for `tool`.

    Explicit `ECDAT_<TOOL>_PATH_TRANSLATE` (`wsl` | `identity`) wins; absent
    that, `wsl` is inferred exactly when `launcher_prefix[0] == "wsl"` (the
    one case this project can infer safely without guessing); anything else
    defaults to identity, never silently guessing at an unfamiliar
    launcher's filesystem semantics.
    """
    environ = env if env is not None else os.environ
    override = environ.get(f"ECDAT_{_env_tool_key(tool)}_PATH_TRANSLATE")
    if override:
        name = override.strip().lower()
    elif launcher_prefix and launcher_prefix[0].lower() == "wsl":
        name = "wsl"
    else:
        name = "identity"
    if name == "wsl":
        return WslPathTranslator()
    return IdentityPathTranslator()


def build_launched_argv(launcher_prefix: list[str], tool_argv: list[str]) -> list[str]:
    """Prepend `launcher_prefix` to `tool_argv`. A pure function so the
    composed argv shape is assertable without shelling out."""
    return [*launcher_prefix, *tool_argv]
