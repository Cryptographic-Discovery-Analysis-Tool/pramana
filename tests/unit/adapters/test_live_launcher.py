"""Generic launcher-prefix + path-translation seam (DEV-016; OI-009).

No real WSL, no real subprocess anywhere in this file: `resolve_*` take an
injected `env` dict, and the translators are pure string logic.
"""
from __future__ import annotations

from ecdat.adapters.live_launcher import (
    IdentityPathTranslator,
    WslPathTranslator,
    build_launched_argv,
    resolve_launcher_prefix,
    resolve_path_translator,
    resolve_tool_bin,
)


# --- resolve_launcher_prefix -------------------------------------------------


def test_no_env_var_means_no_launcher():
    assert resolve_launcher_prefix("semgrep", env={}) == []


def test_generic_launcher_env_var_is_split_with_shlex():
    assert resolve_launcher_prefix("semgrep", env={"ECDAT_TOOL_LAUNCHER": "wsl -e"}) == [
        "wsl",
        "-e",
    ]


def test_per_tool_launcher_env_var_wins_over_generic():
    env = {
        "ECDAT_TOOL_LAUNCHER": "wsl -e",
        "ECDAT_TRIVY_LAUNCHER": "ssh linuxbox",
    }
    assert resolve_launcher_prefix("trivy", env=env) == ["ssh", "linuxbox"]
    # a different tool still falls back to the generic one
    assert resolve_launcher_prefix("semgrep", env=env) == ["wsl", "-e"]


def test_blank_launcher_env_var_means_no_launcher():
    assert resolve_launcher_prefix("semgrep", env={"ECDAT_TOOL_LAUNCHER": "   "}) == []


def test_launcher_prefix_handles_a_quoted_argument():
    env = {"ECDAT_TOOL_LAUNCHER": "ssh 'my host'"}
    assert resolve_launcher_prefix("trivy", env=env) == ["ssh", "my host"]


# --- resolve_tool_bin ---------------------------------------------------------


def test_tool_bin_defaults_to_the_bare_name():
    assert resolve_tool_bin("semgrep", "semgrep", env={}) == "semgrep"


def test_tool_bin_env_var_overrides_default():
    env = {"ECDAT_SEMGREP_BIN": "/usr/local/bin/semgrep"}
    assert resolve_tool_bin("semgrep", "semgrep", env=env) == "/usr/local/bin/semgrep"


def test_tool_bin_env_var_is_tool_specific():
    env = {"ECDAT_TRIVY_BIN": "/usr/local/bin/trivy"}
    assert resolve_tool_bin("semgrep", "semgrep", env=env) == "semgrep"


# --- resolve_path_translator --------------------------------------------------


def test_wsl_launcher_infers_wsl_translator():
    translator = resolve_path_translator("semgrep", ["wsl", "-e"], env={})
    assert isinstance(translator, WslPathTranslator)


def test_non_wsl_launcher_defaults_to_identity():
    translator = resolve_path_translator("semgrep", ["ssh", "host"], env={})
    assert isinstance(translator, IdentityPathTranslator)


def test_no_launcher_defaults_to_identity():
    translator = resolve_path_translator("semgrep", [], env={})
    assert isinstance(translator, IdentityPathTranslator)


def test_explicit_override_forces_identity_even_under_wsl_launcher():
    env = {"ECDAT_SEMGREP_PATH_TRANSLATE": "identity"}
    translator = resolve_path_translator("semgrep", ["wsl", "-e"], env=env)
    assert isinstance(translator, IdentityPathTranslator)


def test_explicit_override_forces_wsl_even_without_a_wsl_launcher():
    env = {"ECDAT_SEMGREP_PATH_TRANSLATE": "wsl"}
    translator = resolve_path_translator("semgrep", ["ssh", "host"], env=env)
    assert isinstance(translator, WslPathTranslator)


# --- build_launched_argv ------------------------------------------------------


def test_build_launched_argv_prepends_the_prefix():
    assert build_launched_argv(["wsl", "-e"], ["semgrep", "--json", "x"]) == [
        "wsl",
        "-e",
        "semgrep",
        "--json",
        "x",
    ]


def test_build_launched_argv_is_a_noop_with_an_empty_prefix():
    assert build_launched_argv([], ["trivy", "rootfs", "x"]) == ["trivy", "rootfs", "x"]


# --- WslPathTranslator ---------------------------------------------------------


def test_wsl_to_tool_translates_a_windows_drive_path():
    t = WslPathTranslator()
    assert t.to_tool(r"C:\Atharv's Stack\ECDAT\ecdat") == "/mnt/c/Atharv's Stack/ECDAT/ecdat"


def test_wsl_to_tool_lowercases_the_drive_letter():
    t = WslPathTranslator()
    assert t.to_tool(r"D:\repo") == "/mnt/d/repo"


def test_wsl_to_tool_leaves_a_non_drive_path_unchanged():
    t = WslPathTranslator()
    assert t.to_tool("relative/path") == "relative/path"


def test_wsl_from_tool_translates_an_mnt_path_back_to_windows():
    t = WslPathTranslator()
    assert t.from_tool("/mnt/c/Atharv's Stack/ECDAT/ecdat") == r"C:\Atharv's Stack\ECDAT\ecdat"


def test_wsl_from_tool_leaves_a_non_mnt_path_unchanged():
    t = WslPathTranslator()
    assert t.from_tool("/home/user/repo") == "/home/user/repo"


def test_wsl_round_trip_is_lossless_for_a_drive_path():
    t = WslPathTranslator()
    original = r"C:\Atharv's Stack\ECDAT\ecdat-harness\targets\payments\payment-gateway\src"
    assert t.from_tool(t.to_tool(original)) == original


def test_identity_translator_never_changes_a_path():
    t = IdentityPathTranslator()
    for path in (r"C:\some\path", "/mnt/c/some/path", "relative/path", ""):
        assert t.to_tool(path) == path
        assert t.from_tool(path) == path
