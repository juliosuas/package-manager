"""CLI commands that do not need Zeek must not warn when it is absent.

The package.zeek.org updater runs ``refresh``, ``list``, ``config``, and
``info`` with no ``zeek`` binary on PATH. Those commands used to log
``unable to discover builtin-packages`` on every invocation.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import zkg

_ROOT = Path(__file__).resolve().parents[1]
_ZKG = _ROOT / "zkg"
_MISSING_ZEEK_WARNING = (
    'unable to discover builtin-packages: No "zeek" executable in PATH'
)

# Minimal ``zeek --build-info`` stand-in so discovery can succeed without
# a real Zeek installation.
_FAKE_ZEEK = """#!/bin/sh
if [ "$1" = "--build-info" ]; then
    printf '%s\\n' '{"zkg":{"provides":[{"name":"spicy-plugin","version":"1.2.3","commit":"abc123"}]}}'
    exit 0
fi
echo "unexpected args: $*" >&2
exit 1
"""


def _isolated_env(tmp_path: Path, *, with_zeek: bool) -> dict[str, str]:
    """Return an environment whose PATH cannot see a real zeek binary."""
    bindir = tmp_path / "pathbin"
    bindir.mkdir()
    git = shutil.which("git")
    assert git is not None
    (bindir / "git").symlink_to(git)

    if with_zeek:
        zeek = bindir / "zeek"
        zeek.write_text(_FAKE_ZEEK)
        zeek.chmod(0o755)

    env = os.environ.copy()
    for key in (
        "ZKG_CONFIG_FILE",
        "ZEEK_ZKG_CONFIG_DIR",
        "ZEEK_ZKG_STATE_DIR",
        "ZKG_DEFAULT_SOURCE",
        "ZKG_DEFAULT_TEMPLATE",
        "ZEEKPATH",
        "ZEEK_PLUGIN_PATH",
    ):
        env.pop(key, None)

    home = tmp_path / "home"
    home.mkdir()
    env["HOME"] = str(home)
    env["PATH"] = str(bindir)
    return env


def _write_config(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.write_text(
        "\n".join(
            [
                "[sources]",
                "[paths]",
                f"state_dir = {tmp_path / 'state'}",
                f"script_dir = {tmp_path / 'scripts'}",
                f"plugin_dir = {tmp_path / 'plugins'}",
                f"bin_dir = {tmp_path / 'bin'}",
                "zeek_dist =",
                "",
            ],
        ),
    )
    return config


def _run_zkg(
    tmp_path: Path,
    args: list[str],
    *,
    with_zeek: bool,
) -> subprocess.CompletedProcess[str]:
    config = _write_config(tmp_path)
    return subprocess.run(
        [sys.executable, str(_ZKG), "--configfile", str(config), *args],
        cwd=tmp_path,
        env=_isolated_env(tmp_path, with_zeek=with_zeek),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


@pytest.mark.parametrize(
    "args",
    [
        ["config", "state_dir"],
        ["list", "all", "--nodesc"],
        ["refresh"],
        ["search", "nosuch"],
        ["env"],
    ],
)
def test_commands_without_zeek_stay_quiet(tmp_path: Path, args: list[str]) -> None:
    """Updater-style commands succeed and do not warn when zeek is missing."""
    result = _run_zkg(tmp_path, args, with_zeek=False)

    assert result.returncode == 0, result.stderr
    assert _MISSING_ZEEK_WARNING not in result.stderr
    assert _MISSING_ZEEK_WARNING not in result.stdout


def test_info_without_zeek_stays_quiet(tmp_path: Path) -> None:
    """``zkg info --nolocal`` does not need a zeek binary."""
    result = _run_zkg(
        tmp_path,
        ["info", "nosuchpkg", "--json", "--nolocal", "--allvers"],
        with_zeek=False,
    )

    assert _MISSING_ZEEK_WARNING not in result.stderr
    assert _MISSING_ZEEK_WARNING not in result.stdout
    assert result.returncode == 1
    assert "invalid" in result.stdout


def test_autoconfig_without_zeek_stays_quiet(tmp_path: Path) -> None:
    """autoconfig reports a missing zeek-config without the builtin warning."""
    result = _run_zkg(tmp_path, ["autoconfig"], with_zeek=False)

    assert _MISSING_ZEEK_WARNING not in result.stderr
    assert 'no "zeek-config" in PATH' in result.stderr
    assert result.returncode != 0


def test_upgrade_still_warns_without_zeek(tmp_path: Path) -> None:
    """Commands that resolve built-in packages still warn when zeek is missing."""
    result = _run_zkg(tmp_path, ["upgrade"], with_zeek=False)

    assert result.returncode == 0, result.stderr
    assert _MISSING_ZEEK_WARNING in result.stderr
    assert "All packages already up-to-date." in result.stdout


def test_remove_still_warns_without_zeek(tmp_path: Path) -> None:
    result = _run_zkg(tmp_path, ["remove", "--force", "nosuch"], with_zeek=False)

    assert _MISSING_ZEEK_WARNING in result.stderr
    assert 'package "nosuch" is not installed' in result.stderr


def test_list_include_builtin_still_uses_zeek(tmp_path: Path) -> None:
    """Discovery still runs for quiet commands when zeek is on PATH."""
    result = _run_zkg(
        tmp_path,
        ["list", "installed", "--include-builtin", "--nodesc"],
        with_zeek=True,
    )

    assert result.returncode == 0, result.stderr
    assert _MISSING_ZEEK_WARNING not in result.stderr
    assert "zeek-builtin/spicy-plugin (installed: 1.2.3)" in result.stdout


def test_list_hides_builtins_by_default(tmp_path: Path) -> None:
    result = _run_zkg(
        tmp_path,
        ["list", "installed", "--nodesc"],
        with_zeek=True,
    )

    assert result.returncode == 0, result.stderr
    assert "spicy-plugin" not in result.stdout


def test_allowlist_matches_commands_that_do_not_need_zeek() -> None:
    for name in (
        "autoconfig",
        "config",
        "create",
        "env",
        "info",
        "list",
        "refresh",
        "search",
    ):
        assert name in zkg.COMMANDS_WITHOUT_ZEEK

    for name in ("install", "upgrade", "test", "remove", "bundle", "unbundle", "load"):
        assert name not in zkg.COMMANDS_WITHOUT_ZEEK
