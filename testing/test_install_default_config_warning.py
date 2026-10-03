"""Warn once when the first install still targets the default ~/.zkg dirs."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ZKG = ROOT / "zkg"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        },
    )


def _make_package(path: Path) -> None:
    path.mkdir(parents=True)
    (path / "zkg.meta").write_text("[package]\n")
    (path / "__load__.zeek").write_text(f'print "{path.name} loaded";\n')
    _git(path, "init", "-b", "main")
    _git(path, "add", ".")
    _git(path, "commit", "-m", "init")


def _zkg_env(home: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["HOME"] = str(home)
    # Avoid cloning the public package source during a config-less install.
    env["ZKG_DEFAULT_SOURCE"] = ""
    for key in ("ZKG_CONFIG_FILE", "ZEEK_ZKG_CONFIG_DIR", "ZEEK_ZKG_STATE_DIR"):
        env.pop(key, None)
    return env


def _install(
    home: Path,
    package: Path,
    configfile: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(ZKG)]
    if configfile is not None:
        cmd.extend(["--configfile", str(configfile)])
    cmd.extend(
        ["install", "--force", "--skiptests", "--nodeps", str(package)],
    )
    return subprocess.run(
        cmd,
        cwd=home,
        env=_zkg_env(home),
        check=False,
        capture_output=True,
        text=True,
    )


def _warned(stderr: str, home: Path) -> bool:
    return (
        "warning:" in stderr
        and "zkg autoconfig" in stderr
        and str(home / ".zkg") in stderr
    )


def test_first_install_warns_once_and_custom_config_does_not(tmp_path: Path) -> None:
    pkg_a = tmp_path / "pkga"
    pkg_b = tmp_path / "pkgb"
    _make_package(pkg_a)
    _make_package(pkg_b)

    home = tmp_path / "home"
    home.mkdir()

    first = _install(home, pkg_a)
    assert first.returncode == 0, first.stderr
    assert _warned(first.stderr, home)
    assert first.stderr.count("zkg autoconfig") == 1
    assert f'Installed "{pkg_a}" (main)' in first.stdout
    assert (
        home / ".zkg" / "script_dir" / "packages" / "pkga" / "__load__.zeek"
    ).is_file()

    second = _install(home, pkg_b)
    assert second.returncode == 0, second.stderr
    assert not _warned(second.stderr, home)
    assert "zkg autoconfig" not in second.stderr
    assert f'Installed "{pkg_b}" (main)' in second.stdout

    custom_home = tmp_path / "custom-home"
    custom_home.mkdir()
    script_dir = tmp_path / "custom-scripts"
    plugin_dir = tmp_path / "custom-plugins"
    state_dir = tmp_path / "custom-state"
    configfile = tmp_path / "config"
    configfile.write_text(
        "[paths]\n"
        f"state_dir = {state_dir}\n"
        f"script_dir = {script_dir}\n"
        f"plugin_dir = {plugin_dir}\n",
    )

    custom = _install(custom_home, pkg_a, configfile)
    assert custom.returncode == 0, custom.stderr
    assert not _warned(custom.stderr, custom_home)
    assert "zkg autoconfig" not in custom.stderr
    assert f'Installed "{pkg_a}" (main)' in custom.stdout
    assert (script_dir / "packages" / "pkga" / "__load__.zeek").is_file()
    assert not (custom_home / ".zkg" / "script_dir" / "packages" / "pkga").exists()
