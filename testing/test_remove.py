"""Regression tests for removing a package other installed packages require."""

import argparse
import configparser
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# `zkg` is a top-level script, not an installed package module.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import zkg
from zeekpkg.manager import Manager
from zeekpkg.package import InstalledPackage, Package, PackageStatus

PROCEED = "Proceed? [Y/n] "
REMOVE_ANYWAY = "Package /foo/B is required by /foo/A, remove anyway? [N/y] "


@pytest.fixture
def manager(tmp_path: Path) -> Manager:
    with patch.object(Manager, "discover_builtin_packages", return_value=[]):
        return Manager(
            state_dir=str(tmp_path / "state"),
            script_dir=str(tmp_path / "scripts"),
            plugin_dir=str(tmp_path / "plugins"),
        )


def _package(
    name: str,
    *,
    depends: str | None = None,
    suggests: str | None = None,
    loaded: bool = False,
) -> InstalledPackage:
    metadata: dict[str, str] = {}

    if depends is not None:
        metadata["depends"] = depends

    if suggests is not None:
        metadata["suggests"] = suggests

    # git_url is the qualified name when the package has no source, matching
    # the paths shown by `zkg remove` for a package installed from a path.
    package = Package(
        git_url=f"/foo/{name}",
        name=name,
        canonical=True,
        metadata=metadata,
    )
    return InstalledPackage(package, PackageStatus(is_loaded=loaded))


def _install(manager: Manager, *packages: InstalledPackage) -> None:
    for ipkg in packages:
        manager.installed_pkgs[ipkg.package.name] = ipkg


def _remove(
    manager: Manager,
    responses: list[str],
    *packages: str,
    force: bool = False,
    nodeps: bool = False,
) -> list[str]:
    prompts: list[str] = []
    pending = list(responses)

    def _input(prompt: str = "") -> str:
        prompts.append(prompt)

        if not pending:
            raise AssertionError(f"unexpected prompt: {prompt!r}")

        return pending.pop(0)

    args = argparse.Namespace(
        package=list(packages),
        force=force,
        nodeps=nodeps,
    )

    with patch("zkg.input", side_effect=_input):
        zkg.cmd_remove(manager, args, configparser.ConfigParser(), "")

    return prompts


def test_default_answer_keeps_package_required_by_another(
    manager: Manager,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Empty answers accept Proceed? and decline the default-no follow-up."""
    _install(manager, _package("A", depends="B *"), _package("B"))

    prompts = _remove(manager, ["", ""], "foo/B")
    output = capsys.readouterr().out

    assert prompts == [PROCEED, REMOVE_ANYWAY]
    assert "The following packages will be REMOVED:" in output
    assert "  /foo/B\n" in output
    assert "UNLOADED" not in output
    assert "Abort." in output
    assert 'Removed "/foo/B"' not in output
    assert manager.find_installed_package("B") is not None
    assert manager.find_installed_package("A") is not None


def test_explicit_yes_still_removes_required_package(
    manager: Manager,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _install(manager, _package("A", depends="B *"), _package("B"))

    prompts = _remove(manager, ["", "y"], "foo/B")
    output = capsys.readouterr().out

    assert prompts == [PROCEED, REMOVE_ANYWAY]
    assert "Abort." not in output
    assert 'Removed "/foo/B"' in output
    assert manager.find_installed_package("B") is None
    assert manager.find_installed_package("A") is not None


def test_package_without_requirers_has_only_the_proceed_prompt(
    manager: Manager,
) -> None:
    _install(manager, _package("A", depends="B *"), _package("B"))

    prompts = _remove(manager, [""], "foo/A")

    assert prompts == [PROCEED]
    assert manager.find_installed_package("A") is None
    assert manager.find_installed_package("B") is not None


def test_declining_proceed_does_not_ask_about_requirers(manager: Manager) -> None:
    _install(manager, _package("A", depends="B *"), _package("B"))

    prompts = _remove(manager, ["n"], "foo/B")

    assert prompts == [PROCEED]
    assert manager.find_installed_package("B") is not None


def test_force_skips_prompts_and_removes_required_package(manager: Manager) -> None:
    _install(manager, _package("A", depends="B *"), _package("B"))

    prompts = _remove(manager, [], "foo/B", force=True)

    assert prompts == []
    assert manager.find_installed_package("B") is None
    assert manager.find_installed_package("A") is not None


def test_nodeps_skips_the_required_by_prompt(manager: Manager) -> None:
    _install(manager, _package("A", depends="B *"), _package("B"))

    prompts = _remove(manager, [""], "foo/B", nodeps=True)

    assert prompts == [PROCEED]
    assert manager.find_installed_package("B") is None


def test_removing_a_package_with_its_requirer_skips_the_extra_prompt(
    manager: Manager,
) -> None:
    _install(manager, _package("A", depends="B *"), _package("B"))

    prompts = _remove(manager, [""], "foo/A", "foo/B")

    assert prompts == [PROCEED]
    assert manager.find_installed_package("A") is None
    assert manager.find_installed_package("B") is None


def test_suggests_does_not_require_the_extra_prompt(manager: Manager) -> None:
    _install(manager, _package("A", suggests="B *"), _package("B"))

    prompts = _remove(manager, [""], "foo/B")

    assert prompts == [PROCEED]
    assert manager.find_installed_package("B") is None


def test_multiple_requirers_are_listed(
    manager: Manager,
) -> None:
    _install(
        manager,
        _package("A", depends="B *"),
        _package("C", depends="B *"),
        _package("B"),
    )

    prompts = _remove(manager, ["", ""], "foo/B")

    assert prompts == [
        PROCEED,
        "Package /foo/B is required by /foo/A, /foo/C, remove anyway? [N/y] ",
    ]
    assert manager.find_installed_package("B") is not None


def test_yes_still_unloads_a_loaded_requirer(
    manager: Manager,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _install(
        manager,
        _package("A", depends="B *", loaded=True),
        _package("B", loaded=True),
    )

    prompts = _remove(manager, ["", "y"], "foo/B")
    output = capsys.readouterr().out
    requirer = manager.find_installed_package("A")

    assert prompts == [PROCEED, REMOVE_ANYWAY]
    assert 'Unloaded "/foo/A"' in output
    assert 'Removed "/foo/B"' in output
    assert requirer is not None
    assert not requirer.status.is_loaded
    assert manager.find_installed_package("B") is None


def test_declining_does_not_unload_a_loaded_requirer(
    manager: Manager,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _install(
        manager,
        _package("A", depends="B *", loaded=True),
        _package("B", loaded=True),
    )

    prompts = _remove(manager, ["", ""], "foo/B")
    output = capsys.readouterr().out
    requirer = manager.find_installed_package("A")

    assert prompts == [PROCEED, REMOVE_ANYWAY]
    assert "The following dependent packages will be UNLOADED:" in output
    assert "  /foo/A\n" in output
    assert 'Unloaded "/foo/A"' not in output
    assert 'Removed "/foo/B"' not in output
    assert requirer is not None
    assert requirer.status.is_loaded
    assert manager.find_installed_package("B") is not None


def test_several_required_packages_share_one_follow_up_prompt(
    manager: Manager,
) -> None:
    _install(
        manager,
        _package("A", depends="B *"),
        _package("B"),
        _package("C", depends="D *"),
        _package("D"),
    )

    prompts = _remove(manager, ["", "n"], "foo/B", "foo/D")

    assert prompts == [
        PROCEED,
        "Package /foo/B is required by /foo/A\n"
        "Package /foo/D is required by /foo/C\n"
        "Remove anyway? [N/y] ",
    ]
    assert manager.find_installed_package("B") is not None
    assert manager.find_installed_package("D") is not None
