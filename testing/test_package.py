"""Package name matching treats a trailing ``.git`` as a URL suffix."""

import json
import os
import subprocess
import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from zeekpkg.manager import Manager
from zeekpkg.package import (
    InstalledPackage,
    Package,
    PackageStatus,
    _request_matches_package,
    name_from_path,
)
from zeekpkg.source import Source


def test_name_from_path_strips_git_suffix() -> None:
    assert name_from_path("https://github.com/initconf/log4j.git") == "log4j"
    assert name_from_path("https://github.com/initconf/log4j.git/") == "log4j"
    assert name_from_path("https://github.com/initconf/log4j") == "log4j"
    assert name_from_path("log4j.git") == "log4j"
    assert name_from_path("git@github.com:initconf/log4j.git") == "log4j"
    # A repo whose own name ends in ``.git`` keeps that name; only one suffix
    # is removed (``foo.git.git`` is the clone URL of a repo named ``foo.git``).
    assert name_from_path("https://github.com/initconf/foo.git.git") == "foo.git"
    # No slash before the repo: leave the scp-style string unchanged.
    assert name_from_path("git@github.com:log4j.git") == "git@github.com:log4j.git"
    assert name_from_path("https://example.com/.git") == ".git"


def test_index_url_git_suffix_matches_package_name() -> None:
    package = Package(
        git_url="https://github.com/initconf/log4j.git",
        source="zeek",
        directory="initconf",
    )

    assert package.git_url == "https://github.com/initconf/log4j.git"
    assert package.name == "log4j"
    assert package.qualified_name() == "zeek/initconf/log4j"
    assert package.matches_path("log4j")
    assert package.matches_path("log4j.git")
    assert package.matches_path("initconf/log4j")
    assert package.matches_path("initconf/log4j.git")
    assert package.matches_path("zeek/initconf/log4j")
    assert package.matches_path("zeek/initconf/log4j.git")
    assert not package.matches_path("log4shell")
    assert not package.matches_path("other/log4j")


def test_git_suffix_is_not_stripped_from_source_directory() -> None:
    package = Package(
        git_url="https://github.com/initconf/bar.git",
        source="zeek",
        directory="logs.git",
    )

    assert package.name == "bar"
    assert package.matches_path("logs.git/bar")
    assert package.matches_path("logs.git/bar.git")
    assert not package.matches_path("logs/bar")


def test_legacy_aggregate_section_still_loads(tmp_path: Path) -> None:
    index_dir = tmp_path / "initconf"
    index_dir.mkdir()
    (index_dir / "zkg.index").write_text(
        "https://github.com/initconf/log4j.git\n",
    )
    (tmp_path / "aggregate.meta").write_text(
        "[initconf/log4j.git]\ndescription = Log4j detector\n",
    )

    source = Source.__new__(Source)
    source.name = "zeek"
    source.clone = MagicMock()
    source.clone.working_dir = str(tmp_path)

    packages = source.packages()

    assert len(packages) == 1
    assert packages[0].name == "log4j"
    assert packages[0].git_url == "https://github.com/initconf/log4j.git"
    assert packages[0].metadata["description"] == "Log4j detector"


def test_find_installed_package_accepts_legacy_git_suffix(tmp_path: Path) -> None:
    with patch.object(Manager, "discover_builtin_packages", return_value=[]):
        manager = Manager(
            state_dir=str(tmp_path / "state"),
            script_dir=str(tmp_path / "scripts"),
            plugin_dir=str(tmp_path / "plugins"),
        )

    legacy = Package(
        git_url="https://github.com/initconf/log4j.git",
        source="zeek",
        directory="initconf",
        name="log4j.git",
        canonical=True,
    )
    installed = InstalledPackage(legacy, PackageStatus())
    manager.installed_pkgs["log4j.git"] = installed

    assert manager.find_installed_package("log4j") is installed
    assert manager.find_installed_package("log4j.git") is installed
    assert manager.find_installed_package("initconf/log4j") is installed
    # One extra suffix is the clone URL of a package named log4j.git, not this one.
    assert manager.find_installed_package("log4j.git.git") is None


def test_repeated_git_suffix_keeps_real_package_name() -> None:
    package = Package(
        git_url="https://github.com/initconf/foo.git.git",
        source="zeek",
        directory="alice",
    )

    assert package.name == "foo.git"
    assert package.matches_path("foo.git")
    assert package.matches_path("foo.git.git")
    assert package.matches_path("alice/foo.git.git")
    assert not package.matches_path("foo")
    assert not package.matches_path("foo.git.git.git")


def test_legacy_name_still_identifies_package() -> None:
    legacy = Package(
        git_url="https://github.com/initconf/log4j.git",
        source="zeek",
        directory="alice",
        name="log4j.git",
        canonical=True,
    )

    assert _request_matches_package(legacy, "log4j")
    assert _request_matches_package(legacy, "log4j.git")
    assert _request_matches_package(legacy, "alice/log4j")
    assert _request_matches_package(legacy, "zeek/alice/log4j")
    assert not _request_matches_package(legacy, "bob/log4j")
    assert not _request_matches_package(legacy, "log4j.git.git")

    double = Package(
        git_url="https://github.com/initconf/foo.git.git",
        source="zeek",
        directory="alice",
        name="foo.git.git",
        canonical=True,
    )

    assert _request_matches_package(double, "foo.git")
    assert _request_matches_package(double, "foo.git.git")
    assert not _request_matches_package(double, "foo")


def test_aggregate_section_url_must_match(tmp_path: Path) -> None:
    index_dir = tmp_path / "initconf"
    index_dir.mkdir()
    (index_dir / "zkg.index").write_text(
        "https://github.com/initconf/foo.git\n"
        "https://github.com/initconf/foo.git.git\n",
    )
    # The legacy key for foo.git is the canonical key for foo.git.git.
    (tmp_path / "aggregate.meta").write_text(
        "[initconf/foo.git]\n"
        "url = https://github.com/initconf/foo.git.git\n"
        "description = genuine foo.git\n"
        "[initconf/foo.git.git]\n"
        "url = https://github.com/initconf/foo.git.git\n"
        "description = ignored duplicate\n",
    )

    source = Source.__new__(Source)
    source.name = "zeek"
    source.clone = MagicMock()
    source.clone.working_dir = str(tmp_path)

    by_url = {pkg.git_url: pkg for pkg in source.packages()}

    assert by_url["https://github.com/initconf/foo.git"].metadata == {}
    assert (
        by_url["https://github.com/initconf/foo.git.git"].metadata["description"]
        == "genuine foo.git"
    )


def _manager(tmp_path: Path) -> Manager:
    with patch.object(Manager, "discover_builtin_packages", return_value=[]):
        return Manager(
            state_dir=str(tmp_path / "state"),
            script_dir=str(tmp_path / "scripts"),
            plugin_dir=str(tmp_path / "plugins"),
        )


def _install(manager: Manager, package: Package) -> InstalledPackage:
    installed = InstalledPackage(package, PackageStatus())
    manager.installed_pkgs[package.name] = installed
    return installed


def test_exact_installed_name_beats_git_alias(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    foo = _install(
        manager,
        Package(
            git_url="https://example.com/foo",
            source="zeek",
            directory="alice",
            name="foo",
            canonical=True,
        ),
    )
    foo_git = _install(
        manager,
        Package(
            git_url="https://example.com/foo.git.git",
            source="zeek",
            directory="alice",
            name="foo.git",
            canonical=True,
        ),
    )

    assert manager.find_installed_package("foo") is foo
    assert manager.find_installed_package("foo.git") is foo_git
    assert manager.find_installed_package("foo.git.git") is foo_git
    assert manager.find_installed_package("alice/foo") is foo

    assert manager.pin("foo.git") is foo_git
    assert foo.status.is_pinned is False
    assert foo_git.status.is_pinned is True

    script = Path(manager.script_dir) / "foo.git" / "__load__.zeek"
    script.parent.mkdir(parents=True)
    script.write_text('print "foo.git";\n')
    assert manager.load("foo.git") == ""
    assert foo_git.status.is_loaded is True
    assert foo.status.is_loaded is False

    assert manager.upgrade("foo") == "package is not outdated"
    assert manager.remove("foo") is True
    assert "foo" not in manager.installed_pkgs
    assert manager.installed_pkgs["foo.git"] is foo_git


def test_ambiguous_installed_alias_is_rejected(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    foo = _install(
        manager,
        Package(
            git_url="https://example.com/foo",
            source="zeek",
            directory="alice",
            name="foo",
            canonical=True,
        ),
    )
    # Legacy manifest key for a repository whose name is foo.git.
    legacy = _install(
        manager,
        Package(
            git_url="https://example.com/foo.git.git",
            source="zeek",
            directory="bob",
            name="foo.git.git",
            canonical=True,
        ),
    )

    assert manager.find_installed_package("foo") is foo
    assert manager.find_installed_package("foo.git.git") is legacy
    assert manager.find_installed_package("foo.git") is None

    reason = manager.install("foo.git")
    assert "matches multiple installed packages" in reason
    assert "foo" in manager.installed_pkgs
    assert "foo.git.git" in manager.installed_pkgs

    assert "matches multiple installed packages" in manager.upgrade("foo.git")
    assert "matches multiple installed packages" in manager.load("foo.git")
    assert manager.pin("foo.git") is None
    assert manager.remove("foo.git") is False
    assert foo.status.is_pinned is False
    assert legacy.status.is_loaded is False


def test_legacy_install_request_reenstalls_same_package(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    legacy = _install(
        manager,
        Package(
            git_url="https://github.com/initconf/log4j.git",
            source="zeek",
            directory="alice",
            name="log4j.git",
            canonical=True,
        ),
    )

    with (
        patch("zeekpkg.manager._clone_package") as clone,
        patch.object(manager, "_install", return_value="") as install,
    ):
        assert manager.install("log4j") == ""
        assert manager.install("bob/log4j") != ""

    clone.assert_called_once()
    install.assert_called_once()
    assert install.call_args.args[0] is legacy.package

    other = manager.install("bob/log4j")
    assert "already installed" in other
    assert manager.installed_pkgs["log4j.git"] is legacy


class _Source:
    def __init__(self, packages: list[Package]) -> None:
        self._packages = packages

    def packages(self) -> list[Package]:
        return self._packages


def test_source_match_prefers_exact_name_and_rejects_duplicates(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    foo = Package(
        git_url="https://example.com/alice/foo.git",
        source="zeek",
        directory="alice",
    )
    genuine = Package(
        git_url="https://example.com/alice/foo.git.git",
        source="zeek",
        directory="alice",
    )
    other_foo = Package(
        git_url="https://example.com/bob/foo",
        source="zeek",
        directory="bob",
    )
    assert foo.name == "foo"
    assert genuine.name == "foo.git"
    assert other_foo.name == "foo"

    manager.sources["zeek"] = _Source([foo, genuine])  # type: ignore[assignment]

    assert [pkg.name for pkg in manager.match_source_packages("foo")] == ["foo"]
    assert [pkg.name for pkg in manager.match_source_packages("foo.git")] == ["foo.git"]
    assert [pkg.name for pkg in manager.match_source_packages("foo.git.git")] == [
        "foo.git",
    ]

    manager.sources["zeek"] = _Source([foo, other_foo])  # type: ignore[assignment]
    reason = manager.install("foo.git")
    assert "matches multiple packages" in reason
    info = manager.info("foo", prefer_installed=False)
    assert "matches multiple packages" in info.invalid_reason


def _git_package(path: Path, script: str) -> str:
    path.mkdir(parents=True)
    (path / "zkg.meta").write_text("[package]\n")
    (path / "__load__.zeek").write_text(script)
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=path, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "commit", "-m", "init"],
        cwd=path,
        check=True,
        capture_output=True,
    )
    branch = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    )
    return branch.stdout.strip()


def test_bundle_round_trip_strips_git_suffix(tmp_path: Path) -> None:
    repo = tmp_path / "repos" / "log4j.git"
    branch = _git_package(repo, 'print "log4j loaded";\n')
    manager = _manager(tmp_path / "bundle-src")
    bundle_file = tmp_path / "log4j.bundle"

    assert manager.bundle(str(bundle_file), [(str(repo), branch)]) == ""

    with tarfile.open(bundle_file) as archive:
        names = [name.removeprefix("./") for name in archive.getnames()]

    assert any(name == "log4j" or name.startswith("log4j/") for name in names)
    assert not any(
        name == "log4j.git" or name.startswith("log4j.git/") for name in names
    )

    destination = _manager(tmp_path / "bundle-dst")
    assert destination.unbundle(str(bundle_file)) == ""
    assert "log4j" in destination.installed_pkgs
    assert "log4j.git" not in destination.installed_pkgs
    script = Path(destination.script_dir) / "log4j" / "__load__.zeek"
    assert "log4j loaded" in script.read_text()

    legacy_dir = tmp_path / "legacy"
    legacy_dir.mkdir()
    with tarfile.open(bundle_file) as archive:
        archive.extractall(legacy_dir, filter="data")
    os.rename(legacy_dir / "log4j", legacy_dir / "log4j.git")
    legacy_bundle = tmp_path / "legacy.bundle"
    with tarfile.open(legacy_bundle, "w:gz") as archive:
        for path in legacy_dir.rglob("*"):
            archive.add(path, arcname=str(path.relative_to(legacy_dir)))

    legacy_destination = _manager(tmp_path / "legacy-dst")
    assert legacy_destination.unbundle(str(legacy_bundle)) == ""
    assert "log4j" in legacy_destination.installed_pkgs
    assert (Path(legacy_destination.script_dir) / "log4j" / "__load__.zeek").is_file()


def test_legacy_manifest_reinstalls_by_new_name(tmp_path: Path) -> None:
    repo = tmp_path / "repos" / "log4j.git"
    branch = _git_package(repo, 'print "log4j loaded";\n')
    manager = _manager(tmp_path)

    class _Index:
        def packages(self) -> list[Package]:
            return [
                Package(
                    git_url=str(repo),
                    source="zeek",
                    directory="alice",
                ),
            ]

    manager.sources["zeek"] = _Index()  # type: ignore[assignment]
    assert manager.install("log4j", branch) == ""
    assert "log4j" in manager.installed_pkgs

    manifest_path = Path(manager.manifest)
    manifest = json.loads(manifest_path.read_text())
    renamed = False
    for item in manifest["installed_packages"]:
        if item["package_dict"]["name"] == "log4j":
            item["package_dict"]["name"] = "log4j.git"
            renamed = True
    assert renamed
    manifest_path.write_text(json.dumps(manifest))

    for base in (manager.package_clonedir, manager.script_dir, manager.plugin_dir):
        src = Path(base) / "log4j"
        if src.is_dir():
            os.rename(src, Path(base) / "log4j.git")

    reloaded = _manager(tmp_path)
    reloaded.sources["zeek"] = _Index()  # type: ignore[assignment]
    installed = reloaded.find_installed_package("log4j")
    assert installed is not None
    assert installed.package.name == "log4j.git"
    assert reloaded.upgrade("log4j") == "package is not outdated"
    assert reloaded.install("log4j", branch) == ""
    assert "log4j.git" in reloaded.installed_pkgs
    assert (Path(reloaded.script_dir) / "log4j.git" / "__load__.zeek").is_file()
