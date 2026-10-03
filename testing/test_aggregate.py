"""Aggregation must survive a single unparsable package metadata file."""

import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from zeekpkg.manager import Manager


def _git(repo: Path, *args: str) -> None:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "zkg",
            "GIT_AUTHOR_EMAIL": "zkg@zeek.org",
            "GIT_COMMITTER_NAME": "zkg",
            "GIT_COMMITTER_EMAIL": "zkg@zeek.org",
        },
    )
    subprocess.run(
        [
            "git",
            "-c",
            "init.defaultBranch=master",
            "-c",
            "user.name=zkg",
            "-c",
            "user.email=zkg@zeek.org",
            "-c",
            "protocol.file.allow=always",
            *args,
        ],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )


def _commit_repo(repo: Path, files: dict[str, str]) -> None:
    repo.mkdir(parents=True)
    _git(repo, "init")
    for name, content in files.items():
        path = repo / name
        path.write_text(content)
        _git(repo, "add", name)
    _git(repo, "commit", "-m", "init")


@pytest.fixture
def manager(tmp_path: Path) -> Manager:
    with patch.object(Manager, "discover_builtin_packages", return_value=[]):
        return Manager(
            state_dir=str(tmp_path / "state"),
            script_dir=str(tmp_path / "scripts"),
            plugin_dir=str(tmp_path / "plugins"),
        )


def test_broken_zkg_meta_does_not_abort_aggregation(
    tmp_path: Path,
    manager: Manager,
) -> None:
    """One metadata file the config parser rejects must not fail the registry.

    The broken package is listed first so an uncaught parse error aborts
    before the valid package is aggregated.
    """
    broken = tmp_path / "broken_pkg"
    good = tmp_path / "good_pkg"
    _commit_repo(
        broken,
        {"zkg.meta": '{\n  "description": "not ini"\n}\n'},
    )
    _commit_repo(
        good,
        {
            "zkg.meta": "[package]\ndescription = a working package\n",
            "__load__.zeek": 'print "hello";\n',
        },
    )

    source_work = tmp_path / "source"
    _commit_repo(
        source_work,
        {"zkg.index": f"{broken}\n{good}\n"},
    )
    bare = tmp_path / "source.git"
    subprocess.run(
        [
            "git",
            "-c",
            "protocol.file.allow=always",
            "clone",
            "--bare",
            str(source_work),
            str(bare),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert manager.add_source("registry", str(bare)) == ""

    result = manager.aggregate_source("registry")

    assert result.refresh_error == ""
    assert len(result.package_issues) == 1
    issue_url, issue_reason = result.package_issues[0]
    assert issue_url == str(broken)
    assert "failed to parse zkg.meta" in issue_reason

    aggregate = Path(manager.source_clonedir) / "registry" / "aggregate.meta"
    text = aggregate.read_text()
    assert "[good_pkg]" in text
    assert "a working package" in text
    assert "[broken_pkg]" not in text
