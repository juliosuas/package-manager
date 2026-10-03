import configparser
from pathlib import Path

import git

from zeekpkg.template import Template

_TEMPLATE_INIT = """\
import zeekpkg.template

TEMPLATE_API_VERSION = "1.0.0"


class Package(zeekpkg.template.Package):
    def contentdir(self) -> str:
        return "package"

    def validate(self, tmpl: zeekpkg.template.Template) -> None:
        pass


class Template(zeekpkg.template.Template):
    def apply_user_vars(self, user_vars: list[zeekpkg.uservar.UserVar]) -> None:
        pass

    def package(self) -> Package:
        return Package()
"""


def _init_template_repo(path: Path) -> git.Repo:
    repo = git.Repo.init(path)
    (path / "__init__.py").write_text(_TEMPLATE_INIT)
    repo.index.add(["__init__.py"])
    actor = git.Actor("Test", "test@example.com")
    repo.index.commit("initial", author=actor, committer=actor)
    return repo


def _load(path: Path) -> Template:
    return Template.load(configparser.ConfigParser(), str(path))


class TestTemplateLoadLocalRepo:
    """Template.load on a local git checkout uses the current commit."""

    def test_attached_head_uses_commit_sha(self, tmp_path: Path) -> None:
        repo = _init_template_repo(tmp_path)
        sha = repo.head.commit.hexsha

        tmpl = _load(tmp_path)

        assert tmpl.version() == sha[:8]

    def test_detached_head_uses_commit_sha(self, tmp_path: Path) -> None:
        repo = _init_template_repo(tmp_path)
        repo.git.checkout("--detach")
        assert repo.head.is_detached
        sha = repo.head.commit.hexsha

        tmpl = _load(tmp_path)

        assert tmpl.version() == sha[:8]
