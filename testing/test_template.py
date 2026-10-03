"""Regression tests for template user-var availability and substitution."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

import zeekpkg.template
import zeekpkg.uservar

REPO_ROOT = Path(__file__).resolve().parents[1]
ZKG = REPO_ROOT / "zkg"


class _Package(zeekpkg.template.Package):
    def __init__(self, needed: list[str]) -> None:
        super().__init__()
        self._needed = needed

    def contentdir(self) -> str:
        return "package"

    def needed_user_vars(self) -> list[str]:
        return self._needed

    def validate(self, tmpl: zeekpkg.template.Template) -> None:
        return


class _Feature(zeekpkg.template.Feature):
    def __init__(self, feature_name: str, needed: list[str]) -> None:
        super().__init__()
        self._feature_name = feature_name
        self._needed = needed

    def name(self) -> str:
        return self._feature_name

    def contentdir(self) -> str:
        return self._feature_name

    def needed_user_vars(self) -> list[str]:
        return self._needed

    def validate(self, tmpl: zeekpkg.template.Template) -> None:
        return


class _Template(zeekpkg.template.Template):
    def __init__(
        self,
        defined: list[zeekpkg.uservar.UserVar],
        package_needed: list[str],
        features: list[zeekpkg.template.Feature] | None = None,
    ) -> None:
        super().__init__(templatedir=".", api_version="1.0.0")
        self._defined = defined
        self._package_needed = package_needed
        self._features = features or []

    def define_user_vars(self) -> list[zeekpkg.uservar.UserVar]:
        return self._defined

    def package(self) -> _Package:
        return _Package(self._package_needed)

    def features(self) -> list[zeekpkg.template.Feature]:
        return self._features


def test_info_aborts_when_feature_requires_undefined_user_var() -> None:
    tmpl = _Template([], [], [_Feature("spicy", ["analyzer"])])

    with pytest.raises(
        zeekpkg.template.InputError,
        match='Feature "spicy" requires undefined user var "analyzer"',
    ):
        tmpl.info()


def test_info_aborts_when_package_requires_undefined_user_var() -> None:
    tmpl = _Template([], ["name"], [])

    with pytest.raises(
        zeekpkg.template.InputError,
        match='Package requires undefined user var "name"',
    ):
        tmpl.info()


def test_info_records_users_of_defined_user_vars() -> None:
    tmpl = _Template(
        [zeekpkg.uservar.UserVar("name", desc="package name")],
        ["name"],
        [_Feature("readme", ["name"])],
    )

    info = tmpl.info()

    assert info["user_vars"]["name"]["used_by"] == ["package", "readme"]


@pytest.mark.parametrize("value", [None, ""])
def test_empty_required_user_var_aborts(value: str | None) -> None:
    uvar = zeekpkg.uservar.UserVar("name", val=value)
    tmpl = _Template([uvar], ["name"], [])

    with pytest.raises(
        zeekpkg.template.InputError,
        match='required user var "name" is not available',
    ):
        tmpl._set_user_vars([uvar])


def test_user_var_becomes_param_without_explicit_mapping() -> None:
    uvar = zeekpkg.uservar.UserVar("name", val="FooBar")
    tmpl = _Template([uvar], ["name"], [])

    tmpl._set_user_vars([uvar])

    assert tmpl.lookup_param("name") == "FooBar"


def test_apply_user_vars_can_override_default_param() -> None:
    class Overriding(_Template):
        def apply_user_vars(self, user_vars: list[zeekpkg.uservar.UserVar]) -> None:
            self.define_param("name", "custom")
            self.define_param("module", "CUSTOM")

    uvar = zeekpkg.uservar.UserVar("name", val="FooBar")
    tmpl = Overriding([uvar], ["name"], [])

    tmpl._set_user_vars([uvar])

    assert tmpl.lookup_param("name") == "custom"
    assert tmpl.lookup_param("module") == "CUSTOM"


def _write_template(directory: Path, source: str) -> None:
    directory.mkdir()
    (directory / "__init__.py").write_text(source)
    package = directory / "package"
    package.mkdir()
    (package / "README").write_text("hello @name@\n")


def _run_zkg(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = (
        str(REPO_ROOT) + os.pathsep + env["PYTHONPATH"]
        if env.get("PYTHONPATH")
        else str(REPO_ROOT)
    )
    env["ZEEK_ZKG_STATE_DIR"] = str(tmp_path / "zkg-state")
    env["ZEEK_ZKG_CONFIG_DIR"] = str(tmp_path / "zkg-config")
    env["GIT_AUTHOR_NAME"] = "Test User"
    env["GIT_AUTHOR_EMAIL"] = "test@example.com"
    env["GIT_COMMITTER_NAME"] = "Test User"
    env["GIT_COMMITTER_EMAIL"] = "test@example.com"
    return subprocess.run(
        [sys.executable, str(ZKG), *args],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


_DIRECT_TEMPLATE = """\
import zeekpkg.template
import zeekpkg.uservar

TEMPLATE_API_VERSION = "1.0.0"


class Package(zeekpkg.template.Package):
    def contentdir(self) -> str:
        return "package"

    def needed_user_vars(self) -> list[str]:
        return ["name"]

    def validate(self, tmpl: zeekpkg.template.Template) -> None:
        # Format checks only. Presence of required user vars is zkg's job.
        return


class Template(zeekpkg.template.Template):
    def define_user_vars(self) -> list[zeekpkg.uservar.UserVar]:
        return [zeekpkg.uservar.UserVar("name", desc="package name")]

    def package(self) -> Package:
        return Package()
"""


_UNDEFINED_FEATURE_TEMPLATE = """\
import zeekpkg.template

TEMPLATE_API_VERSION = "1.0.0"


class Package(zeekpkg.template.Package):
    def contentdir(self) -> str:
        return "package"

    def validate(self, tmpl: zeekpkg.template.Template) -> None:
        return


class Extra(zeekpkg.template.Feature):
    def contentdir(self) -> str:
        return "extra"

    def needed_user_vars(self) -> list[str]:
        return ["missing"]

    def validate(self, tmpl: zeekpkg.template.Template) -> None:
        return


class Template(zeekpkg.template.Template):
    def package(self) -> Package:
        return Package()

    def features(self) -> list[zeekpkg.template.Feature]:
        return [Extra()]
"""


def test_template_info_aborts_on_undefined_feature_user_var(tmp_path: Path) -> None:
    template = tmp_path / "tmpl"
    _write_template(template, _UNDEFINED_FEATURE_TEMPLATE)

    result = _run_zkg(tmp_path, "template", "info", str(template))

    assert result.returncode != 0
    assert (
        'error: Feature "extra" requires undefined user var "missing"' in result.stderr
    )
    assert "Traceback" not in result.stderr


def test_create_aborts_when_feature_requires_undefined_user_var(
    tmp_path: Path,
) -> None:
    template = tmp_path / "tmpl"
    _write_template(template, _UNDEFINED_FEATURE_TEMPLATE)
    packagedir = tmp_path / "out"

    result = _run_zkg(
        tmp_path,
        "create",
        "--force",
        "--packagedir",
        str(packagedir),
        "--template",
        str(template),
    )

    assert result.returncode != 0
    assert (
        'error: Feature "extra" requires undefined user var "missing"' in result.stderr
    )
    assert "Traceback" not in result.stderr
    assert not packagedir.exists()


def test_create_aborts_when_required_user_var_is_empty(tmp_path: Path) -> None:
    template = tmp_path / "tmpl"
    _write_template(template, _DIRECT_TEMPLATE)
    packagedir = tmp_path / "out"

    result = _run_zkg(
        tmp_path,
        "create",
        "--force",
        "--packagedir",
        str(packagedir),
        "--template",
        str(template),
        "--user-var",
        "name=",
    )

    assert result.returncode != 0
    assert 'required user var "name" is not available' in result.stderr
    assert "Traceback" not in result.stderr
    assert not packagedir.exists()


def test_create_substitutes_user_var_without_explicit_mapping(tmp_path: Path) -> None:
    template = tmp_path / "tmpl"
    _write_template(template, _DIRECT_TEMPLATE)
    packagedir = tmp_path / "out"

    result = _run_zkg(
        tmp_path,
        "create",
        "--force",
        "--packagedir",
        str(packagedir),
        "--template",
        str(template),
        "--user-var",
        "name=FooBar",
    )

    assert result.returncode == 0, result.stderr
    assert (packagedir / "README").read_text() == "hello FooBar\n"
