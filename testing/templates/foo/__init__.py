import zeekpkg.template
import zeekpkg.uservar

TEMPLATE_API_VERSION = "1.0.0"


class Package(zeekpkg.template.Package):
    def contentdir(self) -> str:
        return "package"

    def needed_user_vars(self) -> list[str]:
        return ["name"]

    def validate(self, tmpl: zeekpkg.template.Template) -> None:
        pass


class Readme(zeekpkg.template.Feature):
    def contentdir(self) -> str:
        return "readme"

    def needed_user_vars(self) -> list[str]:
        return ["readme"]

    def validate(self, tmpl: zeekpkg.template.Template) -> None:
        pass


class Template(zeekpkg.template.Template):
    def define_user_vars(self) -> list[zeekpkg.uservar.UserVar]:
        return [
            zeekpkg.uservar.UserVar(
                "name",
                desc='the name of the package, e.g. "FooBar"',
            ),
            zeekpkg.uservar.UserVar(
                "readme",
                desc="Content of the README file",
                val="This is a README.",
            ),
        ]

    def apply_user_vars(self, user_vars: list[zeekpkg.uservar.UserVar]) -> None:
        # ``name`` and ``readme`` are already parameters of the same name.
        for uvar in user_vars:
            if uvar.name() == "name":
                val = uvar.val()
                assert val is not None
                self.define_param("module", val.upper())

    def package(self) -> Package:
        return Package()

    def features(self) -> list[zeekpkg.template.Feature]:
        return [Readme()]

    def validate(self, tmpl: zeekpkg.template.Template) -> None:
        pass
