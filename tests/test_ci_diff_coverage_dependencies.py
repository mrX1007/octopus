"""Hermetic branch coverage for dependency preflight and SBOM inputs."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.tools import dependencies as deps
from scripts.quality import sbom

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("factory", "error", "match"),
    [
        (lambda: deps._required_text("\x00", "fixture"), ValueError, "non-empty"),
        (lambda: deps.resource("", "bad\\path"), ValueError, "relative POSIX"),
        (lambda: deps.PythonDependency("fixture", object()), TypeError, "distribution must be text"),
        (lambda: deps.PythonDependency("fixture", "bad package"), ValueError, "package name"),
        (lambda: deps.ResourceDependency(object(), "asset"), TypeError, "package must be text"),
        (lambda: deps.ResourceDependency("bad-package", "asset"), ValueError, "dotted import"),
        (lambda: deps.ResourceDependency("", "asset", "socket"), ValueError, "file or directory"),
        (lambda: deps.ServiceDependency("bad/service"), ValueError, "service name"),
        (lambda: deps.ServiceDependency("catalog", object()), TypeError, "secret name must be text"),
        (lambda: deps.ServiceDependency("catalog", "BAD-NAME"), ValueError, "must be an identifier"),
        (lambda: deps.ServiceDependency("catalog", environment="TOKEN"), TypeError, "must be a sequence"),
        (lambda: deps.VendorDependency("vendor/tool", object()), TypeError, "sha256 must be text"),
        (lambda: deps.DependencyGroup("sometimes", ()), ValueError, "mode must be all or any"),
        (lambda: deps.DependencyGroup(deps.DependencyMode.ALL, []), TypeError, "must be a tuple"),
        (
            lambda: deps.DependencyGroup(deps.DependencyMode.ALL, (object(),)),
            TypeError,
            "invalid dependency",
        ),
        (lambda: deps.normalize_dependencies(42), TypeError, "dependency or sequence"),
        (lambda: deps.DependencyContext(environment=[]), TypeError, "must be mappings"),
        (lambda: deps.DependencyContext(secret_resolver=object()), TypeError, "must be callable"),
    ],
)
def test_dependency_model_rejects_invalid_declarations(factory, error, match: str) -> None:
    with pytest.raises(error, match=match):
        factory()


def test_dependency_model_normalizes_and_serializes_every_token_form() -> None:
    converted_resource = deps.ResourceDependency("fixture.package", "assets", "directory")
    assert converted_resource.resource_type is deps.ResourceType.DIRECTORY

    digest = "a" * 64
    artifact = deps.vendor("vendor/tool.bin", sha256=digest)
    assert artifact.label == "vendor:vendor/tool.bin"
    assert artifact.to_dict() == {"kind": "vendor", "path": "vendor/tool.bin", "sha256": digest}

    environment_only = deps.ServiceDependency("catalog", environment=("TOKEN", "TOKEN"))
    assert environment_only.to_dict() == {
        "environment": ["TOKEN"],
        "kind": "service",
        "name": "catalog",
    }
    secret_only = deps.ServiceDependency("catalog", secret_name="CATALOG_TOKEN")
    assert secret_only.to_dict()["secret_name"] == "CATALOG_TOKEN"
    assert deps.vendor("vendor/tool.bin").to_dict() == {"kind": "vendor", "path": "vendor/tool.bin"}

    converted_group = deps.DependencyGroup("any", (deps.binary("curl"),))
    assert converted_group.mode is deps.DependencyMode.ANY
    assert deps.normalize_dependencies(None).items == ()

    tokens = {
        "all:python:json,binary:curl": deps.DependencyMode.ALL,
        "binary:curl": deps.DependencyKind.BINARY,
        "resource:directory:fixture.package:assets": deps.ResourceType.DIRECTORY,
        "resource:file:assets/schema.json": deps.ResourceType.FILE,
        "resource:fixture.package:assets/schema.json": deps.ResourceType.FILE,
        "service:catalog": deps.DependencyKind.SERVICE,
        "vendor:vendor/tool.bin": deps.DependencyKind.VENDOR,
    }
    for token, expected in tokens.items():
        normalized = deps.normalize_dependency(token)
        if isinstance(expected, deps.DependencyMode):
            assert normalized.mode is expected
        elif isinstance(expected, deps.ResourceType):
            assert normalized.resource_type is expected
        else:
            assert normalized.kind is expected


class _BrokenResource:
    def is_file(self) -> bool:
        raise OSError("fixture denied")

    def is_dir(self) -> bool:
        raise TypeError("fixture unsupported")


def test_dependency_path_and_packaged_resource_probes_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert deps._contained_local_path(tmp_path / "missing", "asset") is None
    assert deps._contained_local_path(tmp_path, "../outside") is None
    assert deps._resource_matches_type(_BrokenResource(), deps.ResourceType.FILE) is False
    assert deps._resource_matches_type(_BrokenResource(), deps.ResourceType.DIRECTORY) is False

    candidate = SimpleNamespace(is_file=lambda: True)
    package = SimpleNamespace(joinpath=lambda _path: candidate)
    monkeypatch.setattr(deps.importlib.resources, "files", lambda _package: package)
    requirement = deps.resource("fixture.package", "asset.txt")
    assert deps._resource_available(requirement, deps.DependencyContext(root=tmp_path)) is True

    def missing_package(_package: str):
        raise ModuleNotFoundError("fixture package")

    monkeypatch.setattr(deps.importlib.resources, "files", missing_package)
    assert deps._resource_available(requirement, deps.DependencyContext(root=tmp_path)) is False


def test_dependency_evaluation_error_paths_and_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable_secret(_name: str) -> str:
        raise RuntimeError("fixture resolver denied")

    context = deps.DependencyContext(root=tmp_path, environment={}, secret_resolver=unavailable_secret)
    secret = deps.service("catalog", secret_name="CATALOG_TOKEN")
    assert deps._service_available(secret, context) is False
    assert deps._service_available(deps.service("catalog"), context) is False

    monkeypatch.setitem(sys.modules, "config", SimpleNamespace(get_secret=lambda _name: "configured"))
    default_resolver_context = deps.DependencyContext(root=tmp_path, environment={})
    assert deps._service_available(secret, default_resolver_context) is True

    monkeypatch.setattr(
        deps.importlib.util,
        "find_spec",
        lambda _name: (_ for _ in ()).throw(ValueError("invalid module")),
    )
    evaluation = deps.evaluate_dependency(deps.python("fixture_missing"), context)
    assert evaluation.available is False
    assert evaluation.to_dict() == {
        "available": False,
        "children": [],
        "detail": "missing",
        "requirement": {"import_name": "fixture_missing", "kind": "python", "name": "fixture_missing"},
    }


def _write_dependency_manifest(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_vendor_dependency_rejects_invalid_manifests_and_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requirement = deps.vendor("vendor/tool.bin")
    assert deps._vendor_available(requirement, deps.DependencyContext(root=tmp_path / "missing")) is False

    manifest = tmp_path / "manifest.json"
    manifest.write_text("not-json", encoding="utf-8")
    context = deps.DependencyContext(root=tmp_path, vendor_manifest=manifest)
    assert deps._vendor_available(requirement, context) is False

    for payload in (
        {"schema_version": 2, "artifacts": []},
        {"schema_version": 1, "artifacts": {}},
        {"schema_version": 1, "artifacts": []},
        {
            "schema_version": 1,
            "artifacts": [{"path": "vendor/tool.bin", "sha256": "invalid"}],
        },
    ):
        _write_dependency_manifest(manifest, payload)
        assert deps._vendor_available(requirement, context) is False

    _write_dependency_manifest(
        manifest,
        {
            "schema_version": 1,
            "artifacts": [{"path": "vendor/tool.bin", "sha256": "a" * 64}],
        },
    )
    assert deps._vendor_available(requirement, context) is False
    assert deps._vendor_available(deps.vendor("vendor/tool.bin", sha256="b" * 64), context) is False

    artifact = tmp_path / "vendor" / "tool.bin"
    artifact.parent.mkdir()
    artifact.write_bytes(b"fixture")
    digest = hashlib.sha256(b"fixture").hexdigest()
    _write_dependency_manifest(
        manifest,
        {"schema_version": 1, "artifacts": [{"path": "vendor/tool.bin", "sha256": digest}]},
    )
    original_read_bytes = Path.read_bytes

    def denied_read(path: Path) -> bytes:
        if path == artifact:
            raise OSError("fixture denied")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", denied_read)
    assert deps._vendor_available(requirement, context) is False


def test_vendor_dependency_rejects_symlink_manifest(tmp_path: Path) -> None:
    target = _write_dependency_manifest(
        tmp_path / "manifest-target.json",
        {"schema_version": 1, "artifacts": []},
    )
    link = tmp_path / "manifest.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("filesystem does not support symlink fixtures")
    context = deps.DependencyContext(root=tmp_path, vendor_manifest=link)
    assert deps._vendor_available(deps.vendor("vendor/tool.bin"), context) is False


def test_sbom_file_and_path_guards_are_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    regular = tmp_path / "regular.txt"
    regular.write_text("fixture", encoding="utf-8")
    link = tmp_path / "linked.txt"
    try:
        link.symlink_to(regular)
    except OSError:
        pytest.skip("filesystem does not support symlink fixtures")

    with pytest.raises(sbom.SbomError, match="must not be a symlink"):
        sbom._read_text(link, "fixture")
    with pytest.raises(sbom.SbomError, match="not a regular file"):
        sbom._sha256_file(tmp_path, "fixture")

    original_read_bytes = Path.read_bytes

    def denied_read(path: Path) -> bytes:
        if path == regular:
            raise OSError("fixture denied")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", denied_read)
    with pytest.raises(sbom.SbomError, match="cannot hash fixture: OSError"):
        sbom._sha256_file(regular, "fixture")

    for value in (None, "", "bad\\path", "/absolute", "../outside", "bad\x00path"):
        with pytest.raises(sbom.SbomError, match="invalid fixture path"):
            sbom._relative_path(value, "fixture path")
    with pytest.raises(sbom.SbomError, match="traverses a symlink"):
        sbom._repository_candidate(tmp_path, "linked.txt", "fixture")
    with pytest.raises(sbom.SbomError, match="escapes the repository"):
        sbom._repository_candidate(tmp_path, "../outside", "fixture")


def test_sbom_tree_digest_rejects_missing_and_symlinked_entries(tmp_path: Path) -> None:
    with pytest.raises(sbom.SbomError, match="resource directory is unavailable"):
        sbom._tree_digest(tmp_path / "missing", tmp_path)

    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "ordinary-directory").mkdir()
    real_directory = tmp_path / "real-directory"
    real_directory.mkdir()
    directory_link = tree / "linked-directory"
    try:
        directory_link.symlink_to(real_directory, target_is_directory=True)
    except OSError:
        pytest.skip("filesystem does not support symlink fixtures")
    with pytest.raises(sbom.SbomError, match="directory contains a symlink"):
        sbom._tree_digest(tree, tmp_path)

    directory_link.unlink()
    target = tmp_path / "target.txt"
    target.write_text("fixture", encoding="utf-8")
    (tree / "linked-file").symlink_to(target)
    with pytest.raises(sbom.SbomError, match="directory contains a non-file"):
        sbom._tree_digest(tree, tmp_path)


def test_sbom_project_identity_defaults_and_ignores_other_sections(tmp_path: Path) -> None:
    assert sbom._project_identity(tmp_path) == ("octopus-security", "0+unknown")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.fixture]\nname = "ignored"\n[project]\nname = "demo_app"\n'
        'description = "ignored"\n[build-system]\nversion = "ignored"\n',
        encoding="utf-8",
    )
    assert sbom._project_identity(tmp_path) == ("demo_app", "0+unknown")


def test_sbom_rejects_duplicate_python_lock_components(tmp_path: Path) -> None:
    lock = tmp_path / "requirements.txt"
    lock.write_text(
        f"Demo_Pkg==1.0 --hash=sha256:{'a' * 64}\ndemo-pkg==1.0 --hash=sha256:{'b' * 64}\n",
        encoding="utf-8",
    )
    with pytest.raises(sbom.SbomError, match="duplicate Python lock component"):
        sbom._python_components(lock)


def _write_go_inputs(tmp_path: Path, go_mod_text: str, go_sum_text: str = "") -> tuple[Path, Path]:
    go_mod = tmp_path / "go.mod"
    go_sum = tmp_path / "go.sum"
    go_mod.write_text(go_mod_text, encoding="utf-8")
    go_sum.write_text(go_sum_text, encoding="utf-8")
    return go_mod, go_sum


@pytest.mark.parametrize(
    ("go_mod_text", "error"),
    [
        ("module example.test/root\nrequire (\nrequire (\n", "nested require block"),
        ("module example.test/root\n)\n", "unexpected closing block"),
        (
            "module example.test/root\nrequire (\nexample.test/dependency v1.0.0 extra\n)\n",
            "invalid go.mod requirement",
        ),
        ("module example.test/root\nrequire example.test/dependency\n", "invalid go.mod requirement"),
        ("module example.test/root\nmodule example.test/other\n", "one module declaration"),
        ("module example.test/root\nreplace old.example/mod => new.example/mod v1.0.0\n", "unsupported go.mod"),
        (
            "module example.test/root\nrequire example.test/dependency v1.0.0\n"
            "require example.test/dependency v2.0.0\n",
            "conflicting versions",
        ),
        ("module example.test/root\nrequire (\n", "unterminated require block"),
        ("go 1.21\n", "missing module declaration"),
    ],
)
def test_sbom_rejects_invalid_go_mod_structures(tmp_path: Path, go_mod_text: str, error: str) -> None:
    go_mod, go_sum = _write_go_inputs(tmp_path, go_mod_text)
    with pytest.raises(sbom.SbomError, match=error):
        sbom._go_requirements(go_mod, go_sum)


_GO_DIGEST_A = base64.b64encode(b"a" * 32).decode("ascii")
_GO_DIGEST_B = base64.b64encode(b"b" * 32).decode("ascii")


@pytest.mark.parametrize(
    ("go_sum_text", "error"),
    [
        ("invalid row\n", "invalid go.sum row"),
        ("example.test/dependency v1.0.0 sha256:value\n", "unsupported Go module checksum"),
        ("example.test/dependency v1.0.0 h1:not-base64!\n", "invalid Go module checksum"),
        (
            f"example.test/dependency v1.0.0 h1:{base64.b64encode(b'short').decode('ascii')}\n",
            "invalid Go SHA-256 checksum",
        ),
        (
            f"example.test/dependency v1.0.0 h1:{_GO_DIGEST_A}\nexample.test/dependency v1.0.0 h1:{_GO_DIGEST_B}\n",
            "conflicting Go module checksums",
        ),
    ],
)
def test_sbom_rejects_invalid_go_sum_rows(tmp_path: Path, go_sum_text: str, error: str) -> None:
    go_mod, go_sum = _write_go_inputs(
        tmp_path,
        "module example.test/root\nrequire example.test/dependency v1.0.0\n",
        go_sum_text,
    )
    with pytest.raises(sbom.SbomError, match=error):
        sbom._go_requirements(go_mod, go_sum)


def test_sbom_accepts_go_mod_checksum_rows_and_indirect_block(tmp_path: Path) -> None:
    go_mod, go_sum = _write_go_inputs(
        tmp_path,
        "module example.test/root\n\n// fixture comment\ngo 1.21\n"
        "require (\nexample.test/dependency v1.0.0 // indirect\n)\n",
        f"example.test/dependency v1.0.0/go.mod h1:{_GO_DIGEST_B}\nexample.test/dependency v1.0.0 h1:{_GO_DIGEST_A}\n",
    )
    module, components = sbom._go_requirements(go_mod, go_sum)
    assert module == "example.test/root"
    assert components[0]["properties"] == [{"name": "octopus:go:indirect", "value": "true"}]


def test_sbom_rejects_a_synthetically_whitespace_bearing_go_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SyntheticDeclaration(str):
        def strip(self, _characters=None):
            return self

        def split(self, separator=None, maxsplit=-1):
            if separator == "//":
                return [self]
            if separator is None:
                return ["require", "bad dependency", "v1.0.0"]
            return super().split(separator, maxsplit)

    class SyntheticText:
        @staticmethod
        def splitlines():
            return [SyntheticDeclaration("require fixture")]

    monkeypatch.setattr(sbom, "_read_text", lambda _path, _label: SyntheticText())
    with pytest.raises(sbom.SbomError, match=r"invalid go\.mod requirement"):
        sbom._go_requirements(tmp_path / "go.mod", tmp_path / "go.sum")


def test_sbom_component_identity_is_required_and_conflicts_fail_closed() -> None:
    with pytest.raises(sbom.SbomError, match="missing bom-ref"):
        sbom._add_component({}, {})
    components = {"fixture": {"bom-ref": "fixture", "name": "first"}}
    with pytest.raises(sbom.SbomError, match="conflicting component identity"):
        sbom._add_component(components, {"bom-ref": "fixture", "name": "second"})


def _write_sbom_manifest(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_sbom_vendor_components_include_submodule_and_platform_filtered_artifact(tmp_path: Path) -> None:
    submodule = tmp_path / "vendor" / "source"
    submodule.mkdir(parents=True)
    artifact = tmp_path / "vendor" / "tool.bin"
    artifact.write_bytes(b"fixture artifact")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    generic_artifact = tmp_path / "vendor" / "generic.bin"
    generic_artifact.write_bytes(b"generic artifact")
    generic_digest = hashlib.sha256(generic_artifact.read_bytes()).hexdigest()
    manifest = _write_sbom_manifest(
        tmp_path / "vendor-manifest.json",
        {
            "schema_version": 1,
            "submodules": [{"path": "vendor/source", "commit": "a" * 40}],
            "artifacts": [
                {
                    "path": "vendor/tool.bin",
                    "sha256": digest,
                    "platform": {"arch": "", "os": "linux"},
                },
                {"path": "vendor/generic.bin", "sha256": generic_digest, "platform": None},
            ],
        },
    )
    components = sbom._vendor_components(tmp_path, manifest)
    assert [component["type"] for component in components] == ["library", "file", "file"]
    platform_component = next(component for component in components if component["name"] == "tool.bin")
    assert platform_component["properties"] == [
        {"name": "octopus:vendor:os", "value": "linux"},
        {"name": "octopus:vendor:path", "value": "vendor/tool.bin"},
    ]


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        ({}, "schema_version must be 1"),
        ({"schema_version": 1, "submodules": {}, "artifacts": []}, "must contain submodules and artifacts lists"),
        ({"schema_version": 1, "submodules": [None], "artifacts": []}, "submodule entry must be an object"),
        (
            {
                "schema_version": 1,
                "submodules": [{"path": "vendor/source", "commit": "invalid"}],
                "artifacts": [],
            },
            "invalid or duplicate vendor submodule",
        ),
        (
            {
                "schema_version": 1,
                "submodules": [{"path": "vendor/missing", "commit": "a" * 40}],
                "artifacts": [],
            },
            "submodule directory is unavailable",
        ),
        ({"schema_version": 1, "submodules": [], "artifacts": [None]}, "artifact entry must be an object"),
        (
            {
                "schema_version": 1,
                "submodules": [],
                "artifacts": [{"path": "vendor/tool.bin", "sha256": "invalid"}],
            },
            "invalid or duplicate vendor artifact",
        ),
    ],
)
def test_sbom_vendor_manifest_validation(tmp_path: Path, payload: object, error: str) -> None:
    manifest = _write_sbom_manifest(tmp_path / "vendor-manifest.json", payload)
    with pytest.raises(sbom.SbomError, match=error):
        sbom._vendor_components(tmp_path, manifest)


def test_sbom_vendor_manifest_rejects_invalid_json(tmp_path: Path) -> None:
    manifest = tmp_path / "vendor-manifest.json"
    manifest.write_text("not-json", encoding="utf-8")
    with pytest.raises(sbom.SbomError, match="not valid JSON"):
        sbom._vendor_components(tmp_path, manifest)


def test_registered_inventory_loader_restores_sys_path_and_validates_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = list(sys.path)
    registry = SimpleNamespace(dependency_inventory=lambda: {"schema_version": "1.0", "tools": []})
    monkeypatch.setattr(
        sbom.importlib,
        "import_module",
        lambda name: registry if name == "core.tools.registry" else SimpleNamespace(),
    )
    assert sbom.load_registered_tool_inventory(tmp_path) == {"schema_version": "1.0", "tools": []}
    assert sys.path == before

    broken_registry = SimpleNamespace(dependency_inventory=list)
    monkeypatch.setattr(
        sbom.importlib,
        "import_module",
        lambda name: broken_registry if name == "core.tools.registry" else SimpleNamespace(),
    )
    with pytest.raises(sbom.SbomError, match="inventory is not an object"):
        sbom.load_registered_tool_inventory(tmp_path)

    def unavailable_import(_name: str):
        raise ImportError("fixture unavailable")

    monkeypatch.setattr(sbom.importlib, "import_module", unavailable_import)
    with pytest.raises(sbom.SbomError, match=r"cannot load registered-tool.*ImportError"):
        sbom.load_registered_tool_inventory(tmp_path)
    assert sys.path == before


def test_registered_inventory_loader_preserves_preexisting_path_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "path", [str(tmp_path), *sys.path])
    registry = SimpleNamespace(dependency_inventory=lambda: {"schema_version": "1.0", "tools": []})
    monkeypatch.setattr(
        sbom.importlib,
        "import_module",
        lambda name: registry if name == "core.tools.registry" else SimpleNamespace(),
    )
    before = list(sys.path)
    assert sbom.load_registered_tool_inventory(tmp_path)["tools"] == []
    assert sys.path == before


def _inventory(expression: object) -> dict:
    return {
        "schema_version": "1.0",
        "tools": [{"name": "fixture", "dependencies": expression}],
    }


@pytest.mark.parametrize(
    ("inventory", "error"),
    [
        ({"schema_version": "2.0", "tools": []}, "inventory schema is invalid"),
        ({"schema_version": "1.0", "tools": [None]}, "record must be an object"),
        ({"schema_version": "1.0", "tools": [{"name": "", "dependencies": {}}]}, "inventory name"),
        (
            {
                "schema_version": "1.0",
                "tools": [
                    {"name": "same", "dependencies": {"kind": "binary", "name": "curl"}},
                    {"name": "same", "dependencies": {"kind": "binary", "name": "curl"}},
                ],
            },
            "duplicate tool inventory name",
        ),
        (_inventory(None), "expression must be an object"),
        (_inventory({"mode": "some", "items": []}), "group is invalid"),
        (_inventory({"kind": "binary", "name": "bad/name"}), "binary dependency name is invalid"),
        (_inventory({"kind": "python", "name": ""}), "Python dependency name is invalid"),
        (
            _inventory({"kind": "resource", "package": "", "path": "asset", "resource_type": "socket"}),
            "resource type is invalid",
        ),
        (_inventory({"kind": "service", "name": "bad/name"}), "service dependency name is invalid"),
        (_inventory({"kind": "unknown"}), "unknown tool dependency kind"),
    ],
)
def test_tool_dependency_inventory_rejects_invalid_records(tmp_path: Path, inventory: dict, error: str) -> None:
    with pytest.raises(sbom.SbomError, match=error):
        sbom._tool_dependency_components(tmp_path, inventory)


def test_tool_dependency_inventory_covers_local_packaged_and_external_families(tmp_path: Path) -> None:
    asset = tmp_path / "asset.txt"
    asset.write_text("fixture", encoding="utf-8")
    tree = tmp_path / "assets"
    tree.mkdir()
    (tree / "nested.txt").write_text("nested", encoding="utf-8")
    inventory = _inventory(
        {
            "mode": "all",
            "items": [
                {"kind": "binary", "name": "curl"},
                {"kind": "python", "distribution": "Demo_Pkg"},
                {
                    "kind": "resource",
                    "package": "fixture.package",
                    "path": "schema.json",
                    "resource_type": "file",
                },
                {"kind": "resource", "package": "", "path": "asset.txt", "resource_type": "file"},
                {"kind": "resource", "package": "", "path": "assets", "resource_type": "directory"},
                {"kind": "service", "name": "catalog"},
                {"kind": "vendor", "path": "vendor/tool.bin"},
            ],
        }
    )
    components, services, properties, references = sbom._tool_dependency_components(tmp_path, inventory)
    assert len(components) == 6
    assert services == [{"bom-ref": "urn:octopus:service:catalog", "name": "catalog"}]
    assert len(properties) == 2
    assert "urn:octopus:service:catalog" in references


def _write_minimal_lock(path: Path) -> Path:
    path.write_text(f"demo==1.0 --hash=sha256:{'a' * 64}\n", encoding="utf-8")
    return path


def test_repository_sbom_without_optional_inputs_and_locked_tool_mapping(tmp_path: Path) -> None:
    lock = _write_minimal_lock(tmp_path / "requirements.lock")
    payload = sbom.build_repository_sbom(Path(lock.name), tmp_path)
    assert payload["metadata"]["component"]["name"] == "octopus-security"
    assert "services" not in payload

    inventory = _inventory(
        {
            "mode": "all",
            "items": [
                {"kind": "python", "distribution": "demo"},
                {"kind": "python", "distribution": "unlocked"},
                {"kind": "binary", "name": "curl"},
                {"kind": "service", "name": "catalog"},
            ],
        }
    )
    with_inventory = sbom.build_repository_sbom(lock, tmp_path, tool_inventory=inventory)
    references = {component["bom-ref"] for component in with_inventory["components"]}
    assert "pkg:pypi/demo@1.0" in references
    assert "pkg:pypi/demo" not in references
    assert with_inventory["services"] == [{"bom-ref": "urn:octopus:service:catalog", "name": "catalog"}]


def test_repository_sbom_rejects_missing_root(tmp_path: Path) -> None:
    with pytest.raises(sbom.SbomError, match="cannot resolve repository root"):
        sbom.build_repository_sbom(Path("requirements.lock"), tmp_path / "missing")
